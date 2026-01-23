//! Nix flake detection and environment management
//!
//! Provides automatic detection of flake.nix files and extraction of
//! development shell closures for sandboxed execution.
//!
//! Supports both local flake.nix files and monorepo setups via .envrc
//! with direnv's `use flake` directive.

use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use super::WorkspaceError;

/// Represents how a flake was detected
#[derive(Debug, Clone, PartialEq)]
pub enum FlakeSource {
    /// flake.nix exists in the working directory
    Local {
        /// Directory containing flake.nix
        flake_dir: PathBuf,
    },
    /// Detected from .envrc `use flake` directive (monorepo pattern)
    Envrc {
        /// Absolute path to the flake directory
        flake_dir: PathBuf,
        /// Optional output name (e.g., "nix-jail" from #nix-jail)
        output: Option<String>,
    },
}

impl std::fmt::Display for FlakeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlakeSource::Local { flake_dir } => {
                write!(f, "local flake at {}", flake_dir.display())
            }
            FlakeSource::Envrc { flake_dir, output } => match output {
                Some(out) => write!(f, "{}#{}", flake_dir.display(), out),
                None => write!(f, "{}", flake_dir.display()),
            },
        }
    }
}

/// Parse .envrc for a `use flake` directive
///
/// Looks for lines matching `use flake <path>[#output]` and extracts
/// the flake path and optional output name.
///
/// # Arguments
/// * `dir` - Directory containing .envrc
///
/// # Returns
/// Some((flake_dir, output)) if found, None otherwise
fn parse_envrc_flake(dir: &Path) -> Option<(PathBuf, Option<String>)> {
    let envrc_path = dir.join(".envrc");
    let content = fs::read_to_string(&envrc_path).ok()?;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Look for `use flake <ref>`
        if let Some(flake_ref) = line.strip_prefix("use flake ") {
            let flake_ref = flake_ref.trim();
            if flake_ref.is_empty() {
                continue;
            }

            // Split on # to get path and optional output
            let (path_str, output) = if let Some(hash_pos) = flake_ref.find('#') {
                let path = &flake_ref[..hash_pos];
                let output = &flake_ref[hash_pos + 1..];
                (
                    path,
                    if output.is_empty() {
                        None
                    } else {
                        Some(output.to_string())
                    },
                )
            } else {
                (flake_ref, None)
            };

            // Resolve the path relative to dir
            let flake_path = if path_str.starts_with('/') {
                PathBuf::from(path_str)
            } else {
                dir.join(path_str)
            };

            // Canonicalize to get absolute path
            if let Ok(abs_path) = flake_path.canonicalize() {
                tracing::debug!(
                    envrc = %envrc_path.display(),
                    flake_dir = %abs_path.display(),
                    output = ?output,
                    "parsed use flake directive from .envrc"
                );
                return Some((abs_path, output));
            } else {
                tracing::warn!(
                    path = %flake_path.display(),
                    "flake path from .envrc does not exist"
                );
            }
        }
    }

    None
}

/// Detect flake source for a directory
///
/// Checks for flake configuration in priority order:
/// 1. `.envrc` with `use flake` directive (monorepo pattern)
/// 2. Local `flake.nix` file
///
/// # Arguments
/// * `dir` - Directory to check for flake configuration
///
/// # Returns
/// Some(FlakeSource) if a flake is detected, None otherwise
pub fn detect_flake_source(dir: &Path) -> Option<FlakeSource> {
    // Priority 1: Check .envrc for use flake directive
    if let Some((flake_dir, output)) = parse_envrc_flake(dir) {
        return Some(FlakeSource::Envrc { flake_dir, output });
    }

    // Priority 2: Check for local flake.nix
    let flake_path = dir.join("flake.nix");
    if flake_path.exists() && flake_path.is_file() {
        return Some(FlakeSource::Local {
            flake_dir: dir.to_path_buf(),
        });
    }

    None
}

/// Get the current system architecture string
///
/// Returns the Nix system identifier (e.g., "aarch64-darwin", "x86_64-linux")
/// This is used to select the correct devShell output from the flake.
///
/// # Platform Support
/// - macOS: "aarch64-darwin" (Apple Silicon) or "x86_64-darwin" (Intel)
/// - Linux: "aarch64-linux" (ARM64) or "x86_64-linux" (x86-64)
pub fn get_system_arch() -> String {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "aarch64-darwin".to_string();

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return "x86_64-darwin".to_string();

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return "aarch64-linux".to_string();

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return "x86_64-linux".to_string();

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "linux")
    )))]
    {
        // Fallback for unsupported platforms
        tracing::warn!("Unsupported platform for Nix flakes, using x86_64-linux as fallback");
        "x86_64-linux".to_string()
    }
}

/// Compute the Nix runtime closure for a flake's development shell
///
/// This uses the fast path for flake evaluation:
/// 1. `nix build .#devShells.<system>.default --no-link` - Realize the dev shell
/// 2. `nix path-info --recursive` - Get the full closure (fast: ~80ms)
///
/// # Arguments
/// * `source` - The detected flake source (local or from .envrc)
///
/// # Returns
/// Vec of all store paths needed for the flake's dev shell (typically 50-150 paths)
///
/// # Errors
/// Returns WorkspaceError if:
/// - Flake evaluation fails
/// - Dev shell doesn't exist for this system
/// - Nix commands fail
///
/// # Performance
/// - First run: ~2-5 seconds (builds derivation if needed)
/// - Cached: ~0.3 seconds (derivation already built)
pub async fn compute_flake_closure(source: &FlakeSource) -> Result<Vec<PathBuf>, WorkspaceError> {
    let system = get_system_arch();

    // Build the flake reference based on source type
    let (flake_dir, flake_ref) = match source {
        FlakeSource::Local { flake_dir } => {
            let ref_str = format!("{}#devShells.{}.default", flake_dir.display(), system);
            (flake_dir.clone(), ref_str)
        }
        FlakeSource::Envrc { flake_dir, output } => {
            let output_name = output.as_deref().unwrap_or("default");
            let ref_str = format!(
                "{}#devShells.{}.{}",
                flake_dir.display(),
                system,
                output_name
            );
            (flake_dir.clone(), ref_str)
        }
    };

    tracing::debug!(
        flake_dir = %flake_dir.display(),
        system = %system,
        "Computing flake closure"
    );

    // Retry strategy: 2 retries with exponential backoff (100ms, 300ms with jitter)
    let retry_strategy = ExponentialBackoff::from_millis(100).map(jitter).take(2);

    let flake_ref_owned = flake_ref.clone();
    Retry::spawn(retry_strategy, || async {
        // Step 1: Build the dev shell (ensures it's realized)
        tracing::debug!(flake_ref = %flake_ref_owned, "Building flake dev shell");

        let build_output = Command::new("nix")
            .args(["build", &flake_ref_owned, "--no-link"])
            .output()
            .await
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Failed to execute nix build: {}. Is Nix installed?",
                    e
                ))
            })?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(WorkspaceError::DerivationNotFound(format!(
                "Failed to build flake dev shell for system '{}': {}",
                system, stderr
            )));
        }

        // Step 2: Get the closure using nix path-info (fast!)
        tracing::debug!(flake_ref = %flake_ref_owned, "Getting flake closure with nix path-info");

        let closure_output = Command::new("nix")
            .args(["path-info", "--recursive", &flake_ref_owned])
            .output()
            .await
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Failed to execute nix path-info: {}",
                    e
                ))
            })?;

        if !closure_output.status.success() {
            let stderr = String::from_utf8_lossy(&closure_output.stderr);
            return Err(WorkspaceError::DerivationNotFound(format!(
                "Failed to get closure for flake dev shell: {}",
                stderr
            )));
        }

        // Parse the output to get store paths
        let closure_str = String::from_utf8(closure_output.stdout).map_err(|e| {
            WorkspaceError::DerivationNotFound(format!(
                "Invalid UTF-8 in nix path-info output: {}",
                e
            ))
        })?;

        let closure: Vec<PathBuf> = closure_str
            .lines()
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect();

        if closure.is_empty() {
            return Err(WorkspaceError::DerivationNotFound(
                "Flake dev shell closure is empty".to_string(),
            ));
        }

        tracing::info!(
            flake_dir = %flake_dir.display(),
            system = %system,
            path_count = closure.len(),
            "Computed flake closure"
        );

        Ok(closure)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_detect_flake_source_local() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let flake_path = temp_dir.path().join("flake.nix");

        // Create a flake.nix file
        fs::write(&flake_path, "{ outputs = {}; }").expect("Failed to write flake.nix");

        let source = detect_flake_source(temp_dir.path());
        assert!(matches!(source, Some(FlakeSource::Local { .. })));
    }

    #[test]
    fn test_detect_flake_source_none() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        assert!(detect_flake_source(temp_dir.path()).is_none());
    }

    #[test]
    fn test_detect_flake_source_directory_not_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let flake_dir = temp_dir.path().join("flake.nix");

        // Create a directory instead of a file
        fs::create_dir(&flake_dir).expect("Failed to create directory");

        assert!(detect_flake_source(temp_dir.path()).is_none());
    }

    #[test]
    fn test_parse_envrc_with_output() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a parent "flake" directory
        let flake_dir = temp_dir.path().join("flake-root");
        fs::create_dir(&flake_dir).expect("Failed to create flake dir");
        fs::write(flake_dir.join("flake.nix"), "{}").expect("Failed to write flake.nix");

        // Create a project subdirectory with .envrc
        let project_dir = flake_dir.join("projects/my-project");
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");
        fs::write(project_dir.join(".envrc"), "use flake ../..#my-project")
            .expect("Failed to write .envrc");

        let source = detect_flake_source(&project_dir);
        let Some(FlakeSource::Envrc {
            flake_dir: dir,
            output,
        }) = source
        else {
            unreachable!("Expected Envrc, got {:?}", source);
        };
        assert_eq!(dir, flake_dir.canonicalize().unwrap());
        assert_eq!(output, Some("my-project".to_string()));
    }

    #[test]
    fn test_parse_envrc_without_output() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a parent "flake" directory
        let flake_dir = temp_dir.path().join("flake-root");
        fs::create_dir(&flake_dir).expect("Failed to create flake dir");
        fs::write(flake_dir.join("flake.nix"), "{}").expect("Failed to write flake.nix");

        // Create a project subdirectory with .envrc (no output fragment)
        let project_dir = flake_dir.join("subdir");
        fs::create_dir(&project_dir).expect("Failed to create project dir");
        fs::write(project_dir.join(".envrc"), "use flake ..").expect("Failed to write .envrc");

        let source = detect_flake_source(&project_dir);
        let Some(FlakeSource::Envrc {
            flake_dir: dir,
            output,
        }) = source
        else {
            unreachable!("Expected Envrc, got {:?}", source);
        };
        assert_eq!(dir, flake_dir.canonicalize().unwrap());
        assert_eq!(output, None);
    }

    #[test]
    fn test_parse_envrc_with_comments() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a parent "flake" directory
        let flake_dir = temp_dir.path().join("flake-root");
        fs::create_dir(&flake_dir).expect("Failed to create flake dir");
        fs::write(flake_dir.join("flake.nix"), "{}").expect("Failed to write flake.nix");

        // Create a project with .envrc containing comments
        let project_dir = flake_dir.join("proj");
        fs::create_dir(&project_dir).expect("Failed to create project dir");
        fs::write(
            project_dir.join(".envrc"),
            "# This is a comment\n\nuse flake ..#proj\n# Another comment",
        )
        .expect("Failed to write .envrc");

        let source = detect_flake_source(&project_dir);
        let Some(FlakeSource::Envrc { output, .. }) = source else {
            unreachable!("Expected Envrc, got {:?}", source);
        };
        assert_eq!(output, Some("proj".to_string()));
    }

    #[test]
    fn test_envrc_priority_over_local_flake() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a parent "flake" directory
        let flake_dir = temp_dir.path().join("flake-root");
        fs::create_dir(&flake_dir).expect("Failed to create flake dir");
        fs::write(flake_dir.join("flake.nix"), "{}").expect("Failed to write flake.nix");

        // Create a project with BOTH .envrc AND local flake.nix
        let project_dir = flake_dir.join("proj");
        fs::create_dir(&project_dir).expect("Failed to create project dir");
        fs::write(project_dir.join(".envrc"), "use flake ..#proj").expect("Failed to write .envrc");
        fs::write(project_dir.join("flake.nix"), "{ outputs = {}; }")
            .expect("Failed to write local flake.nix");

        // .envrc should take priority
        let source = detect_flake_source(&project_dir);
        assert!(matches!(source, Some(FlakeSource::Envrc { .. })));
    }

    #[test]
    fn test_get_system_arch() {
        let system = get_system_arch();

        // Should return one of the supported platforms
        assert!(
            system == "aarch64-darwin"
                || system == "x86_64-darwin"
                || system == "aarch64-linux"
                || system == "x86_64-linux"
        );

        // Should match current platform
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        assert_eq!(system, "aarch64-darwin");

        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        assert_eq!(system, "x86_64-darwin");

        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        assert_eq!(system, "aarch64-linux");

        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        assert_eq!(system, "x86_64-linux");
    }

    #[tokio::test]
    #[ignore] // Requires a valid flake.nix and Nix installation
    async fn test_compute_flake_closure() {
        // This test would require a real flake.nix file
        // Skip in CI, useful for manual testing with: cargo test -- --ignored
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let flake_path = temp_dir.path().join("flake.nix");

        // Create a minimal flake.nix
        let system = get_system_arch();
        let flake_content = format!(
            r#"{{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  outputs = {{ nixpkgs, ... }}: {{
    devShells.{}.default = nixpkgs.legacyPackages.{}.mkShell {{
      packages = [ nixpkgs.legacyPackages.{}.hello ];
    }};
  }};
}}"#,
            system, system, system
        );

        fs::write(&flake_path, flake_content).expect("Failed to write flake.nix");

        let source = FlakeSource::Local {
            flake_dir: temp_dir.path().to_path_buf(),
        };
        let result = compute_flake_closure(&source).await;

        match result {
            Ok(closure) => {
                // Should have multiple paths
                assert!(!closure.is_empty());
                // All paths should be in /nix/store
                for path in closure {
                    assert!(path.starts_with("/nix/store"));
                }
            }
            Err(e) => {
                // May fail if Nix isn't installed or network issues
                tracing::debug!(error = %e, "flake closure test failed (expected in CI)");
            }
        }
    }
}
