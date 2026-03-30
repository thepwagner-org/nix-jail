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

/// Detect flake sources for multiple project paths within a workspace
///
/// Calls `detect_flake_source` for each path's resolved directory. Returns
/// only paths where a flake was actually found.
///
/// # Arguments
/// * `workspace_root` - Root directory of the workspace (git checkout root)
/// * `paths` - Project paths relative to workspace_root
///
/// # Returns
/// Vec of (relative_path, FlakeSource) for each path that has a flake
pub fn detect_flake_sources(
    workspace_root: &Path,
    paths: &[impl AsRef<str>],
) -> Vec<(String, FlakeSource)> {
    let mut sources = Vec::new();
    for path in paths {
        let path_str = path.as_ref();
        if path_str.is_empty() || path_str == "." {
            continue;
        }
        let dir = workspace_root.join(path_str);
        if !dir.is_dir() {
            tracing::debug!(path = %path_str, "skipping non-existent path for flake detection");
            continue;
        }
        if let Some(source) = detect_flake_source(&dir) {
            tracing::info!(path = %path_str, source = %source, "detected flake for extra path");
            sources.push((path_str.to_string(), source));
        }
    }
    sources
}

/// Generate a composite flake.nix that merges multiple project devShells
///
/// Writes a wrapper flake to `workspace_root/flake.nix` that uses `inputsFrom`
/// to combine all detected devShells. The first project's nixpkgs is used as
/// the base via `follows`.
///
/// # Arguments
/// * `workspace_root` - Where to write the composite flake.nix
/// * `sources` - (relative_path, FlakeSource) pairs from `detect_flake_sources`
///
/// # Returns
/// A FlakeSource::Local pointing at the workspace root, or an error if the
/// wrapper could not be written.
///
/// # Panics
/// Panics if `sources` is empty (caller should handle single-source case directly)
pub fn generate_composite_flake(
    workspace_root: &Path,
    sources: &[(String, FlakeSource)],
) -> Result<FlakeSource, WorkspaceError> {
    assert!(
        !sources.is_empty(),
        "generate_composite_flake called with no sources"
    );

    // Check if any source's flake_dir resolves to workspace_root itself.
    // If so, writing the wrapper to workspace_root/flake.nix would overwrite
    // the original and create a circular `path:./` import.  Instead, write
    // the wrapper to a sibling directory outside the git tree.
    let any_source_is_root = sources.iter().any(|(_, source)| {
        let flake_dir = match source {
            FlakeSource::Local { flake_dir } => flake_dir,
            FlakeSource::Envrc { flake_dir, .. } => flake_dir,
        };
        flake_dir == workspace_root
    });

    let (wrapper_dir, use_absolute) = if any_source_is_root {
        let parent = workspace_root.parent().ok_or_else(|| {
            WorkspaceError::IoError(std::io::Error::other(
                "workspace_root has no parent directory",
            ))
        })?;
        let wrapper = parent.join("composite");
        fs::create_dir_all(&wrapper).map_err(WorkspaceError::IoError)?;

        // Wrapper lives outside the workspace tree. Nix copies the flake
        // directory to the store before evaluating, so relative paths like
        // `../workspace` would resolve against /nix/store/<hash>-source/
        // rather than the filesystem. Use absolute paths instead — Nix
        // fetches `path:/absolute/...` inputs from the host before eval.
        (wrapper, true)
    } else {
        (workspace_root.to_path_buf(), false)
    };

    let system = get_system_arch();

    // Build input declarations and devShell references
    // Use alphabetic labels: a, b, c, ...
    let mut input_lines = Vec::new();
    let mut input_names = Vec::new();
    let mut devshell_refs = Vec::new();

    for (i, (path, source)) in sources.iter().enumerate() {
        let label = (b'a' + i as u8) as char;
        let label_str = label.to_string();

        // Determine the flake directory relative to workspace root.
        // For Local sources, the flake_dir IS the project dir (same as path).
        // For Envrc sources, flake_dir may point elsewhere (e.g. monorepo root).
        let flake_dir = match source {
            FlakeSource::Local { flake_dir } => flake_dir,
            FlakeSource::Envrc { flake_dir, .. } => flake_dir,
        };

        // Try to strip workspace_root prefix to get a relative path.
        // Fall back to the project path if the flake_dir is outside the workspace
        // (shouldn't happen in practice since the workspace contains all projects).
        let rel = flake_dir
            .strip_prefix(workspace_root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from(path));

        // When the wrapper lives outside the workspace, use absolute paths
        // so Nix resolves them on the host filesystem before copying to the
        // store. Relative paths like `../workspace` would break because Nix
        // evaluates them relative to the store copy.
        let input_path = if use_absolute {
            if rel.as_os_str().is_empty() {
                workspace_root.to_path_buf()
            } else {
                workspace_root.join(&rel)
            }
        } else {
            // Wrapper is at workspace root — use ./ + rel (safe: inputs are inside the flake tree)
            PathBuf::from(".").join(&rel)
        };

        input_lines.push(format!(
            "    {label}.url = \"path:{}\";",
            input_path.display()
        ));

        let output_name = match source {
            FlakeSource::Envrc { output, .. } => output.as_deref().unwrap_or("default"),
            FlakeSource::Local { .. } => "default",
        };

        devshell_refs.push(format!(
            "          {label}.devShells.{system}.{output_name}"
        ));

        input_names.push(label_str);
    }

    // First project's nixpkgs is inherited via follows
    let first_label = &input_names[0];
    input_lines.push(format!("    nixpkgs.follows = \"{first_label}/nixpkgs\";"));

    let inputs_block = input_lines.join("\n");
    let input_params = input_names
        .iter()
        .map(|n| n.as_str())
        .chain(std::iter::once("nixpkgs"))
        .collect::<Vec<_>>()
        .join(", ");
    let devshells_block = devshell_refs.join("\n");

    let flake_content = format!(
        r#"{{
  inputs = {{
{inputs_block}
  }};
  outputs = {{ {input_params}, ... }}: {{
    devShells.{system}.default = nixpkgs.legacyPackages.{system}.mkShell {{
      inputsFrom = [
{devshells_block}
      ];
    }};
  }};
}}"#
    );

    let flake_path = wrapper_dir.join("flake.nix");
    fs::write(&flake_path, &flake_content).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!(
            "failed to write composite flake.nix: {}",
            e
        )))
    })?;

    tracing::info!(
        path = %flake_path.display(),
        project_count = sources.len(),
        "wrote composite flake.nix"
    );

    Ok(FlakeSource::Local {
        flake_dir: wrapper_dir,
    })
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

    #[test]
    fn test_detect_flake_sources_multiple() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let root = temp_dir.path();

        // Create two project dirs with flakes
        let proj_a = root.join("projects/alpha");
        let proj_b = root.join("projects/beta");
        fs::create_dir_all(&proj_a).unwrap();
        fs::create_dir_all(&proj_b).unwrap();

        fs::write(proj_a.join("flake.nix"), "{}").unwrap();
        fs::write(proj_b.join("flake.nix"), "{}").unwrap();

        // Create a project dir WITHOUT a flake
        let proj_c = root.join("projects/gamma");
        fs::create_dir_all(&proj_c).unwrap();

        let sources =
            detect_flake_sources(root, &["projects/alpha", "projects/beta", "projects/gamma"]);
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].0, "projects/alpha");
        assert_eq!(sources[1].0, "projects/beta");
        assert!(matches!(sources[0].1, FlakeSource::Local { .. }));
        assert!(matches!(sources[1].1, FlakeSource::Local { .. }));
    }

    #[test]
    fn test_detect_flake_sources_skips_nonexistent() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let sources = detect_flake_sources(temp_dir.path(), &["does/not/exist"]);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_detect_flake_sources_skips_dot_and_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let sources = detect_flake_sources(temp_dir.path(), &[".", ""]);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_generate_composite_flake_two_projects() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let root = temp_dir.path();

        let proj_a = root.join("projects/meow");
        let proj_b = root.join("projects/nix-jail");
        fs::create_dir_all(&proj_a).unwrap();
        fs::create_dir_all(&proj_b).unwrap();

        let sources = vec![
            (
                "projects/meow".to_string(),
                FlakeSource::Local {
                    flake_dir: proj_a.clone(),
                },
            ),
            (
                "projects/nix-jail".to_string(),
                FlakeSource::Local {
                    flake_dir: proj_b.clone(),
                },
            ),
        ];

        let result = generate_composite_flake(root, &sources).unwrap();
        assert!(matches!(result, FlakeSource::Local { .. }));

        let flake_content = fs::read_to_string(root.join("flake.nix")).unwrap();

        // Should reference both projects as inputs
        assert!(flake_content.contains("a.url = \"path:./projects/meow\""));
        assert!(flake_content.contains("b.url = \"path:./projects/nix-jail\""));

        // Should use follows for nixpkgs from first input
        assert!(flake_content.contains("nixpkgs.follows = \"a/nixpkgs\""));

        // Should have inputsFrom with both devShells
        assert!(flake_content.contains("inputsFrom"));
        assert!(flake_content.contains("a.devShells."));
        assert!(flake_content.contains("b.devShells."));
    }

    #[test]
    fn test_generate_composite_flake_with_envrc() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let root = temp_dir.path();

        let flake_root = root.join("nix");
        let proj_a = root.join("projects/alpha");
        fs::create_dir_all(&flake_root).unwrap();
        fs::create_dir_all(&proj_a).unwrap();

        let sources = vec![
            (
                "projects/alpha".to_string(),
                FlakeSource::Envrc {
                    flake_dir: flake_root.clone(),
                    output: Some("alpha".to_string()),
                },
            ),
            (
                "projects/beta".to_string(),
                FlakeSource::Local {
                    flake_dir: root.join("projects/beta"),
                },
            ),
        ];

        // Create the beta dir so strip_prefix works
        fs::create_dir_all(root.join("projects/beta")).unwrap();

        let result = generate_composite_flake(root, &sources).unwrap();
        assert!(matches!(result, FlakeSource::Local { .. }));

        let flake_content = fs::read_to_string(root.join("flake.nix")).unwrap();

        // Envrc source should point at the flake root, not the project dir
        assert!(flake_content.contains("a.url = \"path:./nix\""));
        // And use the named output
        assert!(flake_content.contains("a.devShells."));
        assert!(flake_content.contains(".alpha"));

        // Local source uses project path directly
        assert!(flake_content.contains("b.url = \"path:./projects/beta\""));
        assert!(flake_content.contains("b.devShells."));
    }

    #[test]
    fn test_generate_composite_flake_avoids_circular_root_import() {
        // Reproduces the circular import bug: when extra_paths have .envrc
        // pointing back to the workspace root (e.g. `use flake ../..#media`),
        // the composite wrapper must NOT be written to workspace_root/flake.nix
        // because the input `path:./` would reference the wrapper itself.
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Simulate job directory: {base}/workspace/
        let base = temp_dir.path().join("job-base");
        let workspace = base.join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        // Write an original root flake.nix (this should NOT be overwritten)
        fs::write(workspace.join("flake.nix"), "{ /* original root flake */ }").unwrap();

        // Both sources point at workspace root with different outputs
        // (monorepo pattern: projects/media/.envrc → use flake ../..#media)
        let sources = vec![
            (
                "projects/media".to_string(),
                FlakeSource::Envrc {
                    flake_dir: workspace.clone(),
                    output: Some("media".to_string()),
                },
            ),
            (
                "projects/typedown".to_string(),
                FlakeSource::Envrc {
                    flake_dir: workspace.clone(),
                    output: Some("typedown".to_string()),
                },
            ),
        ];

        let result = generate_composite_flake(&workspace, &sources).unwrap();

        // Wrapper should be written to a sibling directory, not workspace root
        match &result {
            FlakeSource::Local { flake_dir } => {
                assert_ne!(
                    flake_dir, &workspace,
                    "wrapper must not be at workspace root"
                );
                assert_eq!(flake_dir, &base.join("composite"));
            }
            _ => panic!("expected FlakeSource::Local"),
        }

        // Original root flake.nix should be preserved
        let original = fs::read_to_string(workspace.join("flake.nix")).unwrap();
        assert!(
            original.contains("original root flake"),
            "root flake.nix was overwritten"
        );

        // Wrapper should use absolute paths to the workspace, not relative paths
        // that would break when Nix copies the flake to the store
        let wrapper = fs::read_to_string(base.join("composite/flake.nix")).unwrap();
        assert!(
            !wrapper.contains("path:./"),
            "wrapper must not self-reference: {}",
            wrapper
        );
        assert!(
            !wrapper.contains("path:../"),
            "wrapper must not use relative paths outside its tree: {}",
            wrapper
        );
        let ws_str = workspace.display().to_string();
        assert!(
            wrapper.contains(&format!("path:{ws_str}")),
            "wrapper should reference workspace via absolute path: {}",
            wrapper
        );

        // Both outputs should be referenced
        assert!(
            wrapper.contains(".media"),
            "missing media output: {}",
            wrapper
        );
        assert!(
            wrapper.contains(".typedown"),
            "missing typedown output: {}",
            wrapper
        );
    }

    #[test]
    fn test_generate_composite_flake_mixed_root_and_local() {
        // One source at workspace root (via envrc), one with a local flake
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let base = temp_dir.path().join("job-base");
        let workspace = base.join("workspace");
        let proj_local = workspace.join("projects/local-proj");
        fs::create_dir_all(&proj_local).unwrap();

        // Write original root flake
        fs::write(workspace.join("flake.nix"), "{ /* root */ }").unwrap();

        let sources = vec![
            (
                "projects/media".to_string(),
                FlakeSource::Envrc {
                    flake_dir: workspace.clone(),
                    output: Some("media".to_string()),
                },
            ),
            (
                "projects/local-proj".to_string(),
                FlakeSource::Local {
                    flake_dir: proj_local.clone(),
                },
            ),
        ];

        let result = generate_composite_flake(&workspace, &sources).unwrap();

        // Should redirect to composite dir since one source is at root
        match &result {
            FlakeSource::Local { flake_dir } => {
                assert_eq!(flake_dir, &base.join("composite"));
            }
            _ => panic!("expected FlakeSource::Local"),
        }

        let wrapper = fs::read_to_string(base.join("composite/flake.nix")).unwrap();
        let ws_str = workspace.display().to_string();

        // Root source: absolute path to workspace
        assert!(
            wrapper.contains(&format!("path:{ws_str}\"")),
            "root source path wrong: {}",
            wrapper
        );
        // Local source: absolute path to workspace/projects/local-proj
        assert!(
            wrapper.contains(&format!("path:{ws_str}/projects/local-proj")),
            "local source path wrong: {}",
            wrapper
        );
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
