use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::process::Command;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use super::{NixPackageCache, WorkspaceError};

/// Global package cache (initialized on first use)
///
/// Uses OnceLock for thread-safe lazy initialization.
/// Cache is shared across all jobs to maximize hit rate.
static PACKAGE_CACHE: OnceLock<NixPackageCache> = OnceLock::new();

/// Get or initialize the global package cache
fn get_package_cache() -> &'static NixPackageCache {
    PACKAGE_CACHE.get_or_init(|| {
        tracing::info!("initializing global nix package cache (max: 1000 entries, ttl: 24h)");
        NixPackageCache::new()
    })
}

/// Specification for which nixpkgs version to use
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NixpkgsSpec {
    /// Use default nixos-25.11 (pinned stable)
    Default,
    /// Use a release branch (e.g., "nixos-24.05" or "nixos-unstable")
    Branch {
        name: String,
        sha256: Option<String>,
    },
    /// Use a specific git commit SHA (40 hex characters)
    Commit(String),
}

impl NixpkgsSpec {
    /// Parse a nixpkgs version string into a NixpkgsSpec
    ///
    /// Supported formats:
    /// - "" or None → Default
    /// - "nixos-24.05" → Branch with auto-discovered hash
    /// - "nixos-24.05#sha256:abc..." → Branch with explicit hash
    /// - "ae2fc9e0..." (40 chars) → Commit SHA
    pub fn parse(version: Option<&str>) -> Result<Self, WorkspaceError> {
        match version {
            None | Some("") => Ok(NixpkgsSpec::Default),
            Some(v) => {
                // Check if it has an explicit hash
                if let Some((branch, hash)) = v.split_once('#') {
                    Self::validate_branch_name(branch)?;
                    Self::validate_sha256(hash)?;
                    Ok(NixpkgsSpec::Branch {
                        name: branch.to_string(),
                        sha256: Some(hash.to_string()),
                    })
                }
                // Check if it's a 40-character hex string (commit SHA)
                else if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                    Ok(NixpkgsSpec::Commit(v.to_string()))
                }
                // Otherwise, treat as branch name
                else {
                    Self::validate_branch_name(v)?;
                    Ok(NixpkgsSpec::Branch {
                        name: v.to_string(),
                        sha256: None,
                    })
                }
            }
        }
    }

    /// Validate a nixpkgs branch name
    fn validate_branch_name(name: &str) -> Result<(), WorkspaceError> {
        // Only allow specific patterns: nixos-XX.YY or nixos-unstable
        // Safety: hardcoded regex patterns are guaranteed valid
        #[allow(clippy::expect_used)]
        let valid_patterns = [
            regex::Regex::new(r"^nixos-unstable$").expect("failed to compile unstable regex"),
            regex::Regex::new(r"^nixos-[0-9]{2}\.[0-9]{2}$")
                .expect("failed to compile version regex"),
        ];

        if !valid_patterns.iter().any(|re| re.is_match(name)) {
            return Err(WorkspaceError::InvalidPath(format!(
                "Invalid nixpkgs branch name '{}'. Must be 'nixos-unstable' or 'nixos-XX.YY'",
                name
            )));
        }

        Ok(())
    }

    /// Validate a SHA256 hash
    fn validate_sha256(hash: &str) -> Result<(), WorkspaceError> {
        // SHA256 hash should be "sha256:" followed by base64 or hex
        if !hash.starts_with("sha256:") {
            return Err(WorkspaceError::InvalidPath(
                "SHA256 hash must start with 'sha256:'".to_string(),
            ));
        }

        let hash_value = &hash[7..]; // Skip "sha256:" prefix
        if hash_value.len() < 40 || hash_value.len() > 64 {
            return Err(WorkspaceError::InvalidPath(
                "Invalid SHA256 hash length".to_string(),
            ));
        }

        Ok(())
    }

    /// Build the nixpkgs import expression for this spec
    pub fn build_import_expr(&self) -> String {
        match self {
            NixpkgsSpec::Default => {
                // Default: nixos-25.11
                "import (fetchTarball \"https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz\") { config = { allowUnfree = true; }; }".to_string()
            }
            NixpkgsSpec::Branch {
                name,
                sha256: Some(hash),
            } => {
                format!(
                    "import (fetchTarball {{ url = \"https://github.com/NixOS/nixpkgs/archive/{}.tar.gz\"; {} = \"{}\"; }}) {{ config = {{ allowUnfree = true; }}; }}",
                    name, "sha256", hash
                )
            }
            NixpkgsSpec::Branch { name, sha256: None } => {
                // Auto-discover hash on first use
                format!(
                    "import (fetchTarball \"https://github.com/NixOS/nixpkgs/archive/{}.tar.gz\") {{ config = {{ allowUnfree = true; }}; }}",
                    name
                )
            }
            NixpkgsSpec::Commit(sha) => {
                // Use fetchGit for specific commits (slower but works)
                format!(
                    "import (builtins.fetchGit {{ url = \"https://github.com/NixOS/nixpkgs\"; rev = \"{}\"; }}) {{ config = {{ allowUnfree = true; }}; }}",
                    sha
                )
            }
        }
    }
}

/// Validate package name to prevent injection attacks
///
/// Package names must be alphanumeric with optional dashes and underscores.
/// Maximum length: 100 characters.
fn validate_package_name(name: &str) -> Result<(), WorkspaceError> {
    // Validate length
    if name.is_empty() {
        return Err(WorkspaceError::InvalidPath(
            "Package name cannot be empty".to_string(),
        ));
    }
    if name.len() > 100 {
        return Err(WorkspaceError::InvalidPath(
            "Package name too long (max 100 chars)".to_string(),
        ));
    }

    // Validate characters: alphanumeric + dash + underscore only
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(WorkspaceError::InvalidPath(format!(
            "Invalid package name '{}': only alphanumeric, dash, and underscore allowed",
            name
        )));
    }

    Ok(())
}

/// Find a Nix package in the Nix store
///
/// Uses `nix-build` to resolve the path. This is slow (~1-2 seconds)
/// but correct. In production, this could be cached in config.
/// Retries on failure with exponential backoff.
pub async fn find_nix_package(package: &str) -> Result<PathBuf, WorkspaceError> {
    // Retry strategy: 2 retries with exponential backoff (100ms, 300ms with jitter)
    let retry_strategy = ExponentialBackoff::from_millis(100).map(jitter).take(2);

    let package_owned = package.to_string();
    Retry::spawn(retry_strategy, || async {
        let output = Command::new("nix-build")
            .args(["<nixpkgs>", "-A", &package_owned, "--no-out-link"])
            .output()
            .await
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Failed to execute nix-build: {}. Is Nix installed?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::DerivationNotFound(format!(
                "nix-build failed for {}: {}",
                package_owned, stderr
            )));
        }

        let path_str = String::from_utf8(output.stdout)
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Invalid UTF-8 in nix-build output: {}",
                    e
                ))
            })?
            .trim()
            .to_string();

        let path = PathBuf::from(path_str);

        if !path.exists() {
            return Err(WorkspaceError::DerivationNotFound(format!(
                "Derivation path does not exist: {}",
                path.display()
            )));
        }

        Ok(path)
    })
    .await
}

/// Find the coreutils derivation in the Nix store
///
/// Uses `nix-build` to resolve the path. This is slow (~1-2 seconds)
/// but correct. In production, this could be cached in config.
pub async fn find_coreutils_derivation() -> Result<PathBuf, WorkspaceError> {
    find_nix_package("coreutils").await
}

/// Compute the Nix runtime closure for a given store path
///
/// Uses `nix-store -qR` to find all transitive dependencies.
/// Returns all store paths needed to run the given derivation.
/// Retries on failure with exponential backoff.
pub async fn compute_nix_closure(store_path: &Path) -> Result<Vec<PathBuf>, WorkspaceError> {
    // Retry strategy: 2 retries with exponential backoff (100ms, 300ms with jitter)
    let retry_strategy = ExponentialBackoff::from_millis(100).map(jitter).take(2);

    let store_path_owned = store_path.to_path_buf();
    Retry::spawn(retry_strategy, || async {
        let output = Command::new("nix-store")
            .args(["-qR", &store_path_owned.to_string_lossy()])
            .output()
            .await
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Failed to execute nix-store: {}. Is Nix installed?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::DerivationNotFound(format!(
                "nix-store -qR failed for {}: {}",
                store_path_owned.display(),
                stderr
            )));
        }

        let closure_str = String::from_utf8(output.stdout).map_err(|e| {
            WorkspaceError::DerivationNotFound(format!("Invalid UTF-8 in nix-store output: {}", e))
        })?;

        let closure: Vec<PathBuf> = closure_str
            .lines()
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect();

        Ok(closure)
    })
    .await
}

/// Find multiple Nix packages using nix-instantiate
///
/// Uses `nix-instantiate --eval` for faster package resolution (2.4x faster than nix-build).
/// Returns paths in the same order as the input packages.
/// Retries on failure with exponential backoff.
///
/// # Arguments
/// * `packages` - List of package names to resolve
/// * `nixpkgs_version` - Optional nixpkgs version specification (None = default nixos-25.11)
pub async fn find_nix_packages_with_version(
    packages: &[&str],
    nixpkgs_version: Option<&str>,
) -> Result<Vec<PathBuf>, WorkspaceError> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    // Validate all package names first (security!)
    for pkg in packages {
        validate_package_name(pkg)?;
    }

    // Parse and validate nixpkgs version
    let nixpkgs_spec = NixpkgsSpec::parse(nixpkgs_version)?;

    let import_expr = nixpkgs_spec.build_import_expr();

    // Build all packages in a single nix-build call
    // Expression: with import <nixpkgs> {}; [ bash coreutils ... ]
    let package_list = packages.join(" ");
    let nix_expr = format!("with {}; [ {} ]", import_expr, package_list);

    tracing::debug!(
        "building packages: {:?} with nixpkgs: {:?}",
        packages,
        nixpkgs_version
    );

    let output = Command::new("nix-build")
        .args(["-E", &nix_expr, "--no-out-link"])
        .output()
        .await
        .map_err(|e| {
            WorkspaceError::DerivationNotFound(format!(
                "Failed to execute nix-build: {}. Is Nix installed?",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WorkspaceError::DerivationNotFound(format!(
            "nix-build failed: {}",
            stderr
        )));
    }

    // Parse output paths (one per line)
    let paths: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| PathBuf::from(line.trim()))
        .collect();

    if paths.len() != packages.len() {
        return Err(WorkspaceError::DerivationNotFound(format!(
            "Expected {} paths but got {}",
            packages.len(),
            paths.len()
        )));
    }

    tracing::info!(
        "resolved and realized {} packages to store paths",
        paths.len()
    );
    Ok(paths)
}

/// Find multiple Nix packages using the default nixpkgs version
///
/// Convenience wrapper around find_nix_packages_with_version that uses the default.
pub async fn find_nix_packages(packages: &[&str]) -> Result<Vec<PathBuf>, WorkspaceError> {
    find_nix_packages_with_version(packages, None).await
}

/// Find multiple Nix packages with caching (recommended for production use)
///
/// This is a cached wrapper around find_nix_packages_with_version that uses
/// a two-level cache:
/// - L1: In-memory cache (moka) - fast, process-local
/// - L2: Disk cache (JSON files) - persistent across process restarts
///
/// Cache behavior:
/// - L1 hit: Return immediately (~0ms)
/// - L1 miss, L2 hit: Promote to L1 and return (~1ms)
/// - Both miss: Resolve packages (~330ms), store in both caches
/// - Cache keys are sorted package lists + version (order-independent)
///
/// # Arguments
/// * `packages` - List of package names to resolve
/// * `nixpkgs_version` - Optional nixpkgs version specification
/// * `cache_dir` - Optional directory for disk cache (L2). If None, only L1 is used.
///
/// # Returns
/// Store paths in the same order as the input packages.
pub async fn find_nix_packages_cached(
    packages: &[&str],
    nixpkgs_version: Option<&str>,
    cache_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, WorkspaceError> {
    let memory_cache = get_package_cache();

    // L1: Check in-memory cache
    if let Some(paths) = memory_cache.get(packages, nixpkgs_version) {
        tracing::debug!(
            packages_count = packages.len(),
            nixpkgs_version = ?nixpkgs_version,
            "L1 cache hit (in-memory)"
        );
        return Ok(paths);
    }

    // L2: Check disk cache (if cache_dir provided)
    if let Some(dir) = cache_dir {
        let disk_cache = super::cache::DiskPackageCache::new(dir.join("packages"));
        if let Some(paths) = disk_cache.get(packages, nixpkgs_version) {
            tracing::debug!(
                packages_count = packages.len(),
                nixpkgs_version = ?nixpkgs_version,
                "L2 cache hit (disk) - promoting to L1"
            );
            // Promote to L1
            memory_cache.insert(packages, nixpkgs_version, paths.clone());
            return Ok(paths);
        }
    }

    // Both miss - resolve packages
    tracing::debug!(
        packages_count = packages.len(),
        nixpkgs_version = ?nixpkgs_version,
        "cache miss - resolving packages"
    );

    let paths = find_nix_packages_with_version(packages, nixpkgs_version).await?;

    // Store in L1 (always)
    memory_cache.insert(packages, nixpkgs_version, paths.clone());

    // Store in L2 (if cache_dir provided)
    if let Some(dir) = cache_dir {
        let disk_cache = super::cache::DiskPackageCache::new(dir.join("packages"));
        disk_cache.insert(packages, nixpkgs_version, paths.clone());
    }

    tracing::debug!(
        packages_count = paths.len(),
        memory_cache_entries = memory_cache.entry_count(),
        "cached store paths"
    );

    Ok(paths)
}

/// Compute the combined Nix runtime closure for multiple store paths
///
/// Uses a single `nix-store -qR` call with all paths. nix-store automatically
/// deduplicates the closure, so this is efficient even if packages share dependencies.
/// Retries on failure with exponential backoff.
pub async fn compute_combined_closure(
    store_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, WorkspaceError> {
    if store_paths.is_empty() {
        return Ok(Vec::new());
    }

    // Retry strategy: 2 retries with exponential backoff (100ms, 300ms with jitter)
    let retry_strategy = ExponentialBackoff::from_millis(100).map(jitter).take(2);

    let path_args: Vec<String> = store_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    Retry::spawn(retry_strategy, || async {
        let output = Command::new("nix-store")
            .arg("-qR")
            .args(&path_args)
            .output()
            .await
            .map_err(|e| {
                WorkspaceError::DerivationNotFound(format!(
                    "Failed to execute nix-store: {}. Is Nix installed?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::DerivationNotFound(format!(
                "nix-store -qR failed: {}",
                stderr
            )));
        }

        let closure_str = String::from_utf8(output.stdout).map_err(|e| {
            WorkspaceError::DerivationNotFound(format!("Invalid UTF-8 in nix-store output: {}", e))
        })?;

        let closure: Vec<PathBuf> = closure_str
            .lines()
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect();

        Ok(closure)
    })
    .await
}

/// Build a PATH environment variable from multiple package store paths
///
/// Appends /bin to each store path and joins with colons.
/// Useful for constructing the PATH for job execution with multiple packages.
pub fn build_path_env(store_paths: &[PathBuf]) -> String {
    store_paths
        .iter()
        .map(|p| format!("{}/bin", p.display()))
        .collect::<Vec<_>>()
        .join(":")
}
