//! Root directory preparation strategies for sandbox execution.
//!
//! This module provides the `JobRoot` trait and implementations for
//! different strategies to make the Nix store available inside the sandbox.

use crate::cache::{CacheManager, StandardStorage, WorkspaceStorage};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How the Nix store closure should be made available to the job
#[derive(Debug, Clone)]
pub enum StoreSetup {
    /// Root directory contains /nix/store closure (btrfs snapshot or copy)
    ///
    /// Executor should use: `--property=RootDirectory={root}`
    Populated,

    /// Root directory is minimal, executor should bind-mount store paths
    ///
    /// Executor should use: `--property=BindReadOnlyPaths={path}:{path}` for each
    BindMounts { paths: Vec<PathBuf> },

    /// Docker volume contains the Nix store closure
    ///
    /// Executor should use: `-v {name}:/nix/store:ro`
    DockerVolume { name: String },
}

/// Strategy for setting up the Nix store in the sandbox
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreStrategy {
    /// Cache and snapshot closure into root directory (default)
    ///
    /// Uses btrfs snapshots when available for O(1) creation,
    /// falls back to reflink or standard copy. Allows inspecting
    /// the full chroot after job completion.
    #[default]
    Cached,

    /// Bind-mount store paths directly from host /nix/store
    ///
    /// Instant startup, no copying required. Uses BindReadOnlyPaths
    /// for each store path in the closure.
    BindMount,

    /// Use Docker volumes for the Nix store (for Docker executor)
    ///
    /// Caches closures in named Docker volumes. On cache miss, runs
    /// nix-build inside a container to populate the volume with
    /// correct-architecture binaries. Essential for macOS where
    /// host /nix/store has different architecture than container.
    DockerVolume,
}

impl std::str::FromStr for StoreStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cached" | "copy" => Ok(StoreStrategy::Cached),
            "bind-mount" | "bind_mount" | "bindmount" => Ok(StoreStrategy::BindMount),
            "docker-volume" | "docker_volume" | "dockervolume" => Ok(StoreStrategy::DockerVolume),
            _ => Err(format!(
                "unknown store strategy '{}'. valid options: 'cached', 'bind-mount', 'docker-volume'",
                s
            )),
        }
    }
}

/// Errors that can occur during root preparation
#[derive(Debug)]
pub enum RootError {
    Io(std::io::Error),
    Cache(crate::cache::CacheError),
}

impl std::fmt::Display for RootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootError::Io(e) => write!(f, "i/o error: {}", e),
            RootError::Cache(e) => write!(f, "cache error: {}", e),
        }
    }
}

impl std::error::Error for RootError {}

impl From<std::io::Error> for RootError {
    fn from(e: std::io::Error) -> Self {
        RootError::Io(e)
    }
}

impl From<crate::cache::CacheError> for RootError {
    fn from(e: crate::cache::CacheError) -> Self {
        RootError::Cache(e)
    }
}

/// Trait for managing job root directories with different strategies
///
/// Implementations encapsulate the specific logic for making the Nix store
/// available inside the sandbox.
#[async_trait::async_trait]
pub trait JobRoot: Send + Sync + std::fmt::Debug {
    /// Create a root directory for job execution
    ///
    /// Returns (StoreSetup, cache_hit) where cache_hit is only meaningful
    /// for strategies that support caching.
    async fn create(
        &self,
        root_dir: &Path,
        closure: &[PathBuf],
    ) -> Result<(StoreSetup, bool), RootError>;

    /// Clean up a root directory after job completion
    fn cleanup(&self, root_dir: &Path) -> Result<(), RootError>;
}

/// Job root that caches and snapshots the closure into the root directory
///
/// Uses btrfs snapshots when available for O(1) creation, with LRU cache
/// for repeated executions.
#[derive(Debug)]
pub struct CachedJobRoot {
    cache_manager: CacheManager,
}

impl CachedJobRoot {
    /// Create a new cached job root with the given cache manager
    pub fn new(cache_manager: CacheManager) -> Self {
        Self { cache_manager }
    }
}

#[async_trait::async_trait]
impl JobRoot for CachedJobRoot {
    async fn create(
        &self,
        root_dir: &Path,
        closure: &[PathBuf],
    ) -> Result<(StoreSetup, bool), RootError> {
        if closure.is_empty() {
            std::fs::create_dir_all(root_dir)?;
            return Ok((StoreSetup::BindMounts { paths: vec![] }, false));
        }

        let cache_key = crate::cache::compute_closure_hash(closure);
        let cache_hit = self
            .cache_manager
            .prepare_root(&cache_key, closure, root_dir)
            .await?;
        tracing::info!(
            cache_hit,
            closure_count = closure.len(),
            "prepared root via cache/snapshot"
        );
        Ok((StoreSetup::Populated, cache_hit))
    }

    fn cleanup(&self, root_dir: &Path) -> Result<(), RootError> {
        if root_dir.exists() {
            self.cache_manager
                .workspace_storage()
                .delete_dir(root_dir)
                .map_err(|e| RootError::Io(std::io::Error::other(e.to_string())))?;
        }
        Ok(())
    }
}

/// Job root that uses bind mounts for the Nix store
///
/// Zero-copy, instant startup. The executor will create BindReadOnlyPaths
/// for each store path.
#[derive(Debug, Default)]
pub struct BindMountJobRoot;

impl BindMountJobRoot {
    /// Create a new bind mount job root
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl JobRoot for BindMountJobRoot {
    async fn create(
        &self,
        root_dir: &Path,
        closure: &[PathBuf],
    ) -> Result<(StoreSetup, bool), RootError> {
        std::fs::create_dir_all(root_dir)?;

        if closure.is_empty() {
            return Ok((StoreSetup::BindMounts { paths: vec![] }, false));
        }

        tracing::info!(
            closure_count = closure.len(),
            "prepared root for bind-mount strategy"
        );
        Ok((
            StoreSetup::BindMounts {
                paths: closure.to_vec(),
            },
            false,
        ))
    }

    fn cleanup(&self, root_dir: &Path) -> Result<(), RootError> {
        if root_dir.exists() {
            StandardStorage
                .delete_dir(root_dir)
                .map_err(|e| RootError::Io(std::io::Error::other(e.to_string())))?;
        }
        Ok(())
    }
}

/// Job root that uses Docker volumes for the Nix store
///
/// Caches closures in named Docker volumes. On cache miss, runs nix-build
/// inside a container to populate the volume. Essential for macOS where
/// host /nix/store has different architecture than container.
#[derive(Debug, Default)]
pub struct DockerVolumeJobRoot {
    /// Nixpkgs channel/version to use for nix-build
    nixpkgs_version: Option<String>,
    /// Package names to install (used instead of extracting from closure)
    packages: Vec<String>,
}

impl DockerVolumeJobRoot {
    /// Create a new Docker volume job root
    pub fn new() -> Self {
        Self {
            nixpkgs_version: None,
            packages: vec![],
        }
    }

    /// Create with specific packages and nixpkgs version
    pub fn with_packages(packages: Vec<String>, nixpkgs_version: Option<String>) -> Self {
        Self {
            nixpkgs_version,
            packages,
        }
    }

    /// Compute the volume name from closure hash
    fn volume_name(closure: &[PathBuf]) -> String {
        let hash = crate::cache::compute_closure_hash(closure);
        // Use first 16 chars of hash for readability
        format!("nix-jail-{}", &hash[..16])
    }

    /// Check if a Docker volume exists
    async fn volume_exists(name: &str) -> Result<bool, RootError> {
        let output = tokio::process::Command::new("docker")
            .args(["volume", "inspect", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map_err(RootError::Io)?;

        Ok(output.success())
    }

    /// Create a Docker volume
    async fn create_volume(name: &str) -> Result<(), RootError> {
        let output = tokio::process::Command::new("docker")
            .args(["volume", "create", name])
            .output()
            .await
            .map_err(RootError::Io)?;

        if !output.status.success() {
            return Err(RootError::Io(std::io::Error::other(format!(
                "failed to create docker volume '{}': {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            ))));
        }

        tracing::info!(volume = name, "created docker volume");
        Ok(())
    }

    /// Populate a Docker volume with packages using nix-build inside a container
    ///
    /// Only copies the runtime closure (not build-time deps, .drv files, patches, etc.)
    async fn populate_volume(
        name: &str,
        packages: &[String],
        nixpkgs_version: Option<&str>,
    ) -> Result<(), RootError> {
        if packages.is_empty() {
            tracing::warn!(volume = name, "no packages to install in docker volume");
            return Ok(());
        }

        let nixpkgs = nixpkgs_version.unwrap_or("nixos-unstable");

        tracing::info!(
            volume = name,
            packages = ?packages,
            nixpkgs = nixpkgs,
            "populating docker volume with runtime closure only"
        );

        // Build packages in container, copy only runtime closure to target volume
        // Uses two volumes: temp build volume (discarded) and target volume (kept)
        //
        // This avoids polluting the target with build-time deps, .drv files, patches

        // Step 1: Build packages in a temp container, export closure to target volume
        let build_script = format!(
            r#"
set -e

# Build packages and capture output paths
outputs=$(nix-build --no-out-link -E 'with import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/{nixpkgs}.tar.gz") {{}}; [{packages}]')

# Get runtime closure (only what's needed to run, not build)
closure=$(nix-store -qR $outputs)

# Copy closure paths to target volume
for path in $closure; do
    cp -a "$path" /target/store/
done

# Create /nix/bin with symlinks to all binaries (for scratch image entrypoint)
# Note: symlinks must point to /nix/store (final mount point) not /target/store
mkdir -p /target/bin
for bindir in /target/store/*/bin; do
    if [ -d "$bindir" ]; then
        # Get the store path portion (e.g., xyz-package-1.0) to construct /nix/store path
        store_path=$(basename $(dirname "$bindir"))
        for bin in "$bindir"/*; do
            [ -f "$bin" ] && ln -sf "/nix/store/$store_path/bin/$(basename "$bin")" /target/bin/ 2>/dev/null || true
        done
    fi
done

echo "Copied $(echo $closure | wc -w) runtime paths"
"#,
            nixpkgs = nixpkgs,
            packages = packages.join(" ")
        );

        let output = tokio::process::Command::new("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/target", name), // Target volume for closure only
                "nixos/nix:latest",
                "sh",
                "-c",
                &build_script,
            ])
            .output()
            .await
            .map_err(RootError::Io)?;

        if !output.status.success() {
            return Err(RootError::Io(std::io::Error::other(format!(
                "failed to populate docker volume '{}': {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            ))));
        }

        tracing::info!(
            volume = name,
            packages = packages.len(),
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            "docker volume populated with runtime closure"
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl JobRoot for DockerVolumeJobRoot {
    async fn create(
        &self,
        root_dir: &Path,
        closure: &[PathBuf],
    ) -> Result<(StoreSetup, bool), RootError> {
        // Create minimal root directory (may be needed for other files)
        std::fs::create_dir_all(root_dir)?;

        if closure.is_empty() {
            // Empty closure - return empty volume name
            return Ok((
                StoreSetup::DockerVolume {
                    name: "nix-jail-empty".to_string(),
                },
                false,
            ));
        }

        let volume_name = Self::volume_name(closure);

        // Check for cache hit
        if Self::volume_exists(&volume_name).await? {
            tracing::info!(volume = %volume_name, "docker volume cache hit");
            return Ok((
                StoreSetup::DockerVolume { name: volume_name },
                true, // cache hit
            ));
        }

        // Cache miss - create and populate volume
        tracing::info!(
            volume = %volume_name,
            closure_count = closure.len(),
            "docker volume cache miss, creating and populating"
        );

        Self::create_volume(&volume_name).await?;
        Self::populate_volume(
            &volume_name,
            &self.packages,
            self.nixpkgs_version.as_deref(),
        )
        .await?;

        Ok((
            StoreSetup::DockerVolume { name: volume_name },
            false, // cache miss
        ))
    }

    fn cleanup(&self, root_dir: &Path) -> Result<(), RootError> {
        // Only clean up the root directory, not the Docker volume
        // (volumes are cached for reuse)
        if root_dir.exists() {
            StandardStorage
                .delete_dir(root_dir)
                .map_err(|e| RootError::Io(std::io::Error::other(e.to_string())))?;
        }
        Ok(())
    }
}

/// Create a JobRoot based on the configured strategy
///
/// This is the factory function for selecting the appropriate implementation.
pub fn get_job_root(strategy: StoreStrategy, cache_manager: CacheManager) -> Arc<dyn JobRoot> {
    match strategy {
        StoreStrategy::Cached => Arc::new(CachedJobRoot::new(cache_manager)),
        StoreStrategy::BindMount => Arc::new(BindMountJobRoot::new()),
        StoreStrategy::DockerVolume => Arc::new(DockerVolumeJobRoot::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_strategy_parsing() {
        assert_eq!(
            "cached".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::Cached
        );
        assert_eq!(
            "copy".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::Cached
        );
        assert_eq!(
            "bind-mount".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::BindMount
        );
        assert_eq!(
            "bindmount".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::BindMount
        );
        assert_eq!(
            "docker-volume".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::DockerVolume
        );
        assert_eq!(
            "dockervolume".parse::<StoreStrategy>().unwrap(),
            StoreStrategy::DockerVolume
        );
        assert!("invalid".parse::<StoreStrategy>().is_err());
    }

    #[test]
    fn test_store_strategy_default() {
        assert_eq!(StoreStrategy::default(), StoreStrategy::Cached);
    }
}
