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
}

impl std::str::FromStr for StoreStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cached" | "copy" => Ok(StoreStrategy::Cached),
            "bind-mount" | "bind_mount" | "bindmount" => Ok(StoreStrategy::BindMount),
            _ => Err(format!(
                "unknown store strategy '{}'. valid options: 'cached', 'bind-mount'",
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
                .storage()
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

/// Create a JobRoot based on the configured strategy
///
/// This is the factory function for selecting the appropriate implementation.
pub fn get_job_root(strategy: StoreStrategy, cache_manager: CacheManager) -> Arc<dyn JobRoot> {
    match strategy {
        StoreStrategy::Cached => Arc::new(CachedJobRoot::new(cache_manager)),
        StoreStrategy::BindMount => Arc::new(BindMountJobRoot::new()),
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
        assert!("invalid".parse::<StoreStrategy>().is_err());
    }

    #[test]
    fn test_store_strategy_default() {
        assert_eq!(StoreStrategy::default(), StoreStrategy::Cached);
    }
}
