//! Cache management for btrfs snapshot-based workspace caching.
//!
//! This module provides caching of Nix closures using btrfs snapshots for
//! copy-on-write workspace creation.

mod btrfs;

use crate::storage::{CacheEntry, JobStorage, StorageError};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

pub use btrfs::{create_snapshot_dir, delete_snapshot, BtrfsError, BtrfsSupport};
pub use btrfs::{
    detect_storage, snapshot_or_copy, BtrfsStorage, ReflinkStorage, StandardStorage,
    WorkspaceStorage,
};

/// Error type for cache operations
#[derive(Debug)]
pub enum CacheError {
    /// Storage/database error
    Storage(StorageError),
    /// Filesystem error
    Io(std::io::Error),
    /// btrfs operation error
    Btrfs(BtrfsError),
    /// Cache directory not initialized
    NotInitialized,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Storage(e) => write!(f, "storage error: {}", e),
            CacheError::Io(e) => write!(f, "io error: {}", e),
            CacheError::Btrfs(e) => write!(f, "btrfs error: {}", e),
            CacheError::NotInitialized => write!(f, "cache not initialized"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<StorageError> for CacheError {
    fn from(e: StorageError) -> Self {
        CacheError::Storage(e)
    }
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e)
    }
}

impl From<BtrfsError> for CacheError {
    fn from(e: BtrfsError) -> Self {
        CacheError::Btrfs(e)
    }
}

/// Manages cached Nix closures for fast workspace creation
#[derive(Debug, Clone)]
pub struct CacheManager {
    /// Root directory for cache storage
    cache_dir: PathBuf,
    /// Database for cache metadata
    storage: JobStorage,
    /// Storage backend for efficient CoW operations
    workspace_storage: std::sync::Arc<dyn WorkspaceStorage>,
}

impl CacheManager {
    /// Create a new cache manager
    ///
    /// Initializes the cache directory structure and detects storage backend.
    pub fn new(cache_dir: PathBuf, storage: JobStorage) -> Result<Self, CacheError> {
        // Create cache directory if it doesn't exist
        std::fs::create_dir_all(&cache_dir)?;

        // Detect storage backend
        let workspace_storage = detect_storage(&cache_dir);
        info!(path = %cache_dir.display(), storage = workspace_storage.name(), "cache storage backend detected");

        Ok(Self {
            cache_dir,
            storage,
            workspace_storage,
        })
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Get the storage backend name
    pub fn storage_name(&self) -> &'static str {
        self.workspace_storage.name()
    }

    /// Get the storage backend
    pub fn storage(&self) -> &std::sync::Arc<dyn WorkspaceStorage> {
        &self.workspace_storage
    }

    /// Get path for a cache entry by NAR hash
    pub fn cache_path(&self, nar_hash: &str) -> PathBuf {
        self.cache_dir.join(nar_hash)
    }

    /// Check if a cache entry exists
    pub fn has_entry(&self, nar_hash: &str) -> Result<bool, CacheError> {
        let entry = self.storage.get_cache_entry(nar_hash)?;
        if let Some(entry) = entry {
            // Verify the snapshot directory still exists
            let path = PathBuf::from(&entry.snapshot_path);
            if path.exists() {
                return Ok(true);
            }
            // Directory missing, clean up stale entry
            warn!(
                nar_hash,
                "cache entry exists but snapshot missing, removing"
            );
            self.storage.delete_cache_entry(nar_hash)?;
        }
        Ok(false)
    }

    /// Get a cache entry and update its usage stats
    pub fn get_entry(&self, nar_hash: &str) -> Result<Option<CacheEntry>, CacheError> {
        let entry = self.storage.get_cache_entry(nar_hash)?;
        if let Some(ref entry) = entry {
            // Verify the snapshot directory still exists
            let path = PathBuf::from(&entry.snapshot_path);
            if !path.exists() {
                warn!(
                    nar_hash,
                    "cache entry exists but snapshot missing, removing"
                );
                self.storage.delete_cache_entry(nar_hash)?;
                return Ok(None);
            }
            // Update usage stats
            self.storage.touch_cache_entry(nar_hash)?;
        }
        Ok(entry)
    }

    /// Create a new cache entry from closure paths
    ///
    /// Copies the closure paths to the cache directory, using btrfs snapshots
    /// or reflinks where available.
    pub async fn create_entry(
        &self,
        nar_hash: &str,
        closure_paths: &[PathBuf],
    ) -> Result<CacheEntry, CacheError> {
        let snapshot_path = self.cache_path(nar_hash);

        debug!(
            nar_hash,
            path = %snapshot_path.display(),
            closure_count = closure_paths.len(),
            "creating cache entry"
        );

        // Create the snapshot directory
        self.workspace_storage.create_dir(&snapshot_path)?;

        // Copy closure paths into the snapshot
        let mut total_size: i64 = 0;
        for src_path in closure_paths {
            let dest = snapshot_path.join("nix").join("store");
            std::fs::create_dir_all(&dest)?;

            // Get the store path name (e.g., "abc123-package")
            if let Some(name) = src_path.file_name() {
                let dest_path = dest.join(name);
                total_size +=
                    btrfs::copy_tree(src_path, &dest_path, &self.workspace_storage).await?;
            }
        }

        let now = SystemTime::now();
        let entry = CacheEntry {
            nar_hash: nar_hash.to_string(),
            snapshot_path: snapshot_path.to_string_lossy().to_string(),
            closure_paths: closure_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            size_bytes: Some(total_size),
            created_at: now,
            last_used_at: now,
            use_count: 0,
        };

        self.storage.save_cache_entry(&entry)?;

        info!(
            nar_hash,
            size_bytes = total_size,
            closure_count = closure_paths.len(),
            "cache entry created"
        );

        Ok(entry)
    }

    /// Create a workspace snapshot from a cached entry
    ///
    /// Uses btrfs snapshot or reflink copy to create a new workspace directory
    /// from the cached closure.
    pub async fn create_workspace_from_cache(
        &self,
        nar_hash: &str,
        workspace_path: &Path,
    ) -> Result<(), CacheError> {
        let entry = self
            .get_entry(nar_hash)?
            .ok_or(CacheError::NotInitialized)?;

        let source = PathBuf::from(&entry.snapshot_path);
        btrfs::snapshot_or_copy(&source, workspace_path, &self.workspace_storage).await?;

        debug!(
            nar_hash,
            dest = %workspace_path.display(),
            "created snapshot from cache"
        );

        Ok(())
    }

    /// Delete a cache entry and its snapshot directory
    pub fn delete_entry(&self, nar_hash: &str) -> Result<(), CacheError> {
        if let Some(entry) = self.storage.get_cache_entry(nar_hash)? {
            let path = PathBuf::from(&entry.snapshot_path);
            if path.exists() {
                self.workspace_storage.delete_dir(&path)?;
            }
            self.storage.delete_cache_entry(nar_hash)?;
            info!(nar_hash, "deleted cache entry");
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> Result<CacheStats, CacheError> {
        let entry_count = self.storage.get_cache_entry_count()?;
        let total_size = self.storage.get_cache_total_size()?;

        Ok(CacheStats {
            entry_count,
            total_size_bytes: total_size,
            storage_backend: self.workspace_storage.name(),
        })
    }

    /// Prepare a root directory for job execution
    ///
    /// This is the main entry point for using the cache. It handles:
    /// - Cache hit: snapshots the cached closure to root_path (instant on btrfs!)
    /// - Cache miss: creates cache entry from closure, then snapshots it
    ///
    /// The root_path will contain /nix/store with all closure dependencies.
    pub async fn prepare_root(
        &self,
        cache_key: &str,
        closure: &[PathBuf],
        root_path: &Path,
    ) -> Result<bool, CacheError> {
        // Check for cache hit
        if self.has_entry(cache_key)? {
            info!(cache_key, "cache hit, creating root from snapshot");
            self.create_workspace_from_cache(cache_key, root_path)
                .await?;
            return Ok(true); // cache hit
        }

        // Cache miss - create entry then snapshot
        info!(
            cache_key,
            closure_count = closure.len(),
            "cache miss, creating entry"
        );
        let _ = self.create_entry(cache_key, closure).await?;
        self.create_workspace_from_cache(cache_key, root_path)
            .await?;
        Ok(false) // cache miss
    }

    /// Run garbage collection using LRU eviction
    ///
    /// Removes the oldest cache entries until the total size is below the target.
    pub async fn gc(&self, target_size_bytes: i64) -> Result<usize, CacheError> {
        let mut deleted = 0;
        let mut current_size = self.storage.get_cache_total_size()?;

        while current_size > target_size_bytes {
            let entries = self.storage.list_cache_entries_lru(1)?;
            if entries.is_empty() {
                break;
            }

            let entry = &entries[0];
            let entry_size = entry.size_bytes.unwrap_or(0);

            self.delete_entry(&entry.nar_hash)?;
            deleted += 1;
            current_size -= entry_size;

            debug!(
                nar_hash = entry.nar_hash,
                size_bytes = entry_size,
                remaining_size = current_size,
                "gc: deleted cache entry"
            );
        }

        if deleted > 0 {
            info!(
                deleted,
                final_size_bytes = current_size,
                "garbage collection completed"
            );
        }

        Ok(deleted)
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: usize,
    pub total_size_bytes: i64,
    pub storage_backend: &'static str,
}

/// Compute a cache key from a list of store paths.
///
/// The key is a SHA256 hash of the sorted, newline-separated store paths.
/// This ensures that the same set of packages always produces the same cache key,
/// regardless of resolution order.
pub fn compute_closure_hash(store_paths: &[PathBuf]) -> String {
    use sha2::{Digest, Sha256};

    let mut paths: Vec<&str> = store_paths.iter().filter_map(|p| p.to_str()).collect();
    paths.sort();

    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(path.as_bytes());
        hasher.update(b"\n");
    }

    let result = hasher.finalize();
    hex::encode(result)
}
