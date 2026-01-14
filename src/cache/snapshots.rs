//! Snapshot management for client cache directories.
//!
//! This module handles snapshots of client-specified caches (cargo registry, pnpm store, etc.)
//! to support ephemeral cache mounts that prevent cache poisoning.
//!
//! ## Directory Structure
//!
//! ```text
//! {state_dir}/cache/{bucket}/{key}/
//! ├── data/                    # Current writable cache data
//! └── .snapshots/
//!     └── {timestamp}/         # Snapshot at specific time
//!         ├── metadata.json    # SnapshotMetadata
//!         └── data/            # Snapshot contents
//! ```

use crate::cache::{BtrfsError, WorkspaceStorage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Error type for snapshot operations
#[derive(Debug)]
pub enum SnapshotError {
    /// Filesystem error
    Io(std::io::Error),
    /// btrfs/storage operation error
    Storage(BtrfsError),
    /// JSON serialization error
    Json(serde_json::Error),
    /// No snapshot exists
    NoSnapshot,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Io(e) => write!(f, "io error: {}", e),
            SnapshotError::Storage(e) => write!(f, "storage error: {}", e),
            SnapshotError::Json(e) => write!(f, "json error: {}", e),
            SnapshotError::NoSnapshot => write!(f, "no snapshot exists"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<std::io::Error> for SnapshotError {
    fn from(e: std::io::Error) -> Self {
        SnapshotError::Io(e)
    }
}

impl From<BtrfsError> for SnapshotError {
    fn from(e: BtrfsError) -> Self {
        SnapshotError::Storage(e)
    }
}

impl From<serde_json::Error> for SnapshotError {
    fn from(e: serde_json::Error) -> Self {
        SnapshotError::Json(e)
    }
}

/// Metadata stored alongside each snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// When the snapshot was created
    pub created_at: SystemTime,
    /// SHA256 hash of the populate command (for cache invalidation)
    pub command_hash: String,
}

/// Compute SHA256 hash of a populate command
pub fn hash_command(command: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(command.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get the snapshots directory for a cache path
fn snapshots_dir(cache_path: &Path) -> PathBuf {
    cache_path.join(".snapshots")
}

/// Get the data directory for a cache path (actual cache contents)
pub fn data_dir(cache_path: &Path) -> PathBuf {
    cache_path.join("data")
}

/// Generate timestamp string for snapshot naming
fn timestamp_string() -> String {
    use std::time::UNIX_EPOCH;
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Create a snapshot of the current cache state.
///
/// Creates a snapshot at `{cache_path}/.snapshots/{timestamp}/` containing:
/// - `metadata.json`: SnapshotMetadata with creation time and command hash
/// - `data/`: Copy of the cache data directory
///
/// Uses CoW operations (btrfs snapshot or reflink) where available.
pub async fn create_snapshot(
    cache_path: &Path,
    command: &str,
    storage: &Arc<dyn WorkspaceStorage>,
) -> Result<PathBuf, SnapshotError> {
    let source = data_dir(cache_path);
    if !source.exists() {
        return Err(SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("cache data directory does not exist: {}", source.display()),
        )));
    }

    let snapshots = snapshots_dir(cache_path);
    std::fs::create_dir_all(&snapshots)?;

    let timestamp = timestamp_string();
    let snapshot_dir = snapshots.join(&timestamp);
    std::fs::create_dir_all(&snapshot_dir)?;

    // Create snapshot of data directory
    let snapshot_data = snapshot_dir.join("data");
    crate::cache::snapshot_or_copy(&source, &snapshot_data, storage).await?;

    // Write metadata
    let metadata = SnapshotMetadata {
        created_at: SystemTime::now(),
        command_hash: hash_command(command),
    };
    let metadata_path = snapshot_dir.join("metadata.json");
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    std::fs::write(&metadata_path, metadata_json)?;

    info!(
        cache = %cache_path.display(),
        snapshot = %snapshot_dir.display(),
        command_hash = %metadata.command_hash[..12],
        "created cache snapshot"
    );

    Ok(snapshot_dir)
}

/// Get the latest snapshot for a cache, optionally matching a command hash.
///
/// Returns the path to the snapshot's data directory (not the snapshot root).
/// If `command_hash` is provided, only returns snapshots with matching command.
pub fn get_latest_snapshot(
    cache_path: &Path,
    command_hash: Option<&str>,
) -> Result<Option<PathBuf>, SnapshotError> {
    let snapshots = snapshots_dir(cache_path);
    if !snapshots.exists() {
        return Ok(None);
    }

    let mut entries: Vec<_> = std::fs::read_dir(&snapshots)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();

    // Sort by name descending (timestamps, so newest first)
    entries.sort_by_key(|e| std::cmp::Reverse(e.file_name()));

    for entry in entries {
        let snapshot_dir = entry.path();
        let data_path = snapshot_dir.join("data");
        let metadata_path = snapshot_dir.join("metadata.json");

        // Verify snapshot is complete
        if !data_path.exists() || !metadata_path.exists() {
            warn!(snapshot = %snapshot_dir.display(), "incomplete snapshot, skipping");
            continue;
        }

        // Check command hash if required
        if let Some(required_hash) = command_hash {
            match std::fs::read_to_string(&metadata_path) {
                Ok(json) => match serde_json::from_str::<SnapshotMetadata>(&json) {
                    Ok(metadata) => {
                        if metadata.command_hash != required_hash {
                            debug!(
                                snapshot = %snapshot_dir.display(),
                                expected = %required_hash[..12],
                                found = %metadata.command_hash[..12],
                                "snapshot command hash mismatch, skipping"
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(snapshot = %snapshot_dir.display(), error = %e, "failed to parse metadata");
                        continue;
                    }
                },
                Err(e) => {
                    warn!(snapshot = %snapshot_dir.display(), error = %e, "failed to read metadata");
                    continue;
                }
            }
        }

        return Ok(Some(data_path));
    }

    Ok(None)
}

/// Clean up old snapshots, keeping only the most recent N.
///
/// Returns the number of snapshots deleted.
pub async fn cleanup_snapshots(
    cache_path: &Path,
    keep_count: usize,
    storage: &Arc<dyn WorkspaceStorage>,
) -> Result<usize, SnapshotError> {
    let snapshots = snapshots_dir(cache_path);
    if !snapshots.exists() {
        return Ok(0);
    }

    let mut entries: Vec<_> = std::fs::read_dir(&snapshots)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();

    if entries.len() <= keep_count {
        return Ok(0);
    }

    // Sort by name descending (timestamps, so newest first)
    entries.sort_by_key(|e| std::cmp::Reverse(e.file_name()));

    let mut deleted = 0;
    for entry in entries.into_iter().skip(keep_count) {
        let snapshot_dir = entry.path();
        match storage.delete_dir(&snapshot_dir) {
            Ok(()) => {
                debug!(snapshot = %snapshot_dir.display(), "deleted old snapshot");
                deleted += 1;
            }
            Err(e) => {
                warn!(snapshot = %snapshot_dir.display(), error = %e, "failed to delete snapshot");
            }
        }
    }

    if deleted > 0 {
        info!(
            cache = %cache_path.display(),
            deleted,
            kept = keep_count,
            "cleaned up old snapshots"
        );
    }

    Ok(deleted)
}

/// Ensure the data directory exists for a cache path.
///
/// Call this before running populate commands to ensure the cache has
/// a proper data directory structure. Creates the data directory as a
/// btrfs subvolume (if supported) to enable instant snapshots.
pub fn ensure_data_dir(
    cache_path: &Path,
    storage: &Arc<dyn WorkspaceStorage>,
) -> Result<PathBuf, SnapshotError> {
    let data = data_dir(cache_path);
    // Create parent directories first (these don't need to be subvolumes)
    if let Some(parent) = data.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Create the data directory as a btrfs subvolume for instant snapshots
    if !data.exists() {
        storage.create_dir(&data)?;
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_storage() -> Arc<dyn WorkspaceStorage> {
        crate::cache::detect_storage(Path::new("/tmp"))
    }

    #[test]
    fn test_hash_command() {
        let hash1 = hash_command("cargo fetch --locked");
        let hash2 = hash_command("cargo fetch --locked");
        let hash3 = hash_command("pnpm fetch");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA256 hex
    }

    #[tokio::test]
    async fn test_create_and_get_snapshot() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("test-cache");
        let storage = create_test_storage();

        // Create data directory with some content
        let data = ensure_data_dir(&cache_path, &storage).unwrap();
        fs::write(data.join("test.txt"), "hello").unwrap();

        // Create snapshot
        let snapshot = create_snapshot(&cache_path, "test command", &storage)
            .await
            .unwrap();
        assert!(snapshot.exists());
        assert!(snapshot.join("data").join("test.txt").exists());

        // Get latest snapshot
        let latest = get_latest_snapshot(&cache_path, None).unwrap();
        assert!(latest.is_some());
        let latest_data = latest.unwrap();
        assert!(latest_data.join("test.txt").exists());

        // Verify content
        let content = fs::read_to_string(latest_data.join("test.txt")).unwrap();
        assert_eq!(content, "hello");
    }

    #[tokio::test]
    async fn test_snapshot_command_hash_filtering() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("test-cache");
        let storage = create_test_storage();

        // Create data directory
        let data = ensure_data_dir(&cache_path, &storage).unwrap();
        fs::write(data.join("test.txt"), "v1").unwrap();

        // Create snapshot with command A
        let _ = create_snapshot(&cache_path, "command-a", &storage)
            .await
            .unwrap();

        // Wait a bit to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Modify data and create snapshot with command B
        fs::write(data.join("test.txt"), "v2").unwrap();
        let _ = create_snapshot(&cache_path, "command-b", &storage)
            .await
            .unwrap();

        // Get latest without filter - should get command-b
        let latest = get_latest_snapshot(&cache_path, None).unwrap().unwrap();
        let content = fs::read_to_string(latest.join("test.txt")).unwrap();
        assert_eq!(content, "v2");

        // Get latest with command-a filter - should get older snapshot
        let hash_a = hash_command("command-a");
        let latest_a = get_latest_snapshot(&cache_path, Some(&hash_a))
            .unwrap()
            .unwrap();
        let content_a = fs::read_to_string(latest_a.join("test.txt")).unwrap();
        assert_eq!(content_a, "v1");
    }

    #[tokio::test]
    async fn test_cleanup_snapshots() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("test-cache");
        let storage = create_test_storage();

        // Create data directory
        let data = ensure_data_dir(&cache_path, &storage).unwrap();
        fs::write(data.join("test.txt"), "content").unwrap();

        // Create multiple snapshots
        for i in 0..5 {
            let _ = create_snapshot(&cache_path, &format!("command-{}", i), &storage)
                .await
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }

        // Count snapshots
        let snapshots = snapshots_dir(&cache_path);
        let count_before = fs::read_dir(&snapshots).unwrap().count();
        assert_eq!(count_before, 5);

        // Cleanup, keep 2
        let deleted = cleanup_snapshots(&cache_path, 2, &storage).await.unwrap();
        assert_eq!(deleted, 3);

        let count_after = fs::read_dir(&snapshots).unwrap().count();
        assert_eq!(count_after, 2);
    }

    #[test]
    fn test_no_snapshot_returns_none() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("nonexistent");

        let result = get_latest_snapshot(&cache_path, None).unwrap();
        assert!(result.is_none());
    }
}
