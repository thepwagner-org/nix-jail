//! Workspace storage backends for efficient copy-on-write operations.
//!
//! Provides a trait abstraction over different storage strategies:
//! - `BtrfsStorage` - btrfs subvolumes and snapshots (Linux only)
//! - `ReflinkStorage` - CoW copies via reflinks (XFS, APFS, btrfs fallback)
//! - `StandardStorage` - regular filesystem operations

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tracing::{debug, warn};

/// Error type for workspace storage operations
#[derive(Debug)]
pub enum WorkspaceStorageError {
    /// Command execution failed
    CommandFailed(String),
    /// IO error
    Io(std::io::Error),
}

impl std::fmt::Display for WorkspaceStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceStorageError::CommandFailed(s) => write!(f, "command failed: {}", s),
            WorkspaceStorageError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for WorkspaceStorageError {}

impl From<std::io::Error> for WorkspaceStorageError {
    fn from(e: std::io::Error) -> Self {
        WorkspaceStorageError::Io(e)
    }
}

pub type BtrfsError = WorkspaceStorageError;
pub type StorageError = WorkspaceStorageError;

/// Trait for workspace storage operations
///
/// Different implementations provide CoW semantics where available:
/// - btrfs subvolumes for instant snapshots
/// - reflinks for efficient copies on XFS/APFS
/// - regular copies as fallback
pub trait WorkspaceStorage: Send + Sync + std::fmt::Debug {
    /// Create a workspace directory
    fn create_dir(&self, path: &Path) -> Result<(), StorageError>;

    /// Delete a workspace directory
    fn delete_dir(&self, path: &Path) -> Result<(), StorageError>;

    /// Copy a directory tree efficiently
    fn copy_tree_sync(&self, src: &Path, dest: &Path) -> Result<i64, StorageError>;

    /// Create a snapshot or copy of a directory
    fn snapshot_or_copy_sync(&self, src: &Path, dest: &Path) -> Result<(), StorageError>;

    /// Human-readable name for logging
    fn name(&self) -> &'static str;
}

/// Detect the best available storage backend for a path
///
/// Call this once at server startup and reuse for all jobs.
pub fn detect_storage(path: &Path) -> Arc<dyn WorkspaceStorage> {
    // First check if we're on btrfs and can create subvolumes
    if check_btrfs_subvolume_support(path) {
        return Arc::new(BtrfsStorage);
    }

    // Check if reflinks work (covers btrfs without perms, XFS, APFS)
    if check_reflink_support(path) {
        return Arc::new(ReflinkStorage);
    }

    Arc::new(StandardStorage)
}

// Detection helpers

fn check_btrfs_subvolume_support(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(path)
            .output();

        if let Ok(output) = output {
            let fstype = String::from_utf8_lossy(&output.stdout);
            if fstype.trim() == "btrfs" {
                // Try a test subvolume create/delete
                let test_path = path.join(".btrfs-test-subvol");
                let create = Command::new("btrfs")
                    .args(["subvolume", "create"])
                    .arg(&test_path)
                    .output();

                if let Ok(output) = create {
                    if output.status.success() {
                        // Clean up test subvolume
                        let _ = Command::new("btrfs")
                            .args(["subvolume", "delete"])
                            .arg(&test_path)
                            .output();
                        return true;
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
    }

    false
}

fn check_reflink_support(path: &Path) -> bool {
    use std::fs;
    use std::io::Write;

    let test_src = path.join(".reflink-test-src");
    let test_dst = path.join(".reflink-test-dst");

    let result = (|| -> std::io::Result<bool> {
        let mut file = fs::File::create(&test_src)?;
        file.write_all(b"reflink test")?;
        drop(file);

        #[cfg(target_os = "linux")]
        let success = Command::new("cp")
            .args(["--reflink=always"])
            .arg(&test_src)
            .arg(&test_dst)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        #[cfg(target_os = "macos")]
        let success = Command::new("cp")
            .args(["-c"])
            .arg(&test_src)
            .arg(&test_dst)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let success = false;

        Ok(success)
    })();

    let _ = fs::remove_file(&test_src);
    let _ = fs::remove_file(&test_dst);

    result.unwrap_or(false)
}

// ============================================================================
// BtrfsStorage - uses btrfs subvolumes
// ============================================================================

/// Storage backend using btrfs subvolumes and snapshots
#[derive(Debug, Clone, Copy)]
pub struct BtrfsStorage;

impl WorkspaceStorage for BtrfsStorage {
    fn create_dir(&self, path: &Path) -> Result<(), StorageError> {
        debug!(path = %path.display(), "creating btrfs subvolume");
        let output = Command::new("btrfs")
            .args(["subvolume", "create"])
            .arg(path)
            .output()?;

        if !output.status.success() {
            return Err(StorageError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(())
    }

    fn delete_dir(&self, path: &Path) -> Result<(), StorageError> {
        if !path.exists() {
            return Ok(());
        }

        debug!(path = %path.display(), "deleting btrfs subvolume");
        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(path)
            .output()?;

        if !output.status.success() {
            warn!(path = %path.display(), "btrfs subvolume delete failed, trying rm -rf");
            std::fs::remove_dir_all(path)?;
        }
        Ok(())
    }

    fn copy_tree_sync(&self, src: &Path, dest: &Path) -> Result<i64, StorageError> {
        debug!(src = %src.display(), dest = %dest.display(), "copying tree with reflinks");
        copy_with_reflink(src, dest)
    }

    fn snapshot_or_copy_sync(&self, src: &Path, dest: &Path) -> Result<(), StorageError> {
        debug!(src = %src.display(), dest = %dest.display(), "creating btrfs snapshot");

        // Clean up existing destination - btrfs snapshot requires dest to not exist
        if dest.exists() {
            debug!(dest = %dest.display(), "removing existing destination before snapshot");
            // Try btrfs subvolume delete first (in case it's a subvolume from previous run)
            let output = Command::new("btrfs")
                .args(["subvolume", "delete"])
                .arg(dest)
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    debug!(dest = %dest.display(), "deleted existing subvolume");
                }
                _ => {
                    // Not a subvolume or delete failed - use rm -rf
                    debug!(dest = %dest.display(), "removing existing directory with rm -rf");
                    std::fs::remove_dir_all(dest)?;
                }
            }
        }

        let output = Command::new("btrfs")
            .args(["subvolume", "snapshot"])
            .arg(src)
            .arg(dest)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(src = %src.display(), stderr = %stderr, "btrfs snapshot failed, falling back to copy");
            let _ = copy_with_reflink(src, dest)?;
        } else {
            // Verify snapshot has content
            let nix_store = dest.join("nix/store");
            if nix_store.exists() {
                match std::fs::read_dir(&nix_store) {
                    Ok(entries) => {
                        let count = entries.count();
                        debug!(dest = %dest.display(), store_paths = count, "btrfs snapshot created");
                    }
                    Err(e) => {
                        warn!(dest = %dest.display(), error = %e, "btrfs snapshot created but cannot read nix/store");
                    }
                }
            } else {
                warn!(dest = %dest.display(), "btrfs snapshot created but nix/store missing");
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "btrfs"
    }
}

// ============================================================================
// ReflinkStorage - uses CoW copies via reflinks
// ============================================================================

/// Storage backend using reflink copies (XFS, APFS, btrfs without perms)
#[derive(Debug, Clone, Copy)]
pub struct ReflinkStorage;

impl WorkspaceStorage for ReflinkStorage {
    fn create_dir(&self, path: &Path) -> Result<(), StorageError> {
        debug!(path = %path.display(), "creating directory");
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn delete_dir(&self, path: &Path) -> Result<(), StorageError> {
        if !path.exists() {
            return Ok(());
        }
        debug!(path = %path.display(), "removing directory tree");
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    fn copy_tree_sync(&self, src: &Path, dest: &Path) -> Result<i64, StorageError> {
        debug!(src = %src.display(), dest = %dest.display(), "copying tree with reflinks");
        copy_with_reflink(src, dest)
    }

    fn snapshot_or_copy_sync(&self, src: &Path, dest: &Path) -> Result<(), StorageError> {
        let _ = copy_with_reflink(src, dest)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "reflink"
    }
}

// ============================================================================
// StandardStorage - regular filesystem operations
// ============================================================================

/// Storage backend using standard filesystem operations
#[derive(Debug, Clone, Copy)]
pub struct StandardStorage;

impl WorkspaceStorage for StandardStorage {
    fn create_dir(&self, path: &Path) -> Result<(), StorageError> {
        debug!(path = %path.display(), "creating directory");
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn delete_dir(&self, path: &Path) -> Result<(), StorageError> {
        if !path.exists() {
            return Ok(());
        }
        debug!(path = %path.display(), "removing directory tree");
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    fn copy_tree_sync(&self, src: &Path, dest: &Path) -> Result<i64, StorageError> {
        debug!(src = %src.display(), dest = %dest.display(), "copying tree");
        copy_standard(src, dest)
    }

    fn snapshot_or_copy_sync(&self, src: &Path, dest: &Path) -> Result<(), StorageError> {
        let _ = copy_standard(src, dest)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "standard"
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

fn copy_with_reflink(src: &Path, dest: &Path) -> Result<i64, StorageError> {
    #[cfg(target_os = "linux")]
    let output = Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .arg(src)
        .arg(dest)
        .output()?;

    #[cfg(target_os = "macos")]
    let output = Command::new("cp")
        .args(["-a", "-c"])
        .arg(src)
        .arg(dest)
        .output()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let output = Command::new("cp")
        .args(["-a"])
        .arg(src)
        .arg(dest)
        .output()?;

    if !output.status.success() {
        return Err(StorageError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    dir_size(dest)
}

fn copy_standard(src: &Path, dest: &Path) -> Result<i64, StorageError> {
    let output = Command::new("cp")
        .args(["-a"])
        .arg(src)
        .arg(dest)
        .output()?;

    if !output.status.success() {
        return Err(StorageError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    dir_size(dest)
}

fn dir_size(path: &Path) -> Result<i64, StorageError> {
    let mut total: i64 = 0;

    if path.is_file() {
        return Ok(path.metadata()?.len() as i64);
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;

        if metadata.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += metadata.len() as i64;
        }
    }

    Ok(total)
}

// ============================================================================
// Async wrappers
// ============================================================================

/// Copy a directory tree asynchronously
pub async fn copy_tree(
    src: &Path,
    dest: &Path,
    storage: &Arc<dyn WorkspaceStorage>,
) -> Result<i64, StorageError> {
    let src = src.to_path_buf();
    let dest = dest.to_path_buf();
    let storage = Arc::clone(storage);

    tokio::task::spawn_blocking(move || storage.copy_tree_sync(&src, &dest))
        .await
        .map_err(|e| StorageError::CommandFailed(format!("task join error: {}", e)))?
}

/// Create a snapshot or copy asynchronously
pub async fn snapshot_or_copy(
    src: &Path,
    dest: &Path,
    storage: &Arc<dyn WorkspaceStorage>,
) -> Result<(), StorageError> {
    let src = src.to_path_buf();
    let dest = dest.to_path_buf();
    let storage = Arc::clone(storage);

    tokio::task::spawn_blocking(move || storage.snapshot_or_copy_sync(&src, &dest))
        .await
        .map_err(|e| StorageError::CommandFailed(format!("task join error: {}", e)))?
}

// ============================================================================
// Backward compatibility aliases
// ============================================================================

/// Level of btrfs/CoW support available (deprecated, use WorkspaceStorage trait)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsSupport {
    Full,
    Reflink,
    None,
}

impl BtrfsSupport {
    pub fn detect(path: &Path) -> Self {
        if check_btrfs_subvolume_support(path) {
            BtrfsSupport::Full
        } else if check_reflink_support(path) {
            BtrfsSupport::Reflink
        } else {
            BtrfsSupport::None
        }
    }
}

/// Create a snapshot directory (deprecated, use WorkspaceStorage trait)
pub fn create_snapshot_dir(path: &Path, support: &BtrfsSupport) -> Result<(), StorageError> {
    match support {
        BtrfsSupport::Full => BtrfsStorage.create_dir(path),
        BtrfsSupport::Reflink | BtrfsSupport::None => StandardStorage.create_dir(path),
    }
}

/// Delete a snapshot directory (deprecated, use WorkspaceStorage trait)
pub fn delete_snapshot(path: &Path, support: &BtrfsSupport) -> Result<(), StorageError> {
    match support {
        BtrfsSupport::Full => BtrfsStorage.delete_dir(path),
        BtrfsSupport::Reflink | BtrfsSupport::None => StandardStorage.delete_dir(path),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_detect_storage() {
        let dir = tempdir().expect("failed to create temp dir");
        let storage = detect_storage(dir.path());
        // Just verify detection doesn't panic
        tracing::debug!("detected storage: {}", storage.name());
    }

    #[test]
    fn test_standard_storage_create_delete() {
        let dir = tempdir().expect("failed to create temp dir");
        let subdir = dir.path().join("test-workspace");

        let storage = StandardStorage;
        storage.create_dir(&subdir).expect("failed to create dir");
        assert!(subdir.exists());

        storage.delete_dir(&subdir).expect("failed to delete dir");
        assert!(!subdir.exists());
    }

    #[test]
    fn test_reflink_storage_create_delete() {
        let dir = tempdir().expect("failed to create temp dir");
        let subdir = dir.path().join("test-workspace");

        let storage = ReflinkStorage;
        storage.create_dir(&subdir).expect("failed to create dir");
        assert!(subdir.exists());

        storage.delete_dir(&subdir).expect("failed to delete dir");
        assert!(!subdir.exists());
    }

    #[test]
    fn test_copy_tree_standard() {
        let dir = tempdir().expect("failed to create temp dir");
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");

        fs::create_dir(&src).expect("failed to create src dir");
        fs::write(src.join("file.txt"), "test content").expect("failed to write file");

        let storage = StandardStorage;
        let size = storage.copy_tree_sync(&src, &dest).expect("failed to copy");

        assert!(dest.exists());
        assert!(dest.join("file.txt").exists());
        assert!(size > 0);
    }

    #[tokio::test]
    async fn test_async_copy_tree() {
        let dir = tempdir().expect("failed to create temp dir");
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");

        fs::create_dir(&src).expect("failed to create src dir");
        fs::write(src.join("file.txt"), "test content").expect("failed to write file");

        let storage: Arc<dyn WorkspaceStorage> = Arc::new(StandardStorage);
        let size = copy_tree(&src, &dest, &storage)
            .await
            .expect("failed to copy");

        assert!(dest.exists());
        assert!(dest.join("file.txt").exists());
        assert!(size > 0);
    }

    #[test]
    fn test_dir_size() {
        let dir = tempdir().expect("failed to create temp dir");

        fs::write(dir.path().join("file1.txt"), "hello").expect("failed to write");
        fs::write(dir.path().join("file2.txt"), "world!").expect("failed to write");

        let size = dir_size(dir.path()).expect("failed to get size");
        assert_eq!(size, 11);
    }
}
