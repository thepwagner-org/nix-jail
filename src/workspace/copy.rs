//! Copy-on-write file system operations
//!
//! Provides efficient directory copying using platform-specific COW mechanisms:
//! - macOS (APFS): Uses `cp -c` for clonefile-based copy-on-write
//! - Linux (btrfs/xfs): Uses `cp --reflink=auto` for reflink copies
//! - Fallback: Standard recursive copy for other filesystems

use std::path::Path;
use tokio::process::Command;

use super::WorkspaceError;

/// Copy a directory tree using copy-on-write where available
///
/// This is the primary function for copying cache artifacts into workspaces.
/// It automatically selects the most efficient method for the current platform:
///
/// - **macOS APFS**: Uses `cp -c` - invokes clonefile for instant clone
/// - **Linux btrfs/xfs**: Uses `cp --reflink=auto` - COW if supported, fallback otherwise
/// - **Other**: Falls back to standard recursive copy
///
/// # Arguments
/// * `src` - Source directory (must exist, typically a Nix store path)
/// * `dest` - Destination path (must not exist, will be created)
///
/// # Errors
/// Returns an error if:
/// - Source doesn't exist
/// - Destination already exists
/// - Copy operation fails
pub async fn copy_tree_cow(src: &Path, dest: &Path) -> Result<(), WorkspaceError> {
    if !src.exists() {
        return Err(WorkspaceError::InvalidPath(format!(
            "Source path does not exist: {}",
            src.display()
        )));
    }

    if dest.exists() {
        return Err(WorkspaceError::InvalidPath(format!(
            "Destination already exists: {}",
            dest.display()
        )));
    }

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(target_os = "macos")]
    {
        copy_tree_clonefile(src, dest).await
    }

    #[cfg(target_os = "linux")]
    {
        copy_tree_reflink(src, dest).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        copy_tree_standard(src, dest).await
    }
}

/// macOS: Use cp -c for clonefile-based APFS clones
#[cfg(target_os = "macos")]
async fn copy_tree_clonefile(src: &Path, dest: &Path) -> Result<(), WorkspaceError> {
    // cp -c uses clonefile(2) on APFS for instant COW copies
    // -R for recursive, -c for clone
    let output = Command::new("cp")
        .args(["-Rc"])
        .arg(src)
        .arg(dest)
        .output()
        .await?;

    if output.status.success() {
        tracing::debug!(
            src = %src.display(),
            dest = %dest.display(),
            "clonefile copy succeeded"
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If clonefile fails, fall back to standard copy
        tracing::debug!(
            src = %src.display(),
            dest = %dest.display(),
            stderr = %stderr,
            "clonefile copy failed, falling back to standard copy"
        );
        copy_tree_standard(src, dest).await
    }
}

/// Linux: Use cp --reflink=auto for btrfs/xfs COW copies
#[cfg(target_os = "linux")]
async fn copy_tree_reflink(src: &Path, dest: &Path) -> Result<(), WorkspaceError> {
    let output = Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .arg(src)
        .arg(dest)
        .output()
        .await?;

    if output.status.success() {
        tracing::debug!(
            src = %src.display(),
            dest = %dest.display(),
            "reflink copy succeeded"
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(WorkspaceError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("cp --reflink failed: {}", stderr),
        )))
    }
}

/// Fallback: Standard recursive copy using cp -a
async fn copy_tree_standard(src: &Path, dest: &Path) -> Result<(), WorkspaceError> {
    let output = Command::new("cp")
        .args(["-a"])
        .arg(src)
        .arg(dest)
        .output()
        .await?;

    if output.status.success() {
        tracing::debug!(
            src = %src.display(),
            dest = %dest.display(),
            "standard copy succeeded"
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(WorkspaceError::IoError(std::io::Error::other(
            format!("cp -a failed: {}", stderr),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_copy_tree_cow_basic() {
        let src_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        // Create a file in source
        let src_file = src_dir.path().join("test.txt");
        std::fs::write(&src_file, "hello world").unwrap();

        // Create a subdirectory
        let src_subdir = src_dir.path().join("subdir");
        std::fs::create_dir(&src_subdir).unwrap();
        std::fs::write(src_subdir.join("nested.txt"), "nested content").unwrap();

        let dest_path = dest_dir.path().join("copied");

        // Copy
        copy_tree_cow(src_dir.path(), &dest_path).await.unwrap();

        // Verify
        assert!(dest_path.join("test.txt").exists());
        assert!(dest_path.join("subdir/nested.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dest_path.join("test.txt")).unwrap(),
            "hello world"
        );
    }

    #[tokio::test]
    async fn test_copy_tree_cow_nonexistent_source() {
        let dest_dir = TempDir::new().unwrap();
        let result = copy_tree_cow(Path::new("/nonexistent/path"), dest_dir.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_copy_tree_cow_dest_exists() {
        let src_dir = TempDir::new().unwrap();
        let dest_dir = TempDir::new().unwrap();

        // Destination already exists as a directory
        let result = copy_tree_cow(src_dir.path(), dest_dir.path()).await;
        assert!(result.is_err());
    }
}
