//! Job directory path container.
//!
//! Provides the `JobDirectory` struct that holds paths for a job's filesystem layout.
//! The orchestrator is responsible for setup and cleanup - this is just a container.

use std::path::{Path, PathBuf};
use std::process::Command;

// Re-export from root for convenience
pub use crate::root::{get_job_root, JobRoot, RootError, StoreSetup, StoreStrategy};

/// Job directory path container
///
/// Holds paths for the job's filesystem layout:
/// ```text
/// {state_dir}/jobs/{job_id}/
/// ├── workspace/           # Working directory (git clone or empty)
/// └── root/                # Chroot root (becomes / in sandbox)
///     └── home/{user}/     # Sandbox home directory ($HOME)
/// ```
///
/// This is a simple container - the orchestrator handles setup and cleanup.
#[derive(Debug, Clone)]
pub struct JobDirectory {
    /// Base directory for this job
    pub base: PathBuf,
    /// Workspace directory for job execution
    pub workspace: PathBuf,
    /// Root directory for chroot
    pub root: PathBuf,
}

impl JobDirectory {
    /// Create a new job directory structure
    ///
    /// Creates only the base directory:
    /// - `{state_dir}/jobs/{job_id}/`
    ///
    /// The workspace and root directories are NOT created here - they are
    /// created by `JobWorkspace::setup()` and `JobRoot::create()` respectively.
    /// This allows those implementations to use btrfs subvolumes when available.
    pub fn new(state_dir: &Path, job_id: &str) -> std::io::Result<Self> {
        let jobs_dir = state_dir.join("jobs");
        std::fs::create_dir_all(&jobs_dir)?;

        let base = jobs_dir.join(job_id);
        std::fs::create_dir_all(&base)?;

        let workspace = base.join("workspace");
        let root = base.join("root");

        Ok(Self {
            base,
            workspace,
            root,
        })
    }
}

/// Clean up orphaned job directories from previous daemon runs
///
/// Scans {state_dir}/jobs/ and removes any remaining job directories,
/// properly handling btrfs subvolumes. Call this at daemon startup to
/// garbage collect jobs that weren't cleaned up due to crashes.
pub fn cleanup_orphaned_jobs(state_dir: &Path) {
    let jobs_dir = state_dir.join("jobs");
    if !jobs_dir.exists() {
        return;
    }

    let entries = match std::fs::read_dir(&jobs_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read jobs directory");
            return;
        }
    };

    let mut cleaned = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let job_id = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Try to delete workspace subvolume
        let workspace = path.join("workspace");
        if workspace.exists() {
            delete_btrfs_subvolume(&workspace);
        }

        // Try to delete root subvolume
        let root = path.join("root");
        if root.exists() {
            delete_btrfs_subvolume(&root);
        }

        // Remove the job directory itself
        if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(job_id, error = %e, "failed to remove orphaned job directory");
        } else {
            cleaned += 1;
            tracing::debug!(job_id, "cleaned up orphaned job directory");
        }
    }

    if cleaned > 0 {
        tracing::info!(count = cleaned, "cleaned up orphaned job directories");
    }
}

/// Delete a path, trying btrfs subvolume delete first
fn delete_btrfs_subvolume(path: &Path) {
    // Try btrfs subvolume delete first
    let output = Command::new("btrfs")
        .args(["subvolume", "delete"])
        .arg(path)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            tracing::debug!(path = %path.display(), "deleted btrfs subvolume");
        }
        _ => {
            // Not a subvolume or btrfs not available, try rm -rf
            if let Err(e) = std::fs::remove_dir_all(path) {
                tracing::warn!(path = %path.display(), error = %e, "failed to delete directory");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_job_directory_creation() {
        let temp = tempdir().expect("Failed to create temp dir");
        let job_dir =
            JobDirectory::new(temp.path(), "test-job-1").expect("Failed to create job dir");

        // Only base is created by JobDirectory::new()
        // workspace and root are created by their respective trait implementations
        assert!(job_dir.base.exists());
        assert!(!job_dir.workspace.exists());
        assert!(!job_dir.root.exists());
        assert!(job_dir.base.ends_with("test-job-1"));
    }

    #[test]
    fn test_job_directory_is_clone() {
        let temp = tempdir().expect("Failed to create temp dir");
        let job_dir =
            JobDirectory::new(temp.path(), "test-clone").expect("Failed to create job dir");
        let cloned = job_dir.clone();

        assert_eq!(job_dir.base, cloned.base);
        assert_eq!(job_dir.workspace, cloned.workspace);
        assert_eq!(job_dir.root, cloned.root);
    }
}
