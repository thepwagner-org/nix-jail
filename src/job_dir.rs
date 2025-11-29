//! Job directory path container.
//!
//! Provides the `JobDirectory` struct that holds paths for a job's filesystem layout.
//! The orchestrator is responsible for setup and cleanup - this is just a container.

use std::path::{Path, PathBuf};

// Re-export from root for convenience
pub use crate::root::{get_job_root, JobRoot, RootError, StoreSetup, StoreStrategy};

/// Job directory path container
///
/// Holds paths for the job's filesystem layout:
/// ```text
/// {state_dir}/jobs/{job_id}/
/// ├── workspace/     # Working directory (git clone or empty)
/// └── root/          # Chroot root
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
