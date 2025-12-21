//! Workspace setup strategies for job execution.
//!
//! This module provides the `JobWorkspace` trait and implementations for
//! different strategies to set up job workspaces (git clone, caching, etc.).

use crate::cache::{CacheManager, StandardStorage, WorkspaceStorage};
use crate::workspace::{git, mirror::RepoMirror, WorkspaceError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Trait for setting up job workspaces with different strategies
///
/// Implementations encapsulate the specific logic for preparing workspaces,
/// including git cloning and optional caching.
#[async_trait::async_trait]
pub trait JobWorkspace: Send + Sync + std::fmt::Debug {
    /// Set up a workspace for job execution
    ///
    /// If repo is empty, creates an empty workspace directory.
    /// Otherwise, clones the repository and optionally navigates to a subpath.
    ///
    /// Returns the resolved workspace directory path.
    async fn setup(
        &self,
        workspace_dir: &Path,
        repo: &str,
        git_ref: Option<&str>,
        path: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<PathBuf, WorkspaceError>;

    /// Clean up a workspace after job completion
    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError>;
}

/// Standard workspace setup (no caching)
///
/// Clones repositories fresh each time. Simple and reliable.
#[derive(Debug, Default)]
pub struct StandardJobWorkspace;

impl StandardJobWorkspace {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl JobWorkspace for StandardJobWorkspace {
    async fn setup(
        &self,
        workspace_dir: &Path,
        repo: &str,
        git_ref: Option<&str>,
        path: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<PathBuf, WorkspaceError> {
        if repo.is_empty() {
            // No repo - just ensure workspace dir exists and is writable
            std::fs::create_dir_all(workspace_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(workspace_dir, std::fs::Permissions::from_mode(0o777))?;
            }
            return Ok(workspace_dir.to_path_buf());
        }

        // Clone the repository
        tracing::info!(
            repo = %repo,
            git_ref = ?git_ref,
            has_token = github_token.is_some(),
            "cloning git repository"
        );

        // Clone into parent directory (git module creates 'src' subdir)
        let parent_dir = workspace_dir
            .parent()
            .ok_or_else(|| WorkspaceError::InvalidPath("workspace has no parent".into()))?;
        git::clone_repository(repo, parent_dir, git_ref, github_token)?;

        // The clone creates a 'src' subdirectory
        let src_dir = parent_dir.join("src");
        if !src_dir.exists() {
            return Err(WorkspaceError::InvalidPath(
                "git clone did not create src directory".into(),
            ));
        }

        // Resolve the working directory (may be subpath)
        let working_dir = if let Some(subpath) = path {
            if !subpath.is_empty() && subpath != "." {
                git::verify_path_in_repo(&src_dir, subpath)?;
                src_dir.join(subpath)
            } else {
                src_dir
            }
        } else {
            src_dir
        };

        Ok(working_dir)
    }

    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError> {
        // Delete workspace first (if it exists)
        if workspace_dir.exists() {
            StandardStorage
                .delete_dir(workspace_dir)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }

        // Then delete the base directory
        let base_dir = workspace_dir
            .parent()
            .ok_or_else(|| WorkspaceError::InvalidPath("workspace has no parent".into()))?;
        if base_dir.exists() {
            std::fs::remove_dir_all(base_dir)?;
        }
        Ok(())
    }
}

/// Cached workspace setup using storage backend
///
/// Uses the configured storage backend (btrfs snapshots or reflinks)
/// for efficient workspace operations. Caches git clones by (repo, commit_sha)
/// for instant workspace creation on cache hits.
#[derive(Debug)]
pub struct CachedJobWorkspace {
    storage: Arc<dyn WorkspaceStorage>,
    cache_manager: CacheManager,
}

impl CachedJobWorkspace {
    pub fn new(cache_manager: CacheManager) -> Self {
        Self {
            storage: cache_manager.storage().clone(),
            cache_manager,
        }
    }

    /// Compute cache key for a git clone
    fn compute_clone_cache_key(repo: &str, commit_sha: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(repo.as_bytes());
        hasher.update(b"\n");
        hasher.update(commit_sha.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get the cache directory for clones
    fn clones_cache_dir(&self) -> PathBuf {
        self.cache_manager.cache_dir().join("clones")
    }
}

#[async_trait::async_trait]
impl JobWorkspace for CachedJobWorkspace {
    async fn setup(
        &self,
        workspace_dir: &Path,
        repo: &str,
        git_ref: Option<&str>,
        path: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<PathBuf, WorkspaceError> {
        if repo.is_empty() {
            // No repo - create workspace using storage backend
            self.storage
                .create_dir(workspace_dir)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(workspace_dir, std::fs::Permissions::from_mode(0o777))?;
            }
            return Ok(workspace_dir.to_path_buf());
        }

        // Step 1: Resolve ref to commit SHA for cache key
        let commit_sha = git::resolve_ref_to_commit(repo, git_ref, github_token)?;
        let cache_key = Self::compute_clone_cache_key(repo, &commit_sha);

        tracing::info!(
            repo = %repo,
            git_ref = ?git_ref,
            commit = %commit_sha,
            cache_key = %cache_key,
            "resolved git ref for caching"
        );

        // Step 2: Check cache
        let clones_dir = self.clones_cache_dir();
        std::fs::create_dir_all(&clones_dir)?;
        let cached_clone = clones_dir.join(&cache_key);

        let parent_dir = workspace_dir
            .parent()
            .ok_or_else(|| WorkspaceError::InvalidPath("workspace has no parent".into()))?;

        // Create parent using storage backend
        self.storage
            .create_dir(parent_dir)
            .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;

        let src_dir = parent_dir.join("src");

        if cached_clone.exists() {
            // Cache hit! Snapshot the cached clone
            tracing::info!(
                cache_key = %cache_key,
                "clone cache hit - creating snapshot"
            );

            crate::cache::snapshot_or_copy(&cached_clone, &src_dir, &self.storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        } else {
            // Cache miss - clone fresh
            tracing::info!(
                repo = %repo,
                commit = %commit_sha,
                "clone cache miss - cloning repository"
            );

            // Clone to a temp location first, then move to cache
            let temp_clone = clones_dir.join(format!("{}.tmp", cache_key));
            if temp_clone.exists() {
                std::fs::remove_dir_all(&temp_clone)?;
            }

            // Create temp dir using storage backend (for btrfs subvolume)
            self.storage
                .create_dir(&temp_clone)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;

            // Clone into temp (git module creates 'src' subdir inside target)
            git::clone_repository(repo, &temp_clone, Some(&commit_sha), github_token)?;

            // The clone creates 'src' inside temp_clone
            let cloned_src = temp_clone.join("src");
            if !cloned_src.exists() {
                return Err(WorkspaceError::InvalidPath(
                    "git clone did not create src directory".into(),
                ));
            }

            // Move cloned src to cache location
            std::fs::rename(&cloned_src, &cached_clone)?;

            // Clean up temp dir
            let _ = self.storage.delete_dir(&temp_clone);

            // Now snapshot from cache to workspace
            crate::cache::snapshot_or_copy(&cached_clone, &src_dir, &self.storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }

        // Make src writable for job execution
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&src_dir, std::fs::Permissions::from_mode(0o777))?;
        }

        // Resolve working directory (may be subpath)
        let working_dir = if let Some(subpath) = path {
            if !subpath.is_empty() && subpath != "." {
                git::verify_path_in_repo(&src_dir, subpath)?;
                src_dir.join(subpath)
            } else {
                src_dir
            }
        } else {
            src_dir
        };

        Ok(working_dir)
    }

    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError> {
        // Delete workspace subvolume first (if it exists)
        if workspace_dir.exists() {
            self.storage
                .delete_dir(workspace_dir)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }

        // Then delete the base directory (regular directory, not a subvolume)
        let base_dir = workspace_dir
            .parent()
            .ok_or_else(|| WorkspaceError::InvalidPath("workspace has no parent".into()))?;
        if base_dir.exists() {
            std::fs::remove_dir_all(base_dir)?;
        }
        Ok(())
    }
}

/// Mirror-based workspace setup with sparse checkout support
///
/// Uses an existing local repository as the source for sparse checkouts.
/// Ideal for monorepo workflows where you already have the repo cloned
/// (e.g., ~/src) and only need a specific subpath for each job.
///
/// Flow:
/// 1. Fetch updates on the local repo
/// 2. Resolve ref using local repo (no network needed after fetch)
/// 3. Sparse blobless checkout from local repo to workspace
#[derive(Debug)]
pub struct MirrorJobWorkspace {
    mirror: RepoMirror,
    storage: Arc<dyn WorkspaceStorage>,
}

impl MirrorJobWorkspace {
    /// Create a new MirrorJobWorkspace using an existing local repository
    ///
    /// The `local_repo` path should point to a full clone of the repository
    /// that will be used as the source for sparse checkouts.
    pub fn new(local_repo: impl Into<PathBuf>, storage: Arc<dyn WorkspaceStorage>) -> Self {
        Self {
            mirror: RepoMirror::new(local_repo),
            storage,
        }
    }
}

#[async_trait::async_trait]
impl JobWorkspace for MirrorJobWorkspace {
    async fn setup(
        &self,
        workspace_dir: &Path,
        repo: &str,
        git_ref: Option<&str>,
        path: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<PathBuf, WorkspaceError> {
        if repo.is_empty() {
            // No repo - create workspace using storage backend
            self.storage
                .create_dir(workspace_dir)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(workspace_dir, std::fs::Permissions::from_mode(0o777))?;
            }
            return Ok(workspace_dir.to_path_buf());
        }

        // Step 1: Sync mirror (fetch --all)
        let mirror_path = self.mirror.sync(repo, github_token)?;

        // Step 2: Resolve ref using mirror (no network needed)
        let commit_sha = git::resolve_ref_from_mirror(&mirror_path, git_ref)?;

        tracing::info!(
            repo = %repo,
            git_ref = ?git_ref,
            commit = %commit_sha,
            path = ?path,
            "setting up sparse checkout from mirror"
        );

        // Step 3: Sparse blobless checkout from remote, using mirror as reference
        let sparse_paths: Vec<&str> = path
            .filter(|p| !p.is_empty() && *p != ".")
            .into_iter()
            .collect();

        git::sparse_checkout_from_mirror(
            repo,
            Some(&mirror_path),
            workspace_dir,
            &commit_sha,
            &sparse_paths,
        )?;

        // Make workspace writable for job execution
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(workspace_dir, std::fs::Permissions::from_mode(0o777))?;
        }

        // Step 4: Return working directory (may be subpath within checkout)
        let working_dir = if let Some(subpath) = path {
            if !subpath.is_empty() && subpath != "." {
                workspace_dir.join(subpath)
            } else {
                workspace_dir.to_path_buf()
            }
        } else {
            workspace_dir.to_path_buf()
        };

        Ok(working_dir)
    }

    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError> {
        // Delete workspace (if it exists)
        if workspace_dir.exists() {
            self.storage
                .delete_dir(workspace_dir)
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }
        Ok(())
    }
}

/// Create a JobWorkspace based on configuration
///
/// If cache_manager is provided, uses CachedJobWorkspace for efficient operations.
/// Otherwise uses StandardJobWorkspace.
pub fn get_job_workspace(cache_manager: Option<CacheManager>) -> Arc<dyn JobWorkspace> {
    match cache_manager {
        Some(cm) => Arc::new(CachedJobWorkspace::new(cm)),
        None => Arc::new(StandardJobWorkspace::new()),
    }
}

/// Create a mirror-based JobWorkspace for monorepo support
///
/// Uses an existing local repository with sparse checkouts for efficient
/// monorepo cloning. The `local_repo` path should point to the full clone.
pub fn get_mirror_workspace(
    local_repo: impl Into<PathBuf>,
    storage: Arc<dyn WorkspaceStorage>,
) -> Arc<dyn JobWorkspace> {
    Arc::new(MirrorJobWorkspace::new(local_repo, storage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_standard_workspace_empty_repo() {
        let temp = tempdir().expect("Failed to create temp dir");
        let workspace_dir = temp.path().join("workspace");

        let ws = StandardJobWorkspace::new();
        let result_dir = ws
            .setup(&workspace_dir, "", None, None, None)
            .await
            .expect("Failed to setup workspace");

        assert!(workspace_dir.exists());
        assert_eq!(result_dir, workspace_dir);
    }

    /// Integration test for MirrorJobWorkspace sparse checkout
    ///
    /// Run with: cargo test test_mirror_sparse_checkout -- --ignored --nocapture
    ///
    /// Requires: The current directory to be inside a git repository
    #[tokio::test]
    #[ignore] // Requires local git repo
    async fn test_mirror_sparse_checkout() {
        use std::process::Command;

        // Find the repo root (we're in projects/nix-jail, repo root is ~/src or similar)
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .expect("Failed to run git");
        let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Using repo root: {}", repo_root);

        // Get current commit
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("Failed to get HEAD");
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Current commit: {}", commit);

        // Get remote URL (needed for actual clone)
        let output = Command::new("git")
            .args(["-C", &repo_root, "remote", "get-url", "origin"])
            .output()
            .expect("Failed to get remote URL");
        let remote_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("Remote URL: {}", remote_url);

        // Create workspace
        let temp = tempdir().expect("Failed to create temp dir");
        let workspace_dir = temp.path().join("workspace");

        let storage: Arc<dyn WorkspaceStorage> = Arc::new(StandardStorage);
        let ws = MirrorJobWorkspace::new(&repo_root, storage);

        // Setup with sparse checkout of just this project
        // Uses remote URL for actual clone, local repo as reference
        let result_dir = ws
            .setup(
                &workspace_dir,
                &remote_url,
                Some(&commit),
                Some("projects/nix-jail"),
                None,
            )
            .await
            .expect("Failed to setup workspace");

        println!("Workspace created at: {}", result_dir.display());

        // Verify the workspace
        assert!(workspace_dir.exists(), "Workspace dir should exist");
        assert!(
            workspace_dir.join(".git").exists(),
            "Should have .git directory"
        );
        assert!(
            workspace_dir.join("projects/nix-jail/Cargo.toml").exists(),
            "Should have nix-jail project"
        );

        // Check git status
        let output = Command::new("git")
            .args(["-C", &workspace_dir.to_string_lossy(), "status", "--short"])
            .output()
            .expect("Failed to run git status");
        println!("Git status:\n{}", String::from_utf8_lossy(&output.stdout));

        // Check sparse-checkout config
        let output = Command::new("git")
            .args([
                "-C",
                &workspace_dir.to_string_lossy(),
                "sparse-checkout",
                "list",
            ])
            .output()
            .expect("Failed to run sparse-checkout list");
        println!(
            "Sparse checkout paths:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        // Verify origin points to remote URL
        let output = Command::new("git")
            .args(["-C", &workspace_dir.to_string_lossy(), "remote", "-v"])
            .output()
            .expect("Failed to run git remote");
        let remotes = String::from_utf8_lossy(&output.stdout);
        println!("Remotes:\n{}", remotes);
        assert!(
            remotes.contains(&remote_url) || remotes.contains("git@"),
            "Origin should point to remote"
        );

        // Check what files are actually present (should be sparse)
        let output = Command::new("ls")
            .args(["-la", &workspace_dir.to_string_lossy()])
            .output()
            .expect("Failed to ls");
        println!(
            "Workspace contents:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        // Check object counts - are we copying the whole monorepo's objects?
        let output = Command::new("git")
            .args([
                "-C",
                &workspace_dir.to_string_lossy(),
                "count-objects",
                "-v",
            ])
            .output()
            .expect("Failed to count objects");
        println!(
            "Workspace git objects:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        let output = Command::new("git")
            .args(["-C", &repo_root, "count-objects", "-v"])
            .output()
            .expect("Failed to count source objects");
        println!(
            "Source repo git objects:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        println!("SUCCESS: Sparse checkout verified!");
    }
}
