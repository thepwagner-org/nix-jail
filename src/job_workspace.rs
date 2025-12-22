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

/// Backend for workspace storage operations
#[derive(Debug, Clone)]
pub enum WorkspaceBackend {
    /// Filesystem-based storage using btrfs snapshots or reflinks
    Filesystem { storage: Arc<dyn WorkspaceStorage> },
    /// Docker volume-based storage (for macOS performance optimization)
    DockerVolume,
}

/// Cached workspace setup with optional mirror support
///
/// Unified workspace implementation that supports:
/// - Full clones (no mirror) or sparse checkouts (with mirror)
/// - Filesystem caching (btrfs snapshots/reflinks) or Docker volumes
/// - Caches by hash(repo, commit) or hash(repo, commit, path) for sparse
#[derive(Debug)]
pub struct CachedJobWorkspace {
    cache_dir: PathBuf,
    mirror: Option<RepoMirror>,
    backend: WorkspaceBackend,
}

impl CachedJobWorkspace {
    /// Create a new CachedJobWorkspace with filesystem backend
    pub fn new(cache_manager: CacheManager) -> Self {
        Self {
            cache_dir: cache_manager.cache_dir().to_path_buf(),
            mirror: None,
            backend: WorkspaceBackend::Filesystem {
                storage: cache_manager.storage().clone(),
            },
        }
    }

    /// Create with Docker volume backend (for macOS optimization)
    pub fn with_docker_volumes(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            mirror: None,
            backend: WorkspaceBackend::DockerVolume,
        }
    }

    /// Set a local mirror for ref resolution and sparse checkouts
    pub fn with_mirror(mut self, local_repo: impl Into<PathBuf>) -> Self {
        self.mirror = Some(RepoMirror::new(local_repo));
        self
    }

    /// Compute cache key for a git clone/checkout
    ///
    /// When path is provided, includes it in the hash (for sparse checkouts).
    /// This ensures different sparse paths have different cache entries.
    pub fn compute_cache_key(repo: &str, commit_sha: &str, path: Option<&str>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(repo.as_bytes());
        hasher.update(b"\n");
        hasher.update(commit_sha.as_bytes());
        if let Some(p) = path {
            hasher.update(b"\n");
            hasher.update(p.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Get the cache directory for full clones
    fn clones_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("clones")
    }

    /// Get the cache directory for sparse checkouts
    fn sparse_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("sparse")
    }

    /// Resolve git ref to commit SHA
    fn resolve_ref(
        &self,
        repo: &str,
        git_ref: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<String, WorkspaceError> {
        if let Some(mirror) = &self.mirror {
            // Sync mirror and resolve locally
            let mirror_path = mirror.sync(repo, github_token)?;
            git::resolve_ref_from_mirror(&mirror_path, git_ref)
        } else {
            // Resolve via network
            git::resolve_ref_to_commit(repo, git_ref, github_token)
        }
    }

    /// Check if using sparse checkout mode
    fn use_sparse_checkout(&self, path: Option<&str>) -> bool {
        self.mirror.is_some() && path.is_some() && path != Some("") && path != Some(".")
    }

    // Docker volume helpers (only used with DockerVolume backend)

    /// Clone into a Docker volume using nixos/nix container
    async fn clone_into_volume(
        repo: &str,
        commit_sha: &str,
        path: Option<&str>,
        volume_name: &str,
    ) -> Result<(), WorkspaceError> {
        use std::process::Command;

        let sparse_path = path.unwrap_or(".");

        let script = format!(
            r#"
            set -e
            cd /workspace
            git clone --depth 1 --filter=blob:none --sparse --no-checkout '{repo}' .
            git sparse-checkout set '{sparse_path}'
            git checkout
            "#,
            repo = repo,
            sparse_path = sparse_path
        );

        tracing::info!(
            volume = %volume_name,
            repo = %repo,
            commit = %commit_sha,
            path = ?path,
            "cloning into docker volume"
        );

        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/workspace", volume_name),
                "nixos/nix:latest",
                "nix-shell",
                "-p",
                "git",
                "--run",
                &script,
            ])
            .output()
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "failed to run docker: {}",
                    e
                )))
            })?;

        if !output.status.success() {
            return Err(WorkspaceError::IoError(std::io::Error::other(format!(
                "docker clone failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))));
        }

        Ok(())
    }

    fn volume_exists(name: &str) -> bool {
        use std::process::Command;
        Command::new("docker")
            .args(["volume", "inspect", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn create_volume(name: &str) -> Result<(), WorkspaceError> {
        use std::process::Command;
        let output = Command::new("docker")
            .args(["volume", "create", name])
            .output()
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "failed to create docker volume: {}",
                    e
                )))
            })?;

        if !output.status.success() {
            return Err(WorkspaceError::IoError(std::io::Error::other(format!(
                "docker volume create failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))));
        }
        Ok(())
    }

    fn delete_volume(name: &str) -> Result<(), WorkspaceError> {
        use std::process::Command;
        let output = Command::new("docker")
            .args(["volume", "rm", name])
            .output()
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "failed to delete docker volume: {}",
                    e
                )))
            })?;

        if !output.status.success() {
            tracing::warn!(
                volume = %name,
                error = %String::from_utf8_lossy(&output.stderr),
                "failed to delete docker volume"
            );
        }
        Ok(())
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
        // Handle empty repo case
        if repo.is_empty() {
            return self.setup_empty_workspace(workspace_dir).await;
        }

        // Step 1: Resolve ref to commit SHA
        let commit_sha = self.resolve_ref(repo, git_ref, github_token)?;

        // Step 2: Determine cache key and strategy
        let use_sparse = self.use_sparse_checkout(path);
        let cache_key = Self::compute_cache_key(
            repo,
            &commit_sha,
            if use_sparse { path } else { None },
        );

        tracing::info!(
            repo = %repo,
            git_ref = ?git_ref,
            commit = %commit_sha,
            cache_key = %cache_key,
            sparse = use_sparse,
            backend = ?self.backend,
            "resolved git ref for caching"
        );

        // Step 3: Backend-specific setup
        match &self.backend {
            WorkspaceBackend::Filesystem { storage } => {
                self.setup_filesystem(
                    workspace_dir,
                    repo,
                    &commit_sha,
                    path,
                    github_token,
                    &cache_key,
                    use_sparse,
                    storage,
                )
                .await
            }
            WorkspaceBackend::DockerVolume => {
                self.setup_docker_volume(repo, &commit_sha, path, &cache_key)
                    .await
            }
        }
    }

    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError> {
        match &self.backend {
            WorkspaceBackend::Filesystem { storage } => {
                // Delete workspace subvolume first (if it exists)
                if workspace_dir.exists() {
                    storage
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
            WorkspaceBackend::DockerVolume => {
                // Parse volume name from special path format
                let path_str = workspace_dir.to_string_lossy();
                if let Some(volume_part) = path_str.strip_prefix("docker-volume:") {
                    let volume_name = volume_part.split(':').next().unwrap_or(volume_part);
                    Self::delete_volume(volume_name)?;
                }
                Ok(())
            }
        }
    }
}

impl CachedJobWorkspace {
    /// Setup empty workspace (no git repo)
    async fn setup_empty_workspace(&self, workspace_dir: &Path) -> Result<PathBuf, WorkspaceError> {
        match &self.backend {
            WorkspaceBackend::Filesystem { storage } => {
                storage
                    .create_dir(workspace_dir)
                    .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        workspace_dir,
                        std::fs::Permissions::from_mode(0o777),
                    )?;
                }
                Ok(workspace_dir.to_path_buf())
            }
            WorkspaceBackend::DockerVolume => {
                let volume_name = format!("nix-jail-ws-empty-{}", ulid::Ulid::new());
                Self::create_volume(&volume_name)?;
                Ok(PathBuf::from(format!("docker-volume:{}", volume_name)))
            }
        }
    }

    /// Setup workspace using filesystem backend
    #[allow(clippy::too_many_arguments)]
    async fn setup_filesystem(
        &self,
        workspace_dir: &Path,
        repo: &str,
        commit_sha: &str,
        path: Option<&str>,
        github_token: Option<&str>,
        cache_key: &str,
        use_sparse: bool,
        storage: &Arc<dyn WorkspaceStorage>,
    ) -> Result<PathBuf, WorkspaceError> {
        // Determine cache directory based on clone strategy
        let cache_dir = if use_sparse {
            self.sparse_cache_dir()
        } else {
            self.clones_cache_dir()
        };
        std::fs::create_dir_all(&cache_dir)?;
        let cached_clone = cache_dir.join(cache_key);

        let parent_dir = workspace_dir
            .parent()
            .ok_or_else(|| WorkspaceError::InvalidPath("workspace has no parent".into()))?;

        storage
            .create_dir(parent_dir)
            .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;

        // For full clones, workspace goes in src/ subdir; for sparse, directly in workspace_dir
        let target_dir = if use_sparse {
            workspace_dir.to_path_buf()
        } else {
            parent_dir.join("src")
        };

        if cached_clone.exists() {
            // Cache hit - snapshot to workspace
            tracing::info!(
                cache_key = %cache_key,
                sparse = use_sparse,
                "cache hit - creating snapshot"
            );

            crate::cache::snapshot_or_copy(&cached_clone, &target_dir, storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        } else {
            // Cache miss - clone/checkout fresh
            tracing::info!(
                repo = %repo,
                commit = %commit_sha,
                sparse = use_sparse,
                "cache miss - cloning repository"
            );

            let temp_clone = cache_dir.join(format!("{}.tmp", cache_key));
            if temp_clone.exists() {
                std::fs::remove_dir_all(&temp_clone)?;
            }

            if use_sparse {
                // Sparse checkout from mirror
                let mirror = self.mirror.as_ref().ok_or_else(|| {
                    WorkspaceError::InvalidPath("sparse checkout requires mirror".into())
                })?;
                let mirror_path = mirror.sync(repo, github_token)?;

                let sparse_paths: Vec<&str> = path
                    .filter(|p| !p.is_empty() && *p != ".")
                    .into_iter()
                    .collect();

                git::sparse_checkout_from_mirror(
                    repo,
                    Some(&mirror_path),
                    &temp_clone,
                    commit_sha,
                    &sparse_paths,
                )?;

                // Move to cache
                std::fs::rename(&temp_clone, &cached_clone)?;
            } else {
                // Full clone
                storage
                    .create_dir(&temp_clone)
                    .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;

                git::clone_repository(repo, &temp_clone, Some(commit_sha), github_token)?;

                let cloned_src = temp_clone.join("src");
                if !cloned_src.exists() {
                    return Err(WorkspaceError::InvalidPath(
                        "git clone did not create src directory".into(),
                    ));
                }

                // Move cloned src to cache location
                std::fs::rename(&cloned_src, &cached_clone)?;
                let _ = storage.delete_dir(&temp_clone);
            }

            // Snapshot from cache to workspace
            crate::cache::snapshot_or_copy(&cached_clone, &target_dir, storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }

        // Make workspace writable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o777))?;
        }

        // Resolve working directory (may be subpath)
        let working_dir = if use_sparse {
            // For sparse checkout, path is already checked out at workspace root
            if let Some(subpath) = path {
                if !subpath.is_empty() && subpath != "." {
                    target_dir.join(subpath)
                } else {
                    target_dir
                }
            } else {
                target_dir
            }
        } else {
            // For full clone, navigate to subpath within src/
            if let Some(subpath) = path {
                if !subpath.is_empty() && subpath != "." {
                    git::verify_path_in_repo(&target_dir, subpath)?;
                    target_dir.join(subpath)
                } else {
                    target_dir
                }
            } else {
                target_dir
            }
        };

        Ok(working_dir)
    }

    /// Setup workspace using Docker volume backend
    async fn setup_docker_volume(
        &self,
        repo: &str,
        commit_sha: &str,
        path: Option<&str>,
        cache_key: &str,
    ) -> Result<PathBuf, WorkspaceError> {
        let volume_name = format!("nix-jail-ws-{}", &cache_key[..16]);

        if Self::volume_exists(&volume_name) {
            tracing::info!(
                volume = %volume_name,
                commit = %commit_sha,
                path = ?path,
                "docker volume cache hit"
            );
        } else {
            // Cache miss - create volume and clone
            Self::create_volume(&volume_name)?;
            Self::clone_into_volume(repo, commit_sha, path, &volume_name).await?;
        }

        // Return volume reference (special path format for DockerExecutor)
        let volume_path = if let Some(subpath) = path {
            if !subpath.is_empty() && subpath != "." {
                format!("docker-volume:{}:{}", volume_name, subpath)
            } else {
                format!("docker-volume:{}", volume_name)
            }
        } else {
            format!("docker-volume:{}", volume_name)
        };

        Ok(PathBuf::from(volume_path))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::mirror::RepoMirror;
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

    /// Integration test for CachedJobWorkspace with mirror (sparse checkout)
    ///
    /// Run with: cargo test test_cached_workspace_with_mirror -- --ignored --nocapture
    ///
    /// Requires: The current directory to be inside a git repository
    #[tokio::test]
    #[ignore] // Requires local git repo
    async fn test_cached_workspace_with_mirror() {
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
        let cache_dir = temp.path().join("cache");

        let storage: Arc<dyn WorkspaceStorage> = Arc::new(StandardStorage);
        let ws = CachedJobWorkspace {
            cache_dir,
            mirror: Some(RepoMirror::new(&repo_root)),
            backend: WorkspaceBackend::Filesystem { storage },
        };

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
