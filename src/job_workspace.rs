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

/// Mirror-based workspace setup with sparse checkout support and caching
///
/// Uses an existing local repository as the source for sparse checkouts.
/// Ideal for monorepo workflows where you already have the repo cloned
/// (e.g., ~/src) and only need a specific subpath for each job.
///
/// Caches sparse checkouts by hash(repo, commit, path) for instant workspace
/// creation on cache hits (O(1) on btrfs, CoW on APFS).
///
/// Flow:
/// 1. Fetch updates on the local repo
/// 2. Resolve ref using local repo (no network needed after fetch)
/// 3. Check cache for existing sparse checkout
/// 4. Cache hit: snapshot to workspace
/// 5. Cache miss: sparse checkout → cache → snapshot to workspace
#[derive(Debug)]
pub struct MirrorJobWorkspace {
    mirror: RepoMirror,
    storage: Arc<dyn WorkspaceStorage>,
    cache_dir: PathBuf,
}

impl MirrorJobWorkspace {
    /// Create a new MirrorJobWorkspace using an existing local repository
    ///
    /// The `local_repo` path should point to a full clone of the repository
    /// that will be used as the source for sparse checkouts.
    /// The `cache_dir` is where sparse checkouts are cached for reuse.
    pub fn new(
        local_repo: impl Into<PathBuf>,
        cache_dir: PathBuf,
        storage: Arc<dyn WorkspaceStorage>,
    ) -> Self {
        Self {
            mirror: RepoMirror::new(local_repo),
            storage,
            cache_dir,
        }
    }

    /// Compute cache key for a sparse checkout
    ///
    /// Includes repo URL, commit SHA, and sparse path for deterministic caching.
    pub fn compute_cache_key(repo: &str, commit_sha: &str, path: Option<&str>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(repo.as_bytes());
        hasher.update(b"\n");
        hasher.update(commit_sha.as_bytes());
        hasher.update(b"\n");
        hasher.update(path.unwrap_or("").as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get the sparse checkout cache directory
    fn sparse_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("sparse")
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

        // Step 3: Check cache
        let cache_key = Self::compute_cache_key(repo, &commit_sha, path);
        let sparse_cache = self.sparse_cache_dir();
        std::fs::create_dir_all(&sparse_cache)?;
        let cached_checkout = sparse_cache.join(&cache_key);

        if cached_checkout.exists() {
            // Cache hit! Snapshot the cached checkout
            tracing::info!(
                cache_key = %cache_key,
                commit = %commit_sha,
                path = ?path,
                "sparse checkout cache hit - creating snapshot"
            );

            crate::cache::snapshot_or_copy(&cached_checkout, workspace_dir, &self.storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        } else {
            // Cache miss - sparse checkout from remote
            tracing::info!(
                repo = %repo,
                git_ref = ?git_ref,
                commit = %commit_sha,
                path = ?path,
                "sparse checkout cache miss - cloning from remote"
            );

            // Clone to temp location first
            let temp_checkout = sparse_cache.join(format!(".tmp-{}", cache_key));
            if temp_checkout.exists() {
                std::fs::remove_dir_all(&temp_checkout)?;
            }

            let sparse_paths: Vec<&str> = path
                .filter(|p| !p.is_empty() && *p != ".")
                .into_iter()
                .collect();

            git::sparse_checkout_from_mirror(
                repo,
                Some(&mirror_path),
                &temp_checkout,
                &commit_sha,
                &sparse_paths,
            )?;

            // Move to cache location
            std::fs::rename(&temp_checkout, &cached_checkout)?;

            // Snapshot from cache to workspace
            crate::cache::snapshot_or_copy(&cached_checkout, workspace_dir, &self.storage)
                .await
                .map_err(|e| WorkspaceError::IoError(std::io::Error::other(e.to_string())))?;
        }

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

/// Docker volume-based workspace for macOS Docker optimization
///
/// On macOS, bind-mounting host directories into Docker containers crosses
/// the VM barrier, causing slow I/O. This workspace type creates Docker
/// volumes and clones directly into them, avoiding the VM barrier.
///
/// Volumes are cached by hash(repo, commit, path) for instant reuse.
///
/// Returns a special path format "docker-volume:{name}" that the Docker
/// executor interprets as a volume mount instead of a bind mount.
#[derive(Debug)]
pub struct DockerVolumeWorkspace {
    mirror: RepoMirror,
}

impl DockerVolumeWorkspace {
    /// Create a new DockerVolumeWorkspace using an existing local repository
    /// for ref resolution.
    pub fn new(local_repo: impl Into<PathBuf>) -> Self {
        Self {
            mirror: RepoMirror::new(local_repo),
        }
    }

    /// Clone a sparse checkout into a Docker volume using nixos/nix
    async fn clone_into_volume(
        &self,
        volume_name: &str,
        repo: &str,
        commit_sha: &str,
        path: Option<&str>,
    ) -> Result<(), WorkspaceError> {
        use std::process::Command;

        let sparse_path = path.unwrap_or(".");

        // Build the git clone script
        // Uses nix-shell to get git, then does sparse blobless checkout
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

    /// Check if a Docker volume exists
    fn volume_exists(name: &str) -> bool {
        use std::process::Command;
        Command::new("docker")
            .args(["volume", "inspect", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Create a Docker volume
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

    /// Delete a Docker volume
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
            // Volume might not exist, which is fine for cleanup
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
impl JobWorkspace for DockerVolumeWorkspace {
    async fn setup(
        &self,
        _workspace_dir: &Path,
        repo: &str,
        git_ref: Option<&str>,
        path: Option<&str>,
        github_token: Option<&str>,
    ) -> Result<PathBuf, WorkspaceError> {
        if repo.is_empty() {
            // No repo - create empty volume
            let volume_name = format!("nix-jail-ws-empty-{}", ulid::Ulid::new());
            Self::create_volume(&volume_name)?;
            return Ok(PathBuf::from(format!("docker-volume:{}", volume_name)));
        }

        // Step 1: Sync mirror and resolve ref
        let mirror_path = self.mirror.sync(repo, github_token)?;
        let commit_sha = git::resolve_ref_from_mirror(&mirror_path, git_ref)?;

        // Step 2: Compute volume name from cache key (enables caching)
        let cache_key = MirrorJobWorkspace::compute_cache_key(repo, &commit_sha, path);
        let volume_name = format!("nix-jail-ws-{}", &cache_key[..16]);

        // Step 3: Check if volume exists (cache hit)
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
            self.clone_into_volume(&volume_name, repo, &commit_sha, path)
                .await?;
        }

        // Return volume reference (special path format for DockerExecutor)
        // Format: docker-volume:{volume_name}[:{subpath}]
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

    fn cleanup(&self, workspace_dir: &Path) -> Result<(), WorkspaceError> {
        // Parse volume name from special path format
        let path_str = workspace_dir.to_string_lossy();
        if let Some(volume_part) = path_str.strip_prefix("docker-volume:") {
            // Volume name is before any colon (subpath separator)
            let volume_name = volume_part.split(':').next().unwrap_or(volume_part);
            Self::delete_volume(volume_name)?;
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
/// The `cache_dir` is where sparse checkouts are cached for instant reuse.
///
/// On Linux: Uses MirrorJobWorkspace with btrfs/CoW snapshot caching
/// On macOS with Docker: Uses DockerVolumeWorkspace to avoid VM barrier
pub fn get_mirror_workspace(
    local_repo: impl Into<PathBuf>,
    cache_dir: PathBuf,
    storage: Arc<dyn WorkspaceStorage>,
    use_docker_volumes: bool,
) -> Arc<dyn JobWorkspace> {
    let local_repo = local_repo.into();

    // On macOS with Docker executor, use volume-based workspace for performance
    // (bind-mounts cross the VM barrier and are slow)
    if use_docker_volumes && cfg!(target_os = "macos") {
        tracing::info!("using docker volume workspace for macos optimization");
        Arc::new(DockerVolumeWorkspace::new(local_repo))
    } else {
        // Linux or non-Docker: use cached snapshots (fast on btrfs, CoW on APFS)
        Arc::new(MirrorJobWorkspace::new(local_repo, cache_dir, storage))
    }
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
        let cache_dir = temp.path().join("cache");

        let storage: Arc<dyn WorkspaceStorage> = Arc::new(StandardStorage);
        let ws = MirrorJobWorkspace::new(&repo_root, cache_dir, storage);

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
