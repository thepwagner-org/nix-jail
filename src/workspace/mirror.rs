//! Repository mirror management for efficient monorepo cloning
//!
//! Supports using an existing local checkout as the source for sparse checkouts,
//! avoiding the need to maintain a separate mirror.

use super::WorkspaceError;
use git2::{FetchOptions, RemoteCallbacks, Repository};
use std::path::{Path, PathBuf};

/// Uses an existing local git repository as the source for sparse checkouts
///
/// Instead of maintaining a separate mirror, this uses an existing checkout
/// (e.g., ~/src) as the source. The repository is fetched before each job
/// to ensure the latest refs are available.
#[derive(Debug, Clone)]
pub struct RepoMirror {
    /// Path to the existing local repository
    local_repo: PathBuf,
}

impl RepoMirror {
    /// Create a RepoMirror using an existing local repository
    ///
    /// The path should point to a git repository that will be used as the
    /// source for sparse checkouts. This repo will be fetched on each sync.
    pub fn new(local_repo: impl Into<PathBuf>) -> Self {
        Self {
            local_repo: local_repo.into(),
        }
    }

    /// Sync the local repository and return its path
    ///
    /// Optionally fetches all refs from the remote. Fetch can fail if
    /// the remote requires authentication not available via token.
    /// The repo_url parameter is ignored since we use the existing local repo.
    pub fn sync(&self, _repo_url: &str, token: Option<&str>) -> Result<PathBuf, WorkspaceError> {
        // Check for either a regular repo (.git subdir) or a bare repo (HEAD file directly)
        let is_regular_repo = self.local_repo.join(".git").exists();
        let is_bare_repo = self.local_repo.join("HEAD").exists();
        if !self.local_repo.exists() || (!is_regular_repo && !is_bare_repo) {
            return Err(WorkspaceError::InvalidPath(format!(
                "local repository does not exist: {}",
                self.local_repo.display()
            )));
        }

        tracing::info!(
            local_repo = %self.local_repo.display(),
            "syncing local repository"
        );

        // Try to fetch, but don't fail if auth isn't available
        // (the local repo may already have the commits we need)
        if let Err(e) = self.fetch_repo(&self.local_repo, token) {
            tracing::warn!(
                error = %e,
                "fetch failed, continuing with existing local refs"
            );
        }

        Ok(self.local_repo.clone())
    }

    /// Fetch all refs from the remote
    fn fetch_repo(&self, repo_path: &Path, token: Option<&str>) -> Result<(), WorkspaceError> {
        let repo = Repository::open(repo_path).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to open repository: {}",
                e
            )))
        })?;

        let mut remote = repo.find_remote("origin").map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to find origin remote: {}",
                e
            )))
        })?;

        // Set up authentication if token provided
        let mut callbacks = RemoteCallbacks::new();
        if let Some(token) = token {
            let token_owned = token.to_string();
            let _ = callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                git2::Cred::userpass_plaintext(username_from_url.unwrap_or("git"), &token_owned)
            });
        }

        let mut fetch_opts = FetchOptions::new();
        let _ = fetch_opts.remote_callbacks(callbacks);

        // Fetch all refs
        remote
            .fetch(
                &["refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"],
                Some(&mut fetch_opts),
                None,
            )
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "failed to fetch from remote: {}",
                    e
                )))
            })?;

        tracing::debug!(
            repo = %repo_path.display(),
            "fetch complete"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_mirror_uses_local_repo_path() {
        let temp = tempdir().expect("Failed to create temp dir");
        let repo_path = temp.path().join("my-repo");
        fs::create_dir_all(&repo_path).expect("Failed to create repo dir");

        let mirror = RepoMirror::new(&repo_path);

        // The mirror should use the exact path we gave it
        assert_eq!(mirror.local_repo, repo_path);
    }

    #[test]
    fn test_sync_fails_for_nonexistent_repo() {
        let mirror = RepoMirror::new("/nonexistent/path");

        let result = mirror.sync("https://example.com/repo", None);
        assert!(result.is_err());
    }
}
