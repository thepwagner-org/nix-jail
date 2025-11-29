//! Git reference tracking for detecting commits and managing branches
//!
//! This module provides functions to:
//! - Get the current HEAD commit
//! - Get the current branch name
//! - Create and checkout new branches
//! - Get commit messages between two refs
//! - Push branches to remote

use super::WorkspaceError;
use git2::{Cred, PushOptions, RemoteCallbacks, Repository};
use std::path::Path;
use std::process::Command;

/// Get the current HEAD commit SHA
pub fn get_head_commit(repo_dir: &Path) -> Result<String, WorkspaceError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to run git rev-parse: {}",
                e
            )))
        })?;

    if !output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(sha)
}

/// Get the current branch name
/// Returns error if in detached HEAD state
pub fn get_current_branch(repo_dir: &Path) -> Result<String, WorkspaceError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("branch")
        .arg("--show-current")
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to run git branch: {}",
                e
            )))
        })?;

    if !output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git branch failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() {
        return Err(WorkspaceError::InvalidPath(
            "Not on a branch (detached HEAD)".into(),
        ));
    }

    Ok(branch)
}

/// Create and checkout a new branch
pub fn create_and_checkout_branch(
    repo_dir: &Path,
    branch_name: &str,
) -> Result<(), WorkspaceError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("checkout")
        .arg("-b")
        .arg(branch_name)
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to run git checkout: {}",
                e
            )))
        })?;

    if !output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git checkout -b failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    tracing::info!(branch = %branch_name, "Created and checked out new branch");
    Ok(())
}

/// Get commit messages between two refs
/// Returns list of commit messages (one-line summaries)
pub fn get_commits_between(
    repo_dir: &Path,
    old_sha: &str,
    new_sha: &str,
) -> Result<Vec<String>, WorkspaceError> {
    let range = format!("{}..{}", old_sha, new_sha);

    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("log")
        .arg("--format=%s")
        .arg(&range)
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to run git log: {}",
                e
            )))
        })?;

    if !output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git log failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    let commits = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    Ok(commits)
}

/// Push a branch to remote using git2 library with authentication
pub fn push_branch(
    repo_dir: &Path,
    branch: &str,
    token: &str,
    _remote_url: &str,
) -> Result<(), WorkspaceError> {
    let repo = Repository::open(repo_dir).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!(
            "Failed to open repository: {}",
            e
        )))
    })?;

    let mut remote = repo.find_remote("origin").map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!(
            "Failed to find origin remote: {}",
            e
        )))
    })?;

    // Set up authentication callback
    let mut callbacks = RemoteCallbacks::new();
    let token_owned = token.to_string();

    let _ = callbacks.credentials(move |_url, username_from_url, _allowed_types| {
        // For GitHub HTTPS, use token as password
        Cred::userpass_plaintext(username_from_url.unwrap_or("git"), &token_owned)
    });

    let mut push_options = PushOptions::new();
    let _ = push_options.remote_callbacks(callbacks);

    // Push the branch
    let refspec = format!("refs/heads/{}:refs/heads/{}", branch, branch);
    remote
        .push(&[&refspec], Some(&mut push_options))
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to push branch: {}",
                e
            )))
        })?;

    tracing::info!(branch = %branch, "Pushed branch to remote");
    Ok(())
}
