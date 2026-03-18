//! Git reference tracking for detecting commits and managing branches
//!
//! This module provides functions to:
//! - Get the current HEAD commit
//! - Get the current branch name
//! - Create and checkout new branches
//! - Get commit messages between two refs
//! - Push branches to remote

use super::WorkspaceError;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Build a `git -C <repo_dir>` command that runs as the directory's owner.
///
/// The daemon runs as root, but workspaces are owned by the sandbox user.
/// Running git as root triggers the safe.directory ownership check.  Since
/// root can setuid to any UID, we simply drop to the workspace owner instead.
fn git_cmd(repo_dir: &Path) -> Result<Command, WorkspaceError> {
    let uid = std::fs::metadata(repo_dir)
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to stat repo dir: {}",
                e
            )))
        })?
        .uid();

    let mut cmd = Command::new("git");
    let _ = cmd.uid(uid).arg("-C").arg(repo_dir);
    Ok(cmd)
}

/// Get the current HEAD commit SHA
pub fn get_head_commit(repo_dir: &Path) -> Result<String, WorkspaceError> {
    let output = git_cmd(repo_dir)?
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
    let output = git_cmd(repo_dir)?
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
    let output = git_cmd(repo_dir)?
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

    let output = git_cmd(repo_dir)?
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

/// Push a branch to the remote using a subprocess git.
///
/// Authenticates via `https://git:{token}@host/repo` — the same pattern used
/// by forgejo-nix-ci.  We avoid libgit2 here because it performs its own
/// owner-validation check that fails when the daemon (root) opens a workspace
/// owned by the sandbox user.
pub fn push_branch(
    repo_dir: &Path,
    repo_url: &str,
    branch: &str,
    token: &str,
) -> Result<(), WorkspaceError> {
    // Embed credentials in the remote URL so that all git operations —
    // including promisor-remote fetches that happen during push — use the
    // same authenticated URL.  The workspace is disposable so we don't
    // bother restoring the original URL.
    // trufflehog:ignore
    let auth_url = repo_url.replacen("https://", &format!("https://git:{}@", token), 1);

    let set_url_output = git_cmd(repo_dir)?
        .arg("remote")
        .arg("set-url")
        .arg("origin")
        .arg(&auth_url)
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to run git remote set-url: {}",
                e
            )))
        })?;

    if !set_url_output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git remote set-url failed: {}",
            String::from_utf8_lossy(&set_url_output.stderr)
        ))));
    }

    let refspec = format!("refs/heads/{}:refs/heads/{}", branch, branch);
    let output = git_cmd(repo_dir)?
        .arg("push")
        .arg("origin")
        .arg(&refspec)
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to run git push: {}",
                e
            )))
        })?;

    if !output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    tracing::info!(branch = %branch, "pushed branch to remote");
    Ok(())
}
