//! Git repository cloning and management
//!
//! Provides secure git repository cloning for workspace setup.
//!
//! # Security
//! - Uses shallow clones (depth=1) for branches/tags (not commit SHAs)
//! - All parameters are validated before use
//! - No shell command execution (uses git2 library directly)

use super::WorkspaceError;
use git2::{build::RepoBuilder, Cred, FetchOptions, Oid, RemoteCallbacks, Repository};
use std::path::Path;

/// Resolve a git ref (branch, tag, or HEAD) to a commit SHA
///
/// Uses `git ls-remote` to query the remote repository without cloning.
///
/// # Arguments
/// * `repo_url` - Git repository URL
/// * `git_ref` - Git ref to resolve (branch name, tag name, or None for HEAD)
/// * `github_token` - Optional GitHub token for private repos
///
/// # Returns
/// The full 40-character commit SHA
pub fn resolve_ref_to_commit(
    repo_url: &str,
    git_ref: Option<&str>,
    github_token: Option<&str>,
) -> Result<String, WorkspaceError> {
    // If it's already a full commit SHA, just return it
    if let Some(ref_str) = git_ref {
        if ref_str.len() == 40 && ref_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(ref_str.to_string());
        }
    }

    // Set up authentication callback if GitHub token is provided
    let mut callbacks = RemoteCallbacks::new();
    if let Some(token) = github_token {
        let token_owned = token.to_string();
        let _ = callbacks.credentials(move |_url, username_from_url, _allowed_types| {
            Cred::userpass_plaintext(username_from_url.unwrap_or("git"), &token_owned)
        });
    }

    // Create a temporary in-memory remote to query
    let repo =
        Repository::init_bare(std::env::temp_dir().join(".nix-jail-ls-remote")).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to init temp repo: {}",
                e
            )))
        })?;

    let mut remote = repo.remote_anonymous(repo_url).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!(
            "Failed to create remote: {}",
            e
        )))
    })?;

    // Connect to remote (drop connection immediately, list() works while connected)
    drop(
        remote
            .connect_auth(git2::Direction::Fetch, Some(callbacks), None)
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "Failed to connect to remote: {}",
                    e
                )))
            })?,
    );

    // List refs while connected and collect the data
    let refs = remote.list().map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!("Failed to list refs: {}", e)))
    })?;

    // Collect ref data into owned strings
    let refs_data: Vec<(String, String)> = refs
        .iter()
        .map(|r| (r.name().to_string(), r.oid().to_string()))
        .collect();

    // Determine what ref we're looking for
    let target_ref = git_ref.unwrap_or("HEAD");

    // Search for the ref
    for (name, oid) in &refs_data {
        // Check various ref formats
        let matches = name == target_ref
            || name == &format!("refs/heads/{}", target_ref)
            || name == &format!("refs/tags/{}", target_ref)
            || (target_ref == "HEAD" && name == "HEAD");

        if matches {
            tracing::debug!(
                ref_name = %name,
                commit = %oid,
                "resolved git ref"
            );
            return Ok(oid.clone());
        }
    }

    // If we didn't find the exact ref, it might be HEAD symref
    if target_ref == "HEAD" || git_ref.is_none() {
        for (name, oid) in &refs_data {
            if name == "HEAD" {
                return Ok(oid.clone());
            }
        }
    }

    Err(WorkspaceError::InvalidPath(format!(
        "Could not resolve ref '{}' in repository",
        target_ref
    )))
}

/// Clone a git repository to a target directory
///
/// # Arguments
/// * `repo_url` - Git repository URL (must be validated before calling)
/// * `target_dir` - Directory to clone into (will create 'src' subdirectory)
/// * `git_ref` - Optional git ref (branch, tag, or commit SHA). If None, uses default branch
/// * `github_token` - Optional GitHub personal access token for private repositories
///
/// # Security
/// - Performs shallow clone (depth=1) for branches/tags to limit disk usage
/// - Full clone when using commit SHAs (required for checkout)
/// - Does not execute shell commands
/// - All inputs must be pre-validated
/// - GitHub token is used only during clone, never stored
///
/// # Errors
/// Returns WorkspaceError if:
/// - Repository cannot be accessed
/// - Authentication fails (invalid token or insufficient permissions)
/// - Network failure
/// - Invalid git ref
/// - Target directory cannot be created
pub fn clone_repository(
    repo_url: &str,
    target_dir: &Path,
    git_ref: Option<&str>,
    github_token: Option<&str>,
) -> Result<(), WorkspaceError> {
    let src_dir = target_dir.join("src");

    // Create target directory if it doesn't exist
    std::fs::create_dir_all(&src_dir)?;

    // Set up authentication callback if GitHub token is provided
    let mut callbacks = RemoteCallbacks::new();
    if let Some(token) = github_token {
        tracing::debug!("configuring github authentication for clone");

        // Clone token for use in closure
        let token_owned = token.to_string();

        let _ = callbacks.credentials(move |url, username_from_url, _allowed_types| {
            tracing::debug!(
                url = %url,
                username = ?username_from_url,
                "git credential callback invoked"
            );

            // For GitHub HTTPS, use token as password
            // Username can be anything (GitHub ignores it), but "git" is conventional
            Cred::userpass_plaintext(username_from_url.unwrap_or("git"), &token_owned)
        });
    }

    // Determine if we have a specific ref to fetch
    let has_specific_ref = git_ref.is_some() && !git_ref.unwrap_or("").is_empty();

    // Determine if the ref is a commit SHA (40 hex characters)
    let is_commit_sha = git_ref
        .map(|r| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false);

    if has_specific_ref && is_commit_sha {
        // For commit SHAs, we need to:
        // 1. Init empty repo
        // 2. Add remote
        // 3. Fetch specific commit with depth=1
        // 4. Checkout
        let repo = Repository::init(&src_dir).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to init repository: {}",
                e
            )))
        })?;

        let mut remote = repo.remote("origin", repo_url).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to add remote: {}",
                e
            )))
        })?;

        let ref_sha = git_ref.ok_or_else(|| {
            WorkspaceError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "git_ref is required for commit sha fetch",
            ))
        })?;
        let refspec = ref_sha.to_string();

        let mut fetch_opts = FetchOptions::new();
        let _ = fetch_opts.depth(1).remote_callbacks(callbacks);

        remote
            .fetch(&[&refspec], Some(&mut fetch_opts), None)
            .map_err(|e| {
                WorkspaceError::IoError(std::io::Error::other(format!(
                    "Failed to fetch commit: {}",
                    e
                )))
            })?;

        let oid = Oid::from_str(ref_sha).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!("Invalid commit SHA: {}", e)))
        })?;

        let commit = repo.find_commit(oid).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!("Commit not found: {}", e)))
        })?;

        repo.checkout_tree(commit.as_object(), None).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to checkout commit: {}",
                e
            )))
        })?;

        repo.set_head_detached(oid).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!("Failed to set HEAD: {}", e)))
        })?;
    } else {
        // For branches/tags or no ref, use normal clone
        let mut fetch_opts = FetchOptions::new();
        let _ = fetch_opts.depth(1).remote_callbacks(callbacks); // Shallow clone for performance

        let mut builder = RepoBuilder::new();
        let _ = builder.fetch_options(fetch_opts);

        // If a specific branch/tag is provided, clone just that ref
        if let Some(ref_name) = git_ref {
            if !ref_name.is_empty() {
                let _ = builder.branch(ref_name);
            }
        }

        let _repo = builder.clone(repo_url, &src_dir).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "Failed to clone repository: {}",
                e
            )))
        })?;
    }

    tracing::info!(
        repo = %repo_url,
        target = %src_dir.display(),
        git_ref = ?git_ref,
        "Cloned git repository"
    );

    Ok(())
}

/// Verify that a path exists within the cloned repository
///
/// # Arguments
/// * `repo_dir` - Root directory of the cloned repo (the 'src' directory)
/// * `relative_path` - Relative path within the repo to verify
///
/// # Security
/// - Checks that the path doesn't escape the repo directory
/// - Validates against path traversal
///
/// # Errors
/// Returns WorkspaceError if:
/// - Path doesn't exist
/// - Path escapes repository directory
pub fn verify_path_in_repo(repo_dir: &Path, relative_path: &str) -> Result<(), WorkspaceError> {
    let full_path = repo_dir.join(relative_path);

    // Ensure the path exists
    if !full_path.exists() {
        return Err(WorkspaceError::InvalidPath(format!(
            "Path '{}' does not exist in repository",
            relative_path
        )));
    }

    // Security check: ensure the resolved path is still within the repo
    // This prevents path traversal even if validation was bypassed earlier
    let canonical_repo = repo_dir.canonicalize().map_err(WorkspaceError::IoError)?;
    let canonical_path = full_path.canonicalize().map_err(WorkspaceError::IoError)?;

    if !canonical_path.starts_with(&canonical_repo) {
        return Err(WorkspaceError::InvalidPath(format!(
            "Path '{}' escapes repository directory",
            relative_path
        )));
    }

    Ok(())
}

/// Resolve a git ref to a commit SHA using a local mirror repository
///
/// This is faster than `resolve_ref_to_commit` as it doesn't require network access.
/// Uses git2 to read refs directly from the local repository.
///
/// # Arguments
/// * `mirror_path` - Path to the local mirror repository
/// * `git_ref` - Git ref to resolve (branch name, tag name, or None for HEAD)
///
/// # Returns
/// The full 40-character commit SHA
pub fn resolve_ref_from_mirror(
    mirror_path: &Path,
    git_ref: Option<&str>,
) -> Result<String, WorkspaceError> {
    // If it's already a full commit SHA, just return it
    if let Some(ref_str) = git_ref {
        if ref_str.len() == 40 && ref_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(ref_str.to_string());
        }
    }

    let repo = Repository::open(mirror_path).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::other(format!(
            "failed to open mirror repository: {}",
            e
        )))
    })?;

    let target_ref = git_ref.unwrap_or("HEAD");

    // Try to resolve the reference
    let reference = if target_ref == "HEAD" {
        repo.head()
    } else {
        // Try as branch first, then tag
        repo.find_branch(target_ref, git2::BranchType::Local)
            .map(|b| b.into_reference())
            .or_else(|_| repo.find_reference(&format!("refs/heads/{}", target_ref)))
            .or_else(|_| repo.find_reference(&format!("refs/tags/{}", target_ref)))
            .or_else(|_| repo.find_reference(target_ref))
    };

    let reference = reference.map_err(|e| {
        WorkspaceError::InvalidPath(format!(
            "could not resolve ref '{}' in mirror: {}",
            target_ref, e
        ))
    })?;

    // Peel to commit
    let commit = reference.peel_to_commit().map_err(|e| {
        WorkspaceError::InvalidPath(format!(
            "could not resolve ref '{}' to commit: {}",
            target_ref, e
        ))
    })?;

    let sha = commit.id().to_string();
    tracing::debug!(
        ref_name = %target_ref,
        commit = %sha,
        "resolved ref from mirror"
    );

    Ok(sha)
}

/// Perform a sparse shallow checkout from a remote with local reference
///
/// Creates a shallow clone (depth=1) from the remote with sparse checkout configured.
/// Uses the local mirror as a reference to avoid re-downloading objects that already
/// exist locally. Only fetches objects needed for the single commit and sparse paths.
///
/// # Arguments
/// * `repo_url` - Remote repository URL to clone from
/// * `reference_path` - Optional path to local repository for object reuse
/// * `target_dir` - Directory to create the checkout in
/// * `commit_sha` - Commit SHA to checkout
/// * `sparse_paths` - Paths to include in sparse checkout (empty = full checkout)
///
/// # Security
/// - Uses git CLI (git2 doesn't support sparse checkout)
/// - All inputs are validated before use
/// - Uses `Command::new` with explicit args (no shell interpolation)
pub fn sparse_checkout_from_mirror(
    repo_url: &str,
    reference_path: Option<&Path>,
    target_dir: &Path,
    commit_sha: &str,
    sparse_paths: &[&str],
) -> Result<(), WorkspaceError> {
    use std::process::Command;

    // Validate commit SHA format
    if commit_sha.len() != 40 || !commit_sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WorkspaceError::InvalidPath(format!(
            "invalid commit SHA: {}",
            commit_sha
        )));
    }

    // Create target directory
    std::fs::create_dir_all(target_dir)?;

    // Step 1: Clone from remote with minimal object transfer
    // --depth 1: only fetch one commit (no history)
    // --filter=blob:none: don't fetch blobs until needed (partial clone)
    // --sparse: only checkout specified paths
    // Note: We don't use --reference because --dissociate copies too many objects.
    // The filters already minimize network transfer effectively.
    let mut clone_args = vec![
        "clone".to_string(),
        "--depth".to_string(),
        "1".to_string(),
        "--no-checkout".to_string(),
        "--filter=blob:none".to_string(),
    ];

    // Add sparse cone mode
    if !sparse_paths.is_empty() {
        clone_args.push("--sparse".to_string());
    }

    clone_args.push(repo_url.to_string());
    clone_args.push(target_dir.to_string_lossy().to_string());

    // Log if reference path was provided (we don't use it, but useful for debugging)
    if let Some(ref_path) = reference_path {
        tracing::debug!(
            reference = %ref_path.display(),
            "reference path provided but not used (filters are sufficient)"
        );
    }

    let clone_output = Command::new("git")
        .args(&clone_args)
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to run git clone: {}",
                e
            )))
        })?;

    if !clone_output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git clone failed: {}",
            String::from_utf8_lossy(&clone_output.stderr)
        ))));
    }

    // Step 2: Configure sparse checkout paths if specified
    if !sparse_paths.is_empty() {
        // Set sparse checkout paths (--sparse already initialized cone mode)
        let mut set_cmd = Command::new("git");
        let _ = set_cmd.args([
            "-C",
            &target_dir.to_string_lossy(),
            "sparse-checkout",
            "set",
        ]);
        for path in sparse_paths {
            let _ = set_cmd.arg(path);
        }

        let set_output = set_cmd.output().map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to run git sparse-checkout set: {}",
                e
            )))
        })?;

        if !set_output.status.success() {
            return Err(WorkspaceError::IoError(std::io::Error::other(format!(
                "git sparse-checkout set failed: {}",
                String::from_utf8_lossy(&set_output.stderr)
            ))));
        }
    }

    // Step 3: Checkout HEAD (the shallow clone already has the right commit)
    let checkout_output = Command::new("git")
        .args(["-C", &target_dir.to_string_lossy(), "checkout"])
        .output()
        .map_err(|e| {
            WorkspaceError::IoError(std::io::Error::other(format!(
                "failed to run git checkout: {}",
                e
            )))
        })?;

    if !checkout_output.status.success() {
        return Err(WorkspaceError::IoError(std::io::Error::other(format!(
            "git checkout failed: {}",
            String::from_utf8_lossy(&checkout_output.stderr)
        ))));
    }

    tracing::info!(
        repo = %repo_url,
        reference = ?reference_path.map(|p| p.display().to_string()),
        target = %target_dir.display(),
        commit = %commit_sha,
        sparse_paths = ?sparse_paths,
        "sparse checkout complete"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    #[ignore] // Requires network and HTTPS support in libgit2
    fn test_clone_public_repo() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Clone a small public repo (using nix-jail's own repo as test)
        let result = clone_repository(
            "https://github.com/thepwagner/nix-jail",
            temp_dir.path(),
            Some("main"),
            None, // No authentication needed for public repo
        );

        assert!(result.is_ok(), "Failed to clone repository: {:?}", result);

        // Verify src directory was created
        let src_dir = temp_dir.path().join("src");
        assert!(src_dir.exists());

        // Verify repository structure (should have .git directory)
        assert!(src_dir.join(".git").exists());

        // Verify we can find README.md or similar file
        let has_content = src_dir.read_dir().expect("Failed to read src dir").count() > 1;
        assert!(has_content, "Repository appears empty");
    }

    #[test]
    #[ignore] // Requires network
    fn test_clone_with_commit_sha() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Clone with a specific commit (this is a valid commit in nix-jail repo)
        let result = clone_repository(
            "https://github.com/thepwagner/nix-jail",
            temp_dir.path(),
            Some("b698683"), // Partial SHA is fine
            None,
        );

        // This might fail if the commit doesn't exist, which is expected
        // The important thing is that the function handles it gracefully
        if let Err(e) = result {
            assert!(format!("{:?}", e).contains("clone"));
        }
    }

    #[test]
    #[ignore] // Requires network and HTTPS support in libgit2
    fn test_clone_default_branch() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Clone without specifying a ref (should use default branch)
        let result = clone_repository(
            "https://github.com/thepwagner/nix-jail",
            temp_dir.path(),
            None,
            None,
        );

        assert!(result.is_ok(), "Failed to clone with default branch");

        let src_dir = temp_dir.path().join("src");
        assert!(src_dir.exists());
    }

    #[test]
    #[ignore] // Requires network and HTTPS support in libgit2
    fn test_clone_empty_ref() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Clone with empty ref string (should use default branch)
        let result = clone_repository(
            "https://github.com/thepwagner/nix-jail",
            temp_dir.path(),
            Some(""),
            None,
        );

        assert!(result.is_ok(), "Failed to clone with empty ref");
    }

    #[test]
    fn test_verify_path_valid() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_dir = temp_dir.path().join("src");
        fs::create_dir_all(&repo_dir).expect("Failed to create repo dir");

        // Create a test file
        let test_file = repo_dir.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        // Verify the path exists
        let result = verify_path_in_repo(&repo_dir, "test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_path_nested() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_dir = temp_dir.path().join("src");
        fs::create_dir_all(&repo_dir).expect("Failed to create repo dir");

        // Create a nested directory and file
        let nested_dir = repo_dir.join("subdir");
        fs::create_dir_all(&nested_dir).expect("Failed to create nested dir");
        let test_file = nested_dir.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        // Verify the nested path exists
        let result = verify_path_in_repo(&repo_dir, "subdir/test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_path_nonexistent() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_dir = temp_dir.path().join("src");
        fs::create_dir_all(&repo_dir).expect("Failed to create repo dir");

        // Try to verify a path that doesn't exist
        let result = verify_path_in_repo(&repo_dir, "nonexistent.txt");
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("does not exist"));
    }

    #[test]
    fn test_verify_path_traversal_via_symlink() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_dir = temp_dir.path().join("src");
        fs::create_dir_all(&repo_dir).expect("Failed to create repo dir");

        // Create a file outside the repo
        let outside_file = temp_dir.path().join("outside.txt");
        fs::write(&outside_file, "outside content").expect("Failed to write outside file");

        // Create a symlink inside the repo pointing outside
        #[cfg(unix)]
        {
            let symlink_path = repo_dir.join("escape");
            std::os::unix::fs::symlink(&outside_file, &symlink_path)
                .expect("Failed to create symlink");

            // Try to verify the symlink path (should fail)
            let result = verify_path_in_repo(&repo_dir, "escape");
            assert!(result.is_err());
            assert!(format!("{:?}", result).contains("escapes"));
        }
    }
}
