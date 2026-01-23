//! Shared executor utilities

use std::path::{Path, PathBuf};

/// Resolves command paths from the Nix closure.
///
/// If the first argument is not an absolute path, searches for it in the
/// closure's bin directories. This is necessary when running in isolated
/// roots where PATH lookup happens before environment setup.
///
/// # Arguments
/// * `command` - The command and arguments
/// * `closure` - The Nix store paths in the closure
///
/// # Returns
/// A new command with resolved paths
pub fn resolve_command_paths(command: &[String], closure: &[PathBuf]) -> Vec<String> {
    let mut resolved_command = command.to_vec();

    if resolved_command.is_empty() {
        return resolved_command;
    }

    let cmd = resolved_command[0].clone();

    // Skip if already an absolute path
    if cmd.starts_with('/') {
        return resolved_command;
    }

    // Search for command in closure bin directories
    for store_path in closure {
        let bin_path = store_path.join("bin").join(&cmd);
        if bin_path.exists() {
            let resolved = bin_path.to_string_lossy().to_string();
            tracing::debug!(command = %cmd, resolved = %resolved, "resolved command from closure");
            resolved_command[0] = resolved;
            return resolved_command;
        }
    }

    tracing::warn!(command = %cmd, "could not resolve command in closure");
    resolved_command
}

/// Creates FHS-compatible symlinks in the root directory.
///
/// Many tools (especially node_modules/.bin scripts) use shebangs like
/// `#!/bin/sh` or `#!/usr/bin/env node`. These paths don't exist in the
/// Nix store chroot, so we create symlinks to make them work.
///
/// Creates:
/// - /bin/sh -> bash in closure
/// - /bin/bash -> bash in closure
/// - /usr/bin/env -> coreutils env in closure
///
/// # Arguments
/// * `root_dir` - The root directory for the chroot
/// * `closure` - The Nix store paths in the closure
pub fn create_fhs_symlinks(root_dir: &Path, closure: &[PathBuf]) -> std::io::Result<()> {
    // Find bash in the closure
    let bash_path = find_binary_in_closure("bash", closure);

    // Find env (from coreutils) in the closure
    let env_path = find_binary_in_closure("env", closure);

    // Create /bin directory
    let bin_dir = root_dir.join("bin");
    std::fs::create_dir_all(&bin_dir)?;

    // Create /usr/bin directory
    let usr_bin_dir = root_dir.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin_dir)?;

    // Create symlinks
    if let Some(bash) = bash_path {
        let sh_link = bin_dir.join("sh");
        let bash_link = bin_dir.join("bash");

        // Remove existing symlinks if they exist
        let _ = std::fs::remove_file(&sh_link);
        let _ = std::fs::remove_file(&bash_link);

        std::os::unix::fs::symlink(&bash, &sh_link)?;
        std::os::unix::fs::symlink(&bash, &bash_link)?;

        tracing::debug!(
            bash = %bash.display(),
            sh_link = %sh_link.display(),
            "created /bin/sh and /bin/bash symlinks"
        );
    } else {
        tracing::warn!("bash not found in closure, /bin/sh symlink not created");
    }

    if let Some(env) = env_path {
        let env_link = usr_bin_dir.join("env");

        // Remove existing symlink if it exists
        let _ = std::fs::remove_file(&env_link);

        std::os::unix::fs::symlink(&env, &env_link)?;

        tracing::debug!(
            env = %env.display(),
            env_link = %env_link.display(),
            "created /usr/bin/env symlink"
        );
    } else {
        tracing::warn!("env not found in closure, /usr/bin/env symlink not created");
    }

    Ok(())
}

/// Find a binary in the closure's bin directories
fn find_binary_in_closure(name: &str, closure: &[PathBuf]) -> Option<PathBuf> {
    for store_path in closure {
        let bin_path = store_path.join("bin").join(name);
        if bin_path.exists() {
            return Some(bin_path);
        }
    }
    None
}

/// Creates the sandbox home directory structure.
///
/// Creates /home/{user} with standard XDG subdirectories:
/// - /home/{user}/.config
/// - /home/{user}/.local/share
/// - /home/{user}/.local/state
/// - /home/{user}/.cache
///
/// # Arguments
/// * `root_dir` - The root directory for the chroot
/// * `sandbox_user` - Optional (user, group) tuple. If Some, creates /home/{user} and chowns to user:group.
///   If None, creates /home/sandbox with no chown (for executors that don't switch users).
pub fn create_home_directory(
    root_dir: &Path,
    sandbox_user: Option<(&str, &str)>,
) -> std::io::Result<()> {
    let user = sandbox_user.map(|(u, _)| u).unwrap_or("sandbox");
    let home_dir = root_dir.join(format!("home/{}", user));

    // Create XDG directories
    std::fs::create_dir_all(home_dir.join(".config"))?;
    std::fs::create_dir_all(home_dir.join(".local/share"))?;
    std::fs::create_dir_all(home_dir.join(".local/state"))?;
    std::fs::create_dir_all(home_dir.join(".cache"))?;

    // Chown to sandbox user if specified (daemon runs as root, jobs run as sandbox user)
    // Skip chown when sandbox_user is None (e.g., macOS sandbox-exec runs as current user)
    if let Some((user, group)) = sandbox_user {
        let owner = format!("{}:{}", user, group);
        let output = std::process::Command::new("chown")
            .args(["-R", &owner, &home_dir.to_string_lossy()])
            .output()?;

        if !output.status.success() {
            tracing::warn!(
                stderr = %String::from_utf8_lossy(&output.stderr),
                "failed to chown home directory"
            );
        }
    }

    tracing::debug!(home_dir = %home_dir.display(), "created sandbox home directory");
    Ok(())
}

/// Creates a minimal /etc/hosts with only localhost entries:
/// - 127.0.0.1 localhost
/// - ::1 localhost
///
/// # Arguments
/// * `root_dir` - The root directory for the chroot
pub fn create_etc_hosts(root_dir: &Path) -> std::io::Result<()> {
    let etc_dir = root_dir.join("etc");
    std::fs::create_dir_all(&etc_dir)?;

    let hosts_path = etc_dir.join("hosts");
    let hosts_content = "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n";

    std::fs::write(&hosts_path, hosts_content)?;

    tracing::debug!(hosts_path = %hosts_path.display(), "created /etc/hosts");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_etc_hosts() {
        let root = tempdir().expect("failed to create temp dir");

        create_etc_hosts(root.path()).expect("failed to create /etc/hosts");

        let hosts_path = root.path().join("etc/hosts");
        assert!(hosts_path.exists(), "/etc/hosts should exist");

        let content = std::fs::read_to_string(&hosts_path).expect("failed to read /etc/hosts");
        assert!(
            content.contains("127.0.0.1"),
            "should contain IPv4 localhost"
        );
        assert!(content.contains("::1"), "should contain IPv6 localhost");
        assert!(content.contains("localhost"), "should contain 'localhost'");
    }

    #[test]
    fn test_create_etc_hosts_idempotent() {
        let root = tempdir().expect("failed to create temp dir");

        // Create twice - should not error
        create_etc_hosts(root.path()).expect("first call failed");
        create_etc_hosts(root.path()).expect("second call failed");

        let hosts_path = root.path().join("etc/hosts");
        assert!(hosts_path.exists());
    }

    #[test]
    fn test_create_home_directory() {
        let root = tempdir().expect("failed to create temp dir");

        // Use None for sandbox_user in tests (no chown, uses "sandbox" as default user)
        create_home_directory(root.path(), None).expect("failed to create home directory");

        let home_dir = root.path().join("home/sandbox");
        assert!(home_dir.exists(), "/home/sandbox should exist");
        assert!(home_dir.join(".config").exists(), ".config should exist");
        assert!(
            home_dir.join(".local/share").exists(),
            ".local/share should exist"
        );
        assert!(
            home_dir.join(".local/state").exists(),
            ".local/state should exist"
        );
        assert!(home_dir.join(".cache").exists(), ".cache should exist");
    }

    #[test]
    fn test_create_home_directory_with_user() {
        let root = tempdir().expect("failed to create temp dir");

        // Test with explicit user (but skip chown check since we may not have permissions)
        create_home_directory(root.path(), Some(("testuser", "testgroup")))
            .expect("failed to create home directory");

        let home_dir = root.path().join("home/testuser");
        assert!(home_dir.exists(), "/home/testuser should exist");
        assert!(home_dir.join(".config").exists(), ".config should exist");
    }

    #[test]
    fn test_create_home_directory_idempotent() {
        let root = tempdir().expect("failed to create temp dir");

        // Create twice - should not error
        create_home_directory(root.path(), None).expect("first call failed");
        create_home_directory(root.path(), None).expect("second call failed");

        let home_dir = root.path().join("home/sandbox");
        assert!(home_dir.exists());
    }
}
