//! Shared executor utilities

use std::path::PathBuf;

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
