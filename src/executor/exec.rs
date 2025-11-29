//! Shared executor utilities

use std::path::PathBuf;

/// Resolves command paths from the Nix closure.
///
/// If the first argument is "bash", finds bash in the closure and returns
/// the full path. This is necessary when running in isolated roots where
/// "bash" is not in PATH.
///
/// # Arguments
/// * `command` - The command and arguments
/// * `closure` - The Nix store paths in the closure
///
/// # Returns
/// A new command with resolved paths
pub fn resolve_command_paths(command: &[String], closure: &[PathBuf]) -> Vec<String> {
    let mut resolved_command = command.to_vec();

    if !resolved_command.is_empty() && resolved_command[0] == "bash" {
        if let Some(bash_path) = closure
            .iter()
            .find(|p| p.to_string_lossy().contains("bash-"))
        {
            let full_bash = bash_path.join("bin/bash");
            if full_bash.exists() {
                resolved_command[0] = full_bash.to_string_lossy().to_string();
                tracing::debug!(bash = %resolved_command[0], "resolved bash from closure");
            }
        }
    }

    resolved_command
}
