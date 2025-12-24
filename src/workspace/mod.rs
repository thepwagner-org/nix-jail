pub mod cache;
pub mod config;
pub mod flake;
pub mod git;
pub mod git_refs;
pub mod mirror;
pub mod nix;
pub mod policy;
pub mod pr;

// Re-export everything from submodules for backward compatibility
pub use self::cache::*;
pub use self::config::*;
pub use self::flake::*;
pub use self::git::*;
pub use self::git_refs::*;
pub use self::mirror::*;
pub use self::nix::*;
pub use self::policy::*;
pub use self::pr::*;

/// Errors that can occur during workspace operations
#[derive(Debug)]
pub enum WorkspaceError {
    IoError(std::io::Error),
    DerivationNotFound(String),
    InvalidPath(String),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceError::IoError(e) => write!(f, "I/O error: {}", e),
            WorkspaceError::DerivationNotFound(msg) => write!(f, "Derivation not found: {}", msg),
            WorkspaceError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<std::io::Error> for WorkspaceError {
    fn from(err: std::io::Error) -> Self {
        WorkspaceError::IoError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Nix to be installed
    async fn test_find_coreutils_derivation() {
        let derivation = nix::find_coreutils_derivation()
            .await
            .expect("Failed to find coreutils derivation");

        // Should be a valid path
        assert!(derivation.exists());

        // Should be in /nix/store
        assert!(derivation.to_string_lossy().starts_with("/nix/store"));

        // Should contain "coreutils" in the name
        assert!(derivation.to_string_lossy().contains("coreutils"));

        // Should have bin/ls (verify it's actually coreutils)
        let ls_bin = derivation.join("bin").join("ls");
        assert!(ls_bin.exists());
    }
}
