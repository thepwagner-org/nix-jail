//! Job execution subsystem
//!
//! Provides platform-specific sandboxed execution:
//! - macOS: `SandboxExecutor` using sandbox-exec with SBPL profiles
//! - Linux: `SystemdExecutor` using systemd-run with hardening properties
//!
//! Use `create_executor()` to get the appropriate executor for the current platform.

mod exec;
mod traits;
mod types;

#[cfg(target_os = "macos")]
pub mod sandbox;

#[cfg(target_os = "macos")]
mod sandbox_policy;

#[cfg(target_os = "linux")]
pub mod systemd;

// Re-export main types
pub use traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError, HardeningProfile};

// Re-export types module for backward compatibility
pub use types::JobExecutor;

// Re-export mock for testing
#[cfg(test)]
pub use traits::mock::MockExecutor;

// Platform-specific executor re-exports (for direct use if needed)
#[cfg(target_os = "macos")]
pub use sandbox::SandboxExecutor;

#[cfg(target_os = "linux")]
pub use systemd::SystemdExecutor;

/// Creates the appropriate executor for the current platform
///
/// Returns a boxed `Executor` trait object that provides sandboxed execution.
/// This is the recommended way to get an executor - it consolidates all
/// platform-specific selection logic to this single location.
///
/// # Example
///
/// ```ignore
/// use nix_jail::executor::{create_executor, ExecutionConfig};
///
/// let executor = create_executor();
/// println!("Using executor: {}", executor.name());
/// ```
#[cfg(target_os = "macos")]
pub fn create_executor() -> Box<dyn Executor> {
    Box::new(SandboxExecutor::new())
}

#[cfg(target_os = "linux")]
pub fn create_executor() -> Box<dyn Executor> {
    Box::new(SystemdExecutor::new())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn create_executor() -> Box<dyn Executor> {
    compile_error!("nix-jail only supports macOS and Linux")
}

/// Get the executor name for the current platform (for display/logging)
#[cfg(target_os = "macos")]
pub const EXECUTOR_NAME: &str = "SandboxExecutor (sandbox-exec)";

#[cfg(target_os = "linux")]
pub const EXECUTOR_NAME: &str = "SystemdExecutor (systemd-run)";

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const EXECUTOR_NAME: &str = "unknown";
