//! Job execution subsystem
//!
//! Provides platform-specific sandboxed execution:
//! - macOS: `SandboxExecutor` using sandbox-exec with SBPL profiles
//! - Linux: `SystemdExecutor` using systemd-run with hardening properties
//! - Linux: `DockerExecutor` using Docker containers (alternative to systemd)
//!
//! Use `create_executor()` to get the platform default, or `create_executor_with_type()`
//! for explicit backend selection.

mod exec;
mod traits;
mod types;

#[cfg(test)]
mod executor_tests;
#[cfg(test)]
mod test_helpers;

#[cfg(target_os = "macos")]
pub mod sandbox;

#[cfg(target_os = "macos")]
mod sandbox_policy;

pub mod docker;

#[cfg(target_os = "linux")]
pub mod systemd;

// Re-export main types
pub use traits::{
    ExecutionConfig, ExecutionHandle, Executor, ExecutorError, HardeningProfile, IoHandle,
};

// Re-export types module for backward compatibility
pub use types::JobExecutor;

// Re-export mock for testing
#[cfg(test)]
pub use traits::mock::MockExecutor;

// Platform-specific executor re-exports (for direct use if needed)
#[cfg(target_os = "macos")]
pub use sandbox::SandboxExecutor;

pub use docker::DockerExecutor;

#[cfg(target_os = "linux")]
pub use systemd::SystemdExecutor;

#[cfg(target_os = "linux")]
pub use systemd::cleanup_stale_network_namespaces;

/// Available executor backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutorType {
    /// Platform default (macOS: Sandbox, Linux: Systemd)
    #[default]
    Auto,
    /// Linux systemd-run executor
    Systemd,
    /// Docker container executor (Linux only)
    Docker,
    /// macOS sandbox-exec executor
    Sandbox,
}

impl std::fmt::Display for ExecutorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorType::Auto => write!(f, "auto"),
            ExecutorType::Systemd => write!(f, "systemd"),
            ExecutorType::Docker => write!(f, "docker"),
            ExecutorType::Sandbox => write!(f, "sandbox"),
        }
    }
}

impl std::str::FromStr for ExecutorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(ExecutorType::Auto),
            "systemd" => Ok(ExecutorType::Systemd),
            "docker" => Ok(ExecutorType::Docker),
            "sandbox" => Ok(ExecutorType::Sandbox),
            _ => Err(format!(
                "unknown executor '{}'. valid options: 'auto', 'systemd', 'docker', 'sandbox'",
                s
            )),
        }
    }
}

/// Creates the appropriate executor for the specified type
///
/// Returns an `Arc<dyn Executor>` trait object that provides sandboxed execution.
///
/// # Errors
///
/// Returns an error if the requested executor type is not available on the current platform.
///
/// # Example
///
/// ```ignore
/// use nix_jail::executor::{create_executor_with_type, ExecutorType};
///
/// let executor = create_executor_with_type(ExecutorType::Docker)?;
/// println!("Using executor: {}", executor.name());
/// ```
pub fn create_executor_with_type(
    executor_type: ExecutorType,
) -> Result<std::sync::Arc<dyn Executor>, String> {
    match executor_type {
        ExecutorType::Auto => Ok(create_default_executor()),
        ExecutorType::Systemd => {
            #[cfg(target_os = "linux")]
            {
                Ok(std::sync::Arc::new(SystemdExecutor::new()))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("systemd executor is only available on Linux".to_string())
            }
        }
        ExecutorType::Docker => Ok(std::sync::Arc::new(DockerExecutor::new())),
        ExecutorType::Sandbox => {
            #[cfg(target_os = "macos")]
            {
                Ok(std::sync::Arc::new(SandboxExecutor::new()))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err("sandbox executor is only available on macOS".to_string())
            }
        }
    }
}

/// Creates the platform default executor
fn create_default_executor() -> std::sync::Arc<dyn Executor> {
    #[cfg(target_os = "macos")]
    {
        std::sync::Arc::new(SandboxExecutor::new())
    }
    #[cfg(target_os = "linux")]
    {
        std::sync::Arc::new(SystemdExecutor::new())
    }
}

/// Creates the appropriate executor for the current platform (default backend)
///
/// Returns an `Arc<dyn Executor>` trait object that provides sandboxed execution.
/// This is the recommended way to get an executor - it consolidates all
/// platform-specific selection logic to this single location.
///
/// For explicit backend selection, use `create_executor_with_type()` instead.
///
/// # Example
///
/// ```ignore
/// use nix_jail::executor::{create_executor, ExecutionConfig};
///
/// let executor = create_executor();
/// println!("Using executor: {}", executor.name());
/// ```
pub fn create_executor() -> std::sync::Arc<dyn Executor> {
    create_default_executor()
}

/// Get the executor name for the current platform (for display/logging)
#[cfg(target_os = "macos")]
pub const EXECUTOR_NAME: &str = "SandboxExecutor (sandbox-exec)";

#[cfg(target_os = "linux")]
pub const EXECUTOR_NAME: &str = "SystemdExecutor (systemd-run)";

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const EXECUTOR_NAME: &str = "unknown";
