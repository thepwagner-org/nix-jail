//! Platform abstraction traits for job execution
//!
//! This module defines the `Executor` trait that abstracts platform-specific
//! execution backends (macOS sandbox-exec, Linux systemd-run).
//!
//! Design goals:
//! - Consolidate `#[cfg(target_os)]` blocks to factory function
//! - Enable testability through trait objects/mocks
//! - Keep platform-specific cleanup internal to implementations

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Errors that can occur during job execution
#[derive(Debug)]
pub enum ExecutorError {
    SpawnFailed(String),
    Timeout,
    IoError(std::io::Error),
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorError::SpawnFailed(msg) => write!(f, "failed to spawn process: {}", msg),
            ExecutorError::Timeout => write!(f, "job execution timed out"),
            ExecutorError::IoError(e) => write!(f, "i/o error: {}", e),
        }
    }
}

impl std::error::Error for ExecutorError {}

impl From<std::io::Error> for ExecutorError {
    fn from(err: std::io::Error) -> Self {
        ExecutorError::IoError(err)
    }
}

/// Hardening profile for execution
///
/// Controls which security restrictions are applied. All profiles maintain
/// maximum security by default - weakening is explicit and documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardeningProfile {
    /// Default profile with all hardening properties enabled
    ///
    /// Maximum security for general workloads. Includes MemoryDenyWriteExecute
    /// which prevents W^X violations but blocks JIT compilation.
    #[default]
    Default,

    /// JIT runtime profile with reduced memory restrictions
    ///
    /// Removes MemoryDenyWriteExecute to allow JIT compilation for runtimes like:
    /// - Node.js (V8 JIT compiler)
    /// - Python (PyPy, CPython JIT extensions)
    /// - Java/JVM languages
    /// - WebAssembly runtimes
    ///
    /// SECURITY JUSTIFICATION (per CLAUDE.md:11):
    /// MemoryDenyWriteExecute is removed to enable legitimate JIT compilation.
    /// All other hardening properties remain active.
    JitRuntime,
}

impl HardeningProfile {
    /// Get the canonical name for this profile
    pub fn as_str(&self) -> &'static str {
        match self {
            HardeningProfile::Default => "default",
            HardeningProfile::JitRuntime => "jit-runtime",
        }
    }
}

impl std::str::FromStr for HardeningProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "default" => Ok(HardeningProfile::Default),
            "jit-runtime" | "jit_runtime" => Ok(HardeningProfile::JitRuntime),
            _ => Err(format!(
                "unknown hardening profile '{}'. valid options: 'default', 'jit-runtime'",
                s
            )),
        }
    }
}

/// A resolved cache mount for execution
///
/// This is the result of resolving a client's CacheRequest against
/// the server's bucket configuration. Contains all information needed
/// for the executor to set up the mount.
#[derive(Debug, Clone)]
pub struct ResolvedCacheMount {
    /// Host path to mount (may include key-based subdirectory)
    pub host_path: PathBuf,

    /// Mount point inside the sandbox (e.g., "/cargo", "/target")
    pub mount_path: String,

    /// Environment variable to set (e.g., "CARGO_HOME")
    /// If set, the env var will be set to mount_path
    pub env_var: Option<String>,

    /// Docker volume name (for Docker executor)
    /// If set, Docker will use this named volume instead of host_path
    pub docker_volume: Option<String>,
}

/// Configuration for job execution (platform-agnostic)
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// Unique job identifier
    pub job_id: String,
    /// Command and arguments to execute
    pub command: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Job directory (parent of root/workspace, for writing sandbox profiles)
    pub job_dir: PathBuf,
    /// Working directory for execution (bind-mounted as /workspace in chroot)
    pub working_dir: PathBuf,
    /// Root directory for chroot isolation
    pub root_dir: PathBuf,
    /// How the Nix store should be made available
    pub store_setup: crate::root::StoreSetup,
    /// Maximum execution time
    pub timeout: Duration,
    /// Store paths (closure) for command resolution
    pub store_paths: Vec<PathBuf>,
    /// Proxy port for network access. None = no network access.
    pub proxy_port: Option<u16>,
    /// Hardening profile (used on Linux, ignored on macOS)
    pub hardening_profile: HardeningProfile,
    /// Use PTY mode for interactive terminal sessions
    pub interactive: bool,
    /// Terminal size for PTY mode (rows, cols)
    pub pty_size: Option<(u16, u16)>,

    /// Resolved cache mounts for this job
    /// These are ready to be bind-mounted by the executor
    pub cache_mounts: Vec<ResolvedCacheMount>,
}

/// I/O handle for job execution
///
/// Differentiates between piped (line-based), PTY (raw byte), and direct (inherited) modes.
#[derive(Debug)]
pub enum IoHandle {
    /// Piped mode: separate stdout/stderr channels with line-based streaming
    Piped {
        /// Channel receiving stdout lines
        stdout: mpsc::Receiver<String>,
        /// Channel receiving stderr lines
        stderr: mpsc::Receiver<String>,
    },
    /// PTY mode: single bidirectional channel for interactive terminal
    Pty {
        /// Channel for sending input bytes to the PTY
        stdin: mpsc::Sender<Vec<u8>>,
        /// Channel receiving output bytes from the PTY
        stdout: mpsc::Receiver<Vec<u8>>,
    },
    /// Direct mode: stdio inherited from parent process
    ///
    /// Used when the executor handles terminal I/O directly (e.g., systemd-run --pty).
    /// No channel forwarding needed - the process connects to the terminal directly.
    Direct,
}

/// Handle to a running job execution
///
/// Provides channels for streaming output and receiving exit status.
/// Platform-specific cleanup is handled internally by each executor.
#[derive(Debug)]
pub struct ExecutionHandle {
    /// I/O handle (piped or PTY mode)
    pub io: IoHandle,
    /// Receiver for the final exit code
    pub exit_code: oneshot::Receiver<i32>,
}

/// Main trait for job executors
///
/// Implementations provide platform-specific sandboxing:
/// - macOS: `SandboxExecutor` using sandbox-exec with SBPL profiles
/// - Linux: `SystemdExecutor` using systemd-run with 33 hardening properties
///
/// Each implementation handles its own cleanup internally.
#[async_trait]
pub trait Executor: Send + Sync {
    /// Execute a job with the given configuration
    ///
    /// Returns an `ExecutionHandle` with channels for output streaming.
    /// The implementation manages cleanup internally when the job exits.
    async fn execute(&self, config: ExecutionConfig) -> Result<ExecutionHandle, ExecutorError>;

    /// Get the proxy listen address for this platform
    ///
    /// - Linux: "0.0.0.0:3128" (bind all interfaces, veth created later)
    /// - macOS: "127.0.0.1:3128" (localhost for sandbox-exec)
    fn proxy_listen_addr(&self) -> &'static str;

    /// Get the proxy connect host for jobs on this platform
    ///
    /// This is the address jobs use to reach the proxy:
    /// - Linux: "10.0.0.1" (veth interface IP in host namespace)
    /// - macOS: "127.0.0.1" (localhost)
    fn proxy_connect_host(&self) -> &'static str;

    /// Whether this executor runs jobs in a chroot (RootDirectory)
    ///
    /// This affects how paths are resolved in environment variables:
    /// - Linux (systemd): true - paths like /etc/ssl/certs are relative to RootDirectory
    /// - macOS (sandbox): false - paths are absolute host paths
    fn uses_chroot(&self) -> bool;

    /// Get the executor name for display/logging
    fn name(&self) -> &'static str;

    /// Clean up job root directory with executor-specific privileges
    ///
    /// Default implementation returns Ok (cleanup handled by JobRoot).
    /// Executors that need privilege escalation (e.g., SystemdExecutor via polkit)
    /// can override this to run cleanup with elevated permissions.
    async fn cleanup_root(&self, _root_dir: &std::path::Path) -> Result<(), ExecutorError> {
        Ok(())
    }

    /// Clean up job workspace directory with executor-specific privileges
    ///
    /// Default implementation returns Ok (cleanup handled by JobWorkspace).
    /// Executors that need privilege escalation (e.g., SystemdExecutor via polkit)
    /// can override this to run cleanup with elevated permissions.
    async fn cleanup_workspace(
        &self,
        _workspace_dir: &std::path::Path,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }

    /// Get the sandbox user/group for this executor
    ///
    /// Returns the (user, group) that jobs run as, or None if the executor
    /// doesn't use user switching (e.g., macOS sandbox-exec runs as current user).
    ///
    /// When Some, the orchestration layer will:
    /// - Create home directory at /home/{user}
    /// - chown job directories to {user}:{group}
    fn sandbox_user(&self) -> Option<(&'static str, &'static str)> {
        None
    }
}

#[cfg(test)]
pub mod mock {
    //! Mock executor for testing
    //!
    //! Provides a test double that doesn't require actual sandboxing.

    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Configuration for mock executor behavior
    #[derive(Debug, Clone, Default)]
    pub struct MockConfig {
        /// Lines to send to stdout
        pub stdout_lines: Vec<String>,
        /// Lines to send to stderr
        pub stderr_lines: Vec<String>,
        /// Exit code to return
        pub exit_code: i32,
        /// Whether to simulate spawn failure
        pub fail_spawn: Option<String>,
    }

    /// Mock executor for testing
    #[derive(Debug)]
    pub struct MockExecutor {
        config: Arc<Mutex<MockConfig>>,
        /// Records of execute() calls for verification
        pub calls: Arc<Mutex<Vec<ExecutionConfig>>>,
    }

    impl MockExecutor {
        pub fn new() -> Self {
            MockExecutor {
                config: Arc::new(Mutex::new(MockConfig::default())),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Configure the mock's behavior
        pub async fn set_config(&self, config: MockConfig) {
            *self.config.lock().await = config;
        }
    }

    impl Default for MockExecutor {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl Executor for MockExecutor {
        async fn execute(&self, config: ExecutionConfig) -> Result<ExecutionHandle, ExecutorError> {
            // Record the call
            self.calls.lock().await.push(config);

            let mock_config = self.config.lock().await.clone();

            // Simulate spawn failure if configured
            if let Some(msg) = mock_config.fail_spawn {
                return Err(ExecutorError::SpawnFailed(msg));
            }

            // Create channels
            let (stdout_tx, stdout_rx) = mpsc::channel(128);
            let (stderr_tx, stderr_rx) = mpsc::channel(128);
            let (exit_tx, exit_rx) = oneshot::channel();

            // Spawn task to send mock output
            let stdout_lines = mock_config.stdout_lines;
            let stderr_lines = mock_config.stderr_lines;
            let exit_code = mock_config.exit_code;

            drop(tokio::spawn(async move {
                for line in stdout_lines {
                    let _ = stdout_tx.send(line).await;
                }
                for line in stderr_lines {
                    let _ = stderr_tx.send(line).await;
                }
                let _ = exit_tx.send(exit_code);
            }));

            Ok(ExecutionHandle {
                io: IoHandle::Piped {
                    stdout: stdout_rx,
                    stderr: stderr_rx,
                },
                exit_code: exit_rx,
            })
        }

        fn proxy_listen_addr(&self) -> &'static str {
            "127.0.0.1:3128"
        }

        fn proxy_connect_host(&self) -> &'static str {
            "127.0.0.1"
        }

        fn uses_chroot(&self) -> bool {
            true // Match Linux behavior for testing
        }

        fn name(&self) -> &'static str {
            "MockExecutor (test)"
        }
    }
}
