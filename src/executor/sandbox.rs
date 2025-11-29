//! macOS-specific executor using sandbox-exec

use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

use super::traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError};

/// macOS sandbox-exec based executor
///
/// Provides sandboxing using macOS sandbox-exec with SBPL (Sandbox Profile Language).
/// On macOS, this enforces filesystem and network isolation via kernel-level policies.
///
/// SECURITY: Always enforces sandboxing when store_paths is provided.
#[derive(Debug)]
pub struct SandboxExecutor;

impl SandboxExecutor {
    pub fn new() -> Self {
        SandboxExecutor
    }
}

#[async_trait]
impl Executor for SandboxExecutor {
    async fn execute(&self, config: ExecutionConfig) -> Result<ExecutionHandle, ExecutorError> {
        if config.command.is_empty() {
            return Err(ExecutorError::SpawnFailed(
                "Command cannot be empty".to_string(),
            ));
        }

        // Create channels for output streaming
        let (stdout_tx, stdout_rx) = mpsc::channel::<String>(128);
        let (stderr_tx, stderr_rx) = mpsc::channel::<String>(128);
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();

        // Track profile path for internal cleanup (will be moved into spawned task)
        let mut cleanup_profile_path: Option<PathBuf> = None;

        // With store paths, use sandbox-exec for kernel-enforced isolation
        let mut child = if !config.store_paths.is_empty() {
            // store_paths is the pre-computed closure from orchestration
            let closure = &config.store_paths;
            tracing::debug!(job_id = %config.job_id, closure_size = closure.len(), "using pre-computed closure for sandbox");

            // Resolve command paths from closure (e.g., "bash" -> "/nix/store/.../bin/bash")
            let resolved_command = super::exec::resolve_command_paths(&config.command, closure);

            // Generate sandbox profile (canonicalize workspace to handle /tmp -> /private/tmp symlink on macOS)
            let canonical_workspace = config
                .working_dir
                .canonicalize()
                .unwrap_or_else(|_| config.working_dir.clone());
            let profile = super::sandbox_policy::generate_profile(
                closure,
                &canonical_workspace,
                config.proxy_port,
            );

            // Debug: log profile content
            tracing::debug!(job_id = %config.job_id, "Generated sandbox profile:\n{}", profile);

            // Write profile to temp file
            let profile_file = NamedTempFile::new().map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to create temp file: {}", e))
            })?;
            std::fs::write(profile_file.path(), profile.as_bytes()).map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to write sandbox profile: {}", e))
            })?;

            // Persist the temp file so it doesn't get deleted when NamedTempFile is dropped
            // Will be cleaned up by caller after job completes
            let (_, persisted_path) = profile_file.keep().map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to persist sandbox profile: {}", e))
            })?;

            tracing::info!(job_id = %config.job_id, "using sandbox-exec for kernel-enforced isolation");
            tracing::debug!(job_id = %config.job_id, profile_path = %persisted_path.display(), command = ?resolved_command, "sandbox-exec configuration");

            // Store profile path for cleanup (handled internally after job exits)
            cleanup_profile_path = Some(persisted_path.clone());

            // Spawn with sandbox-exec
            let child = Command::new("/usr/bin/sandbox-exec")
                .arg("-f")
                .arg(&persisted_path)
                .args(&resolved_command)
                .current_dir(&config.working_dir)
                .env_clear()
                .envs(&config.env)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| ExecutorError::SpawnFailed(format!("sandbox-exec: {}", e)))?;

            child
        } else {
            // No sandboxing - direct execution
            let (program, args) = config
                .command
                .split_first()
                .ok_or_else(|| ExecutorError::SpawnFailed("command cannot be empty".to_string()))?;
            Command::new(program)
                .args(args)
                .current_dir(&config.working_dir)
                .env_clear()
                .envs(&config.env)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| ExecutorError::SpawnFailed(format!("{}: {}", program, e)))?
        };

        // Take stdout and stderr handles
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("Failed to capture stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("Failed to capture stderr".to_string()))?;

        let timeout = config.timeout;
        let job_id = config.job_id.clone();

        // Spawn task to handle process execution, output streaming, and cleanup
        // Intentionally detached: communicates via channels
        drop(tokio::spawn(async move {
            // Stream stdout
            let stdout_task = {
                let stdout_tx = stdout_tx.clone();
                tokio::spawn(async move {
                    let reader = BufReader::new(stdout);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if stdout_tx.send(line).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                })
            };

            // Stream stderr
            let stderr_task = {
                let stderr_tx = stderr_tx.clone();
                tokio::spawn(async move {
                    let reader = BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if stderr_tx.send(line).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                })
            };

            // Wait for process with timeout
            let result = tokio::time::timeout(timeout, child.wait()).await;

            match result {
                Ok(Ok(status)) => {
                    let exit_code = status.code().unwrap_or(-1);
                    let _ = exit_tx.send(exit_code);
                }
                Ok(Err(e)) => {
                    tracing::error!(job_id = %job_id, error = %e, "error waiting for process");
                    let _ = exit_tx.send(-1);
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id, "execution timed out, killing process");
                    let _ = child.kill().await;
                    let _ = exit_tx.send(-1);
                }
            }

            // Wait for output tasks to complete
            let _ = tokio::join!(stdout_task, stderr_task);

            // Cleanup sandbox profile (internal cleanup - no external cleanup needed)
            if let Some(profile_path) = cleanup_profile_path {
                if let Err(e) = std::fs::remove_file(&profile_path) {
                    tracing::warn!(
                        job_id = %job_id,
                        path = %profile_path.display(),
                        error = %e,
                        "failed to cleanup sandbox profile"
                    );
                }
            }
        }));

        Ok(ExecutionHandle {
            stdout: stdout_rx,
            stderr: stderr_rx,
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
        false // macOS sandbox-exec uses host paths, no chroot
    }

    fn name(&self) -> &'static str {
        "SandboxExecutor (sandbox-exec)"
    }
}

impl Default for SandboxExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::HardeningProfile;
    use crate::root::StoreSetup;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn test_simple_executor_success() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-1".to_string(),
            command: vec!["echo".to_string(), "hello world".to_string()],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        // Read stdout
        let line = handle.stdout.recv().await.expect("No stdout received");
        assert_eq!(line, "hello world");

        // Get exit code
        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn test_simple_executor_stderr() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-stderr".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo error >&2".to_string(),
            ],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        // Read stderr
        let line = handle.stderr.recv().await.expect("No stderr received");
        assert_eq!(line, "error");

        // Get exit code
        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn test_simple_executor_non_zero_exit() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-exit".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let handle = executor.execute(config).await.expect("Execution failed");

        // Get exit code
        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 42);
    }

    #[tokio::test]
    async fn test_simple_executor_timeout() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-timeout".to_string(),
            command: vec!["sleep".to_string(), "100".to_string()],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_millis(100), // 100ms timeout
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let handle = executor.execute(config).await.expect("Execution failed");

        // Should timeout and return -1
        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, -1);
    }

    #[tokio::test]
    async fn test_simple_executor_multiline_output() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-multiline".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo line1; echo line2; echo line3".to_string(),
            ],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        // Read multiple lines
        let line1 = handle.stdout.recv().await.expect("No line1");
        let line2 = handle.stdout.recv().await.expect("No line2");
        let line3 = handle.stdout.recv().await.expect("No line3");

        assert_eq!(line1, "line1");
        assert_eq!(line2, "line2");
        assert_eq!(line3, "line3");

        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn test_simple_executor_working_directory() {
        let executor = SandboxExecutor::new();
        let tmp_dir = PathBuf::from("/tmp");

        let config = ExecutionConfig {
            job_id: "test-workdir".to_string(),
            command: vec!["pwd".to_string()],
            env: HashMap::new(),
            working_dir: tmp_dir.clone(),
            root_dir: tmp_dir.clone(),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        let line = handle.stdout.recv().await.expect("No stdout received");

        // On macOS, /tmp is a symlink to /private/tmp, so we canonicalize both
        let expected = std::fs::canonicalize(&tmp_dir)
            .expect("Failed to canonicalize tmp_dir")
            .to_string_lossy()
            .to_string();
        let actual_path = PathBuf::from(&line);
        let actual = std::fs::canonicalize(&actual_path)
            .unwrap_or(actual_path.clone())
            .to_string_lossy()
            .to_string();

        assert_eq!(actual, expected);

        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn test_simple_executor_environment_variables() {
        let executor = SandboxExecutor::new();
        let mut env = HashMap::new();
        let _ = env.insert("TEST_VAR".to_string(), "test_value".to_string());

        let config = ExecutionConfig {
            job_id: "test-env".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo $TEST_VAR".to_string(),
            ],
            env,
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        let line = handle.stdout.recv().await.expect("No stdout received");
        assert_eq!(line, "test_value");

        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn test_simple_executor_invalid_command() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-invalid".to_string(),
            command: vec!["this-command-does-not-exist-xyz123".to_string()],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let result = executor.execute(config).await;
        assert!(result.is_err());
        match result {
            Err(ExecutorError::SpawnFailed(msg)) => {
                assert!(msg.contains("this-command-does-not-exist-xyz123"));
            }
            other => {
                panic!("expected spawnfailed error, got {:?}", other);
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn test_simple_executor_empty_command() {
        let executor = SandboxExecutor::new();
        let config = ExecutionConfig {
            job_id: "test-empty".to_string(),
            command: vec![],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let result = executor.execute(config).await;
        assert!(result.is_err());
        match result {
            Err(ExecutorError::SpawnFailed(msg)) => {
                assert!(msg.contains("cannot be empty"));
            }
            other => {
                panic!("expected spawnfailed error, got {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_simple_executor_with_sandbox() {
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();

        // Find curl derivation for the sandbox
        let curl_derivation = find_nix_package("curl")
            .await
            .expect("Failed to find curl derivation");

        let config = ExecutionConfig {
            job_id: "test-sandbox".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo 'sandboxed execution'".to_string(),
            ],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![curl_derivation],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        // Try to read stdout with a timeout
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            // Spawn tasks to collect all output
            let stdout_task = tokio::spawn(async move {
                let mut lines = Vec::new();
                while let Some(line) = handle.stdout.recv().await {
                    lines.push(line);
                }
                lines
            });

            let stderr_task = tokio::spawn(async move {
                let mut lines = Vec::new();
                while let Some(line) = handle.stderr.recv().await {
                    lines.push(line);
                }
                lines
            });

            // Wait for process to exit
            let exit_code = handle.exit_code.await.expect("Failed to get exit code");

            // Collect all output
            let stdout_lines = stdout_task.await.expect("Stdout task failed");
            let stderr_lines = stderr_task.await.expect("Stderr task failed");

            (exit_code, stdout_lines, stderr_lines)
        })
        .await;

        let (exit_code, stdout_lines, stderr_lines) = result.expect("Test timed out");

        assert!(
            !stdout_lines.is_empty(),
            "No stdout received. Stderr: {:?}",
            stderr_lines
        );
        assert_eq!(stdout_lines[0], "sandboxed execution");
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn test_sandbox_restricts_filesystem_access() {
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();

        // Find a minimal derivation
        let derivation = find_nix_package("hello")
            .await
            .expect("Failed to find hello derivation");

        let config = ExecutionConfig {
            job_id: "test-sandbox-restrict".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                // Try to read /etc/passwd using shell built-in (should fail in sandbox)
                "read line < /etc/passwd 2>&1 && echo 'ACCESS_GRANTED' || echo 'ACCESS_DENIED'"
                    .to_string(),
            ],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![derivation],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
        };

        let mut handle = executor.execute(config).await.expect("Execution failed");

        // Should get ACCESS_DENIED due to sandbox restrictions
        let line = handle.stdout.recv().await.expect("No stdout received");
        assert!(
            line.contains("ACCESS_DENIED"),
            "Sandbox should have restricted access to /etc/passwd, got: {}",
            line
        );

        let exit_code = handle.exit_code.await.expect("Failed to get exit code");
        // Exit code 0 if echo succeeded (access was denied)
        assert_eq!(exit_code, 0);
    }
}
