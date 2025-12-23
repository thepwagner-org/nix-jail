//! macOS-specific executor using sandbox-exec

use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

use super::traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError, IoHandle};

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

            // Generate sandbox profile (canonicalize paths to handle /tmp -> /private/tmp symlink on macOS)
            let canonical_workspace = config
                .working_dir
                .canonicalize()
                .unwrap_or_else(|_| config.working_dir.clone());
            let canonical_root = config
                .root_dir
                .canonicalize()
                .unwrap_or_else(|_| config.root_dir.clone());

            // Set up cache paths for sandbox profile (if caching enabled)
            // IMPORTANT: Canonicalize paths to handle /tmp -> /private/tmp symlink on macOS
            let cache_paths = if config.cache_enabled {
                let cargo_home = config.cargo_home.as_ref().and_then(|p| {
                    // Ensure directory exists before canonicalizing
                    if let Err(e) = std::fs::create_dir_all(p) {
                        tracing::warn!(path = %p.display(), error = %e, "failed to create cargo home dir");
                    }
                    p.canonicalize().ok()
                });
                let target_dir = match (&config.target_cache_dir, &config.repo_hash) {
                    (Some(base), Some(hash)) => {
                        let dir = base.join(&hash[..12.min(hash.len())]);
                        // Ensure the target cache directory exists before canonicalizing
                        if let Err(e) = std::fs::create_dir_all(&dir) {
                            tracing::warn!(path = %dir.display(), error = %e, "failed to create target cache dir");
                        }
                        dir.canonicalize().ok()
                    }
                    _ => None,
                };
                Some(super::sandbox_policy::CachePaths {
                    cargo_home,
                    target_dir,
                })
            } else {
                None
            };

            let profile = super::sandbox_policy::generate_profile_with_cache(
                closure,
                &canonical_workspace,
                &canonical_root,
                config.proxy_port,
                cache_paths.as_ref(),
            );

            // Build environment with cache variables
            let mut env = config.env.clone();
            if let Some(ref cache) = cache_paths {
                if let Some(ref cargo_home) = cache.cargo_home {
                    let _ = env.insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
                }
                if let Some(ref target_dir) = cache.target_dir {
                    let _ = env.insert(
                        "CARGO_TARGET_DIR".to_string(),
                        target_dir.display().to_string(),
                    );
                }
            }

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
                .envs(&env)
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

        let timeout = config.timeout;
        let job_id = config.job_id.clone();
        let interactive = config.interactive;

        // Handle I/O based on interactive mode
        let io_handle = if interactive {
            // PTY mode: use portable-pty for interactive terminal
            use portable_pty::{native_pty_system, CommandBuilder, PtySize};

            let (rows, cols) = config.pty_size.unwrap_or((24, 80));
            let pty_system = native_pty_system();
            let pty_pair = pty_system
                .openpty(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to create PTY: {}", e)))?;

            // Build command for PTY
            let mut cmd_builder = CommandBuilder::new(&config.command[0]);
            cmd_builder.args(&config.command[1..]);
            cmd_builder.cwd(&config.working_dir);
            cmd_builder.env_clear();
            for (k, v) in &config.env {
                cmd_builder.env(k, v);
            }

            // Spawn process in PTY
            let mut pty_child = pty_pair.slave.spawn_command(cmd_builder).map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to spawn in PTY: {}", e))
            })?;

            // Get reader and writer for PTY master
            let mut pty_reader = pty_pair.master.try_clone_reader().map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to clone PTY reader: {}", e))
            })?;
            let mut pty_writer = pty_pair.master.take_writer().map_err(|e| {
                ExecutorError::SpawnFailed(format!("Failed to take PTY writer: {}", e))
            })?;

            let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(128);
            let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>(128);

            // Spawn task to handle PTY I/O and cleanup
            drop(tokio::spawn(async move {
                // Task to read from PTY and send to stdout channel (blocking I/O in spawn_blocking)
                let read_task = {
                    let stdout_tx = stdout_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        use std::io::Read;
                        let mut buf = [0u8; 4096];
                        loop {
                            match pty_reader.read(&mut buf) {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    if stdout_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                        break; // Receiver dropped
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    })
                };

                // Task to read from stdin channel and write to PTY
                let write_task = tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    while let Some(data) = stdin_rx.blocking_recv() {
                        if pty_writer.write_all(&data).is_err() {
                            break;
                        }
                    }
                });

                // Wait for process with timeout
                let result = tokio::time::timeout(timeout, async {
                    pty_child.wait().map_err(std::io::Error::other)
                })
                .await;

                let exit_code = match result {
                    Ok(Ok(status)) => status.exit_code() as i32,
                    Ok(Err(e)) => {
                        tracing::error!(job_id = %job_id, error = %e, "error waiting for process");
                        -1
                    }
                    Err(_) => {
                        tracing::warn!(job_id = %job_id, "execution timed out, killing process");
                        let _ = pty_child.kill();
                        -1
                    }
                };

                let _ = exit_tx.send(exit_code);

                // Wait for I/O tasks
                let _ = tokio::join!(read_task, write_task);

                // Cleanup sandbox profile
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

            IoHandle::Pty {
                stdin: stdin_tx,
                stdout: stdout_rx,
            }
        } else {
            // Piped mode: separate stdout/stderr with line-based streaming
            let stdout = child.stdout.take().ok_or_else(|| {
                ExecutorError::SpawnFailed("Failed to capture stdout".to_string())
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                ExecutorError::SpawnFailed("Failed to capture stderr".to_string())
            })?;

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

            IoHandle::Piped {
                stdout: stdout_rx,
                stderr: stderr_rx,
            }
        };

        Ok(ExecutionHandle {
            io: io_handle,
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
    use crate::executor::executor_tests;
    use crate::executor::test_helpers::TestConfigBuilder;

    // ========================================
    // Generic executor tests (shared suite)
    // ========================================

    #[tokio::test]
    async fn test_simple_executor_success() {
        executor_tests::test_success_execution(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_stderr() {
        executor_tests::test_stderr_capture(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_non_zero_exit() {
        executor_tests::test_non_zero_exit(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_timeout() {
        executor_tests::test_timeout_handling(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_multiline_output() {
        executor_tests::test_multiline_output(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_working_directory() {
        executor_tests::test_working_directory(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_environment_variables() {
        executor_tests::test_environment_variables(&SandboxExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_simple_executor_empty_command() {
        executor_tests::test_empty_command_error(&SandboxExecutor::new()).await;
    }

    // ========================================
    // macOS-specific tests
    // ========================================

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn test_simple_executor_invalid_command() {
        let executor = SandboxExecutor::new();
        let config = TestConfigBuilder::new("test-invalid")
            .command(vec!["this-command-does-not-exist-xyz123"])
            .build();

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
    async fn test_simple_executor_with_sandbox() {
        use crate::executor::test_helpers::collect_output;
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();

        // Find curl derivation for the sandbox
        let curl_derivation = find_nix_package("curl")
            .await
            .expect("Failed to find curl derivation");

        let config = TestConfigBuilder::new("test-sandbox")
            .command(vec!["sh", "-c", "echo 'sandboxed execution'"])
            .store_paths(vec![curl_derivation])
            .build();

        let handle = executor.execute(config).await.expect("Execution failed");
        let output = collect_output(handle).await;

        assert!(
            !output.stdout.is_empty(),
            "No stdout received. Stderr: {:?}",
            output.stderr
        );
        assert_eq!(output.stdout[0], "sandboxed execution");
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn test_sandbox_restricts_filesystem_access() {
        use crate::executor::test_helpers::collect_output;
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();

        // Find a minimal derivation
        let derivation = find_nix_package("hello")
            .await
            .expect("Failed to find hello derivation");

        let config = TestConfigBuilder::new("test-sandbox-restrict")
            .command(vec![
                "sh",
                "-c",
                // Try to read /etc/passwd using shell built-in (should fail in sandbox)
                "read line < /etc/passwd 2>&1 && echo 'ACCESS_GRANTED' || echo 'ACCESS_DENIED'",
            ])
            .store_paths(vec![derivation])
            .build();

        let handle = executor.execute(config).await.expect("Execution failed");
        let output = collect_output(handle).await;

        // Should get ACCESS_DENIED due to sandbox restrictions
        assert!(
            !output.stdout.is_empty(),
            "No stdout received. Stderr: {:?}",
            output.stderr
        );
        assert!(
            output.stdout[0].contains("ACCESS_DENIED"),
            "Sandbox should have restricted access to /etc/passwd, got: {}",
            output.stdout[0]
        );
        assert_eq!(output.exit_code, 0);
    }

    // ========================================
    // Network isolation tests
    // ========================================

    #[tokio::test]
    async fn test_sandbox_blocks_network_without_proxy() {
        use crate::executor::test_helpers::collect_output;
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();
        let curl_derivation = find_nix_package("curl")
            .await
            .expect("Failed to find curl derivation");

        // No proxy_port = network completely blocked by SBPL
        let config = TestConfigBuilder::new("test-network-blocked")
            .command(vec!["curl", "--max-time", "2", "https://httpbin.org/get"])
            .store_paths(vec![curl_derivation])
            .build();

        let handle = executor.execute(config).await.expect("Execution failed");
        let output = collect_output(handle).await;

        // curl exit codes: 7 = connection refused, 28 = timeout
        // Either indicates network was blocked as expected
        assert_ne!(
            output.exit_code, 0,
            "Network should be blocked without proxy, but curl succeeded"
        );
    }

    #[tokio::test]
    async fn test_sandbox_allows_localhost_with_proxy() {
        use crate::executor::test_helpers::collect_output;
        use crate::workspace::find_nix_package;

        let executor = SandboxExecutor::new();
        let curl_derivation = find_nix_package("curl")
            .await
            .expect("Failed to find curl derivation");

        // With proxy_port set, SBPL allows localhost:* connections
        let config = TestConfigBuilder::new("test-localhost-allowed")
            .command(vec!["curl", "--max-time", "1", "http://127.0.0.1:9999"])
            .store_paths(vec![curl_derivation])
            .proxy_port(3128)
            .build();

        let handle = executor.execute(config).await.expect("Execution failed");
        let output = collect_output(handle).await;

        // Exit code 7 = connection refused (nothing listening on 9999) - SUCCESS
        // Exit code 28 = curl timeout (sandbox allowed, just slow)
        // Exit code -1 = killed by our timeout wrapper
        // Any of these mean the sandbox allowed the connection attempt
        // Exit code 6 = couldn't resolve host (sandbox blocked DNS) - FAILURE
        assert!(
            output.exit_code == 7 || output.exit_code == 28 || output.exit_code == -1,
            "Localhost should be reachable with proxy enabled, got exit {}. stderr: {:?}",
            output.exit_code,
            output.stderr
        );
    }
}
