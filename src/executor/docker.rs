//! Docker-based sandboxing for Linux using container isolation.
//!
//! This module implements secure job execution on Linux using Docker containers
//! as an alternative to systemd-run. Useful for environments without systemd
//! (Alpine, Gentoo, WSL2) or where containerized execution is preferred.
//!
//! Security Model:
//! - Container isolation: Job runs in isolated container with restricted capabilities
//! - Filesystem binding: Only Nix closure and workspace accessible via volume mounts
//! - Network isolation: Host network disabled, uses Docker network for proxy access
//! - Resource limits: CPU, memory, process constraints via container limits
//! - Privilege dropping: Runs as non-root user with no capabilities

use super::traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError, IoHandle};
use async_trait::async_trait;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Docker network name for nix-jail jobs with proxy access
const DOCKER_NETWORK: &str = "nix-jail";

/// Proxy listen address for Docker executor
///
/// Binds to 0.0.0.0 (all interfaces) because the Docker bridge interface
/// doesn't exist when the proxy starts.
pub const DOCKER_PROXY_ADDR: &str = "0.0.0.0:3128";

/// Linux Docker-based executor with container isolation.
///
/// Provides isolation using:
/// - Docker container with security options (--cap-drop, --security-opt)
/// - Read-only root filesystem with explicit volume mounts
/// - Resource limits (CPU, memory, PIDs)
/// - Network isolation with proxy-only connectivity via Docker network
#[derive(Debug, Default)]
pub struct DockerExecutor {
    /// Docker network name for proxy connectivity
    network_name: String,
}

impl DockerExecutor {
    pub fn new() -> Self {
        DockerExecutor {
            network_name: DOCKER_NETWORK.to_string(),
        }
    }

    /// Execute in interactive PTY mode using portable-pty
    async fn execute_interactive(
        &self,
        docker_args: Vec<String>,
        container_name: String,
        pty_size: Option<(u16, u16)>,
        timeout_duration: std::time::Duration,
        job_id: String,
        exit_tx: oneshot::Sender<i32>,
    ) -> Result<IoHandle, ExecutorError> {
        use portable_pty::{native_pty_system, CommandBuilder, PtySize};

        let (rows, cols) = pty_size.unwrap_or((24, 80));
        let pty_system = native_pty_system();
        let pty_pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| ExecutorError::SpawnFailed(format!("failed to create pty: {}", e)))?;

        // Build command for PTY: docker run -it ...
        let mut cmd_builder = CommandBuilder::new("docker");
        cmd_builder.args(&docker_args);

        // Spawn docker process in PTY
        let mut pty_child = pty_pair.slave.spawn_command(cmd_builder).map_err(|e| {
            ExecutorError::SpawnFailed(format!("failed to spawn docker in pty: {}", e))
        })?;

        // Get reader and writer for PTY master
        let mut pty_reader = pty_pair.master.try_clone_reader().map_err(|e| {
            ExecutorError::SpawnFailed(format!("failed to clone pty reader: {}", e))
        })?;
        let mut pty_writer = pty_pair
            .master
            .take_writer()
            .map_err(|e| ExecutorError::SpawnFailed(format!("failed to take pty writer: {}", e)))?;

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
            let result = tokio::time::timeout(timeout_duration, async {
                pty_child.wait().map_err(std::io::Error::other)
            })
            .await;

            let exit_code = match result {
                Ok(Ok(status)) => status.exit_code() as i32,
                Ok(Err(e)) => {
                    tracing::error!(job_id = %job_id, error = %e, "error waiting for docker container");
                    -1
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id, "execution timed out, stopping docker container");
                    let _ = pty_child.kill();
                    // Also try to stop the container
                    let _ = std::process::Command::new("docker")
                        .args(["stop", "-t", "5", &container_name])
                        .status();
                    -1
                }
            };

            let _ = exit_tx.send(exit_code);

            // Wait for I/O tasks
            let _ = tokio::join!(read_task, write_task);
        }));

        Ok(IoHandle::Pty {
            stdin: stdin_tx,
            stdout: stdout_rx,
        })
    }

    /// Execute in piped mode with separate stdout/stderr streams
    async fn execute_piped(
        &self,
        docker_args: Vec<String>,
        container_name: String,
        timeout_duration: std::time::Duration,
        job_id: String,
        exit_tx: oneshot::Sender<i32>,
    ) -> Result<IoHandle, ExecutorError> {
        let mut cmd = Command::new("docker");
        let _ = cmd.args(&docker_args);
        let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| ExecutorError::SpawnFailed(format!("failed to spawn docker: {}", e)))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("failed to capture stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("failed to capture stderr".to_string()))?;

        let (stdout_tx, stdout_rx) = mpsc::channel(100);
        let (stderr_tx, stderr_rx) = mpsc::channel(100);

        drop(tokio::spawn(async move {
            let stdout_reader = BufReader::new(stdout);
            let stderr_reader = BufReader::new(stderr);

            let stdout_task = tokio::spawn(async move {
                let mut lines = stdout_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = stdout_tx.send(line).await;
                }
            });

            let stderr_task = tokio::spawn(async move {
                let mut lines = stderr_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = stderr_tx.send(line).await;
                }
            });

            let exit_code = match timeout(timeout_duration, child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                Ok(Err(e)) => {
                    tracing::error!(job_id = %job_id, error = %e, "failed to wait for docker container");
                    -1
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id, "execution timed out, stopping docker container");
                    let _ = Command::new("docker")
                        .args(["stop", "-t", "5", &container_name])
                        .status()
                        .await;
                    -1
                }
            };

            let _ = exit_tx.send(exit_code);
            let _ = tokio::join!(stdout_task, stderr_task);
        }));

        Ok(IoHandle::Piped {
            stdout: stdout_rx,
            stderr: stderr_rx,
        })
    }

    /// Ensure Docker network exists for proxy connectivity
    async fn ensure_network(&self) -> Result<(), ExecutorError> {
        // Check if network exists
        let status = Command::new("docker")
            .args(["network", "inspect", &self.network_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("docker network inspect: {}", e)))?;

        if !status.success() {
            // Create bridge network
            let status = Command::new("docker")
                .args([
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    &self.network_name,
                ])
                .status()
                .await
                .map_err(|e| ExecutorError::SpawnFailed(format!("docker network create: {}", e)))?;

            if !status.success() {
                return Err(ExecutorError::SpawnFailed(format!(
                    "failed to create docker network '{}'",
                    self.network_name
                )));
            }

            tracing::info!(network = %self.network_name, "created docker network for nix-jail");
        }

        Ok(())
    }

    /// Get the gateway IP of the Docker network for proxy access
    #[allow(dead_code)] // Used in tests; may be used for dynamic gateway discovery
    async fn get_network_gateway(&self) -> Result<String, ExecutorError> {
        let output = Command::new("docker")
            .args([
                "network",
                "inspect",
                &self.network_name,
                "--format",
                "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
            ])
            .output()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("docker network inspect: {}", e)))?;

        let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if gateway.is_empty() {
            return Err(ExecutorError::SpawnFailed(
                "could not determine docker network gateway".to_string(),
            ));
        }
        Ok(gateway)
    }
}

/// Adds filesystem mounts to the docker command arguments
fn add_filesystem_mounts_to_args(args: &mut Vec<String>, config: &ExecutionConfig) {
    // Workspace (read-write)
    // Check for special docker-volume: prefix (from DockerVolumeWorkspace)
    let working_dir_str = config.working_dir.to_string_lossy();
    if let Some(volume_spec) = working_dir_str.strip_prefix("docker-volume:") {
        // Format: docker-volume:{volume_name}[:{subpath}]
        let parts: Vec<&str> = volume_spec.splitn(2, ':').collect();
        let volume_name = parts[0];
        let subpath = parts.get(1).copied().unwrap_or("");

        if subpath.is_empty() {
            // Mount volume root as workspace
            args.extend(["-v".to_string(), format!("{}:/workspace", volume_name)]);
        } else {
            // Mount volume and set working directory to subpath
            // The wrapper script will cd to the subpath
            args.extend(["-v".to_string(), format!("{}:/workspace-root", volume_name)]);
            args.extend(["-e".to_string(), format!("WORKSPACE_SUBPATH={}", subpath)]);
        }
    } else {
        // Standard bind-mount from host filesystem
        args.extend([
            "-v".to_string(),
            format!("{}:/workspace", config.working_dir.display()),
        ]);
    };

    // Nix store based on strategy
    match &config.store_setup {
        crate::root::StoreSetup::Populated => {
            // Mount entire root's /nix/store
            let store_dir = config.root_dir.join("nix/store");
            if store_dir.exists() {
                args.extend([
                    "-v".to_string(),
                    format!("{}:/nix/store:ro", store_dir.display()),
                ]);
            }
        }
        crate::root::StoreSetup::BindMounts { paths } => {
            // Bind-mount each store path from host
            for path in paths {
                args.extend([
                    "-v".to_string(),
                    format!("{}:{}:ro", path.display(), path.display()),
                ]);
            }
        }
        crate::root::StoreSetup::DockerVolume { name } => {
            // Mount named Docker volume containing Nix store
            // The volume was pre-populated by DockerVolumeJobRoot
            args.extend(["-v".to_string(), format!("{}:/nix:ro", name)]);
        }
    }

    // SSL certificates for proxy (CA cert is written to job root directory)
    let ca_cert_path = config.root_dir.join("etc/ssl/certs/ca-certificates.crt");
    if ca_cert_path.exists() {
        args.extend([
            "-v".to_string(),
            format!(
                "{}:/etc/ssl/certs/ca-certificates.crt:ro",
                ca_cert_path.display()
            ),
        ]);
    }

    // Cache volumes from resolved cache mounts
    for mount in &config.cache_mounts {
        // For Docker, prefer named volumes if configured, else bind-mount host path
        if let Some(ref volume_name) = mount.docker_volume {
            args.extend([
                "-v".to_string(),
                format!("{}:{}", volume_name, mount.mount_path),
            ]);
        } else {
            args.extend([
                "-v".to_string(),
                format!("{}:{}", mount.host_path.display(), mount.mount_path),
            ]);
        }
    }
}

/// Resolve command paths from the Nix closure
///
/// If the command is a bare name (e.g., "bash"), look for it in the store paths.
/// Otherwise return the command as-is.
fn resolve_command_in_closure(
    command: &[String],
    store_paths: &[std::path::PathBuf],
) -> Vec<String> {
    if command.is_empty() {
        return command.to_vec();
    }

    let mut resolved = command.to_vec();
    let cmd_name = &command[0];

    // If it's already an absolute path, use it
    if cmd_name.starts_with('/') {
        return resolved;
    }

    // Search for the command in store paths
    for store_path in store_paths {
        let bin_path = store_path.join("bin").join(cmd_name);
        if bin_path.exists() {
            resolved[0] = bin_path.to_string_lossy().to_string();
            return resolved;
        }
    }

    // Not found - return as-is and let Docker handle it
    resolved
}

#[async_trait]
impl Executor for DockerExecutor {
    async fn execute(&self, config: ExecutionConfig) -> Result<ExecutionHandle, ExecutorError> {
        let job_id = &config.job_id;
        let command = &config.command;

        if command.is_empty() {
            return Err(ExecutorError::SpawnFailed(
                "command cannot be empty".to_string(),
            ));
        }

        // Verify root directory exists (for Populated store setup)
        if !config.root_dir.exists() {
            return Err(ExecutorError::SpawnFailed(format!(
                "root directory not found: {}",
                config.root_dir.display()
            )));
        }

        // Ensure network exists if we need proxy access
        if config.proxy_port.is_some() {
            self.ensure_network().await?;
        }

        // Resolve command paths from closure (skip for DockerVolume - paths are different architecture)
        let resolved_command = match &config.store_setup {
            crate::root::StoreSetup::DockerVolume { .. } => {
                // Don't resolve - the volume has different (Linux) paths than host (macOS)
                // The PATH will be set up to find binaries
                command.to_vec()
            }
            _ => resolve_command_in_closure(command, &config.store_paths),
        };

        // Build docker command arguments (shared between interactive and piped modes)
        let container_name = format!("nix-jail-{}", job_id);
        let mut docker_args = vec![
            "run".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--rm".to_string(), // Auto-remove on exit
        ];

        // Add -it flags for interactive mode (allocates TTY and keeps stdin open)
        if config.interactive {
            docker_args.push("-it".to_string());
        }

        // Security options
        docker_args.extend([
            "--cap-drop=ALL".to_string(),
            "--security-opt=no-new-privileges".to_string(),
            "--read-only".to_string(),
            "--tmpfs=/tmp:noexec,nosuid,size=64m".to_string(),
            "--user=65534:65534".to_string(),
        ]);

        // Resource limits
        docker_args.extend([
            "--memory=4g".to_string(),
            "--pids-limit=512".to_string(),
            "--ulimit=nofile=1024:1024".to_string(),
            format!("--stop-timeout={}", config.timeout.as_secs()),
        ]);

        // Network configuration
        if config.proxy_port.is_some() {
            docker_args.extend(["--network".to_string(), self.network_name.clone()]);
        } else {
            docker_args.push("--network=none".to_string());
        }

        // Filesystem mounts
        add_filesystem_mounts_to_args(&mut docker_args, &config);

        // Environment variables
        // Set TERM based on interactive mode
        if config.interactive {
            docker_args.extend(["-e".to_string(), "TERM=xterm-256color".to_string()]);
        } else {
            docker_args.extend(["-e".to_string(), "TERM=dumb".to_string()]);
        }

        // Cache environment variables from resolved cache mounts
        for mount in &config.cache_mounts {
            if let Some(ref env_var) = mount.env_var {
                docker_args.extend([
                    "-e".to_string(),
                    format!("{}={}", env_var, mount.mount_path),
                ]);
            }
        }

        for (key, value) in &config.env {
            docker_args.extend(["-e".to_string(), format!("{}={}", key, value)]);
        }

        // Working directory inside container
        docker_args.extend(["-w".to_string(), "/workspace".to_string()]);

        // Choose base image based on store setup strategy
        let base_image = match &config.store_setup {
            crate::root::StoreSetup::DockerVolume { .. } => "busybox",
            _ => "nixos/nix:latest",
        };
        docker_args.push(base_image.to_string());

        // Command to execute
        // For DockerVolume, wrap in a shell that sets up PATH from /nix/store/*/bin
        match &config.store_setup {
            crate::root::StoreSetup::DockerVolume { .. } => {
                // Shell-escape arguments by wrapping in single quotes and escaping single quotes
                let escaped_cmd = resolved_command
                    .iter()
                    .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                let wrapper_script = format!(
                    r#"export PATH="/nix/bin:$PATH" && \
                    export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/workspace-root && \
                    if [ -n "$WORKSPACE_SUBPATH" ]; then cd "/workspace-root/$WORKSPACE_SUBPATH"; fi && \
                    exec {}"#,
                    escaped_cmd
                );
                docker_args.extend(["/bin/sh".to_string(), "-c".to_string(), wrapper_script]);
            }
            _ => {
                docker_args.extend(resolved_command.iter().cloned());
            }
        }

        tracing::debug!(args = ?docker_args, container = %container_name, interactive = config.interactive, "spawning docker container");

        // Branch based on interactive mode
        let (exit_tx, exit_rx) = oneshot::channel();
        let timeout_duration = config.timeout;
        let job_id_clone = job_id.to_string();

        let io_handle = if config.interactive {
            // PTY mode: use portable-pty for interactive terminal
            self.execute_interactive(
                docker_args,
                container_name,
                config.pty_size,
                timeout_duration,
                job_id_clone,
                exit_tx,
            )
            .await?
        } else {
            // Piped mode: separate stdout/stderr with line-based streaming
            self.execute_piped(
                docker_args,
                container_name,
                timeout_duration,
                job_id_clone,
                exit_tx,
            )
            .await?
        };

        Ok(ExecutionHandle {
            io: io_handle,
            exit_code: exit_rx,
        })
    }

    fn proxy_listen_addr(&self) -> &'static str {
        DOCKER_PROXY_ADDR
    }

    fn proxy_connect_host(&self) -> &'static str {
        // Docker containers access host services via platform-specific means:
        // - macOS Docker Desktop: host.docker.internal (DNS resolves to host)
        // - Linux Docker: 172.17.0.1 (docker0 bridge gateway)
        if cfg!(target_os = "macos") {
            "host.docker.internal"
        } else {
            "172.17.0.1"
        }
    }

    fn uses_chroot(&self) -> bool {
        true // Container has isolated root filesystem
    }

    fn name(&self) -> &'static str {
        "DockerExecutor (docker run)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Check if Docker socket exists (faster than running docker version)
    fn docker_socket_exists() -> bool {
        Path::new("/var/run/docker.sock").exists()
    }

    /// Helper to check if Docker is available (socket + daemon running)
    async fn docker_available() -> bool {
        if !docker_socket_exists() {
            return false;
        }
        Command::new("docker")
            .args(["version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn test_executor_type_parsing() {
        use crate::executor::ExecutorType;

        assert_eq!(
            "docker".parse::<ExecutorType>().unwrap(),
            ExecutorType::Docker
        );
        assert_eq!(
            "Docker".parse::<ExecutorType>().unwrap(),
            ExecutorType::Docker
        );
        assert_eq!(
            "DOCKER".parse::<ExecutorType>().unwrap(),
            ExecutorType::Docker
        );
    }

    #[test]
    fn test_resolve_command_absolute_path() {
        let command = vec!["/nix/store/abc/bin/bash".to_string(), "-c".to_string()];
        let store_paths = vec![];
        let resolved = resolve_command_in_closure(&command, &store_paths);
        assert_eq!(resolved[0], "/nix/store/abc/bin/bash");
    }

    #[test]
    fn test_resolve_command_empty() {
        let command: Vec<String> = vec![];
        let store_paths = vec![];
        let resolved = resolve_command_in_closure(&command, &store_paths);
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_docker_executor_requires_root_dir() {
        use crate::executor::test_helpers::TestConfigBuilder;

        let config = TestConfigBuilder::new("test-no-root")
            .command(vec!["echo", "test"])
            .root_dir("/nonexistent/root/dir")
            .build();

        let executor = DockerExecutor::new();
        let result = executor.execute(config).await;
        assert!(
            matches!(&result, Err(ExecutorError::SpawnFailed(msg)) if msg.contains("root directory not found")),
            "expected SpawnFailed error for missing root directory, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_docker_executor_empty_command() {
        use crate::executor::test_helpers::TestConfigBuilder;

        let config = TestConfigBuilder::new("test-empty-cmd")
            .command(vec![])
            .build();

        let executor = DockerExecutor::new();
        let result = executor.execute(config).await;
        assert!(
            matches!(&result, Err(ExecutorError::SpawnFailed(msg)) if msg.contains("command cannot be empty")),
            "expected SpawnFailed error for empty command, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_docker_executor_trait_methods() {
        let executor = DockerExecutor::new();

        assert_eq!(executor.proxy_listen_addr(), "0.0.0.0:3128");
        // proxy_connect_host is platform-specific
        #[cfg(target_os = "macos")]
        assert_eq!(executor.proxy_connect_host(), "host.docker.internal");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(executor.proxy_connect_host(), "172.17.0.1");
        assert!(executor.uses_chroot());
        assert_eq!(executor.name(), "DockerExecutor (docker run)");
    }

    #[tokio::test]
    async fn test_docker_network_creation() {
        if !docker_available().await {
            tracing::debug!("skipping test_docker_network_creation: docker not available");
            return;
        }

        let executor = DockerExecutor::new();
        let result = executor.ensure_network().await;

        // Network creation should succeed (or already exist)
        assert!(
            result.is_ok(),
            "failed to ensure docker network: {:?}",
            result.err()
        );

        // Verify we can get the gateway
        let gateway = executor.get_network_gateway().await;
        assert!(
            gateway.is_ok(),
            "failed to get network gateway: {:?}",
            gateway.err()
        );

        let gateway_ip = gateway.unwrap();
        assert!(!gateway_ip.is_empty(), "gateway IP should not be empty");
        tracing::debug!(gateway = %gateway_ip, "docker network gateway");
    }

    // ========== Execution tests using generic test suite ==========
    // These tests require Docker to be running

    use crate::executor::executor_tests;

    #[tokio::test]
    async fn test_docker_success_execution() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_success_execution(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_stderr_capture() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_stderr_capture(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_non_zero_exit() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_non_zero_exit(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_timeout_handling() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_timeout_handling(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_multiline_output() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_multiline_output(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_working_directory() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_working_directory(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_environment_variables() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_environment_variables(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_empty_command_error_generic() {
        if !docker_available().await {
            return;
        }
        executor_tests::test_empty_command_error(&DockerExecutor::new()).await;
    }

    #[tokio::test]
    async fn test_docker_interactive_mode() {
        use crate::executor::test_helpers::{collect_pty_output, TestConfigBuilder};

        if !docker_available().await {
            return;
        }

        let executor = DockerExecutor::new();
        let config = TestConfigBuilder::new("test-interactive")
            .command(vec!["echo", "hello from pty"])
            .interactive(true)
            .pty_size(24, 80)
            .build();

        let handle = executor.execute(config).await.expect("execution failed");
        let output = collect_pty_output(handle).await;

        // Convert PTY output to string (may contain ANSI codes)
        let output_str = String::from_utf8_lossy(&output.output);
        assert!(
            output_str.contains("hello from pty"),
            "expected 'hello from pty' in output, got: {}",
            output_str
        );
        assert_eq!(output.exit_code, 0, "expected exit code 0");
    }
}
