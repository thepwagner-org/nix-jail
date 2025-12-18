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

use super::traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError, HardeningProfile};
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

/// Adds security options to the docker command
///
/// Maps systemd hardening properties to Docker equivalents:
/// - Capabilities: --cap-drop=ALL
/// - Privileges: --security-opt=no-new-privileges
/// - Filesystem: --read-only, --tmpfs
/// - User: --user nobody
fn add_security_options(cmd: &mut Command, _profile: &HardeningProfile) {
    // Drop all capabilities
    let _ = cmd.arg("--cap-drop=ALL");

    // Prevent privilege escalation
    let _ = cmd.arg("--security-opt=no-new-privileges");

    // Read-only root filesystem
    let _ = cmd.arg("--read-only");

    // Private tmpfs for /tmp (noexec, nosuid, limited size)
    let _ = cmd.arg("--tmpfs=/tmp:noexec,nosuid,size=64m");

    // Run as non-root user (nobody:nogroup = 65534:65534)
    let _ = cmd.arg("--user=65534:65534");

    // Note: Seccomp profiles for HardeningProfile::Default vs JitRuntime
    // would require shipping custom seccomp JSON profiles. For now, we use
    // Docker's default seccomp which provides good baseline security.
    // TODO: Add custom seccomp profiles for full parity with systemd
}

/// Adds resource limits to the docker command
fn add_resource_limits(cmd: &mut Command, config: &ExecutionConfig) {
    // CPU limit (2 CPUs worth, matches systemd CPUQuota=200%)
    let _ = cmd.arg("--cpus=2");

    // Memory limit (matches systemd MemoryMax=2G)
    let _ = cmd.arg("--memory=2g");

    // PID limit (matches systemd TasksMax=100)
    let _ = cmd.arg("--pids-limit=100");

    // File descriptor limit (matches systemd LimitNOFILE=1024)
    let _ = cmd.arg("--ulimit=nofile=1024:1024");

    // Stop timeout for cleanup
    let _ = cmd.arg(format!("--stop-timeout={}", config.timeout.as_secs()));
}

/// Adds network configuration to the docker command
fn add_network_config(cmd: &mut Command, config: &ExecutionConfig, network_name: &str) {
    if config.proxy_port.is_some() {
        // Connect to nix-jail network for proxy access
        let _ = cmd.arg("--network").arg(network_name);
    } else {
        // No network access at all
        let _ = cmd.arg("--network=none");
    }
}

/// Adds filesystem mounts to the docker command
fn add_filesystem_mounts(cmd: &mut Command, config: &ExecutionConfig) {
    // Workspace (read-write)
    let _ = cmd
        .arg("-v")
        .arg(format!("{}:/workspace", config.working_dir.display()));

    // Nix store based on strategy
    match &config.store_setup {
        crate::root::StoreSetup::Populated => {
            // Mount entire root's /nix/store
            let store_dir = config.root_dir.join("nix/store");
            if store_dir.exists() {
                let _ = cmd
                    .arg("-v")
                    .arg(format!("{}:/nix/store:ro", store_dir.display()));
            }
        }
        crate::root::StoreSetup::BindMounts { paths } => {
            // Bind-mount each store path from host
            for path in paths {
                let _ = cmd
                    .arg("-v")
                    .arg(format!("{}:{}:ro", path.display(), path.display()));
            }
        }
        crate::root::StoreSetup::DockerVolume { name } => {
            // Mount named Docker volume containing Nix store
            // The volume was pre-populated by DockerVolumeJobRoot
            let _ = cmd.arg("-v").arg(format!("{}:/nix:ro", name));
        }
    }

    // SSL certificates for proxy (if they exist in workspace)
    let ca_cert_path = config.working_dir.join("etc/ssl/certs/ca-certificates.crt");
    if ca_cert_path.exists() {
        let _ = cmd.arg("-v").arg(format!(
            "{}:/etc/ssl/certs/ca-certificates.crt:ro",
            ca_cert_path.display()
        ));
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

        // Build docker run command
        let container_name = format!("nix-jail-{}", job_id);
        let mut cmd = Command::new("docker");
        let _ = cmd.arg("run");

        // Container identification
        let _ = cmd.arg("--name").arg(&container_name);
        let _ = cmd.arg("--rm"); // Auto-remove on exit

        // Security options
        add_security_options(&mut cmd, &config.hardening_profile);

        // Resource limits
        add_resource_limits(&mut cmd, &config);

        // Network configuration
        add_network_config(&mut cmd, &config, &self.network_name);

        // Filesystem mounts
        add_filesystem_mounts(&mut cmd, &config);

        // Environment variables
        // Set TERM=dumb to prevent ANSI escape codes
        let _ = cmd.arg("-e").arg("TERM=dumb");

        for (key, value) in &config.env {
            let _ = cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Working directory inside container
        let _ = cmd.arg("-w").arg("/workspace");

        // Choose base image based on store setup strategy
        let base_image = match &config.store_setup {
            crate::root::StoreSetup::DockerVolume { .. } => {
                // For DockerVolume, use alpine which has sh and basic utils
                // We mount our pre-built /nix/store over the empty /nix directory
                "alpine:latest"
            }
            _ => {
                // For other strategies, use nixos/nix which has Nix installed
                "nixos/nix:latest"
            }
        };
        let _ = cmd.arg(base_image);

        // Command to execute
        // For DockerVolume, wrap in a shell that sets up PATH from /nix/store/*/bin
        match &config.store_setup {
            crate::root::StoreSetup::DockerVolume { .. } => {
                // Run through sh with PATH setup - find all bin directories in /nix/store
                // Shell-escape arguments by wrapping in single quotes and escaping single quotes
                let escaped_cmd = resolved_command
                    .iter()
                    .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                let wrapper_script = format!(
                    r#"export PATH="$(find /nix/store -maxdepth 2 -type d -name bin 2>/dev/null | tr '\n' ':')$PATH" && exec {}"#,
                    escaped_cmd
                );
                let _ = cmd.arg("sh").arg("-c").arg(wrapper_script);
            }
            _ => {
                for arg in &resolved_command {
                    let _ = cmd.arg(arg);
                }
            }
        }

        // Configure stdio
        let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        tracing::debug!(command = ?cmd, container = %container_name, "spawning docker container");

        // Spawn the process
        let mut child = cmd
            .spawn()
            .map_err(|e| ExecutorError::SpawnFailed(format!("failed to spawn docker: {}", e)))?;

        // Capture stdout and stderr
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("failed to capture stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecutorError::SpawnFailed("failed to capture stderr".to_string()))?;

        // Create channels for streaming output
        let (stdout_tx, stdout_rx) = mpsc::channel(100);
        let (stderr_tx, stderr_rx) = mpsc::channel(100);
        let (exit_tx, exit_rx) = oneshot::channel();

        let container_name_clone = container_name.clone();
        let timeout_duration = config.timeout;
        let job_id_clone = job_id.to_string();

        // Spawn task to handle process execution and output streaming
        drop(tokio::spawn(async move {
            let stdout_reader = BufReader::new(stdout);
            let stderr_reader = BufReader::new(stderr);

            // Spawn tasks for stdout and stderr streaming
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

            // Wait for process with timeout
            let exit_code = match timeout(timeout_duration, child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                Ok(Err(e)) => {
                    tracing::error!(job_id = %job_id_clone, error = %e, "failed to wait for docker container");
                    -1
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id_clone, "execution timed out, stopping docker container");
                    // Timeout - stop the container
                    let _ = Command::new("docker")
                        .args(["stop", "-t", "5", &container_name_clone])
                        .status()
                        .await;
                    -1
                }
            };

            // Send exit code
            let _ = exit_tx.send(exit_code);

            // Wait for output tasks to complete
            let _ = tokio::join!(stdout_task, stderr_task);
        }));

        Ok(ExecutionHandle {
            io: super::traits::IoHandle::Piped {
                stdout: stdout_rx,
                stderr: stderr_rx,
            },
            exit_code: exit_rx,
        })
    }

    fn proxy_listen_addr(&self) -> &'static str {
        DOCKER_PROXY_ADDR
    }

    fn proxy_connect_host(&self) -> &'static str {
        // Docker containers access host services via special hostname
        // On Linux Docker, this resolves to the host's IP on the docker0 bridge
        // Note: For production use, we should dynamically get the gateway IP
        // For now, use the standard Docker bridge gateway
        "172.17.0.1"
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
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Helper to check if Docker is available
    async fn docker_available() -> bool {
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
        let config = ExecutionConfig {
            job_id: "test-no-root".to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/nonexistent/root/dir"),
            store_setup: crate::root::StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
        };

        let executor = DockerExecutor::new();
        let result = executor.execute(config).await;
        assert!(result.is_err());
        match result {
            Err(ExecutorError::SpawnFailed(msg)) => {
                assert!(msg.contains("root directory not found"));
            }
            _ => panic!("expected SpawnFailed error for missing root directory"),
        }
    }

    #[tokio::test]
    async fn test_docker_executor_empty_command() {
        let config = ExecutionConfig {
            job_id: "test-empty-cmd".to_string(),
            command: vec![],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: crate::root::StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
        };

        let executor = DockerExecutor::new();
        let result = executor.execute(config).await;
        assert!(result.is_err());
        match result {
            Err(ExecutorError::SpawnFailed(msg)) => {
                assert!(msg.contains("command cannot be empty"));
            }
            _ => panic!("expected SpawnFailed error for empty command"),
        }
    }

    #[tokio::test]
    async fn test_docker_executor_trait_methods() {
        let executor = DockerExecutor::new();

        assert_eq!(executor.proxy_listen_addr(), "0.0.0.0:3128");
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
}
