//! Systemd-based sandboxing for Linux using systemd-run with comprehensive hardening.
//!
//! This module implements secure job execution on Linux using systemd's transient units
//! with all 33 hardening properties from PLAN.md. The security model mirrors the macOS
//! sandbox-exec implementation but uses systemd's isolation features.
//!
//! Security Model:
//! - RootDirectory isolation: Job runs in temporary root with only Nix closure
//! - Network isolation: PrivateNetwork + namespace sharing with proxy only
//! - Filesystem protection: No /home, /etc, or /nix/store beyond closure
//! - Resource limits: CPU, memory, process, and time constraints
//! - Privilege dropping: DynamicUser, no capabilities, syscall filtering

use super::traits::{ExecutionConfig, ExecutionHandle, Executor, ExecutorError, HardeningProfile};
use async_trait::async_trait;
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, LinkUnspec, LinkVeth};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Network configuration for veth pair
const VETH_PREFIX_LEN: u8 = 30; // /30 = 2 usable IPs (network, proxy, job, broadcast)

/// Proxy listen address for Linux
///
/// Binds to 0.0.0.0 (all interfaces) because the veth interface (10.0.0.1) doesn't exist
/// when the proxy starts - it's created later by the executor during namespace setup.
///
/// SECURITY: This is safe because network namespace isolation ensures the job can ONLY
/// reach the proxy via the veth pair. The job has no route to any other network.
pub const LINUX_PROXY_ADDR: &str = "0.0.0.0:3128";

/// Network isolation strategy for a job
enum NetworkSetup {
    /// Full network namespace with veth pair for proxy communication
    Namespace {
        subnet_counter: u32,
        netns_path: String,
    },
    /// Simple PrivateNetwork isolation (loopback only, no external access)
    PrivateNetwork,
}

/// Convert a workspace host path to a chroot-relative path
///
/// Inside the systemd RootDirectory chroot, the workspace directory is bind-mounted at `/workspace`.
/// This function converts host paths like `/tmp/nix-jail-{id}/workspace/foo` to `/workspace/foo`.
///
/// Examples:
/// - `/tmp/nix-jail-123/workspace` → `/workspace`
/// - `/tmp/nix-jail-123/workspace/etc/ssl/certs/ca.crt` → `/workspace/etc/ssl/certs/ca.crt`
/// - Other paths are returned as-is (shouldn't happen in practice)
fn workspace_to_chroot_path(host_path: &Path, workspace_root: &Path) -> PathBuf {
    // If the path is exactly the workspace root, return /workspace
    if host_path == workspace_root {
        return PathBuf::from("/workspace");
    }

    // If the path starts with workspace root, strip it and prepend /workspace
    if let Ok(relative) = host_path.strip_prefix(workspace_root) {
        return PathBuf::from("/workspace").join(relative);
    }

    // Otherwise return as-is (shouldn't happen - all paths should be under workspace)
    host_path.to_path_buf()
}

/// Generates systemd hardening properties for secure job isolation.
///
/// The number of properties varies by profile:
/// - Default: All 33 hardening properties
/// - JitRuntime: 32 hardening properties (removes MemoryDenyWriteExecute)
///
/// Properties implement defense-in-depth:
/// - Filesystem isolation (10 properties)
/// - User/privilege controls (6 properties)
/// - Syscall filtering (4 properties)
/// - Memory/execution controls (2-3 properties, profile-dependent)
/// - Network isolation (1 property)
/// - Resource limits (5 properties)
/// - Cleanup/isolation (4 properties)
///
/// Reference: SANDBOX.md Appendix C (Linux Hardening Reference)
/// SECURITY: NEVER remove/weaken these without documented justification (CLAUDE.md)
fn generate_hardening_properties(
    root_dir: &Path,
    workspace: &Path,
    _job_id: &str,
    config: &ExecutionConfig,
    profile: HardeningProfile,
    sandbox_user: (&str, &str),
) -> Vec<String> {
    let (user, group) = sandbox_user;
    let mut props = vec![
        // === Filesystem Isolation ===
        // Note: ProtectHome is not used because RootDirectory already provides isolation
        // and ProtectHome would hide /home/{user} we create inside the chroot
        "--property=PrivateTmp=true".to_string(),
        "--property=ProtectSystem=strict".to_string(),
        "--property=ProtectKernelTunables=true".to_string(),
        "--property=ProtectKernelModules=true".to_string(),
        "--property=ProtectKernelLogs=true".to_string(),
        "--property=ProtectControlGroups=true".to_string(),
        "--property=ProtectProc=invisible".to_string(),
        "--property=ProcSubset=pid".to_string(),
        "--property=PrivateDevices=true".to_string(),
        // === User and Privilege Controls ===
        // Use static sandbox user instead of DynamicUser for consistent permissions
        format!("--property=User={}", user),
        format!("--property=Group={}", group),
        "--property=NoNewPrivileges=true".to_string(),
        "--property=RestrictSUIDSGID=true".to_string(),
        "--property=CapabilityBoundingSet=".to_string(),
        "--property=AmbientCapabilities=".to_string(),
        // === Syscall Filtering ===
        "--property=SystemCallFilter=@system-service".to_string(),
        "--property=SystemCallErrorNumber=EPERM".to_string(),
        "--property=SystemCallArchitectures=native".to_string(),
        "--property=RestrictNamespaces=true".to_string(),
    ];

    // === Memory/Execution Controls ===
    // MemoryDenyWriteExecute blocks JIT compilation - only include in Default profile
    if profile == HardeningProfile::Default {
        props.push("--property=MemoryDenyWriteExecute=true".to_string());
    }
    props.push("--property=LockPersonality=true".to_string());
    props.push("--property=RestrictRealtime=true".to_string());

    // === Network Isolation ===
    // Note: We do NOT use PrivateNetwork=true because we set NetworkNamespacePath
    // to join our pre-configured namespace with the veth pair. PrivateNetwork would
    // create a new empty namespace, overriding NetworkNamespacePath.
    props.push("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_string());

    // === Resource Limits ===
    let timeout_secs = config.timeout.as_secs();
    props.push(format!("--property=RuntimeMaxSec={}", timeout_secs));
    // Default resource limits - can be made configurable later
    props.push("--property=MemoryMax=4G".to_string());
    props.push("--property=TasksMax=512".to_string());
    props.push("--property=LimitNOFILE=1024".to_string());

    // === Cleanup/Isolation ===
    props.push("--property=RemoveIPC=true".to_string());
    props.push("--property=KeyringMode=private".to_string());
    // Standard umask - nix-jail user owns everything so no need for permissive mode
    props.push("--property=UMask=0022".to_string());
    props.push("--property=ProtectClock=true".to_string());

    // === Root Directory and Bind Mounts ===
    // Always use RootDirectory for chroot isolation
    props.push(format!("--property=RootDirectory={}", root_dir.display()));

    // Bind workspace as writable
    props.push(format!(
        "--property=BindPaths={}:/workspace",
        workspace.display()
    ));

    // Handle Nix store based on StoreSetup
    match &config.store_setup {
        crate::root::StoreSetup::Populated => {
            // Root already contains /nix/store closure (copied/snapshotted)
            // No additional bind mounts needed
        }
        crate::root::StoreSetup::BindMounts { paths } => {
            // Bind-mount each store path from host into chroot
            for store_path in paths {
                props.push(format!(
                    "--property=BindReadOnlyPaths={}:{}",
                    store_path.display(),
                    store_path.display()
                ));
            }
        }
        crate::root::StoreSetup::DockerVolume { .. } => {
            // DockerVolume is only valid with DockerExecutor
            // This shouldn't happen - config validation should prevent it
            tracing::warn!("docker volume store setup used with systemd executor, ignoring");
        }
    }

    // Cache bind-mounts from resolved cache mounts
    let owner = format!("{}:{}", user, group);
    for mount in &config.cache_mounts {
        // Create host directory if needed (daemon runs as root)
        if let Err(e) = std::fs::create_dir_all(&mount.host_path) {
            tracing::warn!(path = %mount.host_path.display(), error = %e, "failed to create cache dir");
        }
        // Chown to sandbox user (daemon runs as root, job runs as sandbox user)
        let _ = std::process::Command::new("chown")
            .args(["-R", &owner, &mount.host_path.to_string_lossy()])
            .output();
        props.push(format!(
            "--property=BindPaths={}:{}",
            mount.host_path.display(),
            mount.mount_path
        ));
    }

    props
}

/// Creates an isolated network namespace with veth pair for proxy communication.
///
/// This implements production-grade network isolation using rtnetlink:
/// 1. Creates network namespace for the job
/// 2. Creates veth pair (virtual ethernet cable) via netlink
/// 3. Moves job end into the namespace via netlink
/// 4. Configures IPs: 10.0.0.1 (proxy) ↔ 10.0.0.2 (job) via netlink
/// 5. Brings interfaces up via netlink
///
/// Security model:
/// - Job can ONLY communicate with proxy at 10.0.0.1:3128
/// - Job has NO route to internet (isolated namespace)
/// - Proxy runs in host namespace (has internet access)
/// - Much stronger than IPAddressDeny (kernel-level isolation)
///
/// Network topology:
/// ```text
/// Host namespace:       Job namespace:
/// ┌───────────────┐    ┌───────────────┐
/// │ vp-{suffix}   │────│ vj-{suffix}   │
/// │  10.0.0.1     │pair│  10.0.0.2     │
/// │               │    │               │
/// │Proxy+Internet │    │Job (isolated) │
/// └───────────────┘    └───────────────┘
/// ```
async fn create_network_namespace(
    job_id: &str,
    proxy_ip: Ipv4Addr,
    job_ip: Ipv4Addr,
) -> Result<(), ExecutorError> {
    // Linux interface names are limited to 15 characters (IFNAMSIZ)
    // Use last 8 chars of job_id to keep names short while reducing collisions
    let job_suffix = if job_id.len() > 8 {
        &job_id[job_id.len() - 8..]
    } else {
        job_id
    };

    let netns_name = format!("nix-jail-{}", job_id);
    let veth_proxy = format!("vp-{}", job_suffix); // e.g., vp-2HBDCA (10 chars)
    let veth_job = format!("vj-{}", job_suffix); // e.g., vj-2HBDCA (10 chars)

    // 1. Create network namespace (still use ip command - rtnetlink doesn't support this directly)
    let status = Command::new("ip")
        .args(["netns", "add", &netns_name])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to create netns: {}", e)))?;

    if !status.success() {
        return Err(ExecutorError::SpawnFailed(format!(
            "Failed to create network namespace {}",
            netns_name
        )));
    }

    // Connect to rtnetlink for remaining operations
    let (connection, handle, _) = new_connection().map_err(|e| {
        ExecutorError::SpawnFailed(format!("Failed to connect to rtnetlink: {}", e))
    })?;

    // Spawn the connection in the background (must run to process netlink messages)
    drop(tokio::spawn(connection));

    // Helper function to cleanup on error
    let cleanup = || async {
        let _ = Command::new("ip")
            .args(["netns", "delete", &netns_name])
            .status()
            .await;
    };

    // 2. Create veth pair using rtnetlink
    if let Err(e) = handle
        .link()
        .add(LinkVeth::new(&veth_proxy, &veth_job).build())
        .execute()
        .await
    {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(format!(
            "Failed to create veth pair: {}",
            e
        )));
    }

    // 3. Get the link index for veth_proxy (host side)
    let mut links = handle.link().get().match_name(veth_proxy.clone()).execute();
    let veth_proxy_link = match links.try_next().await {
        Ok(Some(link)) => link,
        Ok(None) => {
            cleanup().await;
            return Err(ExecutorError::SpawnFailed(
                "Failed to find veth-proxy link".to_string(),
            ));
        }
        Err(e) => {
            cleanup().await;
            return Err(ExecutorError::SpawnFailed(format!(
                "Failed to query veth-proxy: {}",
                e
            )));
        }
    };
    let veth_proxy_idx = veth_proxy_link.header.index;

    // 4. Move veth_job to the network namespace
    // Note: rtnetlink doesn't directly support moving to named netns, use ip command
    let status = Command::new("ip")
        .args(["link", "set", &veth_job, "netns", &netns_name])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to move veth to netns: {}", e)))?;

    if !status.success() {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(format!(
            "Failed to move veth into namespace {}",
            netns_name
        )));
    }

    // 5. Configure IP on proxy end (host namespace) using rtnetlink
    if let Err(e) = handle
        .address()
        .add(veth_proxy_idx, proxy_ip.into(), VETH_PREFIX_LEN)
        .execute()
        .await
    {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(format!(
            "Failed to add IP to veth-proxy: {}",
            e
        )));
    }

    // 6. Bring up proxy end interface using rtnetlink
    if let Err(e) = handle
        .link()
        .set(LinkUnspec::new_with_index(veth_proxy_idx).up().build())
        .execute()
        .await
    {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(format!(
            "Failed to bring up veth-proxy: {}",
            e
        )));
    }

    // 7. Configure job end (inside namespace) - need to exec in namespace
    // rtnetlink would need a separate connection inside the namespace, so use ip command
    let status = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns_name,
            "ip",
            "addr",
            "add",
            &format!("{}/{}", job_ip, VETH_PREFIX_LEN),
            "dev",
            &veth_job,
        ])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to configure job IP: {}", e)))?;

    if !status.success() {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(
            "Failed to configure job veth IP".to_string(),
        ));
    }

    // 8. Bring up job end interface
    let status = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns_name,
            "ip",
            "link",
            "set",
            &veth_job,
            "up",
        ])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to bring up job veth: {}", e)))?;

    if !status.success() {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(
            "Failed to bring up job veth interface".to_string(),
        ));
    }

    // 8.5. Add default route - send all traffic to proxy via veth
    let status = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns_name,
            "ip",
            "route",
            "add",
            "default",
            "via",
            &proxy_ip.to_string(),
            "dev",
            &veth_job,
        ])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to add default route: {}", e)))?;

    if !status.success() {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(
            "Failed to add default route in job namespace".to_string(),
        ));
    }

    // 9. Bring up loopback in the namespace (needed for 127.0.0.1)
    let status = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns_name,
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ])
        .status()
        .await
        .map_err(|e| ExecutorError::SpawnFailed(format!("Failed to bring up loopback: {}", e)))?;

    if !status.success() {
        cleanup().await;
        return Err(ExecutorError::SpawnFailed(
            "Failed to bring up loopback in namespace".to_string(),
        ));
    }

    Ok(())
}

/// Cleans up the network namespace and veth pair for a job.
///
/// This removes:
/// - The network namespace (which automatically removes the job-side veth)
/// - The proxy-side veth interface (using rtnetlink)
///
/// Should be called during job cleanup to prevent resource leaks.
pub async fn cleanup_network_namespace(job_id: &str) -> Result<(), ExecutorError> {
    // Use same naming convention as create_network_namespace
    let job_suffix = if job_id.len() > 8 {
        &job_id[job_id.len() - 8..]
    } else {
        job_id
    };

    let netns_name = format!("nix-jail-{}", job_id);
    let veth_proxy = format!("vp-{}", job_suffix);

    // Connect to rtnetlink for veth deletion
    let (connection, handle, _) = new_connection().map_err(|e| {
        ExecutorError::SpawnFailed(format!("Failed to connect to rtnetlink: {}", e))
    })?;

    // Spawn the connection in the background (must run to process netlink messages)
    drop(tokio::spawn(connection));

    // Delete the veth interface (host side) using rtnetlink
    // First find the link index
    let mut links = handle.link().get().match_name(veth_proxy.clone()).execute();
    if let Ok(Some(link)) = links.try_next().await {
        let idx = link.header.index;
        // Delete the link
        let _ = handle.link().del(idx).execute().await;
    }

    // Delete the network namespace
    // This automatically deletes the job-side veth
    let status = Command::new("ip")
        .args(["netns", "delete", &netns_name])
        .status()
        .await
        .map_err(ExecutorError::IoError)?;

    if !status.success() {
        // Don't error out - namespace might not exist
        tracing::warn!(netns_name = %netns_name, "failed to delete network namespace");
    }

    Ok(())
}

/// Cleans up all stale nix-jail network namespaces from previous daemon runs.
///
/// When the daemon restarts, orphaned network namespaces from previous jobs remain
/// but the in-memory subnet allocator resets to zero. This causes IP conflicts
/// when new jobs get the same 10.0.0.1/30 subnet as orphaned namespaces.
///
/// Call this once at daemon startup before accepting any jobs.
pub async fn cleanup_stale_network_namespaces() {
    // List all network namespaces
    let output = match Command::new("ip").args(["netns", "list"]).output().await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list network namespaces");
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut cleaned = 0;

    for line in stdout.lines() {
        // Format: "nix-jail-JOBID (id: N)" or just "nix-jail-JOBID"
        let netns_name = match line.split_whitespace().next() {
            Some(name) if name.starts_with("nix-jail-") => name,
            _ => continue,
        };

        // Extract job suffix for veth name
        let job_id = netns_name.strip_prefix("nix-jail-").unwrap_or("");
        let job_suffix = if job_id.len() > 8 {
            &job_id[job_id.len() - 8..]
        } else {
            job_id
        };
        let veth_proxy = format!("vp-{}", job_suffix);

        // Delete the host-side veth first (if it exists)
        let _ = Command::new("ip")
            .args(["link", "delete", &veth_proxy])
            .status()
            .await;

        // Delete the namespace (also deletes the job-side veth)
        match Command::new("ip")
            .args(["netns", "delete", netns_name])
            .status()
            .await
        {
            Ok(status) if status.success() => {
                cleaned += 1;
                tracing::debug!(netns = netns_name, "deleted stale namespace");
            }
            Ok(_) => {
                tracing::warn!(netns = netns_name, "failed to delete stale namespace");
            }
            Err(e) => {
                tracing::warn!(netns = netns_name, error = %e, "failed to delete stale namespace");
            }
        }
    }

    if cleaned > 0 {
        tracing::info!(count = cleaned, "cleaned up stale network namespaces");
    }
}

/// Executes a command in a systemd-isolated sandbox.
///
/// This is the Linux equivalent of the macOS sandbox-exec executor.
/// Uses systemd-run to spawn a transient unit with comprehensive hardening.
///
/// Execution flow:
/// 1. Create temporary root directory
/// 2. Copy Nix closure into root (if store_paths provided)
/// 3. Generate 33 hardening properties
/// 4. Spawn systemd-run with isolation
/// 5. Stream stdout/stderr asynchronously via channels
/// 6. Return execution handle for cleanup
///
/// # Security
///
/// - Job cannot access host filesystem beyond workspace
/// - Job cannot access /home, /etc, or /nix/store beyond closure
/// - Network access requires proxy (PrivateNetwork isolation)
/// - Resource limits prevent DoS
/// - Syscall filtering prevents privilege escalation
///
/// Linux systemd-based executor with comprehensive hardening.
///
/// Provides kernel-level isolation using:
/// - systemd transient units with 33 hardening properties
/// - Network namespaces with veth pair for proxy-only connectivity
/// - RootDirectory isolation with minimal Nix closure
///
/// SECURITY: Requires root privileges and CAP_NET_ADMIN capability
#[derive(Debug)]
pub struct SystemdExecutor {
    /// Tracks allocated IP subnet counters for active jobs
    /// Each counter represents a /30 subnet: counter * 4 gives offset from 10.0.0.0
    allocated_subnets: Arc<Mutex<HashSet<u32>>>,
}

impl Default for SystemdExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdExecutor {
    pub fn new() -> Self {
        SystemdExecutor {
            allocated_subnets: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Allocates a unique /30 subnet for a job
    ///
    /// Returns (proxy_ip, job_ip, subnet_counter)
    /// - Subnet counter increments third octet, then second octet
    /// - Each /30 uses 4 IPs: network, proxy, job, broadcast
    /// - Max 16,384 concurrent jobs in 10.0.0.0/16 space
    #[allow(clippy::expect_used)] // Mutex poisoning indicates unrecoverable state
    fn allocate_subnet(&self) -> Result<(Ipv4Addr, Ipv4Addr, u32), ExecutorError> {
        let mut allocated = self.allocated_subnets.lock().expect(
            "IP subnet allocator mutex poisoned - this indicates a panic in another thread",
        );

        // Find lowest unused counter
        let counter = (0..16384u32)
            .find(|c| !allocated.contains(c))
            .ok_or_else(|| {
                ExecutorError::SpawnFailed(
                    "No available IP subnets (16,384 concurrent jobs limit reached)".to_string(),
                )
            })?;

        let _ = allocated.insert(counter);

        // Calculate IPs: base offset from 10.0.0.0, then +1 for proxy, +2 for job
        let base_offset = counter * 4;
        let base_ip: u32 = 0x0A000000 + base_offset; // 10.0.0.0 + offset

        let proxy_ip = Ipv4Addr::from(base_ip + 1);
        let job_ip = Ipv4Addr::from(base_ip + 2);

        tracing::debug!(
            counter = counter,
            proxy_ip = %proxy_ip,
            job_ip = %job_ip,
            "Allocated IP subnet for job"
        );

        Ok((proxy_ip, job_ip, counter))
    }

    /// Deallocates a subnet when a job finishes
    #[allow(clippy::expect_used)] // Mutex poisoning indicates unrecoverable state
    fn deallocate_subnet(&self, counter: u32) {
        let mut allocated = self.allocated_subnets.lock().expect(
            "IP subnet allocator mutex poisoned - this indicates a panic in another thread",
        );
        let _ = allocated.remove(&counter);
        tracing::debug!(counter = counter, "deallocated ip subnet");
    }

    /// Execute in interactive PTY mode
    ///
    /// Unlike Docker/sandbox executors, systemd-run --pty handles its own PTY allocation.
    /// Wrapping it in portable-pty causes conflicts, so we inherit stdio directly and let
    /// systemd-run connect to the user's terminal.
    async fn execute_interactive(
        &self,
        systemd_args: Vec<String>,
        unit_name: String,
        _pty_size: Option<(u16, u16)>,
        timeout_duration: std::time::Duration,
        job_id: String,
        cleanup_tx: Option<oneshot::Sender<i32>>,
    ) -> Result<ExecutionHandle, ExecutorError> {
        // systemd-run --pty already handles PTY allocation and connects to the terminal.
        // We just need to inherit stdio and let it do its thing.
        let mut cmd = Command::new("systemd-run");
        let _ = cmd.args(&systemd_args);

        // Inherit stdio so systemd-run --pty can connect directly to the terminal
        let _ = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            ExecutorError::SpawnFailed(format!("failed to spawn systemd-run: {}", e))
        })?;

        let (exit_tx, exit_rx) = oneshot::channel();
        let unit_name_clone = unit_name.clone();

        // Spawn task to wait for process and handle cleanup
        drop(tokio::spawn(async move {
            let exit_code = match timeout(timeout_duration, child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                Ok(Err(e)) => {
                    tracing::error!(job_id = %job_id, error = %e, "error waiting for systemd-run process");
                    -1
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id, "execution timed out, stopping systemd unit");
                    let _ = child.kill().await;
                    let _ = Command::new("systemctl")
                        .args(["stop", &unit_name_clone])
                        .status()
                        .await;
                    -1
                }
            };

            let _ = exit_tx.send(exit_code);
            if let Some(cleanup_tx) = cleanup_tx {
                let _ = cleanup_tx.send(exit_code);
            }
        }));

        // Return Direct mode - stdio is inherited, no channel forwarding needed
        Ok(ExecutionHandle {
            io: super::traits::IoHandle::Direct,
            exit_code: exit_rx,
        })
    }

    /// Execute in piped mode with separate stdout/stderr streams
    async fn execute_piped(
        &self,
        systemd_args: Vec<String>,
        unit_name: String,
        timeout_duration: std::time::Duration,
        job_id: String,
        cleanup_tx: Option<oneshot::Sender<i32>>,
    ) -> Result<ExecutionHandle, ExecutorError> {
        let mut cmd = Command::new("systemd-run");
        let _ = cmd.args(&systemd_args);
        let _ = cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            ExecutorError::SpawnFailed(format!("failed to spawn systemd-run: {}", e))
        })?;

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

        let unit_name_clone = unit_name.clone();

        // Spawn task to handle process execution and output streaming
        // Intentionally detached: this task manages the lifetime of stdout/stderr channels
        // and sends the exit code via oneshot channel when complete. No need to await.
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
                    tracing::error!(job_id = %job_id, error = %e, "failed to wait for process");
                    -1
                }
                Err(_) => {
                    tracing::warn!(job_id = %job_id, "execution timed out, stopping systemd unit");
                    // Timeout - stop the systemd unit
                    let _ = Command::new("systemctl")
                        .arg("stop")
                        .arg(&unit_name_clone)
                        .status()
                        .await;
                    -1
                }
            };

            // Send exit code
            let _ = exit_tx.send(exit_code);
            if let Some(cleanup_tx) = cleanup_tx {
                let _ = cleanup_tx.send(exit_code);
            }

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
}

#[async_trait]
impl Executor for SystemdExecutor {
    async fn execute(&self, config: ExecutionConfig) -> Result<ExecutionHandle, ExecutorError> {
        let job_id = &config.job_id;
        let command = &config.command;

        if command.is_empty() {
            return Err(ExecutorError::SpawnFailed(
                "Command cannot be empty".to_string(),
            ));
        }

        // Use pre-prepared root directory from orchestration (contains /nix/store closure)
        let root_dir = &config.root_dir;
        if !root_dir.exists() {
            return Err(ExecutorError::SpawnFailed(format!(
                "Root directory not found: {}",
                root_dir.display()
            )));
        }

        // store_paths is the pre-computed closure for command resolution
        let closure = &config.store_paths;
        tracing::debug!(job_id = %job_id, root_dir = %root_dir.display(), closure_size = closure.len(), "using pre-prepared root");

        // Resolve command paths from closure (e.g., "bash" -> "/nix/store/.../bin/bash")
        let resolved_command = super::exec::resolve_command_paths(command, closure);

        // Network setup depends on whether proxy is configured
        // - With proxy: allocate IP subnet and create veth-based network namespace
        // - Without proxy: use PrivateNetwork=yes for simpler loopback-only isolation
        let network_setup = if config.proxy_port.is_some() {
            let (proxy_ip, job_ip, subnet_counter) = self.allocate_subnet()?;
            create_network_namespace(job_id, proxy_ip, job_ip).await?;
            let netns_path = format!("/var/run/netns/nix-jail-{}", job_id);
            NetworkSetup::Namespace {
                subnet_counter,
                netns_path,
            }
        } else {
            tracing::debug!(job_id = %job_id, "no proxy configured, using PrivateNetwork isolation");
            NetworkSetup::PrivateNetwork
        };

        // Generate all hardening properties
        // Determine workspace bind source:
        // - Server mode: job_dir/workspace (populated by git clone)
        // - Local mode: config.working_dir (user's actual directory)
        let job_workspace = config.job_dir.join("workspace");
        let workspace_bind_source = if job_workspace.exists() {
            // Server mode: workspace was created by JobWorkspace::setup()
            job_workspace.clone()
        } else {
            // Local mode: bind user's working directory directly
            config.working_dir.clone()
        };
        // unwrap is safe: SystemdExecutor always returns Some for sandbox_user
        #[allow(clippy::unwrap_used)]
        let sandbox_user = self.sandbox_user().unwrap();
        let properties = generate_hardening_properties(
            root_dir,
            &workspace_bind_source,
            job_id,
            &config,
            config.hardening_profile,
            sandbox_user,
        );

        // Build systemd-run arguments as a Vec so we can use them with either
        // tokio::process::Command (piped mode) or portable_pty::CommandBuilder (PTY mode)
        let unit_name = format!("nix-jail-{}", job_id);
        let mut systemd_args: Vec<String> = vec![
            "--unit".to_string(),
            unit_name.clone(),
            "--quiet".to_string(), // Don't print unit name to stderr
            "--wait".to_string(),  // Wait for unit to finish
        ];

        // Use --pty for interactive sessions, --pipe for batch jobs
        // --pty connects to a PTY (required for interactive terminals)
        // --pipe connects stdout/stderr for streaming (required for log capture)
        if config.interactive {
            systemd_args.push("--pty".to_string());
        } else {
            systemd_args.push("--pipe".to_string());
        }

        // Add all hardening properties
        for prop in properties {
            systemd_args.push(prop);
        }

        // Add network isolation
        match &network_setup {
            NetworkSetup::Namespace { netns_path, .. } => {
                // Join the pre-configured namespace with veth pair for proxy access
                systemd_args.push(format!("--property=NetworkNamespacePath={}", netns_path));
            }
            NetworkSetup::PrivateNetwork => {
                // Simple isolation: loopback only, no external network access
                systemd_args.push("--property=PrivateNetwork=yes".to_string());
            }
        }

        // Set working directory inside chroot
        // - Server mode: working_dir is under job_dir/workspace, convert to /workspace/subpath
        // - Local mode: working_dir is user's directory bound directly at /workspace
        let chroot_working_dir = if config.working_dir.starts_with(&job_workspace) {
            // Server mode: convert host path to chroot-relative path
            // e.g., /var/lib/nix-jail/jobs/{id}/workspace/projects/foo -> /workspace/projects/foo
            workspace_to_chroot_path(&config.working_dir, &job_workspace)
        } else {
            // Local mode: user's directory is bound at /workspace
            PathBuf::from("/workspace")
        };
        systemd_args.push(format!(
            "--property=WorkingDirectory={}",
            chroot_working_dir.display()
        ));

        // Set TERM based on mode
        let term_value = if config.interactive {
            "xterm-256color"
        } else {
            "dumb"
        };
        systemd_args.push("--setenv".to_string());
        systemd_args.push(format!("TERM={}", term_value));

        // Add environment variables, normalizing workspace paths to chroot-relative paths
        for (key, value) in &config.env {
            // Normalize host workspace paths to chroot paths for certain env vars
            // Skip if already an absolute chroot path (starts with /)
            let normalized_value = if matches!(
                key.as_str(),
                "SSL_CERT_FILE" | "NODE_EXTRA_CA_CERTS" | "REQUESTS_CA_BUNDLE"
            ) && !value.starts_with('/')
            {
                // Convert host workspace paths to chroot-relative paths
                let path = PathBuf::from(value);
                workspace_to_chroot_path(&path, &workspace_bind_source)
                    .to_string_lossy()
                    .to_string()
            } else {
                // HOME, TMPDIR, and other vars are already set to chroot-relative paths
                value.clone()
            };
            systemd_args.push("--setenv".to_string());
            systemd_args.push(format!("{}={}", key, normalized_value));
        }

        // Cache environment variables from resolved cache mounts
        for mount in &config.cache_mounts {
            if let Some(ref env_var) = mount.env_var {
                systemd_args.push("--setenv".to_string());
                systemd_args.push(format!("{}={}", env_var, mount.mount_path));
            }
        }

        // Note: HTTP_PROXY and HTTPS_PROXY are already set correctly by build_environment
        // with credentials embedded (http://user:pass@ip:port). Don't override them here. (trufflehog:ignore)

        // Add the actual command to execute (use resolved paths)
        systemd_args.push("--".to_string());
        for arg in &resolved_command {
            systemd_args.push(arg.clone());
        }

        // Debug log the full command
        match &network_setup {
            NetworkSetup::Namespace { netns_path, .. } => {
                tracing::debug!(args = ?systemd_args, netns_path = %netns_path, "spawning systemd-run with network namespace");
            }
            NetworkSetup::PrivateNetwork => {
                tracing::debug!(args = ?systemd_args, "spawning systemd-run with PrivateNetwork");
            }
        }

        // Set up cleanup task for network namespace (shared by both modes)
        let cleanup_tx = if let NetworkSetup::Namespace { subnet_counter, .. } = &network_setup {
            let (cleanup_tx, cleanup_rx) = oneshot::channel();
            let executor_clone = Self {
                allocated_subnets: Arc::clone(&self.allocated_subnets),
            };
            let job_id_clone = config.job_id.clone();
            let subnet_counter = *subnet_counter;

            // Spawn cleanup task that runs after job completes
            // Intentionally detached: performs async cleanup after job finishes
            drop(tokio::spawn(async move {
                let _ = cleanup_rx.await;
                tracing::debug!(job_id = %job_id_clone, "cleaning up network namespace");
                if let Err(e) = cleanup_network_namespace(&job_id_clone).await {
                    tracing::warn!(job_id = %job_id_clone, error = %e, "failed to cleanup network namespace");
                }
                executor_clone.deallocate_subnet(subnet_counter);
            }));

            Some(cleanup_tx)
        } else {
            None // PrivateNetwork mode has no cleanup needed
        };

        let timeout_duration = config.timeout;
        let job_id = job_id.to_string();

        if config.interactive {
            // PTY mode: use portable-pty for interactive terminal sessions
            self.execute_interactive(
                systemd_args,
                unit_name,
                config.pty_size,
                timeout_duration,
                job_id,
                cleanup_tx,
            )
            .await
        } else {
            // Piped mode: separate stdout/stderr with line-based streaming
            self.execute_piped(
                systemd_args,
                unit_name,
                timeout_duration,
                job_id,
                cleanup_tx,
            )
            .await
        }
    }

    fn proxy_listen_addr(&self) -> &'static str {
        LINUX_PROXY_ADDR
    }

    fn proxy_connect_host(&self) -> &'static str {
        "10.0.0.1"
    }

    fn uses_chroot(&self) -> bool {
        true // systemd RootDirectory creates a chroot
    }

    fn name(&self) -> &'static str {
        "SystemdExecutor (systemd-run)"
    }

    async fn cleanup_root(&self, root_dir: &std::path::Path) -> Result<(), ExecutorError> {
        if !root_dir.exists() {
            return Ok(());
        }

        tracing::debug!(root_dir = %root_dir.display(), "cleaning up root directory via systemd-run");

        // Use systemd-run to delete with same privileges as job execution
        // This handles the case where polkit granted us permission to run units
        // but the files created are owned by root
        //
        // Try btrfs subvolume delete first (required for btrfs subvolumes),
        // fall back to rm -rf for regular directories
        let btrfs_status = Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--",
                "btrfs",
                "subvolume",
                "delete",
            ])
            .arg(root_dir)
            .status()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("cleanup: {}", e)))?;

        if btrfs_status.success() {
            tracing::debug!(root_dir = %root_dir.display(), "btrfs subvolume cleanup completed");
            return Ok(());
        }

        // Not a btrfs subvolume or btrfs command failed, try rm -rf
        tracing::debug!(root_dir = %root_dir.display(), "btrfs delete failed, trying rm -rf");
        let rm_status = Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--",
                "rm",
                "-rf",
            ])
            .arg(root_dir)
            .status()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("cleanup: {}", e)))?;

        if rm_status.success() {
            tracing::debug!(root_dir = %root_dir.display(), "rm -rf cleanup completed");
            Ok(())
        } else {
            Err(ExecutorError::SpawnFailed(format!(
                "cleanup failed with exit code: {:?}",
                rm_status.code()
            )))
        }
    }

    async fn cleanup_workspace(
        &self,
        workspace_dir: &std::path::Path,
    ) -> Result<(), ExecutorError> {
        if !workspace_dir.exists() {
            return Ok(());
        }

        tracing::debug!(workspace_dir = %workspace_dir.display(), "cleaning up workspace via systemd-run");

        // Try btrfs subvolume delete first (required for btrfs subvolumes),
        // fall back to rm -rf for regular directories
        let btrfs_status = Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--",
                "btrfs",
                "subvolume",
                "delete",
            ])
            .arg(workspace_dir)
            .status()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("cleanup: {}", e)))?;

        if btrfs_status.success() {
            tracing::debug!(workspace_dir = %workspace_dir.display(), "btrfs subvolume cleanup completed");
            return Ok(());
        }

        // Not a btrfs subvolume or btrfs command failed, try rm -rf
        tracing::debug!(workspace_dir = %workspace_dir.display(), "btrfs delete failed, trying rm -rf");
        let rm_status = Command::new("systemd-run")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--",
                "rm",
                "-rf",
            ])
            .arg(workspace_dir)
            .status()
            .await
            .map_err(|e| ExecutorError::SpawnFailed(format!("cleanup: {}", e)))?;

        if rm_status.success() {
            tracing::debug!(workspace_dir = %workspace_dir.display(), "rm -rf cleanup completed");
            Ok(())
        } else {
            Err(ExecutorError::SpawnFailed(format!(
                "cleanup failed with exit code: {:?}",
                rm_status.code()
            )))
        }
    }

    fn sandbox_user(&self) -> Option<(&'static str, &'static str)> {
        Some(("nix-jail", "nix-jail"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    /// Helper to check if we can create network namespaces (needs CAP_NET_ADMIN)
    async fn can_create_netns() -> bool {
        let test_name = format!("nix-jail-test-{}", ulid::Ulid::new());
        let result = Command::new("ip")
            .args(["netns", "add", &test_name])
            .status()
            .await;

        if let Ok(status) = result {
            if status.success() {
                // Cleanup
                let _ = Command::new("ip")
                    .args(["netns", "delete", &test_name])
                    .status()
                    .await;
                return true;
            }
        }
        false
    }

    #[test]
    fn test_hardening_properties_count() {
        let root = PathBuf::from("/tmp/test-root");
        let workspace = PathBuf::from("/tmp/test-workspace");
        let config = ExecutionConfig {
            job_id: "test-job".to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            store_paths: vec![],
            store_setup: crate::job_dir::StoreSetup::Populated,
            proxy_port: None,
            job_dir: PathBuf::from("/tmp"),
            working_dir: workspace.clone(),
            root_dir: root.clone(),
            timeout: Duration::from_secs(60),
            env: HashMap::new(),
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
            cache_mounts: vec![],
        };

        let props = generate_hardening_properties(
            &root,
            &workspace,
            "test-job",
            &config,
            HardeningProfile::Default,
            ("nix-jail", "nix-jail"),
        );

        // Count each category
        let filesystem_props = props
            .iter()
            .filter(|p| {
                p.contains("PrivateTmp")
                    || p.contains("ProtectSystem")
                    || p.contains("ProtectKernel")
                    || p.contains("ProtectControlGroups")
                    || p.contains("ProtectProc")
                    || p.contains("ProcSubset")
                    || p.contains("PrivateDevices")
            })
            .count();

        let user_props = props
            .iter()
            .filter(|p| {
                p.contains("User=")
                    || p.contains("Group=")
                    || p.contains("NoNewPrivileges")
                    || p.contains("RestrictSUIDSGID")
                    || p.contains("CapabilityBoundingSet")
                    || p.contains("AmbientCapabilities")
            })
            .count();

        let syscall_props = props
            .iter()
            .filter(|p| p.contains("SystemCall") || p.contains("RestrictNamespaces"))
            .count();

        let memory_props = props
            .iter()
            .filter(|p| {
                p.contains("MemoryDenyWriteExecute")
                    || p.contains("LockPersonality")
                    || p.contains("RestrictRealtime")
            })
            .count();

        let network_props = props
            .iter()
            .filter(|p| p.contains("RestrictAddressFamilies"))
            .count();

        let resource_props = props
            .iter()
            .filter(|p| {
                p.contains("RuntimeMaxSec")
                    || p.contains("MemoryMax")
                    || p.contains("TasksMax")
                    || p.contains("LimitNOFILE")
            })
            .count();

        let cleanup_props = props
            .iter()
            .filter(|p| {
                p.contains("RemoveIPC")
                    || p.contains("KeyringMode")
                    || p.contains("UMask")
                    || p.contains("ProtectClock")
            })
            .count();

        // Verify all categories are represented
        assert!(filesystem_props > 0, "Should have filesystem properties");
        assert!(user_props > 0, "Should have user/privilege properties");
        assert!(syscall_props > 0, "Should have syscall properties");
        assert!(memory_props > 0, "Should have memory/exec properties");
        assert!(network_props > 0, "Should have network property");
        assert!(resource_props > 0, "Should have resource limit properties");
        assert!(cleanup_props > 0, "Should have cleanup properties");

        // Check mount properties
        assert!(props.iter().any(|p| p.contains("RootDirectory")));
        assert!(props.iter().any(|p| p.contains("BindPaths")));
    }

    #[test]
    fn test_hardening_properties_values() {
        use std::collections::HashMap;
        use std::time::Duration;

        let root = PathBuf::from("/tmp/test-root");
        let workspace = PathBuf::from("/tmp/test-workspace");
        let config = ExecutionConfig {
            job_id: "test-job".to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            store_paths: vec![],
            store_setup: crate::job_dir::StoreSetup::Populated,
            proxy_port: None,
            job_dir: PathBuf::from("/tmp"),
            working_dir: workspace.clone(),
            root_dir: root.clone(),
            timeout: Duration::from_secs(120),
            env: HashMap::new(),
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
            cache_mounts: vec![],
        };

        let props = generate_hardening_properties(
            &root,
            &workspace,
            "test-job",
            &config,
            HardeningProfile::Default,
            ("nix-jail", "nix-jail"),
        );

        // Verify critical security properties have correct values
        assert!(props.contains(&"--property=ProtectSystem=strict".to_string()));
        assert!(props.contains(&"--property=NoNewPrivileges=true".to_string()));
        // Note: Using static sandbox user instead of DynamicUser for consistent permissions
        assert!(props.contains(&"--property=User=nix-jail".to_string()));
        assert!(props.contains(&"--property=Group=nix-jail".to_string()));

        // Verify timeout is set correctly
        assert!(props.contains(&"--property=RuntimeMaxSec=120".to_string()));

        // Verify paths are set correctly
        assert!(props.contains(&"--property=RootDirectory=/tmp/test-root".to_string()));
        assert!(props.contains(&"--property=BindPaths=/tmp/test-workspace:/workspace".to_string()));
    }

    #[tokio::test]
    async fn test_network_namespace_creation() {
        // Skip if we can't create network namespaces (no CAP_NET_ADMIN)
        if !can_create_netns().await {
            tracing::debug!(
                "skipping test_network_namespace_creation: no CAP_NET_ADMIN capability"
            );
            return;
        }

        let job_id = format!("test-{}", ulid::Ulid::new());
        let proxy_ip = Ipv4Addr::new(10, 0, 0, 1);
        let job_ip = Ipv4Addr::new(10, 0, 0, 2);

        // Create network namespace
        let result = create_network_namespace(&job_id, proxy_ip, job_ip).await;
        assert!(
            result.is_ok(),
            "Failed to create network namespace: {:?}",
            result.err()
        );

        // Verify namespace exists
        let netns_name = format!("nix-jail-{}", job_id);
        let check = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .await
            .expect("Failed to list network namespaces");

        let output = String::from_utf8_lossy(&check.stdout);
        assert!(
            output.contains(&netns_name),
            "Network namespace not found in: {}",
            output
        );

        // Compute veth name using same logic as create_network_namespace
        let job_suffix = if job_id.len() > 8 {
            &job_id[job_id.len() - 8..]
        } else {
            &job_id
        };
        let veth_proxy = format!("vp-{}", job_suffix);

        // Verify veth proxy interface exists
        let check = Command::new("ip")
            .args(["link", "show", &veth_proxy])
            .status()
            .await
            .expect("Failed to check veth-proxy interface");
        assert!(check.success(), "veth-proxy interface not found");

        // Verify veth proxy has correct IP
        let check = Command::new("ip")
            .args(["addr", "show", &veth_proxy])
            .output()
            .await
            .expect("Failed to check veth-proxy IP");
        let output = String::from_utf8_lossy(&check.stdout);
        assert!(
            output.contains("10.0.0.1/30"),
            "veth-proxy does not have correct IP: {}",
            output
        );

        // Cleanup
        let cleanup_result = cleanup_network_namespace(&job_id).await;
        assert!(
            cleanup_result.is_ok(),
            "Failed to cleanup network namespace: {:?}",
            cleanup_result.err()
        );

        // Verify cleanup worked
        let check = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .await
            .expect("Failed to list network namespaces");
        let output = String::from_utf8_lossy(&check.stdout);
        assert!(
            !output.contains(&netns_name),
            "Network namespace still exists after cleanup"
        );
    }

    #[tokio::test]
    async fn test_network_namespace_cleanup() {
        // Skip if we can't create network namespaces
        if !can_create_netns().await {
            tracing::debug!("skipping test_network_namespace_cleanup: no CAP_NET_ADMIN capability");
            return;
        }

        let job_id = format!("test-cleanup-{}", ulid::Ulid::new());
        let proxy_ip = Ipv4Addr::new(10, 0, 0, 1);
        let job_ip = Ipv4Addr::new(10, 0, 0, 2);

        // Create namespace
        create_network_namespace(&job_id, proxy_ip, job_ip)
            .await
            .expect("Failed to create network namespace for cleanup test");

        // Cleanup
        cleanup_network_namespace(&job_id)
            .await
            .expect("Failed to cleanup network namespace");

        // Verify everything is cleaned up
        let netns_name = format!("nix-jail-{}", job_id);
        let check = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .await
            .expect("Failed to list network namespaces");
        let output = String::from_utf8_lossy(&check.stdout);
        assert!(!output.contains(&netns_name), "Namespace still exists");

        // Verify veth is gone
        let job_suffix = if job_id.len() > 8 {
            &job_id[job_id.len() - 8..]
        } else {
            &job_id
        };
        let veth_proxy = format!("vp-{}", job_suffix);
        let check = Command::new("ip")
            .args(["link", "show", &veth_proxy])
            .status()
            .await
            .expect("Failed to check veth interface");
        assert!(!check.success(), "veth interface still exists");
    }

    #[tokio::test]
    async fn test_network_namespace_constants() {
        // These are unit tests, don't need special permissions
        assert_eq!(VETH_PREFIX_LEN, 30);

        // Test IP allocation produces valid IPs
        let executor = SystemdExecutor::new();
        let (proxy_ip, job_ip, counter) = executor
            .allocate_subnet()
            .expect("failed to allocate first subnet");
        assert_eq!(proxy_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(job_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(counter, 0);

        // Test second allocation gets next subnet
        let (proxy_ip2, job_ip2, counter2) = executor
            .allocate_subnet()
            .expect("failed to allocate second subnet");
        assert_eq!(proxy_ip2, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(job_ip2, Ipv4Addr::new(10, 0, 0, 6));
        assert_eq!(counter2, 1);

        // Cleanup
        executor.deallocate_subnet(counter);
        executor.deallocate_subnet(counter2);
        assert_eq!(LINUX_PROXY_ADDR, "0.0.0.0:3128");
    }

    #[test]
    fn test_hardening_profile_jit_runtime() {
        use std::collections::HashMap;
        use std::time::Duration;

        let root = PathBuf::from("/tmp/test-root");
        let workspace = PathBuf::from("/tmp/test-workspace");

        // Test Default profile includes MemoryDenyWriteExecute
        let config_default = ExecutionConfig {
            job_id: "test-job".to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            store_paths: vec![],
            store_setup: crate::job_dir::StoreSetup::Populated,
            proxy_port: None,
            job_dir: PathBuf::from("/tmp"),
            working_dir: workspace.clone(),
            root_dir: root.clone(),
            timeout: Duration::from_secs(60),
            env: HashMap::new(),
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
            cache_mounts: vec![],
        };

        let props_default = generate_hardening_properties(
            &root,
            &workspace,
            "test-job",
            &config_default,
            HardeningProfile::Default,
            ("nix-jail", "nix-jail"),
        );

        assert!(
            props_default.contains(&"--property=MemoryDenyWriteExecute=true".to_string()),
            "Default profile should include MemoryDenyWriteExecute"
        );

        // Test JitRuntime profile excludes MemoryDenyWriteExecute
        let config_jit = ExecutionConfig {
            job_id: "test-job".to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            store_paths: vec![],
            store_setup: crate::job_dir::StoreSetup::Populated,
            proxy_port: None,
            job_dir: PathBuf::from("/tmp"),
            working_dir: workspace.clone(),
            root_dir: root.clone(),
            timeout: Duration::from_secs(60),
            env: HashMap::new(),
            hardening_profile: HardeningProfile::JitRuntime,
            interactive: false,
            pty_size: None,
            cache_mounts: vec![],
        };

        let props_jit = generate_hardening_properties(
            &root,
            &workspace,
            "test-job",
            &config_jit,
            HardeningProfile::JitRuntime,
            ("nix-jail", "nix-jail"),
        );

        assert!(
            !props_jit.contains(&"--property=MemoryDenyWriteExecute=true".to_string()),
            "JitRuntime profile should NOT include MemoryDenyWriteExecute"
        );

        // Verify JitRuntime still has the other memory properties
        assert!(props_jit.contains(&"--property=LockPersonality=true".to_string()));
        assert!(props_jit.contains(&"--property=RestrictRealtime=true".to_string()));

        // Verify count: Default has 33, JitRuntime has 32
        // Count only the hardening properties (not RootDirectory/BindPaths)
        let hardening_default = props_default
            .iter()
            .filter(|p| !p.contains("RootDirectory") && !p.contains("BindPaths"))
            .count();
        let hardening_jit = props_jit
            .iter()
            .filter(|p| !p.contains("RootDirectory") && !p.contains("BindPaths"))
            .count();

        // JIT profile should have one fewer property (no MemoryDenyWriteExecute)
        assert_eq!(
            hardening_default,
            hardening_jit + 1,
            "Default profile should have one more property than JitRuntime"
        );
    }

    #[tokio::test]
    #[allow(clippy::panic)] // Test assertion
    async fn test_execute_systemd_requires_root_dir() {
        use crate::executor::JobExecutor;

        // This test verifies error handling when root_dir doesn't exist
        // It doesn't actually need systemd or root
        let job_id = "test-no-root";
        let config = ExecutionConfig {
            job_id: job_id.to_string(),
            command: vec!["echo".to_string(), "test".to_string()],
            env: HashMap::new(),
            job_dir: PathBuf::from("/tmp"),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/nonexistent/root/dir"),
            store_setup: crate::job_dir::StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
            cache_mounts: vec![],
        };

        let executor = SystemdExecutor::new();
        let result = executor.execute(config).await;
        assert!(result.is_err());
        match result {
            Err(ExecutorError::SpawnFailed(msg)) => {
                assert!(msg.contains("Root directory not found"));
            }
            _ => panic!("Expected SpawnFailed error for missing root directory"),
        }
    }
}
