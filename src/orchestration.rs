//! Job orchestration and execution coordination
//!
//! This module handles the complex orchestration of:
//! - Workspace preparation
//! - Proxy management
//! - Job execution
//! - Log streaming

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, mpsc};
use tonic::Status;
use tracing::Instrument;

use crate::config::{Credential, CredentialType};
use crate::executor::{ExecutionConfig, Executor, HardeningProfile};
use crate::jail::{LogEntry, LogSource, NetworkPolicy};
use crate::job_dir::JobDirectory;
use crate::job_workspace::JobWorkspace;
use crate::log_sink::{LogSink, StorageLogSink};
use crate::proxy_manager::ProxyManager;
use crate::root::JobRoot;
use crate::storage::{JobMetadata, JobStatus, JobStorage, LogEntry as StorageLogEntry};
use crate::streaming;
use crate::workspace;

/// Error type for orchestration failures
#[derive(Debug, thiserror::Error)]
pub enum OrchestrationError {
    #[error("failed to resolve state directory: {0}")]
    StateDirError(String),

    #[error("failed to create job directory: {0}")]
    JobDirError(String),

    #[error("failed to prepare workspace: {0}")]
    WorkspaceError(String),

    #[error("failed to configure proxy: {0}")]
    ProxyConfigError(String),

    #[error("failed to start proxy: {0}")]
    ProxyStartError(String),

    #[error("failed to compute flake closure: {0}")]
    FlakeClosureError(String),

    #[error("failed to find packages: {0}")]
    PackageError(String),

    #[error("failed to compute closure: {0}")]
    ClosureError(String),

    #[error("failed to prepare root: {0}")]
    RootError(String),

    #[error("invalid hardening profile '{0}': {1}")]
    HardeningProfileError(String, String),

    #[error("failed to execute job: {0}")]
    ExecutionError(String),

    #[error("proxy stdout not available")]
    ProxyStdoutError,

    #[error("proxy stderr not available")]
    ProxyStderrError,
}

/// Context for job execution containing all required services and configuration
pub struct ExecuteJobContext {
    pub storage: JobStorage,
    pub config: crate::config::ServerConfig,
    pub tx: broadcast::Sender<Result<LogEntry, Status>>,
    pub registry: crate::job_registry::JobRegistry,
    pub executor: Arc<dyn Executor>,
    pub job_root: Arc<dyn JobRoot>,
    pub job_workspace: Arc<dyn JobWorkspace>,
    pub session_registry: Option<Arc<crate::session::SessionRegistry>>,
}

impl std::fmt::Debug for ExecuteJobContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecuteJobContext")
            .field("storage", &self.storage)
            .field("config", &self.config)
            .field("registry", &self.registry)
            .field("executor", &self.executor.name())
            .field("job_root", &self.job_root)
            .field("job_workspace", &self.job_workspace)
            .finish()
    }
}

/// Extract credential names referenced in a network policy
fn extract_credential_names(policy: Option<&NetworkPolicy>) -> HashSet<String> {
    let mut names = HashSet::new();

    if let Some(policy) = policy {
        for rule in &policy.rules {
            if let Some(ref cred_name) = rule.credential {
                let _ = names.insert(cred_name.clone());
            }
        }
    }

    names
}

/// Filter credentials to only those referenced in the policy
fn filter_credentials<'a>(
    all_credentials: &'a [Credential],
    policy: Option<&NetworkPolicy>,
) -> Vec<&'a Credential> {
    let referenced_names = extract_credential_names(policy);

    all_credentials
        .iter()
        .filter(|c| referenced_names.contains(&c.name))
        .collect()
}

/// Check if any of the credentials has the specified type
fn has_credential_with_type(credentials: &[&Credential], cred_type: CredentialType) -> bool {
    credentials.iter().any(|c| c.credential_type == cred_type)
}

/// Serve stored logs for a completed job
pub async fn serve_stored_logs(
    job_id: String,
    storage: JobStorage,
    tx: mpsc::Sender<Result<LogEntry, Status>>,
) {
    tracing::debug!(job_id = %job_id, "serving stored logs");

    // Spawn task to serve stored logs (intentionally detached, communicates via channel)
    drop(tokio::spawn(async move {
        match storage.get_logs(&job_id) {
            Ok(logs) => {
                for log in logs {
                    let timestamp_secs = log
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let entry = LogEntry {
                        content: log.message,
                        timestamp: Some(prost_types::Timestamp {
                            seconds: timestamp_secs,
                            nanos: 0,
                        }),
                        source: log.source,
                    };

                    if tx.send(Ok(entry)).await.is_err() {
                        tracing::warn!(job_id = %job_id, "client disconnected while serving logs");
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::error!(job_id = %job_id, error = %e, "failed to get logs");
                let _ = tx
                    .send(Err(Status::internal("Failed to retrieve logs")))
                    .await;
            }
        }
    }));
}

/// Execute a job and stream logs in real-time via broadcast channel
///
/// This function is designed to be spawned as a background task by the caller.
/// It uses a broadcast channel to allow multiple clients to subscribe to the same job's output.
/// Note: This function is called from within an instrumented span created by the service layer.
pub async fn execute_job(job: JobMetadata, ctx: ExecuteJobContext, interactive: bool) {
    tracing::debug!(status = %job.status.to_string(), "executing job");

    let ExecuteJobContext {
        storage,
        config,
        tx,
        registry,
        executor,
        job_root,
        job_workspace,
        session_registry,
    } = ctx;

    // Create log sink for this job (replaces send_info/send_error pattern)
    let log_sink: Arc<dyn LogSink> = Arc::new(StorageLogSink::new(storage.clone(), tx.clone()));

    let job_id = job.id.clone();
    let packages = job.packages.clone();
    let script = job.script.clone();
    let repo = job.repo.clone();
    let path = job.path.clone();
    let git_ref = job.git_ref.clone();
    let is_exec_mode = !packages.is_empty();
    // Fetch GitHub token if needed for git cloning
    let github_token = if !repo.is_empty() {
        // Look for GitHub credential in server config
        if let Some(github_cred) = config
            .credentials
            .iter()
            .find(|c| c.credential_type == crate::config::CredentialType::GitHub)
        {
            match crate::config::fetch_credential_token(github_cred).await {
                Ok(token) => {
                    tracing::info!(job_id = %job_id, "fetched github token for private repository access");
                    Some(token)
                }
                Err(e) => {
                    tracing::warn!(
                        job_id = %job_id,
                        error = %e,
                        "failed to fetch github token, will attempt public clone"
                    );
                    None
                }
            }
        } else {
            tracing::debug!(job_id = %job_id, "no github credential configured, cloning as public repository");
            None
        }
    } else {
        None
    };

    // Create job directory structure
    let state_dir = match config.state_dir.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            log_sink.error(
                &job_id,
                &format!("Failed to resolve state_dir to absolute path: {}", e),
            );
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };

    let job_dir = match JobDirectory::new(&state_dir, &job_id) {
        Ok(dir) => dir,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to create job directory: {}", e));
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };

    // Set up workspace (git clone, caching, etc.)
    let workspace_dir = {
        let result = job_workspace
            .setup(
                &job_dir.workspace,
                &repo,
                git_ref.as_deref(),
                Some(&path),
                github_token.as_deref(),
            )
            .instrument(tracing::info_span!("setup_workspace"))
            .await;
        match result {
            Ok(dir) => {
                tracing::info!(
                    workspace_dir = %dir.display(),
                    "workspace prepared"
                );
                dir
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to prepare workspace: {}", e));
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        }
    };

    // Detect flake.nix in workspace
    let has_flake = workspace::flake::detect_flake(&workspace_dir);

    // Capture git state before execution (if push enabled and repo provided)
    let (head_before, base_branch) = if job.push && !repo.is_empty() {
        let head = workspace::git_refs::get_head_commit(&workspace_dir).ok();
        let branch = workspace::git_refs::get_current_branch(&workspace_dir).ok();
        (head, branch)
    } else {
        (None, None)
    };

    // Phase 1: Create proxy config if network policy has rules
    let proxy_config_path = match configure_proxy(
        &job_id,
        &job_dir,
        job.network_policy.as_ref(),
        &config.credentials,
        executor.proxy_listen_addr(),
        &log_sink,
    )
    .await
    {
        Ok(path) => path,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to configure proxy: {}", e));
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };

    // Check if workspace has a flake - if so, use it instead of explicit packages
    let store_paths = if has_flake {
        // Flake detected - use flake shell and ignore explicit packages
        if !packages.is_empty() {
            let pkg_list = packages.join(", ");
            log_sink.info(
                &job_id,
                &format!(
                    "Found flake.nix - using flake shell (ignoring specified packages: {})",
                    pkg_list
                ),
            );
        }

        log_sink.info(
            &job_id,
            &format!("Computing flake closure from {}", workspace_dir.display()),
        );

        match workspace::compute_flake_closure(&workspace_dir).await {
            Ok(paths) => {
                tracing::info!(
                    job_id = %job_id,
                    path_count = paths.len(),
                    "computed flake closure"
                );
                log_sink.info(
                    &job_id,
                    &format!("Flake closure: {} store paths", paths.len()),
                );
                paths
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to compute flake closure: {}", e));
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        }
    } else {
        // No flake - use explicit packages (original behavior)
        let nixpkgs_version = job.nixpkgs_version.as_deref();
        let store_paths = find_packages(
            is_exec_mode,
            &packages,
            nixpkgs_version,
            &job_id,
            &storage,
            &log_sink,
        )
        .instrument(tracing::info_span!("resolve_packages"))
        .await;
        match store_paths {
            Some(paths) => paths,
            None => return, // Error already logged
        }
    };

    // Compute full closure once (used for both cache and executor)
    let closure = if !store_paths.is_empty() {
        match workspace::compute_combined_closure(&store_paths)
            .instrument(tracing::info_span!("compute_closure"))
            .await
        {
            Ok(c) => {
                tracing::info!(closure_count = c.len(), "computed full closure");
                c
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to compute closure: {}", e));
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        }
    } else {
        vec![]
    };

    // Create root directory using JobRoot trait (btrfs snapshot or copy from cache)
    let (store_setup, cache_hit) = match job_root
        .create(&job_dir.root, &closure)
        .instrument(tracing::info_span!("prepare_root"))
        .await
    {
        Ok((setup, hit)) => {
            // Send appropriate info message based on strategy and result
            let msg = match (&setup, hit) {
                (crate::root::StoreSetup::Populated, true) => {
                    "Cache hit: root created from snapshot".to_string()
                }
                (crate::root::StoreSetup::Populated, false) => {
                    "Cache miss: created and cached closure".to_string()
                }
                (crate::root::StoreSetup::BindMounts { paths }, _) => {
                    format!("Using bind-mount strategy ({} store paths)", paths.len())
                }
                (crate::root::StoreSetup::DockerVolume { name }, true) => {
                    format!("Docker volume cache hit: {}", name)
                }
                (crate::root::StoreSetup::DockerVolume { name }, false) => {
                    format!("Docker volume cache miss: created {}", name)
                }
            };
            log_sink.info(&job_id, &msg);
            (setup, hit)
        }
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to prepare root: {}", e));
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };
    let _ = cache_hit; // Silence unused warning, info logged above

    // Phase 2: Start proxy now that root exists (proxy writes cert to root/etc/ssl/certs/)
    let mut proxy = match start_proxy_if_configured(
        &job_id,
        &job_dir,
        proxy_config_path.as_ref(),
        executor.proxy_listen_addr(),
    )
    .instrument(tracing::info_span!("start_proxy"))
    .await
    {
        Ok(p) => p,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to start proxy: {}", e));
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };

    // Configure execution environment
    let mut env = build_environment(
        proxy.as_ref(),
        &workspace_dir,
        executor.proxy_connect_host(),
        executor.uses_chroot(),
        &job_dir.root,
    );

    // Update PATH with package binaries (skip for DockerVolume - paths are different architecture)
    if !store_paths.is_empty()
        && !matches!(store_setup, crate::root::StoreSetup::DockerVolume { .. })
    {
        let path_env = workspace::build_path_env(&store_paths);
        let current_path = env.get("PATH").cloned().unwrap_or_default();
        let _ = env.insert("PATH".to_string(), format!("{}:{}", path_env, current_path));
    }

    // Configure credentials (Claude Code, GitHub token)
    setup_credentials_env(
        &job_id,
        &workspace_dir,
        &job_dir,
        &mut env,
        &config.credentials,
        job.network_policy.as_ref(),
        &log_sink,
    );

    let command = build_command(is_exec_mode, script);

    // Working directory was already resolved by job_workspace.setup() based on path
    let exec_working_dir = workspace_dir.clone();

    // Parse hardening profile from job metadata
    let hardening_profile = {
        use std::str::FromStr;
        let profile_str = job.hardening_profile.as_deref().unwrap_or("default");
        match HardeningProfile::from_str(profile_str) {
            Ok(profile) => profile,
            Err(e) => {
                log_sink.error(
                    &job_id,
                    &format!("Invalid hardening profile '{}': {}", profile_str, e),
                );
                return;
            }
        }
    };

    let exec_config = ExecutionConfig {
        job_id: job_id.clone(),
        command,
        env,
        working_dir: exec_working_dir,
        root_dir: job_dir.root.clone(),
        store_setup,
        timeout: std::time::Duration::from_secs(3600),
        store_paths: closure.clone(), // For command path resolution
        proxy_port: proxy.as_ref().map(|p| p.port),
        hardening_profile,
        interactive,
        pty_size: None, // Server mode uses WebSocket for terminal size
    };

    // Execute job using platform-specific executor (created earlier)
    let handle = match executor
        .execute(exec_config)
        .instrument(tracing::info_span!("executor_start"))
        .await
    {
        Ok(h) => {
            tracing::debug!(job_id = %job_id, "job execution started");
            h
        }
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to execute job: {}", e));
            let _ = storage.update_job_status(&job_id, JobStatus::Failed);
            return;
        }
    };

    // Extract stdout/stderr from handle based on mode
    let (stdout_task, stderr_task) = match handle.io {
        crate::executor::IoHandle::Piped { stdout, stderr } => {
            let stdout_task = spawn_stream_task(
                job_id.clone(),
                LogSource::JobStdout,
                stdout,
                storage.clone(),
                tx.clone(),
            );

            let stderr_task = spawn_stream_task(
                job_id.clone(),
                LogSource::JobStderr,
                stderr,
                storage.clone(),
                tx.clone(),
            );

            (stdout_task, stderr_task)
        }
        crate::executor::IoHandle::Pty { stdin, stdout } => {
            // Store PTY channels in session registry for WebSocket access
            if let Some(ref registry) = session_registry {
                let _ = registry.set_channels(&job_id, stdin, stdout).await;
                tracing::info!(job_id = %job_id, "pty channels stored for websocket access");
                // No streaming tasks needed - WebSocket handles I/O directly
                (
                    tokio::spawn(async {}), // dummy task
                    tokio::spawn(async {}), // dummy task
                )
            } else {
                tracing::error!(job_id = %job_id, "pty mode requires session registry");
                log_sink.error(&job_id, "PTY mode requires session registry");
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        }
    };

    let proxy_tasks = if let Some(ref mut proxy) = proxy {
        let proxy_stdout = match proxy.take_stdout() {
            Some(s) => s,
            None => {
                tracing::error!(job_id = %job_id, "proxy stdout not available");
                log_sink.error(&job_id, "proxy stdout not available");
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        };

        let proxy_stderr = match proxy.take_stderr() {
            Some(s) => s,
            None => {
                tracing::error!(job_id = %job_id, "proxy stderr not available");
                log_sink.error(&job_id, "proxy stderr not available");
                let _ = storage.update_job_status(&job_id, JobStatus::Failed);
                return;
            }
        };

        let proxy_stdout_task = spawn_stream_task(
            job_id.clone(),
            LogSource::ProxyStdout,
            proxy_stdout,
            storage.clone(),
            tx.clone(),
        );

        let proxy_stderr_task = spawn_stream_task(
            job_id.clone(),
            LogSource::ProxyStderr,
            proxy_stderr,
            storage.clone(),
            tx.clone(),
        );
        Some((proxy_stdout_task, proxy_stderr_task))
    } else {
        None
    };

    tracing::debug!("waiting for job to exit");
    let exit_code = async { handle.exit_code.await.unwrap_or(-1) }
        .instrument(tracing::info_span!("run_job"))
        .await;
    tracing::debug!(exit_code = exit_code, "job exited");

    // Stop proxy and wait for stream tasks to finish
    async {
        if let Some(ref mut proxy) = proxy {
            proxy.stop().await;
        }

        if let Some((proxy_stdout_task, proxy_stderr_task)) = proxy_tasks {
            let _ = tokio::join!(
                stdout_task,
                stderr_task,
                proxy_stdout_task,
                proxy_stderr_task
            );
        } else {
            let _ = tokio::join!(stdout_task, stderr_task);
        }
    }
    .instrument(tracing::info_span!("drain_streams"))
    .await;

    // Note: Executor cleanup (sandbox profile, network namespace, etc.) is handled
    // internally by each executor implementation when the job exits.

    let final_status = if exit_code == 0 {
        JobStatus::Completed
    } else {
        JobStatus::Failed
    };

    let msg = format!("[DONE] Job exited with code: {}\n", exit_code);
    let _ = storage.append_log(
        &job_id,
        &StorageLogEntry {
            timestamp: SystemTime::now(),
            message: msg.clone(),
            source: LogSource::System as i32,
        },
    );

    let _ = tx.send(Ok(LogEntry {
        content: msg,
        timestamp: Some(prost_types::Timestamp {
            seconds: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            nanos: 0,
        }),
        source: LogSource::System as i32,
    }));

    // Handle PR creation if push is enabled
    if job.push && !repo.is_empty() && exit_code == 0 {
        if let (Some(before_sha), Some(original_branch)) = (head_before, base_branch) {
            match handle_pr_creation(PrCreationContext {
                repo_dir: &workspace_dir,
                job_id: &job_id,
                repo_url: &repo,
                head_before: &before_sha,
                base_branch: &original_branch,
                config: &config,
                log_sink: &log_sink,
            })
            .await
            {
                Ok(pr_url) => {
                    log_sink.info(&job_id, &format!("Pull request created: {}", pr_url));
                }
                Err(e) => {
                    log_sink.info(&job_id, &format!("PR creation skipped: {}", e));
                }
            }
        }
    }

    let _ = storage.update_job_status(&job_id, final_status.clone());
    tracing::info!(exit_code = exit_code, status = %final_status.to_string(), "job completed");

    // Remove job from registry - this closes the broadcast channel
    // so clients stop waiting while we clean up
    registry.remove(&job_id).await;

    // Cleanup root directory and workspace
    // Try executor-specific cleanup first (handles privilege escalation on Linux)
    if let Err(e) = executor
        .cleanup_root(&job_dir.root)
        .instrument(tracing::info_span!("cleanup_root"))
        .await
    {
        tracing::debug!(error = %e, "executor cleanup failed, trying direct cleanup");
        if let Err(e) = job_root.cleanup(&job_dir.root) {
            tracing::warn!(error = %e, "failed to cleanup root directory");
        }
    }
    if let Err(e) = job_workspace.cleanup(&job_dir.workspace) {
        tracing::warn!(error = %e, "failed to cleanup workspace");
    }
}

// Helper functions

fn build_environment(
    proxy: Option<&ProxyManager>,
    working_dir: &Path,
    proxy_connect_host: &str,
    uses_chroot: bool,
    root_dir: &Path,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Proxy configuration (only if proxy is running)
    if let Some(proxy) = proxy {
        // Build proxy URL with platform-specific connect address and credentials
        // connect_host is where the job connects (10.0.0.1 on Linux, 127.0.0.1 on macOS)
        let proxy_url = proxy.proxy_url_with_host(proxy_connect_host);
        let _ = env.insert("HTTP_PROXY".to_string(), proxy_url.clone());
        let _ = env.insert("HTTPS_PROXY".to_string(), proxy_url);

        // CA cert path depends on executor type:
        // - Linux (chroot): use chroot-relative path (e.g., /etc/ssl/certs/ca-certificates.crt)
        // - macOS (no chroot): use full host path (e.g., /tmp/nix-jail-.../root/etc/ssl/certs/...)
        let ca_cert_path = if uses_chroot {
            crate::proxy_manager::CA_CERT_CHROOT_PATH.to_string()
        } else {
            crate::proxy_manager::ProxyManager::ca_cert_host_path(root_dir)
                .to_string_lossy()
                .to_string()
        };
        let _ = env.insert("SSL_CERT_FILE".to_string(), ca_cert_path.clone());
        let _ = env.insert("NODE_EXTRA_CA_CERTS".to_string(), ca_cert_path.clone());
        let _ = env.insert("REQUESTS_CA_BUNDLE".to_string(), ca_cert_path);
        let _ = env.insert("NO_PROXY".to_string(), "localhost,127.0.0.1".to_string());
    }

    // Sandbox isolation
    let _ = env.insert(
        "HOME".to_string(),
        working_dir.to_string_lossy().to_string(),
    );

    let _ = env.insert("USER".to_string(), "sbc-admin".to_string());
    let _ = env.insert("LOGNAME".to_string(), "sbc-admin".to_string());

    let _ = env.insert("TMPDIR".to_string(), "/tmp".to_string());

    // Set minimal locale to avoid locale warnings (sandbox doesn't have full locale data)
    let _ = env.insert("LANG".to_string(), "C".to_string());
    let _ = env.insert("LC_ALL".to_string(), "C".to_string());

    env
}

async fn find_packages(
    is_exec_mode: bool,
    packages: &[String],
    nixpkgs_version: Option<&str>,
    job_id: &str,
    storage: &JobStorage,
    log_sink: &Arc<dyn LogSink>,
) -> Option<Vec<std::path::PathBuf>> {
    if is_exec_mode {
        let pkg_refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
        match workspace::find_nix_packages_cached(&pkg_refs, nixpkgs_version).await {
            Ok(paths) => {
                let version_info = nixpkgs_version.unwrap_or("(none)");
                tracing::info!(packages = ?packages, nixpkgs_version = %version_info, "found nix packages");
                Some(paths)
            }
            Err(e) => {
                log_sink.error(job_id, &format!("Failed to find packages: {}", e));
                let _ = storage.update_job_status(job_id, JobStatus::Failed);
                None
            }
        }
    } else {
        // Submit mode: use curl for now
        match workspace::find_nix_package("curl").await {
            Ok(curl_path) => Some(vec![curl_path]),
            Err(e) => {
                tracing::warn!(job_id = %job_id, error = %e, "failed to find curl");
                Some(vec![])
            }
        }
    }
}

/// Detect hashbang from script content and return (interpreter_name, is_bash)
fn detect_hashbang(script: &str) -> Option<(String, bool)> {
    let interpreter = crate::hashbang::detect_interpreter(script)?;
    let is_bash = crate::hashbang::is_bash_like(&interpreter);
    Some((interpreter, is_bash))
}

fn build_command(is_exec_mode: bool, script: String) -> Vec<String> {
    if is_exec_mode {
        // Check for hashbang to determine interpreter
        if let Some((interpreter, is_bash)) = detect_hashbang(&script) {
            if !is_bash {
                // Non-bash interpreter: execute with that interpreter
                tracing::info!(
                    "detected non-bash interpreter '{}', executing directly",
                    interpreter
                );
                return vec![interpreter, "-c".to_string(), script];
            }
        }
        // Default to bash (either explicit bash hashbang or no hashbang)
        vec!["bash".to_string(), "-c".to_string(), script]
    } else {
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "echo '=== Proxy Configuration ===' && \
             echo \"HTTP_PROXY=$HTTP_PROXY\" && \
             echo \"HTTPS_PROXY=$HTTPS_PROXY\" && \
             echo \"SSL_CERT_FILE=$SSL_CERT_FILE\" && \
             echo '=== Testing Direct Access (should fail) ===' && \
             (curl -s --max-time 1 --noproxy '*' https://httpbin.org/anything 2>&1 || echo 'Direct access blocked (expected)') && \
             echo '=== Testing HTTPS via Proxy (should succeed) ===' && \
             curl -s --http1.1 https://httpbin.org/anything 2>&1 && \
             echo '=== Workspace Files ===' && \
             for f in *; do echo \"$f\"; done && \
             echo '=== Test Complete ===' && \
             exit 0"
                .to_string(),
        ]
    }
}

/// Configure proxy for network policy enforcement
///
/// Returns the path to the proxy config file if network policy has rules,
/// or None if network should be blocked (no policy).
async fn configure_proxy(
    job_id: &str,
    job_dir: &JobDirectory,
    network_policy: Option<&NetworkPolicy>,
    credentials: &[Credential],
    proxy_listen_addr: &str,
    log_sink: &Arc<dyn LogSink>,
) -> Result<Option<PathBuf>, OrchestrationError> {
    let has_network_rules = network_policy
        .map(|policy| !policy.rules.is_empty())
        .unwrap_or(false);

    if !has_network_rules {
        log_sink.info(job_id, "Network access blocked (no policy)");
        return Ok(None);
    }

    let filtered_credentials = filter_credentials(credentials, network_policy);
    let proxy_username = Some(format!("job-{}", job_id));
    let proxy_password = Some(workspace::generate_proxy_password());

    let ca_cert_host_path = crate::proxy_manager::ProxyManager::ca_cert_host_path(&job_dir.root);
    let path = workspace::write_proxy_config(
        &job_dir.base,
        &ca_cert_host_path,
        proxy_listen_addr,
        network_policy.cloned(),
        &filtered_credentials,
        proxy_username,
        proxy_password,
    )
    .map_err(|e| OrchestrationError::ProxyConfigError(e.to_string()))?;

    let credential_names: Vec<&str> = filtered_credentials
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    tracing::info!(
        path = %path.display(),
        credentials = ?credential_names,
        "created proxy config"
    );

    if let Some(policy) = network_policy {
        log_sink.info(
            job_id,
            &format!(
                "Network policy configured with {} rules",
                policy.rules.len()
            ),
        );
    }

    Ok(Some(path))
}

/// Resolve packages and compute closure
///
/// Handles both flake-based and explicit package resolution.
/// Returns (store_paths, closure).
async fn resolve_packages_and_closure(
    job_id: &str,
    working_dir: &Path,
    packages: &[String],
    nixpkgs_version: Option<&str>,
    has_flake: bool,
    log_sink: &Arc<dyn LogSink>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), OrchestrationError> {
    let store_paths = if has_flake {
        if !packages.is_empty() {
            log_sink.info(
                job_id,
                &format!(
                    "Ignoring explicit packages ({}), using flake.nix",
                    packages.join(", ")
                ),
            );
        }
        log_sink.info(
            job_id,
            &format!("Computing flake closure from {}", working_dir.display()),
        );
        workspace::compute_flake_closure(working_dir)
            .await
            .map_err(|e| OrchestrationError::FlakeClosureError(e.to_string()))?
    } else if !packages.is_empty() {
        let pkg_refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
        workspace::find_nix_packages_cached(&pkg_refs, nixpkgs_version)
            .await
            .map_err(|e| OrchestrationError::PackageError(e.to_string()))?
    } else {
        vec![]
    };

    let closure = if !store_paths.is_empty() {
        workspace::compute_combined_closure(&store_paths)
            .await
            .map_err(|e| OrchestrationError::ClosureError(e.to_string()))?
    } else {
        vec![]
    };

    log_sink.info(job_id, &format!("Closure: {} store paths", closure.len()));

    Ok((store_paths, closure))
}

/// Start proxy if config path is provided
async fn start_proxy_if_configured(
    job_id: &str,
    job_dir: &JobDirectory,
    proxy_config_path: Option<&PathBuf>,
    proxy_listen_addr: &str,
) -> Result<Option<ProxyManager>, OrchestrationError> {
    let Some(config_path) = proxy_config_path else {
        return Ok(None);
    };

    let listen_host = proxy_listen_addr
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();

    let proxy = ProxyManager::start(
        job_id.to_string(),
        job_dir.root.clone(),
        config_path.clone(),
        listen_host,
    )
    .await
    .map_err(|e| OrchestrationError::ProxyStartError(e.to_string()))?;

    tracing::debug!(port = proxy.port, "proxy started");
    Ok(Some(proxy))
}

/// Setup credential-related environment variables
fn setup_credentials_env(
    job_id: &str,
    working_dir: &Path,
    job_dir: &JobDirectory,
    env: &mut HashMap<String, String>,
    credentials: &[Credential],
    network_policy: Option<&NetworkPolicy>,
    log_sink: &Arc<dyn LogSink>,
) {
    let filtered_credentials = filter_credentials(credentials, network_policy);

    // Claude Code credential
    if has_credential_with_type(&filtered_credentials, CredentialType::Claude) {
        if let Ok(()) = workspace::setup_claude_config(working_dir, job_id, &filtered_credentials) {
            let wrapper_bin = job_dir.base.join("bin");
            if let Some(path) = env.get("PATH").cloned() {
                let _ = env.insert(
                    "PATH".to_string(),
                    format!("{}:{}", wrapper_bin.display(), path),
                );
            }
            log_sink.info(job_id, "Claude Code credentials configured");
        }
    }

    // GitHub token credential
    if has_credential_with_type(&filtered_credentials, CredentialType::GitHub) {
        if let Some(github_cred) = filtered_credentials
            .iter()
            .find(|c| c.credential_type == CredentialType::GitHub)
        {
            if let Some(ref dummy_token) = github_cred.dummy_token {
                let _ = env.insert("GITHUB_TOKEN".to_string(), dummy_token.clone());
                log_sink.info(
                    job_id,
                    "GitHub token configured (proxy will inject real token)",
                );
            }
        }
    }
}

fn spawn_stream_task(
    job_id: String,
    source: LogSource,
    receiver: mpsc::Receiver<String>,
    storage: JobStorage,
    tx: broadcast::Sender<Result<LogEntry, Status>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { streaming::stream_logs(job_id, source, receiver, storage, tx).await })
}

/// Configuration for PR creation
struct PrCreationContext<'a> {
    repo_dir: &'a Path,
    job_id: &'a str,
    repo_url: &'a str,
    head_before: &'a str,
    base_branch: &'a str,
    config: &'a crate::config::ServerConfig,
    log_sink: &'a Arc<dyn LogSink>,
}

async fn handle_pr_creation(
    ctx: PrCreationContext<'_>,
) -> Result<String, workspace::WorkspaceError> {
    let PrCreationContext {
        repo_dir,
        job_id,
        repo_url,
        head_before,
        base_branch,
        config,
        log_sink,
    } = ctx;

    // Check if HEAD moved (commits were made)
    let head_after = workspace::git_refs::get_head_commit(repo_dir)?;
    if head_before == head_after {
        return Err(workspace::WorkspaceError::InvalidPath(
            "No commits detected".into(),
        ));
    }

    tracing::info!(
        job_id = %job_id,
        before = %head_before,
        after = %head_after,
        "commits detected, creating PR"
    );

    log_sink.info(
        job_id,
        &format!(
            "Detected commits ({} -> {}), preparing pull request...",
            &head_before[..8],
            &head_after[..8]
        ),
    );

    // Get commit messages for PR body
    let commits = workspace::git_refs::get_commits_between(repo_dir, head_before, &head_after)?;

    // Create a new branch job-${jobID} for the PR
    let pr_branch = format!("job-{}", job_id);
    workspace::git_refs::create_and_checkout_branch(repo_dir, &pr_branch)?;

    log_sink.info(
        job_id,
        &format!("Created branch '{}' for pull request", pr_branch),
    );

    // Get GitHub token
    let github_cred = config
        .credentials
        .iter()
        .find(|c| c.credential_type == crate::config::CredentialType::GitHub)
        .ok_or_else(|| {
            workspace::WorkspaceError::InvalidPath("No GitHub credential configured".into())
        })?;

    let token = crate::config::fetch_credential_token(github_cred)
        .await
        .map_err(|e| {
            workspace::WorkspaceError::InvalidPath(format!("Failed to fetch GitHub token: {}", e))
        })?;

    // Push the new branch
    log_sink.info(
        job_id,
        &format!("Pushing branch '{}' to remote...", pr_branch),
    );

    workspace::git_refs::push_branch(repo_dir, &pr_branch, &token, repo_url)?;

    // Create PR: job-${jobID} -> base_branch
    log_sink.info(
        job_id,
        &format!("Creating pull request: {} -> {}", pr_branch, base_branch),
    );

    let pr_url =
        workspace::pr::create_pull_request(repo_url, &pr_branch, base_branch, &commits, &token)
            .await?;

    Ok(pr_url)
}

/// Configuration for local (serverless) execution
pub struct LocalExecutionConfig {
    /// Nix packages to include in the environment
    pub packages: Vec<String>,

    /// Command to execute (e.g., ["bash", "-c", "..."])
    pub command: Vec<String>,

    /// Working directory for execution
    pub working_dir: PathBuf,

    /// Network policy (optional)
    pub network_policy: Option<NetworkPolicy>,

    /// Credentials for proxy injection
    pub credentials: Vec<Credential>,

    /// Hardening profile
    pub hardening_profile: HardeningProfile,

    /// State directory for job files
    pub state_dir: PathBuf,

    /// Nixpkgs version (optional)
    pub nixpkgs_version: Option<String>,

    /// Interactive mode (use PTY)
    pub interactive: bool,

    /// Terminal size for PTY mode (rows, cols)
    pub pty_size: Option<(u16, u16)>,

    /// Callback invoked right before PTY I/O starts (for enabling raw mode)
    pub on_pty_ready: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for LocalExecutionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalExecutionConfig")
            .field("packages", &self.packages)
            .field("command", &self.command)
            .field("working_dir", &self.working_dir)
            .field("interactive", &self.interactive)
            .field("pty_size", &self.pty_size)
            .field("on_pty_ready", &self.on_pty_ready.is_some())
            .finish_non_exhaustive()
    }
}

/// Execute a job locally without a server
///
/// This is the client-side execution path for `nix-jail run`.
/// Unlike `execute_job()`, this:
/// - Uses LogSink instead of storage + broadcast
/// - Doesn't clone git repos (uses provided working_dir)
/// - Doesn't create PRs
/// - Returns exit code directly
pub async fn execute_local(
    config: LocalExecutionConfig,
    executor: Arc<dyn Executor>,
    job_root: Arc<dyn JobRoot>,
    log_sink: Arc<dyn LogSink>,
) -> Result<i32, OrchestrationError> {
    let job_id = ulid::Ulid::new().to_string();
    tracing::info!(job_id = %job_id, "starting local execution");

    // Create job directory
    let state_dir = config
        .state_dir
        .canonicalize()
        .map_err(|e| OrchestrationError::StateDirError(e.to_string()))?;

    let job_dir = JobDirectory::new(&state_dir, &job_id)
        .map_err(|e| OrchestrationError::JobDirError(e.to_string()))?;

    // Detect flake.nix in working directory
    let has_flake = workspace::flake::detect_flake(&config.working_dir);

    // Phase 1: Create proxy config if needed
    let proxy_config_path = configure_proxy(
        &job_id,
        &job_dir,
        config.network_policy.as_ref(),
        &config.credentials,
        executor.proxy_listen_addr(),
        &log_sink,
    )
    .await?;

    // Phase 2: Resolve packages and compute closure
    let (store_paths, closure) = resolve_packages_and_closure(
        &job_id,
        &config.working_dir,
        &config.packages,
        config.nixpkgs_version.as_deref(),
        has_flake,
        &log_sink,
    )
    .instrument(tracing::info_span!("resolve_packages"))
    .await?;

    // Phase 3: Prepare root using injected JobRoot implementation
    let (store_setup, cache_hit) = async {
        job_root
            .create(&job_dir.root, &closure)
            .await
            .map_err(|e| OrchestrationError::RootError(e.to_string()))
    }
    .instrument(tracing::info_span!("prepare_root"))
    .await?;

    let msg = match (&store_setup, cache_hit) {
        (crate::root::StoreSetup::Populated, true) => {
            "Cache hit: root created from snapshot".to_string()
        }
        (crate::root::StoreSetup::Populated, false) => {
            "Cache miss: created and cached closure".to_string()
        }
        (crate::root::StoreSetup::BindMounts { paths }, _) => {
            format!("Using bind-mount strategy ({} store paths)", paths.len())
        }
        (crate::root::StoreSetup::DockerVolume { name }, true) => {
            format!("Docker volume cache hit: {}", name)
        }
        (crate::root::StoreSetup::DockerVolume { name }, false) => {
            format!("Docker volume cache miss: created {}", name)
        }
    };
    log_sink.info(&job_id, &msg);

    // Phase 4: Start proxy if configured
    let mut proxy = start_proxy_if_configured(
        &job_id,
        &job_dir,
        proxy_config_path.as_ref(),
        executor.proxy_listen_addr(),
    )
    .await?;

    // Phase 5: Build environment
    let mut env = build_environment(
        proxy.as_ref(),
        &config.working_dir,
        executor.proxy_connect_host(),
        executor.uses_chroot(),
        &job_dir.root,
    );

    // Update PATH with package binaries (skip for DockerVolume - paths are different architecture)
    if !store_paths.is_empty()
        && !matches!(store_setup, crate::root::StoreSetup::DockerVolume { .. })
    {
        let path_env = workspace::build_path_env(&store_paths);
        let current_path = env.get("PATH").cloned().unwrap_or_default();
        let _ = env.insert("PATH".to_string(), format!("{}:{}", path_env, current_path));
    }

    // Configure credentials
    setup_credentials_env(
        &job_id,
        &config.working_dir,
        &job_dir,
        &mut env,
        &config.credentials,
        config.network_policy.as_ref(),
        &log_sink,
    );

    // Phase 6: Execute
    let exec_config = ExecutionConfig {
        job_id: job_id.clone(),
        command: config.command,
        env,
        working_dir: config.working_dir.clone(),
        root_dir: job_dir.root.clone(),
        store_setup,
        timeout: std::time::Duration::from_secs(3600),
        store_paths: closure.clone(),
        proxy_port: proxy.as_ref().map(|p| p.port),
        hardening_profile: config.hardening_profile,
        interactive: config.interactive,
        pty_size: config.pty_size,
    };

    let handle = async {
        executor
            .execute(exec_config)
            .await
            .map_err(|e| OrchestrationError::ExecutionError(e.to_string()))
    }
    .instrument(tracing::info_span!("execute"))
    .await?;

    // Extract stdout/stderr from handle based on mode
    let (stdout_task, stderr_task) = match handle.io {
        crate::executor::IoHandle::Piped { stdout, stderr } => {
            let log_sink_stdout = log_sink.clone();
            let log_sink_stderr = log_sink.clone();
            let job_id_stdout = job_id.clone();
            let job_id_stderr = job_id.clone();

            let stdout_task = tokio::spawn(async move {
                streaming::stream_to_sink(
                    job_id_stdout,
                    LogSource::JobStdout,
                    stdout,
                    log_sink_stdout,
                )
                .await
            });

            let stderr_task = tokio::spawn(async move {
                streaming::stream_to_sink(
                    job_id_stderr,
                    LogSource::JobStderr,
                    stderr,
                    log_sink_stderr,
                )
                .await
            });

            (stdout_task, stderr_task)
        }
        crate::executor::IoHandle::Pty { stdin, stdout } => {
            // PTY mode: connect directly to user's terminal
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Call the on_pty_ready callback (enables raw mode at the right time)
            if let Some(callback) = config.on_pty_ready {
                callback();
            }

            // Forward user stdin to PTY stdin
            let stdin_task = tokio::spawn(async move {
                let mut user_stdin = tokio::io::stdin();
                let mut buf = [0u8; 1024];
                loop {
                    match user_stdin.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            if stdin.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Forward PTY stdout to user stdout
            let stdout_task = tokio::spawn(async move {
                let mut user_stdout = tokio::io::stdout();
                let mut stdout = stdout;
                while let Some(data) = stdout.recv().await {
                    if user_stdout.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = user_stdout.flush().await;
                }
            });

            (stdin_task, stdout_task)
        }
    };

    // Handle proxy streams if running
    let proxy_tasks = if let Some(ref mut p) = proxy {
        let proxy_stdout = p
            .take_stdout()
            .ok_or(OrchestrationError::ProxyStdoutError)?;
        let proxy_stderr = p
            .take_stderr()
            .ok_or(OrchestrationError::ProxyStderrError)?;

        let log_sink_pout = log_sink.clone();
        let log_sink_perr = log_sink.clone();
        let job_id_pout = job_id.clone();
        let job_id_perr = job_id.clone();

        let pout_task = tokio::spawn(async move {
            streaming::stream_to_sink(
                job_id_pout,
                LogSource::ProxyStdout,
                proxy_stdout,
                log_sink_pout,
            )
            .await
        });

        let perr_task = tokio::spawn(async move {
            streaming::stream_to_sink(
                job_id_perr,
                LogSource::ProxyStderr,
                proxy_stderr,
                log_sink_perr,
            )
            .await
        });

        Some((pout_task, perr_task))
    } else {
        None
    };

    // Wait for job to complete
    let exit_code = handle.exit_code.await.unwrap_or(-1);

    // Cleanup
    if let Some(ref mut p) = proxy {
        p.stop().await;
    }

    if let Some((pout, perr)) = proxy_tasks {
        let _ = tokio::join!(stdout_task, stderr_task, pout, perr);
    } else {
        let _ = tokio::join!(stdout_task, stderr_task);
    }

    log_sink.done(&job_id, exit_code);

    // Cleanup job directory
    // Try executor-specific cleanup first (handles privilege escalation on Linux)
    if let Err(e) = executor.cleanup_root(&job_dir.root).await {
        tracing::debug!(error = %e, "executor cleanup failed, trying direct cleanup");
        // Fall back to JobRoot cleanup
        if let Err(e) = job_root.cleanup(&job_dir.root) {
            tracing::warn!(error = %e, "failed to cleanup root directory");
        }
    }

    Ok(exit_code)
}
