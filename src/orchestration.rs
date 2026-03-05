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

use crate::config::{Credential, CredentialSource, CredentialType, ServerConfig};
use crate::executor::{ExecutionConfig, Executor, HardeningProfile, ResolvedCacheMount};
use crate::jail::{CacheRequest, CacheScope, EphemeralCredential};
use crate::jail::{LogEntry, LogSource, NetworkPolicy};
use crate::job_dir::JobDirectory;
use crate::job_workspace::JobWorkspace;
use crate::log_sink::{format_info, LogSink, StorageLogSink};
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

    #[error("cache populate phase failed for '{0}': {1}")]
    PopulatePhaseError(String, String),

    #[error("failed to create cache snapshot: {0}")]
    SnapshotError(String),
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
    pub metrics: Option<crate::metrics::SharedMetrics>,
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
            .field("metrics", &self.metrics.is_some())
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

/// Merge ephemeral credentials with server credentials
///
/// Ephemeral credentials override server credentials with the same name.
/// Logs a warning when an override occurs.
fn merge_ephemeral_credentials(
    server_credentials: &[Credential],
    ephemeral: &[EphemeralCredential],
) -> Vec<Credential> {
    let mut credentials: Vec<Credential> = server_credentials.to_vec();

    for ec in ephemeral {
        // Check for override
        if credentials.iter().any(|c| c.name == ec.name) {
            tracing::warn!(
                credential_name = %ec.name,
                "ephemeral credential overrides server credential"
            );
            credentials.retain(|c| c.name != ec.name);
        }
        credentials.push(Credential::from(ec));
    }

    credentials
}

/// Strip embedded credentials from a git URL and return an owned clean URL string.
///
/// Callers (e.g. forgejo-nix-ci) used to embed a PAT directly in the clone URL.
/// nix-jail now owns the credential, so we strip any `userinfo@` component and
/// use the server-configured credential instead.  Warns if stripping was necessary.
fn sanitize_repo_url(url: &str, job_id: &str) -> String {
    let prefix = if url.starts_with("https://") {
        "https://"
    } else if url.starts_with("http://") {
        "http://"
    } else {
        return url.to_string();
    };

    let rest = &url[prefix.len()..];
    if let Some(at_pos) = rest.find('@') {
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        if at_pos < slash_pos {
            tracing::warn!(
                job_id = %job_id,
                "repo URL contained embedded credentials — stripped; configure a server credential instead"
            );
            return format!("{}{}", prefix, &rest[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Check if a hostname matches a credential host pattern.
///
/// Supports exact match and wildcard prefix (`*.example.com`).
fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Find a credential whose `allowed_host_patterns` matches the host extracted
/// from the given git repository URL.
fn find_credential_for_host<'a>(
    credentials: &'a [Credential],
    repo_url: &str,
) -> Option<&'a Credential> {
    let remote = workspace::pr::parse_git_url(repo_url).ok()?;
    credentials.iter().find(|c| {
        c.allowed_host_patterns
            .iter()
            .any(|pattern| host_matches_pattern(&remote.host, pattern))
    })
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
                        exit_code: None,
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

/// Guard that ensures job metrics are recorded on all exit paths
struct JobMetricsGuard {
    metrics: Option<crate::metrics::SharedMetrics>,
    start_time: std::time::Instant,
    completed: bool,
}

impl JobMetricsGuard {
    fn new(metrics: Option<crate::metrics::SharedMetrics>) -> Self {
        if let Some(ref m) = metrics {
            m.job_started();
        }
        Self {
            metrics,
            start_time: std::time::Instant::now(),
            completed: false,
        }
    }

    /// Mark job as completed with success/failure status
    fn complete(&mut self, success: bool) {
        if self.completed {
            return;
        }
        self.completed = true;
        if let Some(ref m) = self.metrics {
            m.job_finished();
            let duration_secs = self.start_time.elapsed().as_secs_f64();
            let status = if success { "success" } else { "failure" };
            m.record_job_completed(status, duration_secs);
        }
    }
}

impl Drop for JobMetricsGuard {
    fn drop(&mut self) {
        // If not explicitly completed, treat as failure (early return)
        if !self.completed {
            self.complete(false);
        }
    }
}

/// Execute a job and stream logs in real-time via broadcast channel
///
/// This function is designed to be spawned as a background task by the caller.
/// It uses a broadcast channel to allow multiple clients to subscribe to the same job's output.
/// Note: This function is called from within an instrumented span created by the service layer.
///
/// # Arguments
/// * `ephemeral_credentials` - Client-provided credentials valid only for this job (not persisted)
/// * `job_env` - Client-provided environment variables for this job (merged with server defaults, server wins)
pub async fn execute_job(
    job: JobMetadata,
    ctx: ExecuteJobContext,
    interactive: bool,
    ephemeral_credentials: Vec<EphemeralCredential>,
    job_env: HashMap<String, String>,
) {
    let job_id = job.id.clone();
    let registry = ctx.registry.clone();
    let tx = ctx.tx.clone();

    execute_job_inner(job, ctx, interactive, ephemeral_credentials, job_env).await;

    // Guard: ensure registry cleanup on early failures.
    // execute_job_inner has many early return points (setup errors, flake
    // resolution failures, etc.) that skip the normal completion path's
    // registry.remove() call. Without this, the broadcast channel stays
    // open and stream_job clients hang forever.
    //
    // On the normal completion path, registry.remove() was already called
    // inside execute_job_inner, so is_running() returns false and this is
    // a no-op.
    if registry.is_running(&job_id).await {
        // Send failure exit_code so stream clients know the job failed
        let _ = tx.send(Ok(LogEntry {
            content: String::new(),
            timestamp: Some(prost_types::Timestamp {
                seconds: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                nanos: 0,
            }),
            source: LogSource::System as i32,
            exit_code: Some(1),
        }));
        registry.remove(&job_id).await;
    }
}

async fn execute_job_inner(
    job: JobMetadata,
    ctx: ExecuteJobContext,
    interactive: bool,
    ephemeral_credentials: Vec<EphemeralCredential>,
    job_env: HashMap<String, String>,
) {
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
        metrics,
    } = ctx;

    // Guard ensures metrics are recorded on all exit paths (including early returns)
    // Keep a clone for recording other metrics (cache hits, closure size)
    let metrics_ref = metrics.clone();
    let mut metrics_guard = JobMetricsGuard::new(metrics);

    // Create log sink for this job (replaces send_info/send_error pattern)
    let log_sink: Arc<dyn LogSink> = Arc::new(StorageLogSink::new(storage.clone(), tx.clone()));

    let job_id = job.id.clone();

    // Log job start with version info for debugging (visible in job output)
    log_sink.info(
        &job_id,
        &format!("nix-jail v{} job={}", env!("NIX_JAIL_VERSION"), job_id),
    );
    let packages = job.packages.clone();
    let script = job.script.clone();
    let repo = sanitize_repo_url(&job.repo, &job_id);
    let path = job.path.clone();
    let extra_paths = job.extra_paths.clone();
    let git_ref = job.git_ref.clone();
    let is_exec_mode = !packages.is_empty();
    // Fetch git credential for cloning (matched by repo host)
    let git_token = if !repo.is_empty() {
        if let Some(cred) = find_credential_for_host(&config.credentials, &repo) {
            match crate::config::fetch_credential_token(cred).await {
                Ok(token) => {
                    tracing::info!(
                        job_id = %job_id,
                        credential = %cred.name,
                        "fetched git credential for private repository access"
                    );
                    Some(token)
                }
                Err(e) => {
                    tracing::warn!(
                        job_id = %job_id,
                        error = %e,
                        "failed to fetch git credential, will attempt public clone"
                    );
                    None
                }
            }
        } else {
            tracing::debug!(job_id = %job_id, "no credential matches repo host, cloning as public");
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
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
            return;
        }
    };

    let job_dir = match JobDirectory::new(&state_dir, &job_id) {
        Ok(dir) => dir,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to create job directory: {}", e));
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
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
                &extra_paths,
                git_token.as_deref(),
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
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }
        }
    };

    // Detect flake source (local flake.nix or .envrc with use flake)
    let flake_source = workspace::flake::detect_flake_source(&workspace_dir);

    // Capture HEAD SHA before execution so we can detect new commits for PR creation
    let head_before = if job.push && !repo.is_empty() {
        workspace::git_refs::get_head_commit(&workspace_dir).ok()
    } else {
        None
    };

    // Merge server credentials with ephemeral credentials (ephemeral overrides server)
    let merged_credentials =
        merge_ephemeral_credentials(&config.credentials, &ephemeral_credentials);

    // If the job wants an inbound reverse proxy, set up the network namespace now
    // so we know the job's IP before writing alice's config.
    let reverse_proxy_setup = if let Some(port) = job.service_port {
        match executor.setup_network(&job_id) {
            Ok(Some(job_ip)) => {
                tracing::info!(
                    job_id = %job_id,
                    job_ip = %job_ip,
                    service_port = port,
                    "allocated network for reverse proxy job"
                );
                Some(workspace::ReverseProxySetup {
                    listen: "127.0.0.1:0".to_string(),
                    backend: format!("{}:{}", job_ip, port),
                })
            }
            Ok(None) => {
                tracing::warn!(
                    job_id = %job_id,
                    "executor does not support network namespaces, reverse proxy unavailable"
                );
                None
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to set up network: {}", e));
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }
        }
    } else {
        None
    };

    // Phase 1: Create alice proxy config if network policy has rules or reverse proxy is needed
    let proxy_config = match configure_proxy(
        &job_id,
        &job_dir,
        job.network_policy.as_ref(),
        &merged_credentials,
        executor.proxy_listen_addr(),
        &log_sink,
        config.otlp_endpoint.as_deref(),
        reverse_proxy_setup.as_ref(),
    )
    .instrument(tracing::info_span!("configure_proxy"))
    .await
    {
        Ok(config) => config,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to configure proxy: {}", e));
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
            return;
        }
    };

    // Resolve explicit packages, then additively merge the workspace devShell closure.
    // Both are combined so the sandbox gets the profile's toolchain AND the project's
    // flake devShell (e.g. cargo, language servers) when a flake.nix is present.
    let mut store_paths: Vec<std::path::PathBuf> = Vec::new();

    if !packages.is_empty() {
        let nixpkgs_version = job.nixpkgs_version.as_deref();
        match find_packages(
            is_exec_mode,
            &packages,
            nixpkgs_version,
            &job_id,
            &storage,
            &log_sink,
        )
        .instrument(tracing::info_span!("resolve_packages"))
        .await
        {
            Some(paths) => store_paths.extend(paths),
            None => return, // Error already logged
        }
    }

    if let Some(ref source) = flake_source {
        log_sink.info(&job_id, &format!("Computing flake closure from {}", source));
        match workspace::compute_flake_closure(source).await {
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
                store_paths.extend(paths);
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to compute flake closure: {}", e));
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }
        }
    }

    // Compute full closure once (used for both cache and executor)
    let closure = if !store_paths.is_empty() {
        match workspace::compute_combined_closure(&store_paths)
            .instrument(tracing::info_span!("compute_closure"))
            .await
        {
            Ok(c) => {
                tracing::info!(closure_count = c.len(), "computed full closure");
                // Record closure size metric
                if let Some(ref m) = metrics_ref {
                    m.record_closure_size(c.len());
                }
                c
            }
            Err(e) => {
                log_sink.error(&job_id, &format!("Failed to compute closure: {}", e));
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
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
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
            return;
        }
    };
    // Record cache hit/miss metrics for root
    if let Some(ref m) = metrics_ref {
        if cache_hit {
            m.record_cache_hit("root");
        } else {
            m.record_cache_miss("root");
        }
    }

    // Create FHS-compatible symlinks (/bin/sh, /usr/bin/env) for scripts with shebangs
    if let Err(e) = crate::executor::exec::create_fhs_symlinks(&job_dir.root, &closure) {
        log_sink.error(&job_id, &format!("Failed to create FHS symlinks: {}", e));
        // Non-fatal: continue execution, scripts might still work
    }

    // Create /etc/hosts for localhost resolution
    if let Err(e) = crate::executor::exec::create_etc_hosts(&job_dir.root) {
        log_sink.error(&job_id, &format!("Failed to create /etc/hosts: {}", e));
        // Non-fatal: continue execution
    }

    // Create sandbox home directory (/home/{user} with XDG subdirs)
    let sandbox_user = executor.sandbox_user();
    if let Err(e) = crate::executor::exec::create_home_directory(&job_dir.root, sandbox_user) {
        log_sink.error(&job_id, &format!("Failed to create home directory: {}", e));
        // Non-fatal: continue execution
    }

    // Phase 2: Start alice proxy now that root exists (writes cert to root/etc/ssl/certs/)
    let mut proxy = match start_proxy_if_configured(
        &job_id,
        &job_dir,
        proxy_config,
        executor.proxy_listen_addr(),
        &merged_credentials,
        config.proxy_binary.as_deref(),
    )
    .instrument(tracing::info_span!("start_proxy"))
    .await
    {
        Ok(p) => p,
        Err(e) => {
            log_sink.error(&job_id, &format!("Failed to start proxy: {}", e));
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
            return;
        }
    };

    // Store reverse proxy port in registry so ListJobs can expose it for routing
    if let Some(ref p) = proxy {
        if let Some(rp_port) = p.reverse_proxy_port {
            registry.set_reverse_proxy_port(&job_id, rp_port).await;
        }
    }

    // Create tmp directory for the job
    let tmp_dir = workspace_dir.join("tmp");
    let _ = std::fs::create_dir_all(&tmp_dir);

    // Chown job directory to sandbox user so jobs can write to it
    // (daemon runs as root, jobs run as sandbox user)
    // Skip chown when sandbox_user is None (e.g., macOS sandbox-exec runs as current user)
    if let Some((user, group)) = sandbox_user {
        let _span = tracing::info_span!("chown_job_dir").entered();
        let owner = format!("{}:{}", user, group);
        if let Err(e) = std::process::Command::new("chown")
            .args(["-R", &owner, &job_dir.base.to_string_lossy()])
            .output()
        {
            tracing::warn!(job_id = %job_id, error = %e, "failed to chown job directory");
        }
    }

    // Configure execution environment
    // Paths inside the chroot:
    // - HOME = /home/{user} (isolated from workspace)
    // - workspace root = /workspace (where .git lives)
    // - working dir = /workspace/projects/foo (where commands run)
    let mut env = {
        let _span = tracing::info_span!("build_environment").entered();
        // Use chroot-relative paths when using chroot, else host paths
        let (home_dir_for_env, workspace_root_for_env) = if executor.uses_chroot() {
            let user = sandbox_user.map(|(u, _)| u).unwrap_or("sandbox");
            (
                PathBuf::from(format!("/home/{}", user)),
                PathBuf::from("/workspace"),
            )
        } else {
            // Local mode: use workspace as home (matches existing behavior)
            (workspace_dir.clone(), job_dir.workspace.clone())
        };
        build_environment(
            proxy.as_ref(),
            &workspace_dir,
            &home_dir_for_env,
            &workspace_root_for_env,
            executor.proxy_connect_host(),
            executor.uses_chroot(),
            &job_dir.root,
            &job_env,
            &config.default_env,
        )
    };

    // Update PATH, NIX_LDFLAGS, NIX_CFLAGS_COMPILE with package paths
    // (skip for DockerVolume - paths are different architecture)
    if !store_paths.is_empty()
        && !matches!(store_setup, crate::root::StoreSetup::DockerVolume { .. })
    {
        let path_env = workspace::build_path_env(&store_paths);
        let current_path = env.get("PATH").cloned().unwrap_or_default();
        let _ = env.insert("PATH".to_string(), format!("{}:{}", path_env, current_path));

        // Set NIX_LDFLAGS for linker to find libraries (e.g., libiconv)
        let ldflags = workspace::build_ldflags_env(&store_paths);
        if !ldflags.is_empty() {
            let _ = env.insert("NIX_LDFLAGS".to_string(), ldflags);
        }

        // Set NIX_CFLAGS_COMPILE for compiler to find headers
        let cflags = workspace::build_cflags_env(&store_paths);
        if !cflags.is_empty() {
            let _ = env.insert("NIX_CFLAGS_COMPILE".to_string(), cflags);
        }

        // Set LIBRARY_PATH for linkers (rustc/cc) that don't use NIX_LDFLAGS
        let lib_path = workspace::build_library_path_env(&store_paths);
        if !lib_path.is_empty() {
            let _ = env.insert("LIBRARY_PATH".to_string(), lib_path.clone());
        }

        // Set PKG_CONFIG_PATH for pkg-config to find .pc files (e.g., openssl.pc)
        let pkg_config_path = workspace::build_pkg_config_path_env(&store_paths);
        if !pkg_config_path.is_empty() {
            let _ = env.insert("PKG_CONFIG_PATH".to_string(), pkg_config_path.clone());
        }

        // Prevent openssl-sys from vendoring OpenSSL - use system OpenSSL via pkg-config
        let _ = env.insert("OPENSSL_NO_VENDOR".to_string(), "1".to_string());

        // Set SHELL to nix-managed zsh or bash if available and not already overridden
        if !env.contains_key("SHELL") {
            if let Some(shell) = workspace::find_shell(&store_paths) {
                tracing::info!(shell = %shell.display(), "setting SHELL from store paths");
                let _ = env.insert("SHELL".to_string(), shell.display().to_string());
            }
        }

        // Log env vars for debugging
        log_sink.info(
            &job_id,
            &format!(
                "env: PKG_CONFIG_PATH={} paths, LIBRARY_PATH={} paths",
                pkg_config_path.split(':').filter(|s| !s.is_empty()).count(),
                lib_path.split(':').filter(|s| !s.is_empty()).count()
            ),
        );
    } else {
        // Log when env vars are NOT set
        log_sink.info(
            &job_id,
            &format!(
                "env: skipped (store_paths={}, docker_volume={})",
                store_paths.len(),
                matches!(store_setup, crate::root::StoreSetup::DockerVolume { .. })
            ),
        );
    }

    // Configure credentials (Claude Code, GitHub token)
    // Server always uses secure mode (insecure_credentials = false)
    {
        let _span = tracing::info_span!("setup_credentials").entered();
        let ctx = CredentialsSetupContext {
            job_id: &job_id,
            working_dir: &workspace_dir,
            job_dir: &job_dir,
            credentials: &merged_credentials,
            network_policy: job.network_policy.as_ref(),
            log_sink: &log_sink,
            insecure_credentials: false,
            sandbox_username: sandbox_user.map(|(u, _)| u).unwrap_or("sandbox"),
        };
        setup_credentials_env(&ctx, &mut env);
    }

    let command = build_command(script);

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

    // Compute repo hash for cache isolation
    let repo_hash = if !repo.is_empty() {
        Some(hash_repo(&repo))
    } else {
        None
    };

    // Resolve cache mounts from client request (or empty if none specified)
    // For caches with populate_command: run populate, snapshot, then mount live cache
    let cache_mounts = if job.caches.is_empty() {
        vec![]
    } else {
        // Partition caches: those with populate_command vs without
        let (populate_caches, normal_caches): (Vec<_>, Vec<_>) = job
            .caches
            .clone()
            .into_iter()
            .partition(|c| c.populate_command.is_some());

        // Phase 1: Run populate commands sequentially, then snapshot
        let workspace_storage = crate::cache::detect_storage(&config.cache_dir());
        let mut populated_mounts = Vec::new();
        for cache in &populate_caches {
            // SAFETY: Only called for caches where populate_command.is_some() from partition
            #[allow(clippy::expect_used)]
            let populate_cmd = cache
                .populate_command
                .as_ref()
                .expect("populate_command is Some");
            let cache_host_path = resolve_cache_host_path(cache, &config, repo_hash.as_deref());

            // Ensure data directory exists (as btrfs subvolume if supported)
            let data_path = match crate::cache::snapshots::ensure_data_dir(
                &cache_host_path,
                &workspace_storage,
            ) {
                Ok(path) => path,
                Err(e) => {
                    log_sink.error(
                        &job_id,
                        &format!(
                            "Failed to create cache data dir for {}: {}",
                            cache.bucket, e
                        ),
                    );
                    if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return;
                }
            };

            log_sink.info(
                &job_id,
                &format!(
                    "Populate phase: running '{}' for cache {}",
                    populate_cmd, cache.bucket
                ),
            );

            // Run populate command
            let populate_result = run_populate_phase(
                &job_id,
                cache,
                &data_path,
                proxy.as_ref().map(|p| p.port),
                &executor,
                &job_dir,
                &workspace_dir,
                &env,
                &closure,
                &store_setup,
                hardening_profile,
            )
            .instrument(tracing::info_span!("run_populate_phase", bucket = %cache.bucket))
            .await;

            match populate_result {
                Ok(0) => {
                    log_sink.info(
                        &job_id,
                        &format!("Populate phase completed for cache {}", cache.bucket),
                    );
                }
                Ok(exit_code) => {
                    log_sink.error(
                        &job_id,
                        &format!(
                            "Populate phase failed for cache {} (exit code {})",
                            cache.bucket, exit_code
                        ),
                    );
                    if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return;
                }
                Err(e) => {
                    log_sink.error(
                        &job_id,
                        &format!("Populate phase error for cache {}: {}", cache.bucket, e),
                    );
                    if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return;
                }
            }

            // Create snapshot of the populated cache
            let snapshot_data_path = match crate::cache::snapshots::create_snapshot(
                &cache_host_path,
                populate_cmd,
                &workspace_storage,
            )
            .instrument(tracing::info_span!("create_snapshot", bucket = %cache.bucket))
            .await
            {
                Ok(snapshot_dir) => {
                    log_sink.info(
                        &job_id,
                        &format!("Created snapshot for cache {}", cache.bucket),
                    );

                    // Clean up old snapshots (keep 3)
                    let _ = crate::cache::snapshots::cleanup_snapshots(
                        &cache_host_path,
                        3,
                        &workspace_storage,
                    )
                    .await;

                    // Return path to the data directory inside the snapshot
                    snapshot_dir.join("data")
                }
                Err(e) => {
                    log_sink.error(
                        &job_id,
                        &format!(
                            "Failed to create snapshot for cache {}: {}",
                            cache.bucket, e
                        ),
                    );
                    if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return;
                }
            };

            // Create a working copy from snapshot for this build (CoW on btrfs/reflink)
            // This copy is writable but discarded after job - protects snapshot from corruption
            let working_copies_dir = job_dir.base.join("cache-workcopies");
            let working_copy_path = working_copies_dir.join(&cache.bucket);
            if let Err(e) = std::fs::create_dir_all(&working_copies_dir) {
                log_sink.error(
                    &job_id,
                    &format!("Failed to create working copy dir: {}", e),
                );
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }

            if let Err(e) = crate::cache::snapshot_or_copy(
                &snapshot_data_path,
                &working_copy_path,
                &workspace_storage,
            )
            .instrument(tracing::info_span!("create_working_copy", bucket = %cache.bucket))
            .await
            {
                log_sink.error(
                    &job_id,
                    &format!(
                        "Failed to create working copy for cache {}: {}",
                        cache.bucket, e
                    ),
                );
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }

            log_sink.info(
                &job_id,
                &format!(
                    "Created working copy for cache {} (will be discarded after job)",
                    cache.bucket
                ),
            );

            // Mount the working copy - writable, but discarded with job directory
            let mount_path = if cache.mount_path.is_empty() {
                format!("/{}", cache.bucket)
            } else {
                cache.mount_path.clone()
            };

            populated_mounts.push(ResolvedCacheMount {
                host_path: working_copy_path,
                mount_path,
                env_var: cache.env_var.clone(),
                docker_volume: None,
            });
        }

        // Phase 2: Resolve normal caches (no populate_command)
        let mut mounts = resolve_caches(&normal_caches, &config, repo_hash.as_deref());

        // Add populated cache mounts
        mounts.extend(populated_mounts);

        mounts
    };

    let exec_config = ExecutionConfig {
        job_id: job_id.clone(),
        command,
        env,
        job_dir: job_dir.base.clone(),
        working_dir: exec_working_dir,
        root_dir: job_dir.root.clone(),
        store_setup,
        timeout: std::time::Duration::from_secs(3600),
        store_paths: closure.clone(), // For command path resolution
        proxy_port: proxy.as_ref().map(|p| p.port),
        hardening_profile,
        interactive,
        pty_size: None, // Server mode uses WebSocket for terminal size
        cwd: job.cwd.as_ref().map(|c| workspace_dir.join(c)),
        cache_mounts,
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
            if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
            }
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
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }
        }
        crate::executor::IoHandle::Direct => {
            // Direct mode: stdio inherited, no channel forwarding needed
            // This shouldn't happen in server mode, but handle gracefully
            tracing::warn!(job_id = %job_id, "direct io mode in server context");
            (
                tokio::spawn(async {}), // dummy task
                tokio::spawn(async {}), // dummy task
            )
        }
    };

    let proxy_tasks = if let Some(ref mut proxy) = proxy {
        let proxy_stdout = match proxy.take_stdout() {
            Some(s) => s,
            None => {
                tracing::error!(job_id = %job_id, "proxy stdout not available");
                log_sink.error(&job_id, "proxy stdout not available");
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
                return;
            }
        };

        let proxy_stderr = match proxy.take_stderr() {
            Some(s) => s,
            None => {
                tracing::error!(job_id = %job_id, "proxy stderr not available");
                log_sink.error(&job_id, "proxy stderr not available");
                if let Err(e) = storage.update_job_status(&job_id, JobStatus::Failed) {
                    tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                }
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
    let exit_code = async {
        match handle.exit_code.await {
            Ok(code) => code,
            Err(_) => {
                tracing::warn!("exit code channel closed unexpectedly");
                -1
            }
        }
    }
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

    // Collect stats from alice's metrics endpoints (queried before stop)
    if let Some(ref proxy) = proxy {
        let stats = proxy.collect_stats().await;
        let (approved, denied) = stats.request_counts();
        if approved > 0 || denied > 0 {
            log_sink.info(
                &job_id,
                &format!("Proxy stats: {} approved, {} denied", approved, denied),
            );
        }

        // Record LLM usage metrics
        if let Some(ref m) = metrics_ref {
            for completion in &stats.llm_completions {
                m.record_llm_usage(
                    completion.host.as_deref().unwrap_or("unknown"),
                    "", // credential not tracked per-completion in alice
                    completion.model.as_deref(),
                    completion.input_tokens,
                    completion.output_tokens,
                    completion.cache_read_tokens,
                    completion.tool_calls.as_deref().unwrap_or(&[]),
                );
            }
        }
    }

    let final_status = if exit_code == 0 {
        JobStatus::Completed
    } else {
        JobStatus::Failed
    };

    let msg = format_info(&format!("job completed exit_code={}", exit_code));
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
        exit_code: Some(exit_code),
    }));

    // Handle PR creation if push is enabled
    if job.push && !repo.is_empty() && exit_code == 0 {
        if let Some(before_sha) = head_before {
            match handle_pr_creation(PrCreationContext {
                repo_dir: &workspace_dir,
                job_id: &job_id,
                repo_url: &repo,
                head_before: &before_sha,
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

    if let Err(e) = storage.update_job_status(&job_id, final_status.clone()) {
        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
    }

    // Record job completion metrics (success = exit_code 0)
    metrics_guard.complete(exit_code == 0);

    tracing::info!(exit_code = exit_code, status = %final_status.to_string(), "job completed");

    // Remove job from registry - this closes the broadcast channel
    // so clients stop waiting while we clean up
    registry.remove(&job_id).await;

    // Cleanup root directory and workspace
    // Try executor-specific cleanup first (handles privilege escalation and btrfs on Linux)
    if let Err(e) = executor
        .cleanup_root(&job_dir.root)
        .instrument(tracing::info_span!("cleanup_root"))
        .await
    {
        tracing::warn!(error = %e, "executor cleanup failed, trying direct cleanup");
        if let Err(e) = job_root.cleanup(&job_dir.root) {
            tracing::warn!(error = %e, "failed to cleanup root directory");
        }
    }
    if let Err(e) = executor
        .cleanup_workspace(&job_dir.workspace)
        .instrument(tracing::info_span!("cleanup_workspace"))
        .await
    {
        tracing::warn!(error = %e, "executor workspace cleanup failed, trying direct cleanup");
        if let Err(e) = job_workspace.cleanup(&job_dir.workspace) {
            tracing::warn!(error = %e, "failed to cleanup workspace");
        }
    }
}

// Helper functions

/// Compute a SHA256 hash of a repo URL for cache isolation
fn hash_repo(repo: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(repo.as_bytes());
    let result = hasher.finalize();
    // Return first 12 characters of hex digest
    format!("{:x}", result)[..12].to_string()
}

/// Validate that a bucket name is safe for use as a path component
/// Only alphanumeric characters, hyphens, and underscores are allowed
fn is_valid_bucket_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Resolve cache requests into mount configurations
///
/// The server doesn't define buckets - it accepts any valid bucket name
/// and creates directories dynamically under {cache_dir}/{bucket}/
fn resolve_caches(
    requests: &[CacheRequest],
    config: &ServerConfig,
    repo_hash: Option<&str>,
) -> Vec<ResolvedCacheMount> {
    if !config.cache.enabled {
        return vec![];
    }

    let cache_dir = config.cache_dir();
    let mut mounts = Vec::new();

    for request in requests {
        // Validate bucket name
        if !is_valid_bucket_name(&request.bucket) {
            tracing::warn!(bucket = %request.bucket, "invalid cache bucket name (must be alphanumeric with hyphens/underscores)");
            continue;
        }

        // Validate key
        if !is_valid_bucket_name(&request.key) {
            tracing::warn!(key = %request.key, "invalid cache key (must be alphanumeric with hyphens/underscores)");
            continue;
        }

        // Build host path: {cache_dir}/{bucket}/{scope}/{key}
        let bucket_dir = cache_dir.join(&request.bucket);
        let host_path = match CacheScope::try_from(request.scope).unwrap_or(CacheScope::Shared) {
            CacheScope::PerRepo => {
                if let Some(hash) = repo_hash {
                    find_cache_with_fallbacks(
                        &bucket_dir.join(hash).join(&request.key),
                        &request.fallback_keys,
                        &bucket_dir.join(hash),
                    )
                } else {
                    tracing::warn!(bucket = %request.bucket, "per-repo cache without repo context");
                    continue;
                }
            }
            CacheScope::Shared => find_cache_with_fallbacks(
                &bucket_dir.join(&request.key),
                &request.fallback_keys,
                &bucket_dir,
            ),
        };

        // Use mount_path from request (required)
        let mount_path = if request.mount_path.is_empty() {
            format!("/{}", request.bucket)
        } else {
            request.mount_path.clone()
        };

        mounts.push(ResolvedCacheMount {
            host_path,
            mount_path,
            env_var: request.env_var.clone(),
            docker_volume: None, // Docker volume naming handled by client
        });
    }

    mounts
}

/// Try primary path, then fallbacks in order, returning first existing path or primary
fn find_cache_with_fallbacks(
    primary: &Path,
    fallback_keys: &[String],
    base_path: &Path,
) -> PathBuf {
    if primary.exists() {
        return primary.to_path_buf();
    }

    for fallback_key in fallback_keys {
        if !is_valid_bucket_name(fallback_key) {
            continue;
        }
        let fallback_path = base_path.join(fallback_key);
        if fallback_path.exists() {
            tracing::debug!(
                primary = %primary.display(),
                fallback = %fallback_path.display(),
                "using fallback cache"
            );
            return fallback_path;
        }
    }

    // No cache hit, return primary (will be created)
    primary.to_path_buf()
}

/// Resolve the host path for a cache request (without fallback logic for populate phase)
fn resolve_cache_host_path(
    request: &CacheRequest,
    config: &ServerConfig,
    repo_hash: Option<&str>,
) -> PathBuf {
    let cache_dir = config.cache_dir();
    let bucket_dir = cache_dir.join(&request.bucket);

    match CacheScope::try_from(request.scope).unwrap_or(CacheScope::Shared) {
        CacheScope::PerRepo => {
            if let Some(hash) = repo_hash {
                bucket_dir.join(hash).join(&request.key)
            } else {
                // Fallback to shared if no repo context
                bucket_dir.join(&request.key)
            }
        }
        CacheScope::Shared => bucket_dir.join(&request.key),
    }
}

/// Run the populate phase for a cache with populate_command
///
/// Executes the populate command with:
/// - Network access enabled (via proxy)
/// - Cache mounted writable at the expected location
/// - Same environment as the main job
///
/// Returns the exit code on success, or an error on failure to execute.
#[allow(clippy::too_many_arguments, clippy::expect_used)]
async fn run_populate_phase(
    job_id: &str,
    cache: &CacheRequest,
    data_path: &Path,
    proxy_port: Option<u16>,
    executor: &Arc<dyn Executor>,
    job_dir: &JobDirectory,
    working_dir: &Path,
    env: &HashMap<String, String>,
    closure: &[PathBuf],
    store_setup: &crate::root::StoreSetup,
    hardening_profile: HardeningProfile,
) -> Result<i32, crate::executor::ExecutorError> {
    // SAFETY: Only called for caches where populate_command.is_some() from partition
    let populate_cmd = cache
        .populate_command
        .as_ref()
        .expect("populate_command is Some");

    // Build command: bash -c "populate_command"
    let command = vec!["bash".to_string(), "-c".to_string(), populate_cmd.clone()];

    // Mount path for the cache
    let mount_path = if cache.mount_path.is_empty() {
        format!("/{}", cache.bucket)
    } else {
        cache.mount_path.clone()
    };

    // Create a single cache mount for this populate phase
    let cache_mount = ResolvedCacheMount {
        host_path: data_path.to_path_buf(),
        mount_path: mount_path.clone(),
        env_var: cache.env_var.clone(),
        docker_volume: None,
    };

    // Build environment with cache env var
    let mut populate_env = env.clone();
    if let Some(ref env_var) = cache.env_var {
        let _ = populate_env.insert(env_var.clone(), mount_path);
    }

    let populate_config = ExecutionConfig {
        job_id: format!("{}-populate-{}", job_id, cache.bucket),
        command,
        env: populate_env,
        job_dir: job_dir.base.clone(),
        working_dir: working_dir.to_path_buf(),
        root_dir: job_dir.root.clone(),
        store_setup: store_setup.clone(),
        timeout: std::time::Duration::from_secs(600), // 10 min timeout for populate
        store_paths: closure.to_vec(),
        proxy_port, // Network enabled for populate phase
        hardening_profile,
        interactive: false,
        pty_size: None,
        cwd: None,
        cache_mounts: vec![cache_mount],
    };

    tracing::debug!(
        job_id = %job_id,
        cache = %cache.bucket,
        command = %populate_cmd,
        "starting populate phase"
    );

    let handle = executor.execute(populate_config).await?;

    // Collect output from the populate command for debugging on failure
    let mut output_lines = Vec::new();
    let (mut stdout_rx, mut stderr_rx) = match handle.io {
        crate::executor::IoHandle::Piped { stdout, stderr } => (stdout, stderr),
        crate::executor::IoHandle::Pty { .. } | crate::executor::IoHandle::Direct => {
            // PTY/Direct mode shouldn't happen for populate phase (interactive=false)
            unreachable!("populate phase should never use PTY or Direct mode");
        }
    };

    // Drain stdout/stderr into output buffer
    loop {
        tokio::select! {
            Some(line) = stdout_rx.recv() => {
                output_lines.push(format!("stdout: {}", line));
            }
            Some(line) = stderr_rx.recv() => {
                output_lines.push(format!("stderr: {}", line));
            }
            else => break,
        }
    }

    let exit_code = handle.exit_code.await.unwrap_or(-1);

    // Log output on failure for debugging
    if exit_code != 0 {
        tracing::warn!(
            job_id = %job_id,
            cache = %cache.bucket,
            exit_code,
            output = ?output_lines,
            "populate phase failed"
        );
    } else {
        tracing::debug!(
            job_id = %job_id,
            cache = %cache.bucket,
            "populate phase completed"
        );
    }

    Ok(exit_code)
}

#[allow(clippy::too_many_arguments)]
fn build_environment(
    proxy: Option<&ProxyManager>,
    working_dir: &Path,
    home_dir: &Path,
    workspace_root: &Path,
    proxy_connect_host: &str,
    uses_chroot: bool,
    root_dir: &Path,
    job_env: &HashMap<String, String>,
    server_env: &[(String, String)],
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Set default TERM for proper terminal output (colors, etc.)
    let _ = env.insert("TERM".to_string(), "xterm-256color".to_string());

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
        let _ = env.insert("REQUESTS_CA_BUNDLE".to_string(), ca_cert_path.clone());
        // Cargo maps this to curl's CURLOPT_CAINFO, which works with all TLS
        // backends. SSL_CERT_FILE only works with OpenSSL — macOS curl uses
        // SecureTransport which ignores it, breaking cargo fetch through the proxy.
        let _ = env.insert("CARGO_HTTP_CAINFO".to_string(), ca_cert_path);
        let _ = env.insert("NO_PROXY".to_string(), "localhost,127.0.0.1".to_string());
    }

    // Sandbox isolation - HOME is separate from working_dir in local mode
    // to avoid project's .claude/ shadowing user config
    let home_str = home_dir.to_string_lossy().to_string();
    let _ = env.insert("HOME".to_string(), home_str.clone());

    let _ = env.insert("USER".to_string(), "sbc-admin".to_string());
    let _ = env.insert("LOGNAME".to_string(), "sbc-admin".to_string());

    // XDG Base Directory Specification - isolate application data within sandbox home
    // This ensures tools like OpenCode store their data in the sandbox, not on the host
    let _ = env.insert(
        "XDG_DATA_HOME".to_string(),
        format!("{}/.local/share", home_str),
    );
    let _ = env.insert(
        "XDG_CONFIG_HOME".to_string(),
        format!("{}/.config", home_str),
    );
    let _ = env.insert("XDG_CACHE_HOME".to_string(), format!("{}/.cache", home_str));
    let _ = env.insert(
        "XDG_STATE_HOME".to_string(),
        format!("{}/.local/state", home_str),
    );

    // Temp directory - use /tmp which is isolated by systemd's PrivateTmp=true
    // In chroot mode, /tmp is a private mount; in local mode, use workspace/tmp
    let tmp_dir = if uses_chroot {
        PathBuf::from("/tmp")
    } else {
        working_dir.join("tmp")
    };
    let _ = env.insert("TMPDIR".to_string(), tmp_dir.to_string_lossy().to_string());

    // Set minimal locale with UTF-8 support (C.UTF-8 is available on most Linux systems)
    let _ = env.insert("LANG".to_string(), "C.UTF-8".to_string());
    let _ = env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());

    // macOS: Set SDKROOT to avoid xcrun warnings during Rust builds
    #[cfg(target_os = "macos")]
    {
        let sdk_path = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";
        if std::path::Path::new(sdk_path).exists() {
            let _ = env.insert("SDKROOT".to_string(), sdk_path.to_string());
        }
    }

    // Interpolate placeholders in env var values
    let workspace_root_str = workspace_root.to_string_lossy();
    let interpolate =
        |value: &str| -> String { value.replace("${WORKSPACE_ROOT}", &workspace_root_str) };

    // Merge environment variables with proper precedence:
    // 1. Job-specific env (from request) - applied first, with interpolation
    for (key, value) in job_env {
        let _ = env.insert(key.clone(), interpolate(value));
    }
    // 2. Server defaults (from config) - override job env ("server wins")
    for (key, value) in server_env {
        let _ = env.insert(key.clone(), interpolate(value));
    }

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
        // Partition into plain nixpkgs names and flake installables (store paths,
        // github: refs, path#attr expressions, etc.).
        let (plain, flake): (Vec<&str>, Vec<&str>) = packages
            .iter()
            .map(|s| s.as_str())
            .partition(|p| !workspace::is_flake_installable(p));

        let mut all_paths: Vec<std::path::PathBuf> = Vec::new();

        if !plain.is_empty() {
            // Server mode: in-memory cache only (daemon stays running)
            match workspace::find_nix_packages_cached(&plain, nixpkgs_version, None).await {
                Ok(paths) => {
                    let version_info = nixpkgs_version.unwrap_or("(none)");
                    tracing::info!(packages = ?plain, nixpkgs_version = %version_info, "found nix packages");
                    all_paths.extend(paths);
                }
                Err(e) => {
                    log_sink.error(job_id, &format!("Failed to find packages: {}", e));
                    if let Err(e) = storage.update_job_status(job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return None;
                }
            }
        }

        for installable in &flake {
            match workspace::resolve_flake_installable(installable).await {
                Ok(path) => match workspace::compute_combined_closure(&[path]).await {
                    Ok(closure) => all_paths.extend(closure),
                    Err(e) => {
                        log_sink.error(
                            job_id,
                            &format!("Failed to compute closure for '{}': {}", installable, e),
                        );
                        if let Err(e) = storage.update_job_status(job_id, JobStatus::Failed) {
                            tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                        }
                        return None;
                    }
                },
                Err(e) => {
                    log_sink.error(
                        job_id,
                        &format!(
                            "Failed to resolve flake installable '{}': {}",
                            installable, e
                        ),
                    );
                    if let Err(e) = storage.update_job_status(job_id, JobStatus::Failed) {
                        tracing::error!(job_id = %job_id, error = %e, "failed to update job status");
                    }
                    return None;
                }
            }
        }

        Some(all_paths)
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

fn build_command(script: String) -> Vec<String> {
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
}

/// Configure proxy for network policy enforcement
///
/// Returns the alice proxy config result if network policy has rules,
/// or None if network should be blocked (no policy).
#[allow(clippy::too_many_arguments)]
async fn configure_proxy(
    job_id: &str,
    job_dir: &JobDirectory,
    network_policy: Option<&NetworkPolicy>,
    credentials: &[Credential],
    proxy_listen_addr: &str,
    log_sink: &Arc<dyn LogSink>,
    otlp_endpoint: Option<&str>,
    reverse_proxy: Option<&workspace::ReverseProxySetup>,
) -> Result<Option<workspace::ProxyConfigResult>, OrchestrationError> {
    let has_network_rules = network_policy
        .map(|policy| !policy.rules.is_empty())
        .unwrap_or(false);

    if !has_network_rules && reverse_proxy.is_none() {
        log_sink.info(job_id, "Network access blocked (no policy)");
        return Ok(None);
    }

    let filtered_credentials = filter_credentials(credentials, network_policy);

    let proxy_username = Some(format!("job-{}", job_id));
    let proxy_password = Some(workspace::generate_proxy_password());

    let ca_cert_host_path = crate::proxy_manager::ProxyManager::ca_cert_host_path(&job_dir.root);

    // Use port 0 so the OS assigns a free ephemeral port for the metrics server.
    // This avoids collisions when multiple alice instances run concurrently.
    // The actual bound port is parsed from alice's startup log by ProxyManager.
    let metrics_port = Some(0u16);

    let result = workspace::write_proxy_config(
        &job_dir.base,
        &ca_cert_host_path,
        proxy_listen_addr,
        network_policy.cloned(),
        &filtered_credentials,
        proxy_username,
        proxy_password,
        otlp_endpoint.map(|s| s.to_string()),
        metrics_port,
        reverse_proxy,
    )
    .map_err(|e| OrchestrationError::ProxyConfigError(e.to_string()))?;

    let credential_names: Vec<&str> = filtered_credentials
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    tracing::info!(
        path = %result.config_path.display(),
        credentials = ?credential_names,
        "created alice proxy config"
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

    Ok(Some(result))
}

/// Resolve packages and compute closure
///
/// Handles both flake-based and explicit package resolution.
/// Returns (store_paths, closure).
///
/// # Arguments
/// * `cache_dir` - Directory for persistent disk cache (L2). If None, only in-memory cache is used.
async fn resolve_packages_and_closure(
    job_id: &str,
    packages: &[String],
    nixpkgs_version: Option<&str>,
    flake_source: Option<&workspace::FlakeSource>,
    log_sink: &Arc<dyn LogSink>,
    cache_dir: Option<&Path>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), OrchestrationError> {
    // Resolve explicit packages (if any).
    let mut store_paths = Vec::new();

    if !packages.is_empty() {
        // Partition packages into plain nixpkgs names and flake installables
        let (plain, flake): (Vec<&str>, Vec<&str>) = packages
            .iter()
            .map(|s| s.as_str())
            .partition(|p| !workspace::is_flake_installable(p));

        // Resolve plain nixpkgs packages in a single batch
        if !plain.is_empty() {
            let nixpkgs_paths =
                workspace::find_nix_packages_cached(&plain, nixpkgs_version, cache_dir)
                    .await
                    .map_err(|e| OrchestrationError::PackageError(e.to_string()))?;
            store_paths.extend(nixpkgs_paths);
        }

        // Resolve flake installables individually.  Include their full
        // recursive closure in store_paths so that devShell buildInputs
        // (and any other transitive deps) end up on PATH.
        for installable in &flake {
            let path = workspace::resolve_flake_installable(installable)
                .await
                .map_err(|e| OrchestrationError::PackageError(e.to_string()))?;
            let flake_closure = workspace::compute_combined_closure(&[path])
                .await
                .map_err(|e| OrchestrationError::PackageError(e.to_string()))?;
            store_paths.extend(flake_closure);
        }
    }

    // Merge in devshell closure from detected flake source (if any).
    // This runs alongside explicit packages so the sandbox gets both
    // the requested packages and the project's development toolchain.
    if let Some(source) = flake_source {
        log_sink.info(job_id, &format!("Computing flake closure from {}", source));
        let flake_paths = workspace::compute_flake_closure(source)
            .await
            .map_err(|e| OrchestrationError::FlakeClosureError(e.to_string()))?;
        store_paths.extend(flake_paths);
    }

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

/// Start alice proxy if config result is provided
async fn start_proxy_if_configured(
    job_id: &str,
    job_dir: &JobDirectory,
    proxy_config: Option<workspace::ProxyConfigResult>,
    proxy_listen_addr: &str,
    credentials: &[Credential],
    configured_binary: Option<&Path>,
) -> Result<Option<ProxyManager>, OrchestrationError> {
    let Some(config_result) = proxy_config else {
        return Ok(None);
    };

    let listen_host = proxy_listen_addr
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();

    // Pre-resolve credentials that need orchestrator-level resolution
    // (keychain, opencode auth, inline) and build env var map for alice
    let mut resolved_cred_env = HashMap::new();
    for (i, cred) in credentials.iter().enumerate() {
        let env_var_name = format!("ALICE_CRED_{}", i);
        let needs_resolution = matches!(
            &cred.source,
            CredentialSource::Keychain { .. }
                | CredentialSource::OpenCodeAuth { .. }
                | CredentialSource::Inline { .. }
        );
        if needs_resolution {
            match crate::config::fetch_credential_token(cred).await {
                Ok(token) => {
                    let _ = resolved_cred_env.insert(env_var_name, token);
                }
                Err(e) => {
                    tracing::warn!(
                        credential = %cred.name,
                        error = %e,
                        "failed to resolve credential for alice"
                    );
                }
            }
        }
    }

    let proxy = ProxyManager::start(
        job_id.to_string(),
        job_dir.root.clone(),
        config_result,
        listen_host,
        resolved_cred_env,
        configured_binary,
    )
    .await
    .map_err(|e| OrchestrationError::ProxyStartError(e.to_string()))?;

    tracing::debug!(port = proxy.port, "alice proxy started");
    Ok(Some(proxy))
}

/// Context for setting up credential-related environment variables
struct CredentialsSetupContext<'a> {
    job_id: &'a str,
    working_dir: &'a Path,
    job_dir: &'a JobDirectory,
    credentials: &'a [Credential],
    network_policy: Option<&'a NetworkPolicy>,
    log_sink: &'a Arc<dyn LogSink>,
    insecure_credentials: bool,
    /// Username of the sandboxed process (e.g. "nix-jail"). Used to write files
    /// into the correct home directory under job_dir.root/home/{sandbox_username}/
    sandbox_username: &'a str,
}

/// Setup credential-related environment variables
fn setup_credentials_env(ctx: &CredentialsSetupContext<'_>, env: &mut HashMap<String, String>) {
    let CredentialsSetupContext {
        job_id,
        working_dir,
        job_dir,
        credentials,
        network_policy,
        log_sink,
        insecure_credentials,
        sandbox_username,
    } = ctx;
    let filtered_credentials = filter_credentials(credentials, *network_policy);

    tracing::debug!(
        job_id = %job_id,
        total_credentials = credentials.len(),
        filtered_credentials = filtered_credentials.len(),
        has_claude = has_credential_with_type(&filtered_credentials, CredentialType::Claude),
        insecure = insecure_credentials,
        working_dir = %working_dir.display(),
        "setting up credentials environment"
    );

    // Claude Code credential
    if has_credential_with_type(&filtered_credentials, CredentialType::Claude) {
        tracing::info!(job_id = %job_id, "setting up claude config");
        match workspace::setup_claude_config(
            &job_dir.base,
            working_dir,
            job_id,
            &filtered_credentials,
            *insecure_credentials,
        ) {
            Ok(()) => {
                tracing::info!(job_id = %job_id, "claude config setup succeeded");
                let wrapper_bin = job_dir.base.join("bin");
                if let Some(path) = env.get("PATH").cloned() {
                    let new_path = format!("{}:{}", wrapper_bin.display(), path);
                    tracing::info!(
                        job_id = %job_id,
                        wrapper_bin = %wrapper_bin.display(),
                        new_path = %new_path,
                        "injecting security wrapper into PATH"
                    );
                    let _ = env.insert("PATH".to_string(), new_path);
                }
                log_sink.info(job_id, "Claude Code credentials configured");
            }
            Err(e) => {
                tracing::error!(job_id = %job_id, error = %e, "failed to setup claude config");
                log_sink.info(
                    job_id,
                    &format!("WARNING: Claude config setup failed: {}", e),
                );
            }
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

    // Generic credentials with env var source - inject dummy token
    for cred in filtered_credentials.iter() {
        tracing::info!(
            name = %cred.name,
            credential_type = ?cred.credential_type,
            source = ?cred.source,
            has_dummy = cred.dummy_token.is_some(),
            "checking credential for env injection"
        );
        if matches!(cred.credential_type, CredentialType::Generic) {
            if let CredentialSource::Environment { source_env } = &cred.source {
                if let Some(ref dummy_token) = cred.dummy_token {
                    let _ = env.insert(source_env.clone(), dummy_token.clone());
                    log_sink.info(
                        job_id,
                        &format!("{} configured (proxy will inject real token)", source_env),
                    );
                }
            }
        }
    }

    // OpenCodeAuth credentials - write dummy auth.json into sandbox so the opencode
    // auth plugin reads the dummy token and sets Authorization: Bearer <dummy>.
    // Alice then swaps the dummy for the real OAuth token in-flight.
    for cred in filtered_credentials.iter() {
        if let CredentialSource::OpenCodeAuth {
            opencode_provider_id,
        } = &cred.source
        {
            if let Some(ref dummy_token) = cred.dummy_token {
                let auth_dir = job_dir
                    .root
                    .join(format!("home/{}/.local/share/opencode", sandbox_username));
                if let Err(e) = std::fs::create_dir_all(&auth_dir) {
                    tracing::warn!(error = %e, "failed to create opencode auth dir in sandbox");
                    continue;
                }
                let auth_json = serde_json::json!({
                    opencode_provider_id: {
                        "type": "oauth",
                        "access": dummy_token,
                        "refresh": "dummy-refresh-token",
                        "expires": 4102444800000_u64  // 2100-01-01
                    }
                });
                let auth_path = auth_dir.join("auth.json");
                match std::fs::write(&auth_path, auth_json.to_string()) {
                    Ok(()) => {
                        tracing::info!(
                            provider = %opencode_provider_id,
                            path = %auth_path.display(),
                            "wrote dummy auth.json into sandbox for oauth credential injection"
                        );
                        // Chown the .local tree to the sandbox user so opencode can write
                        // subdirectories (e.g. bin/) inside .local/share/opencode at runtime.
                        // The daemon runs as root and create_dir_all creates dirs owned by
                        // root; without this chown opencode gets EACCES.
                        let local_dir = job_dir
                            .root
                            .join(format!("home/{}/.local", sandbox_username));
                        let owner = format!("{}:{}", sandbox_username, sandbox_username);
                        match std::process::Command::new("chown")
                            .args(["-R", &owner, &local_dir.to_string_lossy()])
                            .output()
                        {
                            Ok(out) if !out.status.success() => {
                                tracing::warn!(
                                    stderr = %String::from_utf8_lossy(&out.stderr),
                                    "chown opencode auth dir failed"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to run chown on opencode auth dir");
                            }
                            Ok(_) => {}
                        }
                        log_sink.info(
                            job_id,
                            &format!(
                                "opencode {} oauth configured (proxy will inject real token)",
                                opencode_provider_id
                            ),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %auth_path.display(),
                            "failed to write dummy auth.json into sandbox"
                        );
                    }
                }
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

    // Find credential matching the repo host
    let cred = find_credential_for_host(&config.credentials, repo_url).ok_or_else(|| {
        workspace::WorkspaceError::InvalidPath(format!(
            "no credential matches repo host for {}",
            repo_url
        ))
    })?;

    let token = crate::config::fetch_credential_token(cred)
        .await
        .map_err(|e| {
            workspace::WorkspaceError::InvalidPath(format!("failed to fetch credential: {}", e))
        })?;

    let auth_header_value = cred.header_format.replace("{token}", &token);

    // Push the new branch
    log_sink.info(
        job_id,
        &format!("Pushing branch '{}' to remote...", pr_branch),
    );

    workspace::git_refs::push_branch(repo_dir, &pr_branch, &token)?;

    // Create PR: job-${jobID} -> main
    let base_branch = "main";
    log_sink.info(
        job_id,
        &format!("Creating pull request: {} -> {}", pr_branch, base_branch),
    );

    let (pr_number, pr_url) = workspace::pr::create_pull_request(
        repo_url,
        &pr_branch,
        base_branch,
        &commits,
        &auth_header_value,
    )
    .await?;

    // Request auto-merge (logs result, does not fail the PR creation)
    log_sink.info(job_id, "Requesting auto-merge...");
    if let Err(e) =
        workspace::pr::auto_merge_pull_request(repo_url, pr_number, &auth_header_value).await
    {
        tracing::warn!(job_id = %job_id, error = %e, "auto-merge request failed");
        log_sink.info(job_id, &format!("Auto-merge request failed: {}", e));
    }

    Ok(pr_url)
}

/// Configuration for local (serverless) execution
pub struct LocalExecutionConfig {
    /// Nix packages to include in the environment
    pub packages: Vec<String>,

    /// Command to execute (e.g., ["bash", "-c", "..."])
    pub command: Vec<String>,

    /// Working directory for execution (mounted as workspace in sandbox)
    pub working_dir: PathBuf,

    /// Override the process CWD independently of the workspace mount.
    ///
    /// When set, the sandboxed process starts in this directory instead of
    /// `working_dir`. Must be a path within `working_dir`. Also used for
    /// flake/devshell auto-detection (reads `.envrc` from here).
    pub cwd: Option<PathBuf>,

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

    /// Additional environment variables
    pub env: Vec<(String, String)>,

    /// Pass real credentials to sandbox (INSECURE - for debugging only)
    pub insecure_credentials: bool,

    /// OpenTelemetry OTLP endpoint for proxy tracing
    pub otlp_endpoint: Option<String>,

    /// Explicit path to alice proxy binary (overrides PATH lookup)
    pub proxy_binary: Option<PathBuf>,
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
            .field("insecure_credentials", &self.insecure_credentials)
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

    // Detect flake source (local flake.nix or .envrc with use flake).
    // When a separate cwd is provided (e.g. project subdir inside a monorepo),
    // look there for the .envrc / flake.nix so we pick up the right devshell.
    let flake_detect_dir = config.cwd.as_deref().unwrap_or(&config.working_dir);
    let flake_source = workspace::flake::detect_flake_source(flake_detect_dir);

    // Phase 1: Create alice proxy config if needed
    let proxy_config = configure_proxy(
        &job_id,
        &job_dir,
        config.network_policy.as_ref(),
        &config.credentials,
        executor.proxy_listen_addr(),
        &log_sink,
        config.otlp_endpoint.as_deref(),
        None, // TODO: wire reverse_proxy setup after executor refactor
    )
    .await?;

    // Phase 2: Resolve packages and compute closure
    // CLI mode: use disk cache for persistence across process restarts
    let (store_paths, closure) = resolve_packages_and_closure(
        &job_id,
        &config.packages,
        config.nixpkgs_version.as_deref(),
        flake_source.as_ref(),
        &log_sink,
        Some(&state_dir),
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

    // Create FHS-compatible symlinks (/bin/sh, /usr/bin/env) for scripts with shebangs
    if let Err(e) = crate::executor::exec::create_fhs_symlinks(&job_dir.root, &closure) {
        log_sink.error(&job_id, &format!("Failed to create FHS symlinks: {}", e));
        // Non-fatal: continue execution, scripts might still work
    }

    // Create /etc/hosts for localhost resolution
    if let Err(e) = crate::executor::exec::create_etc_hosts(&job_dir.root) {
        log_sink.error(&job_id, &format!("Failed to create /etc/hosts: {}", e));
        // Non-fatal: continue execution
    }

    // Create sandbox home directory (/home/{user} with XDG subdirs)
    let sandbox_user = executor.sandbox_user();
    if let Err(e) = crate::executor::exec::create_home_directory(&job_dir.root, sandbox_user) {
        log_sink.error(&job_id, &format!("Failed to create home directory: {}", e));
        // Non-fatal: continue execution
    }

    // Phase 4: Start alice proxy if configured
    let mut proxy = start_proxy_if_configured(
        &job_id,
        &job_dir,
        proxy_config,
        executor.proxy_listen_addr(),
        &config.credentials,
        config.proxy_binary.as_deref(),
    )
    .await?;

    // Phase 5: Build environment
    // Create tmp directory for the job
    let tmp_dir = config.working_dir.join("tmp");
    let _ = std::fs::create_dir_all(&tmp_dir);

    // Chown job directory to sandbox user so jobs can write to it
    // (daemon runs as root, jobs run as sandbox user)
    // Skip chown when sandbox_user is None (e.g., macOS sandbox-exec runs as current user)
    if let Some((user, group)) = sandbox_user {
        let owner = format!("{}:{}", user, group);
        if let Err(e) = std::process::Command::new("chown")
            .args(["-R", &owner, &job_dir.base.to_string_lossy()])
            .output()
        {
            tracing::warn!(job_id = %job_id, error = %e, "failed to chown job directory");
        }
    }

    // Configure execution environment
    // Home directory is always under root/home/{user}/, but path representation differs:
    // - Chroot mode: $HOME=/home/{user} (relative to chroot)
    // - Non-chroot mode: $HOME={job_dir.root}/home/{user} (absolute host path)
    let user = sandbox_user.map(|(u, _)| u).unwrap_or("sandbox");
    let (home_dir_for_env, workspace_root_for_env) = if executor.uses_chroot() {
        (
            PathBuf::from(format!("/home/{}", user)),
            PathBuf::from("/workspace"),
        )
    } else {
        (
            job_dir.root.join(format!("home/{}", user)),
            config.working_dir.clone(),
        )
    };

    let mut env = build_environment(
        proxy.as_ref(),
        &config.working_dir,
        &home_dir_for_env,
        &workspace_root_for_env,
        executor.proxy_connect_host(),
        executor.uses_chroot(),
        &job_dir.root,
        &HashMap::new(), // No job-specific env in local mode
        &config.env,     // Local config env acts as server defaults
    );

    // Update PATH, NIX_LDFLAGS, NIX_CFLAGS_COMPILE with package paths
    // (skip for DockerVolume - paths are different architecture)
    if !store_paths.is_empty()
        && !matches!(store_setup, crate::root::StoreSetup::DockerVolume { .. })
    {
        let path_env = workspace::build_path_env(&store_paths);
        let current_path = env.get("PATH").cloned().unwrap_or_default();
        let _ = env.insert("PATH".to_string(), format!("{}:{}", path_env, current_path));

        // Set NIX_LDFLAGS for linker to find libraries (e.g., libiconv)
        let ldflags = workspace::build_ldflags_env(&store_paths);
        if !ldflags.is_empty() {
            let _ = env.insert("NIX_LDFLAGS".to_string(), ldflags);
        }

        // Set NIX_CFLAGS_COMPILE for compiler to find headers
        let cflags = workspace::build_cflags_env(&store_paths);
        if !cflags.is_empty() {
            let _ = env.insert("NIX_CFLAGS_COMPILE".to_string(), cflags);
        }

        // Set LIBRARY_PATH for linkers (rustc/cc) that don't use NIX_LDFLAGS
        let lib_path = workspace::build_library_path_env(&store_paths);
        if !lib_path.is_empty() {
            let _ = env.insert("LIBRARY_PATH".to_string(), lib_path);
        }

        // Set PKG_CONFIG_PATH for pkg-config to find .pc files (e.g., openssl.pc)
        let pkg_config_path = workspace::build_pkg_config_path_env(&store_paths);
        if !pkg_config_path.is_empty() {
            let _ = env.insert("PKG_CONFIG_PATH".to_string(), pkg_config_path);
        }

        // Prevent openssl-sys from vendoring OpenSSL - use system OpenSSL via pkg-config
        let _ = env.insert("OPENSSL_NO_VENDOR".to_string(), "1".to_string());

        // Set SHELL to nix-managed zsh or bash if available and not already overridden
        if !env.contains_key("SHELL") {
            if let Some(shell) = workspace::find_shell(&store_paths) {
                tracing::info!(shell = %shell.display(), "setting SHELL from store paths");
                let _ = env.insert("SHELL".to_string(), shell.display().to_string());
            }
        }
    }

    // Configure credentials in home directory (host filesystem path for writing files)
    let home_dir_host = job_dir.root.join(format!("home/{}", user));
    let ctx = CredentialsSetupContext {
        job_id: &job_id,
        working_dir: &home_dir_host,
        job_dir: &job_dir,
        credentials: &config.credentials,
        network_policy: config.network_policy.as_ref(),
        log_sink: &log_sink,
        insecure_credentials: config.insecure_credentials,
        sandbox_username: user,
    };
    setup_credentials_env(&ctx, &mut env);

    // Phase 6: Execute
    // Note: Local execution doesn't have repo context, so no cache mounts
    let exec_config = ExecutionConfig {
        job_id: job_id.clone(),
        command: config.command,
        env,
        job_dir: job_dir.base.clone(),
        working_dir: config.working_dir.clone(),
        root_dir: job_dir.root.clone(),
        store_setup,
        timeout: std::time::Duration::from_secs(3600),
        store_paths: closure.clone(),
        proxy_port: proxy.as_ref().map(|p| p.port),
        hardening_profile: config.hardening_profile,
        interactive: config.interactive,
        pty_size: config.pty_size,
        cwd: config.cwd,
        cache_mounts: vec![], // No caching for local execution
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
    // In PTY mode, stdout_task is the stdin forwarder which blocks on user input
    // and must be aborted when the job exits
    let (stdout_task, stderr_task, is_pty_mode) = match handle.io {
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

            (stdout_task, stderr_task, false)
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

            // Return (stdin_task, stdout_task, true) - stdin needs to be aborted on exit
            // since it blocks forever on user input
            (stdin_task, stdout_task, true)
        }
        crate::executor::IoHandle::Direct => {
            // Direct mode: stdio inherited by child process, no forwarding needed
            // systemd-run --pty handles terminal I/O directly
            (
                tokio::spawn(async {}), // dummy task
                tokio::spawn(async {}), // dummy task
                false,                  // no stdin task to abort
            )
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
    let exit_code = match handle.exit_code.await {
        Ok(code) => code,
        Err(_) => {
            tracing::warn!("exit code channel closed unexpectedly");
            -1
        }
    };

    // Cleanup
    if let Some(ref mut p) = proxy {
        p.stop().await;
    }

    // In PTY mode, stdout_task is actually stdin forwarder which blocks on read
    // We must abort it since it won't complete on its own
    if is_pty_mode {
        stdout_task.abort();
        if let Some((pout, perr)) = proxy_tasks {
            let _ = tokio::join!(stderr_task, pout, perr);
        } else {
            let _ = stderr_task.await;
        }
    } else if let Some((pout, perr)) = proxy_tasks {
        let _ = tokio::join!(stdout_task, stderr_task, pout, perr);
    } else {
        let _ = tokio::join!(stdout_task, stderr_task);
    }

    // Collect stats from alice's metrics endpoints (queried before stop)
    if let Some(ref proxy) = proxy {
        let stats = proxy.collect_stats().await;
        let (approved, denied) = stats.request_counts();
        if approved > 0 || denied > 0 {
            log_sink.info(
                &job_id,
                &format!("Proxy stats: {} approved, {} denied", approved, denied),
            );
        }

        // Log LLM usage stats
        for completion in &stats.llm_completions {
            if let Some(ref model) = completion.model {
                tracing::info!(
                    model = %model,
                    input_tokens = completion.input_tokens.unwrap_or(0),
                    output_tokens = completion.output_tokens.unwrap_or(0),
                    cache_read_tokens = completion.cache_read_tokens.unwrap_or(0),
                    "llm usage"
                );
            }
        }
    }

    log_sink.done(&job_id, exit_code);

    // Cleanup job directory
    // Try executor-specific cleanup first (handles privilege escalation on Linux)
    if let Err(e) = executor.cleanup_root(&job_dir.root).await {
        tracing::warn!(error = %e, "executor cleanup failed, trying direct cleanup");
        // Fall back to JobRoot cleanup
        if let Err(e) = job_root.cleanup(&job_dir.root) {
            tracing::warn!(error = %e, "failed to cleanup root directory");
        }
    }

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialSource;

    fn test_server_credential(name: &str) -> Credential {
        Credential {
            name: name.to_string(),
            credential_type: CredentialType::Generic,
            source: CredentialSource::Environment {
                source_env: "TEST_TOKEN".to_string(),
            },
            allowed_host_patterns: vec!["api.example.com".to_string()],
            header_format: "Bearer {token}".to_string(),
            dummy_token: None,
            redact_response: true,
            redact_paths: vec![r"/oauth/token".to_string(), r"/token$".to_string()],
            extract_llm_metrics: false,
            llm_provider: None,
        }
    }

    fn test_ephemeral_credential(name: &str) -> EphemeralCredential {
        EphemeralCredential {
            name: name.to_string(),
            token: "ephemeral-secret-token".to_string(),
            allowed_hosts: vec!["github.com".to_string()],
            header_format: "token {token}".to_string(),
        }
    }

    #[test]
    fn test_merge_ephemeral_credentials_empty() {
        let server = vec![test_server_credential("github")];
        let ephemeral: Vec<EphemeralCredential> = vec![];

        let merged = merge_ephemeral_credentials(&server, &ephemeral);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "github");
    }

    #[test]
    fn test_merge_ephemeral_credentials_additive() {
        let server = vec![test_server_credential("github")];
        let ephemeral = vec![test_ephemeral_credential("my-token")];

        let merged = merge_ephemeral_credentials(&server, &ephemeral);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|c| c.name == "github"));
        assert!(merged.iter().any(|c| c.name == "my-token"));
    }

    #[test]
    fn test_merge_ephemeral_credentials_override() {
        let server = vec![test_server_credential("github")];
        let ephemeral = vec![test_ephemeral_credential("github")]; // Same name

        let merged = merge_ephemeral_credentials(&server, &ephemeral);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "github");
        // Verify it's the ephemeral one (Inline source)
        assert!(matches!(merged[0].source, CredentialSource::Inline { .. }));
    }

    #[test]
    fn test_merge_ephemeral_credentials_multiple_override() {
        let server = vec![
            test_server_credential("github"),
            test_server_credential("anthropic"),
        ];
        let ephemeral = vec![
            test_ephemeral_credential("github"),   // Override
            test_ephemeral_credential("new-cred"), // Add
        ];

        let merged = merge_ephemeral_credentials(&server, &ephemeral);
        assert_eq!(merged.len(), 3);

        // anthropic should be from server (Environment source)
        let anthropic = merged.iter().find(|c| c.name == "anthropic").unwrap();
        assert!(matches!(
            anthropic.source,
            CredentialSource::Environment { .. }
        ));

        // github should be from ephemeral (Inline source)
        let github = merged.iter().find(|c| c.name == "github").unwrap();
        assert!(matches!(github.source, CredentialSource::Inline { .. }));

        // new-cred should be from ephemeral (Inline source)
        let new_cred = merged.iter().find(|c| c.name == "new-cred").unwrap();
        assert!(matches!(new_cred.source, CredentialSource::Inline { .. }));
    }

    #[test]
    fn test_ephemeral_credential_conversion() {
        let ec = test_ephemeral_credential("test-cred");
        let cred = Credential::from(&ec);

        assert_eq!(cred.name, "test-cred");
        assert_eq!(cred.credential_type, CredentialType::Generic);
        assert!(
            matches!(cred.source, CredentialSource::Inline { ref token } if token == "ephemeral-secret-token")
        );
        assert_eq!(cred.allowed_host_patterns, vec!["github.com".to_string()]);
        assert_eq!(cred.header_format, "token {token}");
        // redact_response defaults to true for security
        assert!(cred.redact_response);
        assert!(!cred.extract_llm_metrics);
    }

    #[test]
    fn test_build_environment_xdg_vars() {
        let working_dir = PathBuf::from("/workspace");
        let home_dir = PathBuf::from("/sandbox/home");
        let workspace_root = PathBuf::from("/workspace");
        let root_dir = PathBuf::from("/sandbox/root");

        let env = build_environment(
            None, // No proxy
            &working_dir,
            &home_dir,
            &workspace_root,
            "127.0.0.1",
            false, // No chroot
            &root_dir,
            &HashMap::new(),
            &[],
        );

        // Verify XDG vars are set relative to home_dir
        assert_eq!(
            env.get("XDG_DATA_HOME").unwrap(),
            "/sandbox/home/.local/share"
        );
        assert_eq!(env.get("XDG_CONFIG_HOME").unwrap(), "/sandbox/home/.config");
        assert_eq!(env.get("XDG_CACHE_HOME").unwrap(), "/sandbox/home/.cache");
        assert_eq!(
            env.get("XDG_STATE_HOME").unwrap(),
            "/sandbox/home/.local/state"
        );

        // Verify HOME is set
        assert_eq!(env.get("HOME").unwrap(), "/sandbox/home");
    }

    #[test]
    fn test_build_environment_env_merging_server_wins() {
        let working_dir = PathBuf::from("/workspace");
        let home_dir = PathBuf::from("/sandbox/home");
        let root_dir = PathBuf::from("/sandbox/root");

        // Job env: set both a unique var and one that conflicts with server
        let mut job_env = HashMap::new();
        let _ = job_env.insert("JOB_SPECIFIC".to_string(), "from-job".to_string());
        let _ = job_env.insert("SHARED_VAR".to_string(), "from-job".to_string());

        // Server env: set a server-specific var and override the shared one
        let server_env = vec![
            ("SERVER_SPECIFIC".to_string(), "from-server".to_string()),
            ("SHARED_VAR".to_string(), "from-server".to_string()),
        ];

        let env = build_environment(
            None,
            &working_dir,
            &home_dir,
            &working_dir,
            "127.0.0.1",
            false,
            &root_dir,
            &job_env,
            &server_env,
        );

        // Job-specific var should be present
        assert_eq!(env.get("JOB_SPECIFIC").unwrap(), "from-job");

        // Server-specific var should be present
        assert_eq!(env.get("SERVER_SPECIFIC").unwrap(), "from-server");

        // Shared var should be from server (server wins)
        assert_eq!(env.get("SHARED_VAR").unwrap(), "from-server");
    }

    #[test]
    fn test_build_environment_opencode_sandbox_vars() {
        let working_dir = PathBuf::from("/workspace");
        let home_dir = PathBuf::from("/sandbox/home");
        let root_dir = PathBuf::from("/sandbox/root");

        // Simulate OpenCode sandbox configuration
        let server_env = vec![
            (
                "OPENCODE_DISABLE_LSP_DOWNLOAD".to_string(),
                "true".to_string(),
            ),
            (
                "OPENCODE_DISABLE_AUTOUPDATE".to_string(),
                "true".to_string(),
            ),
            (
                "OPENCODE_DISABLE_MODELS_FETCH".to_string(),
                "true".to_string(),
            ),
            (
                "ANTHROPIC_API_KEY".to_string(),
                "opencode-anthropic-dummy".to_string(),
            ),
        ];

        let env = build_environment(
            None,
            &working_dir,
            &home_dir,
            &working_dir,
            "127.0.0.1",
            false,
            &root_dir,
            &HashMap::new(),
            &server_env,
        );

        // Verify OpenCode sandbox vars are set
        assert_eq!(env.get("OPENCODE_DISABLE_LSP_DOWNLOAD").unwrap(), "true");
        assert_eq!(env.get("OPENCODE_DISABLE_AUTOUPDATE").unwrap(), "true");
        assert_eq!(env.get("OPENCODE_DISABLE_MODELS_FETCH").unwrap(), "true");
        assert_eq!(
            env.get("ANTHROPIC_API_KEY").unwrap(),
            "opencode-anthropic-dummy"
        );

        // Verify XDG vars are also set (for OpenCode data isolation)
        assert!(env.contains_key("XDG_DATA_HOME"));
        assert!(env.contains_key("XDG_CONFIG_HOME"));
    }

    #[test]
    fn test_build_environment_workspace_root_interpolation() {
        let working_dir = PathBuf::from("/workspace/project");
        let home_dir = PathBuf::from("/sandbox/home");
        let workspace_root = PathBuf::from("/workspace");
        let root_dir = PathBuf::from("/sandbox/root");

        // Job env with ${WORKSPACE_ROOT} placeholder
        let mut job_env = HashMap::new();
        let _ = job_env.insert(
            "MEOW_REPO_PATH".to_string(),
            "${WORKSPACE_ROOT}".to_string(),
        );
        let _ = job_env.insert(
            "SOME_PATH".to_string(),
            "${WORKSPACE_ROOT}/subdir".to_string(),
        );
        let _ = job_env.insert("NORMAL_VAR".to_string(), "unchanged".to_string());

        let env = build_environment(
            None,
            &working_dir,
            &home_dir,
            &workspace_root,
            "127.0.0.1",
            false,
            &root_dir,
            &job_env,
            &[],
        );

        // ${WORKSPACE_ROOT} should be replaced with actual path
        assert_eq!(env.get("MEOW_REPO_PATH").unwrap(), "/workspace");
        assert_eq!(env.get("SOME_PATH").unwrap(), "/workspace/subdir");

        // Normal vars should be unchanged
        assert_eq!(env.get("NORMAL_VAR").unwrap(), "unchanged");
    }

    #[test]
    fn test_version_info_available_at_compile_time() {
        // Verify the build.rs env var is set and contains a reasonable value
        let version = env!("NIX_JAIL_VERSION");

        // Version should look like semver (e.g., "0.15.6")
        assert!(
            version.contains('.'),
            "version should contain dots: {}",
            version
        );

        // Format string should work
        let formatted = format!("nix-jail v{} job=test", version);
        assert!(formatted.starts_with("nix-jail v"));
        assert!(formatted.contains("job="));
    }

    #[test]
    fn test_version_logged_via_log_sink() {
        use crate::log_sink::test_helpers::CapturingLogSink;

        let sink = CapturingLogSink::new();
        let job_id = "test-job-123";

        // Simulate what execute_job does
        sink.info(
            job_id,
            &format!("nix-jail v{} job={}", env!("NIX_JAIL_VERSION"), job_id),
        );

        // Verify the message was logged
        assert!(
            sink.contains("nix-jail v"),
            "version prefix not found in logs"
        );
        assert!(
            sink.contains(env!("NIX_JAIL_VERSION")),
            "version number not found in logs"
        );
        assert!(sink.contains("job="), "job_id not found in logs");

        // Check it's the first message
        let messages = sink.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, job_id);
    }
}
