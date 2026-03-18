use std::sync::Arc;
use std::time::SystemTime;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::cache::CacheManager;
use crate::config;
use crate::jail::jail_service_server::JailService;
use crate::jail::{
    CancelJobRequest, CancelJobResponse, JobLifecycleEvent, JobRequest, JobResponse, LogEntry,
    StreamJobEventsRequest, StreamRequest,
};
use crate::job_workspace::JobWorkspace;
use crate::orchestration;
use crate::storage::{JobMetadata, JobStatus, JobStorage};
use crate::validation;
use ulid::Ulid;

/// Extract OpenTelemetry trace context from incoming gRPC request metadata
fn extract_trace_context<T>(request: &Request<T>) -> opentelemetry::Context {
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    let propagator = TraceContextPropagator::new();
    let extractor = MetadataExtractor(request.metadata());
    propagator.extract(&extractor)
}

/// Helper to extract trace context from tonic metadata
struct MetadataExtractor<'a>(&'a tonic::metadata::MetadataMap);

impl opentelemetry::propagation::Extractor for MetadataExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .filter_map(|k| match k {
                tonic::metadata::KeyRef::Ascii(key) => Some(key.as_str()),
                tonic::metadata::KeyRef::Binary(_) => None,
            })
            .collect()
    }
}

/// Configuration for creating a JailServiceImpl
pub struct JailServiceConfig {
    pub storage: JobStorage,
    pub config: config::ServerConfig,
    pub registry: crate::job_registry::JobRegistry,
    pub cache_manager: CacheManager,
    pub executor: Arc<dyn crate::executor::Executor>,
    pub job_root: Arc<dyn crate::job_dir::JobRoot>,
    pub job_workspace: Arc<dyn JobWorkspace>,
    pub session_registry: Arc<crate::session::SessionRegistry>,
    pub metrics: Option<crate::metrics::SharedMetrics>,
}

impl std::fmt::Debug for JailServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailServiceConfig")
            .field("executor", &self.executor.name())
            .finish_non_exhaustive()
    }
}

/// gRPC service implementation
#[derive(Clone)]
pub struct JailServiceImpl {
    storage: JobStorage,
    config: config::ServerConfig,
    registry: crate::job_registry::JobRegistry,
    cache_manager: CacheManager,
    executor: Arc<dyn crate::executor::Executor>,
    job_root: Arc<dyn crate::job_dir::JobRoot>,
    job_workspace: Arc<dyn JobWorkspace>,
    session_registry: Arc<crate::session::SessionRegistry>,
    metrics: Option<crate::metrics::SharedMetrics>,
}

impl std::fmt::Debug for JailServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailServiceImpl")
            .field("storage", &self.storage)
            .field("config", &self.config)
            .field("registry", &self.registry)
            .field("cache_manager", &self.cache_manager)
            .field("executor", &self.executor.name())
            .field("job_root", &self.job_root)
            .field("job_workspace", &self.job_workspace)
            .field("session_registry", &self.session_registry)
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

impl JailServiceImpl {
    pub fn new(cfg: JailServiceConfig) -> Self {
        Self {
            storage: cfg.storage,
            config: cfg.config,
            registry: cfg.registry,
            cache_manager: cfg.cache_manager,
            executor: cfg.executor,
            job_root: cfg.job_root,
            job_workspace: cfg.job_workspace,
            session_registry: cfg.session_registry,
            metrics: cfg.metrics,
        }
    }
}

#[tonic::async_trait]
impl JailService for JailServiceImpl {
    async fn submit_job(
        &self,
        request: Request<JobRequest>,
    ) -> Result<Response<JobResponse>, Status> {
        // Extract parent trace context from client and create instrumented span
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.submit_job");
        let _ = span.set_parent(parent_context);

        let mut req = request.into_inner();
        let this = self.clone();

        async move {
        // Apply job profile defaults before validation so the profile can supply
        // the script, network policy, env vars, etc.
        // Profiles are applied left-to-right; additive fields accumulate,
        // singular fields (script, hardening, etc.) are set by the first profile
        // that supplies them. Explicit request fields always win.
        for profile_name in &req.profiles.clone() {
            match this.config.load_profile(profile_name) {
                Ok(profile) => {
                    tracing::info!(profile = %profile_name, "applying job profile");
                    profile.apply_defaults_to(&mut req, &this.config.credentials, &this.config.shells);
                }
                Err(e) => {
                    tracing::warn!(profile = %profile_name, error = %e, "failed to load profile");
                    return Err(Status::invalid_argument(format!(
                        "unknown profile {profile_name:?}: {e}"
                    )));
                }
            }
        }

        // Validation (after profile application so profile-supplied values are checked)
        validation::validate_script(&req.script)?;
        if !req.repo.is_empty() {
            validation::validate_repo(&req.repo)?;
            validation::validate_path(&req.path)?;

            if let Some(ref git_ref_val) = req.git_ref {
                validation::validate_ref(git_ref_val)?;
            }
        }
        if let Some(ref policy) = req.network_policy {
            validation::validate_network_policy(policy, &this.config.credentials)?;
            tracing::debug!("validated network policy with {} rules", policy.rules.len());
        }
        if let Some(ref nixpkgs_version) = req.nixpkgs_version {
            validation::validate_nixpkgs_version(nixpkgs_version)?;
        }
        // Validate ephemeral credentials (never log token values!)
        if !req.ephemeral_credentials.is_empty() {
            validation::validate_ephemeral_credentials(&req.ephemeral_credentials)?;
            tracing::debug!(
                count = req.ephemeral_credentials.len(),
                "validated ephemeral credentials"
            );
        }

        let job_id = Ulid::new().to_string();
        let interactive = req.interactive.unwrap_or(false);

        // Append a short job-ID suffix to any requested subdomain so each job
        // gets a fresh browser origin → fresh localStorage → no stale opencode
        // session state from a previous job with the same name.
        // E.g. "opencode" → "opencode-8qsr7k" (last 6 chars of ULID, lowercased).
        if let Some(ref base) = req.subdomain.clone() {
            if !base.is_empty() {
                let suffix = job_id[job_id.len() - 6..].to_ascii_lowercase();
                req.subdomain = Some(format!("{base}-{suffix}"));
            }
        }

        tracing::info!(
            job_id = %job_id,
            packages = ?req.packages,
            repo = %req.repo,
            git_ref = %req.git_ref.as_deref().unwrap_or("(none)"),
            path = %req.path,
            nixpkgs_version = %req.nixpkgs_version.as_deref().unwrap_or("(none)"),
            hardening_profile = %req.hardening_profile.as_deref().unwrap_or("default"),
            interactive = interactive,
            "job received"
        );

        // Save job metadata with Running status
        let job_metadata = JobMetadata {
            id: job_id.clone(),
            repo: req.repo.clone(),
            path: req.path.clone(),
            script: req.script.clone(),
            packages: req.packages.clone(),
            network_policy: req.network_policy.clone(),
            nixpkgs_version: req.nixpkgs_version.clone(),
            git_ref: req.git_ref.clone(),
            hardening_profile: req.hardening_profile.clone(),
            push: req.push.unwrap_or(false),
            caches: req.caches.clone(),
            extra_paths: req.extra_paths.clone(),
            cwd: req.cwd.clone(),
            subdomain: req.subdomain.clone(),
            service_port: req.service_port,
            no_cleanup: req.no_cleanup.unwrap_or(false),
            status: JobStatus::Running,
            created_at: SystemTime::now(),
            completed_at: None,
        };
        this.storage
            .save_job(&job_metadata)
            .map_err(|e| Status::internal(format!("Failed to save job: {}", e)))?;

        // Start job execution in background
        let job_for_exec = job_metadata.clone();
        let storage_for_exec = this.storage.clone();
        let config_for_exec = this.config.clone();
        let registry_for_exec = this.registry.clone();
        let executor_for_exec = this.executor.clone();
        let job_root_for_exec = this.job_root.clone();
        let job_workspace_for_exec = this.job_workspace.clone();
        let metrics_for_exec = this.metrics.clone();
        // Ephemeral credentials are NOT saved to JobMetadata (security: never persist)
        let ephemeral_credentials_for_exec = req.ephemeral_credentials.clone();
        // Job-specific env vars (not saved to JobMetadata, merged with server defaults)
        let job_env_for_exec = req.env.clone();

        // Create broadcast channel for this job
        let (log_tx, _) = tokio::sync::broadcast::channel(1000);
        let log_tx_for_exec = log_tx.clone();

        // Generate WebSocket URL and register session if interactive
        let (websocket_url, session_registry_for_exec) = if interactive {
            // Register session for token validation (channels added by executor)
            let token = this.session_registry.register(job_id.clone()).await;

            // Calculate WebSocket URL (gRPC port + 1)
            let ws_port = this.config.addr.port() + 1;
            let ws_host = this.config.addr.ip();
            let url = format!(
                "ws://{}:{}/session/{}?token={}",
                ws_host,
                ws_port,
                job_id,
                token.as_str()
            );

            tracing::info!(
                job_id = %job_id,
                websocket_url = %url,
                "created interactive session"
            );

            (Some(url), Some(this.session_registry.clone()))
        } else {
            (None, None)
        };

        // Spawn execution task with trace context propagated
        let exec_span = tracing::info_span!(parent: tracing::Span::current(), "execute_job", job_id = %job_id, repo = %req.repo, path = %req.path);
        let task_handle = tokio::spawn(
            async move {
                orchestration::execute_job(
                    job_for_exec,
                    orchestration::ExecuteJobContext {
                        storage: storage_for_exec,
                        config: config_for_exec,
                        tx: log_tx_for_exec,
                        registry: registry_for_exec,
                        executor: executor_for_exec,
                        job_root: job_root_for_exec,
                        job_workspace: job_workspace_for_exec,
                        session_registry: session_registry_for_exec,
                        metrics: metrics_for_exec,
                    },
                    interactive,
                    ephemeral_credentials_for_exec,
                    job_env_for_exec,
                )
                .await;
            }
            .instrument(exec_span),
        );

        // Register the running job and emit a lifecycle "started" event.
        let job_path = if req.path.is_empty() || req.path == "." {
            None
        } else {
            Some(req.path.clone())
        };
        this.registry
            .register_job(job_id.clone(), log_tx, task_handle, req.subdomain.clone(), job_path)
            .await;

        Ok(Response::new(JobResponse {
            job_id,
            websocket_url,
        }))
        }.instrument(span).await
    }

    type StreamJobStream = ReceiverStream<Result<LogEntry, Status>>;

    async fn stream_job(
        &self,
        request: Request<StreamRequest>,
    ) -> Result<Response<Self::StreamJobStream>, Status> {
        // Extract parent trace context from client and create span
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.stream_job");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        let req = request.into_inner();
        let job_id = req.job_id;
        let tail_lines = req.tail_lines;
        let follow = req.follow;

        // Check if job exists
        let job = self
            .storage
            .get_job(&job_id)
            .map_err(|e| Status::internal(format!("Failed to get job: {}", e)))?
            .ok_or_else(|| Status::not_found(format!("Job not found: {}", job_id)))?;

        tracing::debug!(
            job_id = %job_id,
            status = %job.status.to_string(),
            tail_lines = ?tail_lines,
            follow = follow,
            "streaming job"
        );

        match job.status {
            JobStatus::Running if follow => {
                // Job is running and client wants live output: subscribe to broadcast channel
                if let Some(mut broadcast_rx) = self.registry.subscribe(&job_id).await {
                    let (tx, rx) = tokio::sync::mpsc::channel(config::CHANNEL_BUFFER_SIZE);
                    let storage = self.storage.clone();
                    let job_id_clone = job_id.clone();

                    // Spawn task to:
                    // 1. Optionally send last N lines from storage (if tail_lines specified)
                    // 2. Then forward live updates from broadcast channel
                    drop(tokio::spawn(async move {
                        // Send historical buffer if requested by client
                        if let Some(n) = tail_lines {
                            if n > 0 {
                                match storage.get_logs_tail(&job_id_clone, n as usize) {
                                    Ok(logs) => {
                                        for log in logs {
                                            let timestamp_secs = log
                                                .timestamp
                                                .duration_since(SystemTime::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs()
                                                as i64;

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
                                                tracing::debug!(
                                                    job_id = %job_id_clone,
                                                    "client disconnected while sending historical logs"
                                                );
                                                return;
                                            }
                                        }
                                        tracing::debug!(
                                            job_id = %job_id_clone,
                                            tail_lines = n,
                                            "sent historical buffer, switching to live stream"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            job_id = %job_id_clone,
                                            error = %e,
                                            "failed to get historical logs, continuing with live stream"
                                        );
                                    }
                                }
                            }
                        }

                        // Now forward live updates from broadcast channel
                        loop {
                            match broadcast_rx.recv().await {
                                Ok(log_entry) => {
                                    if tx.send(log_entry).await.is_err() {
                                        // Client disconnected
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::warn!(
                                        job_id = %job_id_clone,
                                        skipped = n,
                                        "client lagged, skipped messages"
                                    );
                                    // Continue receiving
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    // Job finished, channel closed
                                    break;
                                }
                            }
                        }
                    }));

                    Ok(Response::new(ReceiverStream::new(rx)))
                } else {
                    // Job is marked as running but not in registry
                    // This could happen if the job just completed
                    // Fall back to serving stored logs
                    let (tx, rx) = tokio::sync::mpsc::channel(config::CHANNEL_BUFFER_SIZE);
                    orchestration::serve_stored_logs(job_id, self.storage.clone(), tx).await;
                    Ok(Response::new(ReceiverStream::new(rx)))
                }
            }
            JobStatus::Running | JobStatus::Completed | JobStatus::Failed => {
                // Job is done, or running but client does not want to follow:
                // serve stored logs only and close the stream.
                let (tx, rx) = tokio::sync::mpsc::channel(config::CHANNEL_BUFFER_SIZE);
                orchestration::serve_stored_logs(job_id, self.storage.clone(), tx).await;
                Ok(Response::new(ReceiverStream::new(rx)))
            }
            JobStatus::Pending => {
                // This shouldn't happen with the new model
                // submit_job should immediately start execution
                Err(Status::internal(
                    "Job is pending - this shouldn't happen. Try resubmitting.",
                ))
            }
        }
    }

    async fn list_jobs(
        &self,
        request: Request<crate::jail::ListJobsRequest>,
    ) -> Result<Response<crate::jail::ListJobsResponse>, Status> {
        // Extract parent trace context from client and create span
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.list_jobs");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        let req = request.into_inner();

        // Parse status filter if provided
        let status_filter = if let Some(status_str) = req.status {
            Some(
                JobStatus::from_string(&status_str)
                    .map_err(|e| Status::invalid_argument(format!("Invalid status: {}", e)))?,
            )
        } else {
            None
        };

        let limit = req.limit.unwrap_or(50) as usize;
        let offset = req.offset.unwrap_or(0) as usize;

        tracing::debug!(
            status = ?status_filter,
            limit = limit,
            offset = offset,
            "listing jobs"
        );

        // Query storage
        let (jobs, total_count) = self
            .storage
            .list_jobs(status_filter, limit, offset)
            .map_err(|e| Status::internal(format!("Failed to list jobs: {}", e)))?;

        // Convert JobMetadata to JobInfo, enriching running jobs with
        // live data from the job registry (reverse proxy port, subdomain).
        let registry = &self.registry;
        let mut job_infos: Vec<crate::jail::JobInfo> = Vec::with_capacity(jobs.len());
        for job in jobs {
            let created_timestamp = job
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let completed_timestamp = job.completed_at.map(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });

            // Calculate runtime
            let runtime_seconds = if let Some(completed_at) = job.completed_at {
                completed_at
                    .duration_since(job.created_at)
                    .unwrap_or_default()
                    .as_secs()
            } else {
                SystemTime::now()
                    .duration_since(job.created_at)
                    .unwrap_or_default()
                    .as_secs()
            };

            // Enrich with live data from job registry (for running jobs)
            let (reverse_proxy_port, subdomain) =
                registry.get_web_info(&job.id).await.unwrap_or((None, None));

            // Extract allowed host patterns from the network policy for display/retry
            let allowed_hosts: Vec<String> = job
                .network_policy
                .as_ref()
                .map(|policy| {
                    policy
                        .rules
                        .iter()
                        .filter_map(|rule| {
                            use crate::jail::network_pattern::Pattern;
                            rule.pattern
                                .as_ref()
                                .and_then(|p| p.pattern.as_ref())
                                .and_then(|p| match p {
                                    Pattern::Host(h) => Some(h.host.clone()),
                                    Pattern::Ip(_) => None,
                                })
                        })
                        .collect()
                })
                .unwrap_or_default();

            job_infos.push(crate::jail::JobInfo {
                job_id: job.id,
                status: job.status.to_string(),
                created_at: Some(prost_types::Timestamp {
                    seconds: created_timestamp,
                    nanos: 0,
                }),
                completed_at: completed_timestamp
                    .map(|seconds| prost_types::Timestamp { seconds, nanos: 0 }),
                repo: if job.repo.is_empty() {
                    None
                } else {
                    Some(job.repo)
                },
                path: if job.path.is_empty() || job.path == "." {
                    None
                } else {
                    Some(job.path)
                },
                packages: job.packages,
                runtime_seconds,
                reverse_proxy_port: reverse_proxy_port.map(|p| p as u32),
                subdomain,
                script: if job.script.is_empty() {
                    None
                } else {
                    Some(job.script)
                },
                service_port: job.service_port,
                allowed_hosts,
            });
        }

        tracing::info!(count = job_infos.len(), total = total_count, "listed jobs");

        Ok(Response::new(crate::jail::ListJobsResponse {
            jobs: job_infos,
            total_count: total_count as u32,
        }))
    }

    async fn gc(
        &self,
        request: Request<crate::jail::GcRequest>,
    ) -> Result<Response<crate::jail::GcResponse>, Status> {
        // Extract parent trace context from client and create span
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.gc");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        tracing::info!("gc requested");

        // Run GC to delete all cache entries
        let stats = self
            .cache_manager
            .gc()
            .await
            .map_err(|e| Status::internal(format!("gc failed: {}", e)))?;

        let total_deleted = stats.nix_entries_deleted + stats.workspace_entries_deleted;
        tracing::info!(
            nix_deleted = stats.nix_entries_deleted,
            workspace_deleted = stats.workspace_entries_deleted,
            "gc completed"
        );

        Ok(Response::new(crate::jail::GcResponse {
            deleted_count: total_deleted as u32,
        }))
    }

    type StreamJobEventsStream =
        tokio_stream::wrappers::ReceiverStream<Result<JobLifecycleEvent, Status>>;

    async fn stream_job_events(
        &self,
        request: Request<StreamJobEventsRequest>,
    ) -> Result<Response<Self::StreamJobEventsStream>, Status> {
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.stream_job_events");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        tracing::info!("job events stream connected");

        // Subscribe to the lifecycle broadcast BEFORE taking a snapshot so we
        // don't miss events that fire between the snapshot and the loop start.
        let mut lifecycle_rx = self.registry.subscribe_lifecycle();

        // Snapshot currently-running jobs for the replay burst.
        let running = self.registry.snapshot_running_jobs().await;
        let replay_ids: std::collections::HashSet<String> =
            running.iter().map(|(id, ..)| id.clone()).collect();

        let (tx, rx) = tokio::sync::mpsc::channel(config::CHANNEL_BUFFER_SIZE);

        drop(tokio::spawn(async move {
            // 1. Replay all running jobs
            for (job_id, subdomain, reverse_proxy_port, path) in running {
                let event = JobLifecycleEvent {
                    event_type: "started".to_string(),
                    job_id,
                    subdomain,
                    reverse_proxy_port: reverse_proxy_port.map(|p| p as u32),
                    path,
                };
                if tx.send(Ok(event)).await.is_err() {
                    return; // client disconnected during replay
                }
            }

            // 2. Sentinel: client can now reconcile
            if tx
                .send(Ok(JobLifecycleEvent {
                    event_type: "replay_complete".to_string(),
                    job_id: String::new(),
                    subdomain: None,
                    reverse_proxy_port: None,
                    path: None,
                }))
                .await
                .is_err()
            {
                return;
            }

            // 3. Stream live events, deduplicating starts already in the replay
            loop {
                match lifecycle_rx.recv().await {
                    Ok(event) => {
                        // Skip "started" events for jobs already replayed to avoid
                        // double-open on the client side for jobs that started just
                        // before we subscribed but were captured in the snapshot.
                        if event.event_type == "started" && replay_ids.contains(&event.job_id) {
                            continue;
                        }
                        if tx.send(Ok(event)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "job events stream lagged, skipping events");
                        // continue — client will re-connect and get a fresh replay
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break; // registry dropped, daemon shutting down
                    }
                }
            }
        }));

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<CancelJobResponse>, Status> {
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.cancel_job");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        let job_id = request.into_inner().job_id;

        // Verify the job exists and is running
        let job = self
            .storage
            .get_job(&job_id)
            .map_err(|e| Status::internal(format!("storage error: {}", e)))?
            .ok_or_else(|| Status::not_found(format!("job not found: {}", job_id)))?;

        if job.status != JobStatus::Running {
            return Ok(Response::new(CancelJobResponse { cancelled: false }));
        }

        // Send SIGTERM to the systemd transient unit. Unit name matches the
        // pattern used in SystemdExecutor::execute(): "nix-jail-{job_id}".
        let unit_name = format!("nix-jail-{}.service", job_id);
        tracing::info!(job_id = %job_id, unit = %unit_name, "cancelling job");

        let output = tokio::process::Command::new("systemctl")
            .args(["kill", "--kill-whom=all", "--signal=SIGTERM", &unit_name])
            .output()
            .await
            .map_err(|e| Status::internal(format!("systemctl kill failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Unit may have already exited — not a hard error
            tracing::warn!(job_id = %job_id, stderr = %stderr, "systemctl kill returned non-zero");
        }

        Ok(Response::new(CancelJobResponse { cancelled: true }))
    }
}
