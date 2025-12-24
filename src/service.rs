use std::sync::Arc;
use std::time::SystemTime;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::cache::CacheManager;
use crate::config;
use crate::jail::jail_service_server::JailService;
use crate::jail::{JobRequest, JobResponse, LogEntry, StreamRequest};
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
        }
    }
}

#[tonic::async_trait]
impl JailService for JailServiceImpl {
    async fn submit_job(
        &self,
        request: Request<JobRequest>,
    ) -> Result<Response<JobResponse>, Status> {
        // Extract parent trace context from client and create span
        let parent_context = extract_trace_context(&request);
        let span = tracing::info_span!("grpc.submit_job");
        let _ = span.set_parent(parent_context);
        let _guard = span.enter();

        let req = request.into_inner();

        // Validation
        validation::validate_script(&req.script)?;
        if !req.repo.is_empty() {
            validation::validate_repo(&req.repo)?;
            validation::validate_path(&req.path)?;

            if let Some(ref git_ref_val) = req.git_ref {
                validation::validate_ref(git_ref_val)?;
            }
        }
        if let Some(ref policy) = req.network_policy {
            validation::validate_network_policy(policy, &self.config.credentials)?;
            tracing::debug!("validated network policy with {} rules", policy.rules.len());
        }
        if let Some(ref nixpkgs_version) = req.nixpkgs_version {
            validation::validate_nixpkgs_version(nixpkgs_version)?;
        }

        let job_id = Ulid::new().to_string();
        let interactive = req.interactive.unwrap_or(false);

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
            status: JobStatus::Running,
            created_at: SystemTime::now(),
            completed_at: None,
        };
        self.storage
            .save_job(&job_metadata)
            .map_err(|e| Status::internal(format!("Failed to save job: {}", e)))?;

        // Start job execution in background
        let job_for_exec = job_metadata.clone();
        let storage_for_exec = self.storage.clone();
        let config_for_exec = self.config.clone();
        let registry_for_exec = self.registry.clone();
        let executor_for_exec = self.executor.clone();
        let job_root_for_exec = self.job_root.clone();
        let job_workspace_for_exec = self.job_workspace.clone();

        // Create broadcast channel for this job
        let (log_tx, _) = tokio::sync::broadcast::channel(1000);
        let log_tx_for_exec = log_tx.clone();

        // Generate WebSocket URL and register session if interactive
        let (websocket_url, session_registry_for_exec) = if interactive {
            // Register session for token validation (channels added by executor)
            let token = self.session_registry.register(job_id.clone()).await;

            // Calculate WebSocket URL (gRPC port + 1)
            let ws_port = self.config.addr.port() + 1;
            let ws_host = self.config.addr.ip();
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

            (Some(url), Some(self.session_registry.clone()))
        } else {
            (None, None)
        };

        // Spawn execution task with trace context propagated
        let exec_span = tracing::info_span!(parent: &span, "execute_job", job_id = %job_id);
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
                    },
                    interactive,
                )
                .await;
            }
            .instrument(exec_span),
        );

        // Register the running job and get the broadcast sender
        // Note: register creates its own channel, but we need to use our own
        // so we have the sender to pass to execute_job. We'll need to refactor this.
        // For now, let's manually insert into the registry.
        use crate::job_registry::RunningJob;
        let running_job = RunningJob {
            log_tx,
            task_handle,
        };
        let mut jobs = self.registry.jobs.write().await;
        let _ = jobs.insert(job_id.clone(), running_job);

        Ok(Response::new(JobResponse {
            job_id,
            websocket_url,
        }))
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
            "streaming job"
        );

        match job.status {
            JobStatus::Running => {
                // Job is running, subscribe to its broadcast channel
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
            JobStatus::Completed | JobStatus::Failed => {
                // Job is done, serve existing logs
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

        // Convert JobMetadata to JobInfo
        let job_infos: Vec<crate::jail::JobInfo> = jobs
            .into_iter()
            .map(|job| {
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
                    // For running jobs, calculate elapsed time
                    SystemTime::now()
                        .duration_since(job.created_at)
                        .unwrap_or_default()
                        .as_secs()
                };

                crate::jail::JobInfo {
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
                }
            })
            .collect();

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

        // Get stats before GC to calculate bytes freed
        let stats_before = self
            .cache_manager
            .stats()
            .map_err(|e| Status::internal(format!("failed to get cache stats: {}", e)))?;

        // Run GC with target of 0 bytes (delete everything)
        let deleted_count = self
            .cache_manager
            .gc(0)
            .await
            .map_err(|e| Status::internal(format!("gc failed: {}", e)))?;

        tracing::info!(
            deleted_count,
            bytes_freed = stats_before.total_size_bytes,
            "gc completed"
        );

        Ok(Response::new(crate::jail::GcResponse {
            deleted_count: deleted_count as u32,
            bytes_freed: stats_before.total_size_bytes,
        }))
    }
}
