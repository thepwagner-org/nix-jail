//! In-process job cache for nj-web.
//!
//! Maintains a consistent view of running jobs by subscribing to the daemon's
//! `StreamJobEvents` gRPC stream. This eliminates per-request `ListJobs` calls
//! from the subdomain routing path — every incoming HTTP request can look up a
//! job's backend address from in-memory state instead of round-tripping to the
//! daemon.
//!
//! The cache also fans out lifecycle events to SSE clients via an internal
//! `broadcast` channel that backs `GET /api/events`.
//!
//! # Consistency model
//!
//! The sync task subscribes to `StreamJobEvents`, which replays all running
//! jobs on connect (the `replay_complete` sentinel marks the end of the burst).
//! During a reconnect the cache is *not* cleared — stale entries are cleaned up
//! by the reconciliation step that runs after `replay_complete` arrives: any
//! job in the cache that was not seen in the replay burst is emitted as
//! `stopped` and removed.

use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::StreamJobEventsRequest;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Public event type (fan-out to SSE clients)
// ---------------------------------------------------------------------------

/// A lifecycle event that nj-web fans out to browser SSE clients.
#[derive(Clone, Debug)]
pub enum SseEvent {
    /// A job has started running.
    Started { job_id: String, subdomain: String },
    /// A job has stopped (completed, failed, or cancelled).
    Stopped { job_id: String, subdomain: String },
}

// ---------------------------------------------------------------------------
// Cached job entry
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CachedJob {
    pub job_id: String,
    pub subdomain: Option<String>,
    pub reverse_proxy_port: Option<u16>,
    pub path: Option<String>,
}

// ---------------------------------------------------------------------------
// JobCache
// ---------------------------------------------------------------------------

/// Shared in-process cache of running jobs and SSE broadcast bus.
pub struct JobCache {
    jobs: RwLock<HashMap<String, CachedJob>>,
    /// Internal broadcast channel for SSE fan-out.
    events_tx: broadcast::Sender<SseEvent>,
}

impl JobCache {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            jobs: RwLock::new(HashMap::new()),
            events_tx,
        }
    }

    /// Subscribe to lifecycle events for SSE fan-out.
    pub fn subscribe(&self) -> broadcast::Receiver<SseEvent> {
        self.events_tx.subscribe()
    }

    /// Snapshot all currently-running jobs for the SSE replay burst.
    pub async fn running_jobs_snapshot(&self) -> Vec<CachedJob> {
        self.jobs.read().await.values().cloned().collect()
    }

    /// Look up a running job by its subdomain.
    ///
    /// Returns `None` if no running job has that subdomain — the caller
    /// should fall back to a gRPC query for completed/failed job state.
    pub async fn lookup_subdomain(&self, subdomain: &str) -> Option<CachedJob> {
        let jobs = self.jobs.read().await;
        jobs.values()
            .find(|j| j.subdomain.as_deref() == Some(subdomain))
            .cloned()
    }

    // ------------------------------------------------------------------
    // Internal mutators (used only by the sync task)
    // ------------------------------------------------------------------

    async fn insert(&self, job: CachedJob) {
        let subdomain = job.subdomain.clone().unwrap_or_default();
        let job_id = job.job_id.clone();
        {
            let mut jobs = self.jobs.write().await;
            let _ = jobs.insert(job_id.clone(), job);
        }
        let _ = self.events_tx.send(SseEvent::Started { job_id, subdomain });
    }

    async fn update_port(&self, job_id: &str, port: u16) {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.reverse_proxy_port = Some(port);
        }
        // No SSE event for port_ready — meowser doesn't need it
    }

    async fn remove(&self, job_id: &str) {
        let removed = {
            let mut jobs = self.jobs.write().await;
            jobs.remove(job_id)
        };
        if let Some(ref job) = removed {
            let subdomain = job.subdomain.clone().unwrap_or_default();
            let _ = self.events_tx.send(SseEvent::Stopped {
                job_id: job_id.to_string(),
                subdomain,
            });
        }
    }

    /// Remove jobs that are still in the cache but were absent from the most
    /// recent replay burst.  Called after `replay_complete` arrives following
    /// a reconnect.
    async fn reconcile(&self, replayed_ids: &HashSet<String>) {
        let stale: Vec<String> = {
            let jobs = self.jobs.read().await;
            jobs.keys()
                .filter(|id| !replayed_ids.contains(*id))
                .cloned()
                .collect()
        };
        for job_id in stale {
            warn!(job_id = %job_id, "removing stale job from cache after reconnect");
            self.remove(&job_id).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Background sync task
// ---------------------------------------------------------------------------

/// Spawn a task that maintains `cache` in sync with the daemon's
/// `StreamJobEvents` gRPC stream.
///
/// The task reconnects automatically on disconnect with exponential backoff.
pub fn spawn_cache_sync(daemon: String, cache: Arc<JobCache>) {
    drop(tokio::spawn(async move {
        let mut backoff_secs: u64 = 1;

        loop {
            info!(daemon = %daemon, "connecting to daemon job events stream");

            match run_sync_loop(&daemon, &cache).await {
                Ok(()) => {
                    // Server closed the stream cleanly (daemon shutdown).
                    // Back off before reconnecting.
                    info!("daemon events stream closed, reconnecting");
                }
                Err(e) => {
                    error!(error = %e, "daemon events stream error, reconnecting");
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(30);
        }
    }));
}

/// Inner loop: connect and drain the event stream until it closes or errors.
/// On a clean `replay_complete`→live cycle the backoff resets to 1s.
async fn run_sync_loop(daemon: &str, cache: &JobCache) -> anyhow::Result<()> {
    let mut client = JailServiceClient::connect(daemon.to_string()).await?;
    let mut stream = client
        .stream_job_events(StreamJobEventsRequest {})
        .await?
        .into_inner();

    // Track job_ids seen during the current replay burst for reconciliation.
    let mut replay_ids: HashSet<String> = HashSet::new();
    let mut in_replay = true;

    loop {
        match stream.message().await {
            Ok(Some(event)) => {
                debug!(
                    event_type = %event.event_type,
                    job_id = %event.job_id,
                    "received lifecycle event"
                );

                match event.event_type.as_str() {
                    "started" => {
                        let job = CachedJob {
                            job_id: event.job_id.clone(),
                            subdomain: event.subdomain.clone(),
                            reverse_proxy_port: event.reverse_proxy_port.map(|p| p as u16),
                            path: event.path.clone(),
                        };
                        if in_replay {
                            // Replay burst: insert without emitting SSE (the
                            // SSE handler does its own replay from the snapshot).
                            let mut jobs = cache.jobs.write().await;
                            let _ = jobs.insert(event.job_id.clone(), job);
                            let _ = replay_ids.insert(event.job_id.clone());
                        } else {
                            cache.insert(job).await;
                        }
                    }
                    "port_ready" => {
                        if let Some(port) = event.reverse_proxy_port {
                            cache.update_port(&event.job_id, port as u16).await;
                        }
                    }
                    "stopped" => {
                        cache.remove(&event.job_id).await;
                    }
                    "replay_complete" => {
                        if in_replay {
                            // Clean up jobs that disappeared while we were disconnected.
                            cache.reconcile(&replay_ids).await;
                            replay_ids.clear();
                            in_replay = false;
                            info!("job cache synced with daemon");
                        }
                    }
                    other => {
                        warn!(event_type = %other, "unknown lifecycle event type, ignoring");
                    }
                }
            }
            Ok(None) => {
                // Stream closed by server
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
