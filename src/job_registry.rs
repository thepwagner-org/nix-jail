use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tonic::Status;

use crate::jail::{JobLifecycleEvent, LogEntry};

/// Capacity for the global job lifecycle event broadcast channel.
/// Sized for the number of concurrent SSE clients that might be lagging;
/// each event is tiny so this is cheap.
const LIFECYCLE_BROADCAST_CAPACITY: usize = 256;

/// A running job with its log broadcast channel and task handle
#[derive(Debug)]
pub struct RunningJob {
    /// Broadcast sender for log entries - multiple clients can subscribe
    pub log_tx: broadcast::Sender<Result<LogEntry, Status>>,
    /// Task handle for the job execution
    pub task_handle: JoinHandle<()>,
    /// Port of alice's reverse proxy listener on the host (set after proxy starts)
    pub reverse_proxy_port: Option<u16>,
    /// Subdomain for web frontend routing (from JobRequest)
    pub subdomain: Option<String>,
    /// Path within the repository (from JobRequest)
    pub path: Option<String>,
}

/// Registry of currently running jobs
#[derive(Debug, Clone)]
pub struct JobRegistry {
    pub(crate) jobs: Arc<RwLock<HashMap<String, RunningJob>>>,
    /// Global lifecycle event bus.  All mutations (register, set_port, remove)
    /// broadcast here so nj-web can maintain a consistent cache without polling.
    lifecycle_tx: broadcast::Sender<JobLifecycleEvent>,
}

impl JobRegistry {
    /// Create a new empty job registry
    pub fn new() -> Self {
        let (lifecycle_tx, _) = broadcast::channel(LIFECYCLE_BROADCAST_CAPACITY);
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            lifecycle_tx,
        }
    }

    /// Subscribe to global job lifecycle events.
    ///
    /// The caller should subscribe *before* taking a snapshot of running jobs
    /// (via `snapshot_running_jobs`) to avoid missing events between the two.
    pub fn subscribe_lifecycle(&self) -> broadcast::Receiver<JobLifecycleEvent> {
        self.lifecycle_tx.subscribe()
    }

    /// Snapshot all currently-running jobs for replay.
    ///
    /// Returns `(job_id, subdomain, reverse_proxy_port, path)` tuples.
    pub async fn snapshot_running_jobs(
        &self,
    ) -> Vec<(String, Option<String>, Option<u16>, Option<String>)> {
        let jobs = self.jobs.read().await;
        jobs.iter()
            .map(|(id, j)| {
                (
                    id.clone(),
                    j.subdomain.clone(),
                    j.reverse_proxy_port,
                    j.path.clone(),
                )
            })
            .collect()
    }

    /// Register a new running job and emit a `started` lifecycle event.
    ///
    /// The caller creates `log_tx` before spawning the execution task (so the
    /// task receives a clone) and passes the resulting `JoinHandle` here.
    /// Replaces the previous manual `jobs.insert()` in service.rs.
    pub async fn register_job(
        &self,
        job_id: String,
        log_tx: broadcast::Sender<Result<LogEntry, Status>>,
        task_handle: JoinHandle<()>,
        subdomain: Option<String>,
        path: Option<String>,
    ) {
        let running_job = RunningJob {
            log_tx,
            task_handle,
            reverse_proxy_port: None,
            subdomain: subdomain.clone(),
            path: path.clone(),
        };

        {
            let mut jobs = self.jobs.write().await;
            let _ = jobs.insert(job_id.clone(), running_job);
        }

        let _ = self.lifecycle_tx.send(JobLifecycleEvent {
            event_type: "started".to_string(),
            job_id,
            subdomain,
            reverse_proxy_port: None,
            path,
        });
    }

    /// Subscribe to a running job's logs
    ///
    /// Returns None if the job is not in the registry (not running)
    pub async fn subscribe(
        &self,
        job_id: &str,
    ) -> Option<broadcast::Receiver<Result<LogEntry, Status>>> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).map(|job| job.log_tx.subscribe())
    }

    /// Remove a job from the registry and emit a `stopped` lifecycle event.
    ///
    /// This should be called when a job completes.
    pub async fn remove(&self, job_id: &str) {
        let subdomain = {
            let mut jobs = self.jobs.write().await;
            jobs.remove(job_id).and_then(|j| j.subdomain)
        };

        let _ = self.lifecycle_tx.send(JobLifecycleEvent {
            event_type: "stopped".to_string(),
            job_id: job_id.to_string(),
            subdomain,
            reverse_proxy_port: None,
            path: None,
        });
    }

    /// Check if a job is currently running
    pub async fn is_running(&self, job_id: &str) -> bool {
        let jobs = self.jobs.read().await;
        jobs.contains_key(job_id)
    }

    /// Update the reverse proxy port for a running job and emit a `port_ready` event.
    ///
    /// Called from the execution task after alice starts and reports
    /// its reverse proxy listener port.
    pub async fn set_reverse_proxy_port(&self, job_id: &str, port: u16) {
        let subdomain = {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(job_id) {
                job.reverse_proxy_port = Some(port);
                job.subdomain.clone()
            } else {
                return;
            }
        };

        let _ = self.lifecycle_tx.send(JobLifecycleEvent {
            event_type: "port_ready".to_string(),
            job_id: job_id.to_string(),
            subdomain,
            reverse_proxy_port: Some(port as u32),
            path: None,
        });
    }

    /// Get the reverse proxy port and subdomain for a running job.
    pub async fn get_web_info(&self, job_id: &str) -> Option<(Option<u16>, Option<String>)> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id)
            .map(|j| (j.reverse_proxy_port, j.subdomain.clone()))
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}
