use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tonic::Status;

use crate::jail::LogEntry;

/// Capacity for broadcast channel (number of messages that can be buffered)
const BROADCAST_CAPACITY: usize = 1000;

/// A running job with its log broadcast channel and task handle
#[derive(Debug)]
pub struct RunningJob {
    /// Broadcast sender for log entries - multiple clients can subscribe
    pub log_tx: broadcast::Sender<Result<LogEntry, Status>>,
    /// Task handle for the job execution
    pub task_handle: JoinHandle<()>,
}

/// Registry of currently running jobs
#[derive(Debug, Clone)]
pub struct JobRegistry {
    pub(crate) jobs: Arc<RwLock<HashMap<String, RunningJob>>>,
}

impl JobRegistry {
    /// Create a new empty job registry
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new running job
    ///
    /// Returns the broadcast sender to use for logging
    pub async fn register(
        &self,
        job_id: String,
        task_handle: JoinHandle<()>,
    ) -> broadcast::Sender<Result<LogEntry, Status>> {
        let (log_tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        let running_job = RunningJob {
            log_tx: log_tx.clone(),
            task_handle,
        };

        let mut jobs = self.jobs.write().await;
        let _ = jobs.insert(job_id, running_job);

        log_tx
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

    /// Remove a job from the registry
    ///
    /// This should be called when a job completes
    pub async fn remove(&self, job_id: &str) {
        let mut jobs = self.jobs.write().await;
        let _ = jobs.remove(job_id);
    }

    /// Check if a job is currently running
    pub async fn is_running(&self, job_id: &str) -> bool {
        let jobs = self.jobs.read().await;
        jobs.contains_key(job_id)
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}
