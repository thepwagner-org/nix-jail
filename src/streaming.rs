//! Log streaming utilities for job execution
//!
//! Provides helpers to stream logs from various sources (stdout, stderr, proxy)
//! to both storage and gRPC clients.

use std::sync::Arc;

use crate::jail::LogEntry as GrpcLogEntry;
use crate::jail::LogSource;
use crate::log_sink::LogSink;
use crate::storage::{JobStorage, LogEntry as StorageLogEntry};
use std::time::SystemTime;
use tokio::sync::{broadcast, mpsc};
use tonic::Status;

/// Stream logs from a channel to a LogSink
///
/// This is the core streaming primitive that handles:
/// - Receiving log lines from a source channel (mpsc from executor)
/// - Forwarding them to a LogSink implementation
///
/// # Arguments
/// * `job_id` - Job ID for logging
/// * `source` - Type of log source
/// * `receiver` - Channel receiving log lines from executor
/// * `log_sink` - Destination for logs
pub async fn stream_to_sink(
    job_id: String,
    source: LogSource,
    mut receiver: mpsc::Receiver<String>,
    log_sink: Arc<dyn LogSink>,
) {
    while let Some(line) = receiver.recv().await {
        let message = format!("{}\n", line);
        log_sink.log(&job_id, source, &message);
    }
}

/// Stream logs from a channel to both storage and broadcast channel
///
/// This is the legacy streaming primitive that handles:
/// - Receiving log lines from a source channel (mpsc from executor)
/// - Persisting them to storage
/// - Forwarding them to the broadcast channel (for multiple clients)
///
/// # Arguments
/// * `job_id` - Job ID for storage
/// * `source` - Type of log source (for gRPC metadata)
/// * `mut receiver` - Channel receiving log lines from executor
/// * `storage` - Storage backend for persistence
/// * `sender` - Broadcast channel to send logs to all subscribers
pub async fn stream_logs(
    job_id: String,
    source: LogSource,
    mut receiver: mpsc::Receiver<String>,
    storage: JobStorage,
    sender: broadcast::Sender<Result<GrpcLogEntry, Status>>,
) {
    while let Some(line) = receiver.recv().await {
        let timestamp = SystemTime::now();
        let message = format!("{}\n", line);

        // Store log (best effort, don't fail if storage errors)
        let _ = storage.append_log(
            &job_id,
            &StorageLogEntry {
                timestamp,
                message: message.clone(),
                source: source as i32,
            },
        );

        // Send to broadcast channel
        let timestamp_secs = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let entry = GrpcLogEntry {
            content: message,
            timestamp: Some(prost_types::Timestamp {
                seconds: timestamp_secs,
                nanos: 0,
            }),
            source: source as i32,
        };

        // Broadcast to all clients (ignore errors - clients may have disconnected)
        let _ = sender.send(Ok(entry));
    }
}
