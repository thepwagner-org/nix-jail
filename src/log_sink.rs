//! Log sink abstraction for decoupling orchestration from storage
//!
//! This module provides a trait-based abstraction for logging that allows
//! the same orchestration code to work with different output backends:
//! - StorageLogSink: persists logs to SQLite and broadcasts to gRPC clients
//! - StdioLogSink: prints directly to stdout/stderr for local execution

use chrono::{DateTime, Utc};
use std::io::Write;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::broadcast;
use tonic::Status;

use crate::jail::{LogEntry, LogSource};
use crate::storage::{JobStorage, LogEntry as StorageLogEntry};

// ANSI color codes matching tracing-subscriber
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

/// Format a log line matching tracing-subscriber's format with colors
pub fn format_info(message: &str) -> String {
    let now: DateTime<Utc> = Utc::now();
    let ts = now.format("%Y-%m-%dT%H:%M:%S%.6fZ");
    format!(
        "{ANSI_DIM}{ts}{ANSI_RESET} {ANSI_GREEN} INFO{ANSI_RESET} {ANSI_DIM}nix_jail:{ANSI_RESET} {message}\n"
    )
}

/// Format an error log line matching tracing-subscriber's format with colors
fn format_error(message: &str) -> String {
    let now: DateTime<Utc> = Utc::now();
    let ts = now.format("%Y-%m-%dT%H:%M:%S%.6fZ");
    format!(
        "{ANSI_DIM}{ts}{ANSI_RESET} {ANSI_RED}ERROR{ANSI_RESET} {ANSI_DIM}nix_jail:{ANSI_RESET} {message}\n"
    )
}

/// A sink for job execution logs
///
/// Implementations handle where logs go - database, broadcast channel, stdout, etc.
pub trait LogSink: Send + Sync {
    /// Log a message with the given source
    fn log(&self, job_id: &str, source: LogSource, message: &str);

    /// Signal that job execution is complete
    fn done(&self, job_id: &str, exit_code: i32);

    /// Log an info message with timestamp and colors (matches tracing format)
    fn info(&self, job_id: &str, message: &str) {
        self.log(job_id, LogSource::System, &format_info(message));
    }

    /// Log an error message with timestamp and colors (matches tracing format)
    fn error(&self, job_id: &str, message: &str) {
        self.log(job_id, LogSource::System, &format_error(message));
    }
}

/// Log sink that persists to SQLite storage and broadcasts to gRPC clients
pub struct StorageLogSink {
    storage: JobStorage,
    tx: broadcast::Sender<Result<LogEntry, Status>>,
}

impl std::fmt::Debug for StorageLogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageLogSink")
            .field("storage", &self.storage)
            .field("tx", &"broadcast::Sender<...>")
            .finish()
    }
}

impl StorageLogSink {
    pub fn new(storage: JobStorage, tx: broadcast::Sender<Result<LogEntry, Status>>) -> Self {
        Self { storage, tx }
    }
}

impl LogSink for StorageLogSink {
    fn log(&self, job_id: &str, source: LogSource, message: &str) {
        let now = SystemTime::now();
        let timestamp_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Persist to storage
        let _ = self.storage.append_log(
            job_id,
            &StorageLogEntry {
                timestamp: now,
                message: message.to_string(),
                source: source as i32,
            },
        );

        // Broadcast to connected clients
        let _ = self.tx.send(Ok(LogEntry {
            content: message.to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: timestamp_secs,
                nanos: 0,
            }),
            source: source as i32,
            exit_code: None,
        }));
    }

    fn done(&self, job_id: &str, exit_code: i32) {
        self.log(
            job_id,
            LogSource::System,
            &format_info(&format!("job completed exit_code={}", exit_code)),
        );
    }
}

/// Log sink that prints to stdout/stderr for local execution
#[derive(Debug)]
pub struct StdioLogSink {
    show_prefix: bool,
}

impl StdioLogSink {
    pub fn new(show_prefix: bool) -> Self {
        Self { show_prefix }
    }
}

impl LogSink for StdioLogSink {
    fn log(&self, _job_id: &str, source: LogSource, message: &str) {
        let output = if self.show_prefix {
            let prefix = match source {
                LogSource::JobStdout => "[job:out] ",
                LogSource::JobStderr => "[job:err] ",
                LogSource::ProxyStdout => "[proxy:out] ",
                LogSource::ProxyStderr => "[proxy:err] ",
                LogSource::System => "[system] ",
                _ => "",
            };
            format!("{}{}", prefix, message)
        } else {
            message.to_string()
        };

        // Route stderr sources to stderr, everything else to stdout
        match source {
            LogSource::JobStderr | LogSource::ProxyStderr => {
                let _ = std::io::stderr().write_all(output.as_bytes());
            }
            _ => {
                let _ = std::io::stdout().write_all(output.as_bytes());
            }
        }
    }

    fn done(&self, _job_id: &str, exit_code: i32) {
        if self.show_prefix {
            let msg = format_info(&format!("job completed exit_code={}", exit_code));
            let _ = std::io::stdout().write_all(msg.as_bytes());
        }
    }
}

/// Wrapper to allow using LogSink behind Arc
impl<T: LogSink + ?Sized> LogSink for Arc<T> {
    fn log(&self, job_id: &str, source: LogSource, message: &str) {
        (**self).log(job_id, source, message)
    }

    fn done(&self, job_id: &str, exit_code: i32) {
        (**self).done(job_id, exit_code)
    }
}
