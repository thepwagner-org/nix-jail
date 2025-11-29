#[cfg(test)]
use crate::jail::LogSource;
use crate::jail::NetworkPolicy;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobStatus::Pending => write!(f, "pending"),
            JobStatus::Running => write!(f, "running"),
            JobStatus::Completed => write!(f, "completed"),
            JobStatus::Failed => write!(f, "failed"),
        }
    }
}

impl JobStatus {
    pub fn from_string(s: &str) -> Result<Self, StorageError> {
        match s {
            "pending" => Ok(JobStatus::Pending),
            "running" => Ok(JobStatus::Running),
            "completed" => Ok(JobStatus::Completed),
            "failed" => Ok(JobStatus::Failed),
            _ => Err(StorageError::InvalidStatus(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMetadata {
    pub id: String,
    pub repo: String,
    pub path: String,
    pub script: String,
    pub packages: Vec<String>,
    pub network_policy: Option<NetworkPolicy>,
    #[serde(default)]
    pub nixpkgs_version: Option<String>,
    #[serde(default)]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub hardening_profile: Option<String>,
    #[serde(default)]
    pub push: bool,
    pub status: JobStatus,
    pub created_at: SystemTime,
    pub completed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub message: String,
    pub source: i32,
}

/// Metadata for a cached Nix closure snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// NAR hash identifying this closure
    pub nar_hash: String,
    /// Path to the snapshot directory
    pub snapshot_path: String,
    /// Nix store paths included in this closure
    pub closure_paths: Vec<String>,
    /// Size of the snapshot in bytes (if known)
    pub size_bytes: Option<i64>,
    /// When this cache entry was created
    pub created_at: SystemTime,
    /// When this cache entry was last used
    pub last_used_at: SystemTime,
    /// Number of times this cache entry has been used
    pub use_count: i64,
}

#[derive(Clone)]
pub struct JobStorage {
    conn: Arc<Mutex<Connection>>,
    db_path: String,
}

impl std::fmt::Debug for JobStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobStorage")
            .field("db", &self.db_path)
            .finish()
    }
}

impl JobStorage {
    /// Create a new JobStorage instance
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, StorageError> {
        let path_str = db_path.as_ref().display().to_string();
        let conn = Connection::open(db_path)?;

        // Set exclusive locking mode to prevent multiple server instances from accessing
        // the same database. This prevents a second server from incorrectly marking all
        // running jobs as failed during its startup recovery.
        // PRAGMA returns a result row, so we use query_row instead of execute
        let _: String = conn.query_row("PRAGMA locking_mode=EXCLUSIVE", [], |row| row.get(0))?;

        // Create tables
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                path TEXT NOT NULL,
                script TEXT NOT NULL,
                packages TEXT NOT NULL,
                network_policy TEXT,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            )",
            [],
        )?;

        // Migrate existing tables to add network_policy column
        let _ = conn
            .execute("ALTER TABLE jobs ADD COLUMN network_policy TEXT", [])
            .ok(); // Ignore error if column already exists

        // Migrate existing tables to add nixpkgs_version column
        let _ = conn
            .execute("ALTER TABLE jobs ADD COLUMN nixpkgs_version TEXT", [])
            .ok(); // Ignore error if column already exists

        // Migrate existing tables to add git_ref column
        let _ = conn
            .execute("ALTER TABLE jobs ADD COLUMN git_ref TEXT", [])
            .ok(); // Ignore error if column already exists

        // Migrate existing tables to add hardening_profile column
        let _ = conn
            .execute(
                "ALTER TABLE jobs ADD COLUMN hardening_profile TEXT DEFAULT 'default'",
                [],
            )
            .ok(); // Ignore error if column already exists

        // Migrate existing tables to add push column
        let _ = conn
            .execute("ALTER TABLE jobs ADD COLUMN push BOOLEAN DEFAULT 0", [])
            .ok(); // Ignore error if column already exists

        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES jobs(id)
            )",
            [],
        )?;

        // Migrate existing logs table to add source column (0 = Unspecified)
        let _ = conn
            .execute(
                "ALTER TABLE logs ADD COLUMN source INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .ok(); // Ignore error if column already exists

        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_job_id ON logs(job_id, timestamp)",
            [],
        )?;

        // Create cache_entries table for btrfs snapshot caching
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS cache_entries (
                nar_hash TEXT PRIMARY KEY,
                snapshot_path TEXT NOT NULL,
                closure_paths TEXT NOT NULL,
                size_bytes INTEGER,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL,
                use_count INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;

        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_last_used ON cache_entries(last_used_at)",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: path_str,
        })
    }

    /// Recover orphaned jobs that were left in "running" state from previous server instance
    ///
    /// When the server crashes or is killed, jobs in the "running" state remain in the database
    /// but are no longer actually executing. This method marks all such orphaned jobs as "failed"
    /// during server startup to maintain database consistency.
    ///
    /// Returns the number of jobs that were recovered (marked as failed).
    pub fn recover_orphaned_jobs(&self) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let count = conn.execute(
            "UPDATE jobs SET status = 'failed', completed_at = ?1 WHERE status = 'running'",
            params![now],
        )?;

        Ok(count)
    }

    /// Save job metadata
    pub fn save_job(&self, job: &JobMetadata) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let created_at = job
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let completed_at = job
            .completed_at
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        let packages_json = serde_json::to_string(&job.packages)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let network_policy_json = job
            .network_policy
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let _ = conn.execute(
            "INSERT OR REPLACE INTO jobs (id, repo, path, script, packages, network_policy, nixpkgs_version, git_ref, hardening_profile, push, status, created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                job.id,
                job.repo,
                job.path,
                job.script,
                packages_json,
                network_policy_json,
                job.nixpkgs_version,
                job.git_ref,
                job.hardening_profile,
                job.push,
                job.status.to_string(),
                created_at,
                completed_at,
            ],
        )?;

        Ok(())
    }

    /// Get job metadata by ID
    pub fn get_job(&self, job_id: &str) -> Result<Option<JobMetadata>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT id, repo, path, script, packages, network_policy, nixpkgs_version, git_ref, hardening_profile, push, status, created_at, completed_at
             FROM jobs WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![job_id])?;

        match rows.next()? {
            Some(row) => {
                let packages_json: String = row.get(4)?;
                let packages: Vec<String> = serde_json::from_str(&packages_json)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                let network_policy_json: Option<String> = row.get(5)?;
                let network_policy = network_policy_json
                    .map(|json| serde_json::from_str(&json))
                    .transpose()
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                let nixpkgs_version: Option<String> = row.get(6)?;
                let git_ref: Option<String> = row.get(7)?;
                let hardening_profile: Option<String> = row.get(8)?;
                let push: bool = row.get(9)?;
                let status_str: String = row.get(10)?;
                let created_at_secs: i64 = row.get(11)?;
                let completed_at_secs: Option<i64> = row.get(12)?;

                Ok(Some(JobMetadata {
                    id: row.get(0)?,
                    repo: row.get(1)?,
                    path: row.get(2)?,
                    script: row.get(3)?,
                    packages,
                    network_policy,
                    nixpkgs_version,
                    git_ref,
                    hardening_profile,
                    push,
                    status: JobStatus::from_string(&status_str)?,
                    created_at: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(created_at_secs as u64),
                    completed_at: completed_at_secs
                        .map(|s| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s as u64)),
                }))
            }
            None => Ok(None),
        }
    }

    /// Update job status
    pub fn update_job_status(&self, job_id: &str, status: JobStatus) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let completed_at = if status == JobStatus::Completed || status == JobStatus::Failed {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| StorageError::TimeError(e.to_string()))?
                    .as_secs() as i64,
            )
        } else {
            None
        };

        let rows_affected = conn.execute(
            "UPDATE jobs SET status = ?1, completed_at = ?2 WHERE id = ?3",
            params![status.to_string(), completed_at, job_id],
        )?;

        if rows_affected == 0 {
            return Err(StorageError::JobNotFound(job_id.to_string()));
        }

        Ok(())
    }

    /// Append a log entry for a job
    pub fn append_log(&self, job_id: &str, entry: &LogEntry) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let timestamp = entry
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let _ = conn.execute(
            "INSERT INTO logs (job_id, timestamp, message, source) VALUES (?1, ?2, ?3, ?4)",
            params![job_id, timestamp, entry.message, entry.source],
        )?;

        Ok(())
    }

    /// Get all log entries for a job
    pub fn get_logs(&self, job_id: &str) -> Result<Vec<LogEntry>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT timestamp, message, source FROM logs WHERE job_id = ?1 ORDER BY timestamp ASC",
        )?;

        let logs = stmt
            .query_map(params![job_id], |row| {
                let timestamp_secs: i64 = row.get(0)?;
                let message: String = row.get(1)?;
                let source: i32 = row.get(2)?;

                Ok(LogEntry {
                    timestamp: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(timestamp_secs as u64),
                    message,
                    source,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(logs)
    }

    /// Get the last N log entries for a job (most recent entries)
    ///
    /// Returns up to `limit` log entries in chronological order (oldest to newest).
    /// Useful for showing recent history when attaching to a running job.
    pub fn get_logs_tail(&self, job_id: &str, limit: usize) -> Result<Vec<LogEntry>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        // Query in DESC order with LIMIT, then reverse to get chronological order
        let mut stmt = conn.prepare(
            "SELECT timestamp, message, source FROM logs WHERE job_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;

        let mut logs: Vec<LogEntry> = stmt
            .query_map(params![job_id, limit as i64], |row| {
                let timestamp_secs: i64 = row.get(0)?;
                let message: String = row.get(1)?;
                let source: i32 = row.get(2)?;

                Ok(LogEntry {
                    timestamp: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(timestamp_secs as u64),
                    message,
                    source,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Reverse to get chronological order (oldest to newest)
        logs.reverse();

        Ok(logs)
    }

    /// List jobs with optional filtering and pagination
    ///
    /// Returns a tuple of (jobs, total_count) where jobs is the paginated result
    /// and total_count is the total number of jobs matching the filter.
    pub fn list_jobs(
        &self,
        status_filter: Option<JobStatus>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<JobMetadata>, usize), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        // Build WHERE clause for status filter
        let (where_clause, status_param) = if let Some(status) = status_filter {
            ("WHERE status = ?1", Some(status.to_string()))
        } else {
            ("", None)
        };

        // Get total count matching filter
        let count_query = format!("SELECT COUNT(*) FROM jobs {}", where_clause);
        let total_count: usize = if let Some(ref status_str) = status_param {
            conn.query_row(&count_query, params![status_str], |row| row.get(0))?
        } else {
            conn.query_row(&count_query, [], |row| row.get(0))?
        };

        // Get paginated results
        let query = format!(
            "SELECT id, repo, path, script, packages, network_policy, status, created_at, completed_at, \
             nixpkgs_version, git_ref, hardening_profile, push \
             FROM jobs {} ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}",
            where_clause,
            if status_param.is_some() { "2" } else { "1" },
            if status_param.is_some() { "3" } else { "2" }
        );

        let mut stmt = conn.prepare(&query)?;
        let rows: Vec<JobMetadata> = if let Some(ref status_str) = status_param {
            stmt.query_map(params![status_str, limit as i64, offset as i64], |row| {
                Self::row_to_job_metadata(row)
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![limit as i64, offset as i64], |row| {
                Self::row_to_job_metadata(row)
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let jobs = rows;

        Ok((jobs, total_count))
    }

    /// Helper to convert a database row to JobMetadata
    fn row_to_job_metadata(row: &rusqlite::Row) -> Result<JobMetadata, rusqlite::Error> {
        let id: String = row.get(0)?;
        let repo: String = row.get(1)?;
        let path: String = row.get(2)?;
        let script: String = row.get(3)?;
        let packages_json: String = row.get(4)?;
        let network_policy_json: Option<String> = row.get(5)?;
        let status_str: String = row.get(6)?;
        let created_at_secs: i64 = row.get(7)?;
        let completed_at_secs: Option<i64> = row.get(8)?;
        let nixpkgs_version: Option<String> = row.get(9)?;
        let git_ref: Option<String> = row.get(10)?;
        let hardening_profile: Option<String> = row.get(11)?;
        let push: bool = row.get(12)?;

        let packages: Vec<String> = serde_json::from_str(&packages_json).unwrap_or_default();
        let network_policy = network_policy_json
            .as_ref()
            .and_then(|json| serde_json::from_str(json).ok());

        let status = JobStatus::from_string(&status_str)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);
        let completed_at = completed_at_secs
            .map(|secs| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64));

        Ok(JobMetadata {
            id,
            repo,
            path,
            script,
            packages,
            network_policy,
            nixpkgs_version,
            git_ref,
            hardening_profile,
            push,
            status,
            created_at,
            completed_at,
        })
    }

    // ==================== Cache Entry Methods ====================

    /// Save or update a cache entry
    pub fn save_cache_entry(&self, entry: &CacheEntry) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let created_at = entry
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let last_used_at = entry
            .last_used_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let closure_paths_json = serde_json::to_string(&entry.closure_paths)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let _ = conn.execute(
            "INSERT OR REPLACE INTO cache_entries
             (nar_hash, snapshot_path, closure_paths, size_bytes, created_at, last_used_at, use_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.nar_hash,
                entry.snapshot_path,
                closure_paths_json,
                entry.size_bytes,
                created_at,
                last_used_at,
                entry.use_count,
            ],
        )?;

        Ok(())
    }

    /// Get a cache entry by NAR hash
    pub fn get_cache_entry(&self, nar_hash: &str) -> Result<Option<CacheEntry>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT nar_hash, snapshot_path, closure_paths, size_bytes, created_at, last_used_at, use_count
             FROM cache_entries WHERE nar_hash = ?1",
        )?;

        let mut rows = stmt.query(params![nar_hash])?;

        match rows.next()? {
            Some(row) => {
                let closure_paths_json: String = row.get(2)?;
                let closure_paths: Vec<String> = serde_json::from_str(&closure_paths_json)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                let created_at_secs: i64 = row.get(4)?;
                let last_used_at_secs: i64 = row.get(5)?;

                Ok(Some(CacheEntry {
                    nar_hash: row.get(0)?,
                    snapshot_path: row.get(1)?,
                    closure_paths,
                    size_bytes: row.get(3)?,
                    created_at: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(created_at_secs as u64),
                    last_used_at: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(last_used_at_secs as u64),
                    use_count: row.get(6)?,
                }))
            }
            None => Ok(None),
        }
    }

    /// Touch a cache entry (update last_used_at and increment use_count)
    pub fn touch_cache_entry(&self, nar_hash: &str) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::TimeError(e.to_string()))?
            .as_secs() as i64;

        let rows_affected = conn.execute(
            "UPDATE cache_entries SET last_used_at = ?1, use_count = use_count + 1 WHERE nar_hash = ?2",
            params![now, nar_hash],
        )?;

        if rows_affected == 0 {
            return Err(StorageError::CacheEntryNotFound(nar_hash.to_string()));
        }

        Ok(())
    }

    /// Delete a cache entry by NAR hash
    pub fn delete_cache_entry(&self, nar_hash: &str) -> Result<(), StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let _ = conn.execute(
            "DELETE FROM cache_entries WHERE nar_hash = ?1",
            params![nar_hash],
        )?;

        Ok(())
    }

    /// List cache entries ordered by last_used_at (oldest first, for LRU eviction)
    pub fn list_cache_entries_lru(&self, limit: usize) -> Result<Vec<CacheEntry>, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let mut stmt = conn.prepare(
            "SELECT nar_hash, snapshot_path, closure_paths, size_bytes, created_at, last_used_at, use_count
             FROM cache_entries ORDER BY last_used_at ASC LIMIT ?1",
        )?;

        let entries = stmt
            .query_map(params![limit as i64], |row| {
                let closure_paths_json: String = row.get(2)?;
                let closure_paths: Vec<String> =
                    serde_json::from_str(&closure_paths_json).unwrap_or_default();

                let created_at_secs: i64 = row.get(4)?;
                let last_used_at_secs: i64 = row.get(5)?;

                Ok(CacheEntry {
                    nar_hash: row.get(0)?,
                    snapshot_path: row.get(1)?,
                    closure_paths,
                    size_bytes: row.get(3)?,
                    created_at: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(created_at_secs as u64),
                    last_used_at: SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(last_used_at_secs as u64),
                    use_count: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Get total cache size in bytes
    pub fn get_cache_total_size(&self) -> Result<i64, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM cache_entries",
            [],
            |row| row.get(0),
        )?;

        Ok(total)
    }

    /// Get count of cache entries
    pub fn get_cache_entry_count(&self) -> Result<usize, StorageError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let count: usize =
            conn.query_row("SELECT COUNT(*) FROM cache_entries", [], |row| row.get(0))?;

        Ok(count)
    }
}

#[derive(Debug)]
pub enum StorageError {
    DbError(rusqlite::Error),
    InvalidStatus(String),
    InvalidPath(String),
    JobNotFound(String),
    CacheEntryNotFound(String),
    TimeError(String),
    LockError(String),
    SerializationError(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::DbError(e) => write!(f, "database error: {}", e),
            StorageError::InvalidStatus(s) => write!(f, "invalid status: {}", s),
            StorageError::InvalidPath(s) => write!(f, "invalid path: {}", s),
            StorageError::JobNotFound(id) => write!(f, "job not found: {}", id),
            StorageError::CacheEntryNotFound(h) => write!(f, "cache entry not found: {}", h),
            StorageError::TimeError(e) => write!(f, "time error: {}", e),
            StorageError::LockError(e) => write!(f, "lock error: {}", e),
            StorageError::SerializationError(e) => write!(f, "serialization error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        StorageError::DbError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn create_test_storage() -> JobStorage {
        JobStorage::new(":memory:").expect("Failed to create test storage")
    }

    #[test]
    fn test_save_and_get_job() {
        let storage = create_test_storage();
        let job = JobMetadata {
            id: "test-job-1".to_string(),
            repo: "https://github.com/test/repo".to_string(),
            path: "test/path".to_string(),
            script: "echo test".to_string(),
            packages: vec![],
            network_policy: None,
            nixpkgs_version: None,
            git_ref: None,
            hardening_profile: None,
            push: false,
            status: JobStatus::Pending,
            created_at: SystemTime::now(),
            completed_at: None,
        };

        storage.save_job(&job).expect("Failed to save job");

        let retrieved = storage.get_job("test-job-1").expect("Failed to get job");
        assert!(retrieved.is_some());
        let retrieved = retrieved.expect("job should exist");
        assert_eq!(retrieved.id, "test-job-1");
        assert_eq!(retrieved.repo, "https://github.com/test/repo");
        assert_eq!(retrieved.status, JobStatus::Pending);
    }

    #[test]
    fn test_get_nonexistent_job() {
        let storage = create_test_storage();
        let result = storage.get_job("nonexistent").expect("Failed to query");
        assert!(result.is_none());
    }

    #[test]
    fn test_update_job_status() {
        let storage = create_test_storage();
        let job = JobMetadata {
            id: "test-job-2".to_string(),
            repo: "https://github.com/test/repo".to_string(),
            path: "test/path".to_string(),
            script: "echo test".to_string(),
            packages: vec![],
            network_policy: None,
            nixpkgs_version: None,
            git_ref: None,
            hardening_profile: None,
            push: false,
            status: JobStatus::Pending,
            created_at: SystemTime::now(),
            completed_at: None,
        };

        storage.save_job(&job).expect("Failed to save job");
        storage
            .update_job_status("test-job-2", JobStatus::Running)
            .expect("Failed to update status");

        let retrieved = storage
            .get_job("test-job-2")
            .expect("Failed to get job")
            .expect("job should exist");
        assert_eq!(retrieved.status, JobStatus::Running);
        assert!(retrieved.completed_at.is_none());
    }

    #[test]
    fn test_update_job_status_to_completed() {
        let storage = create_test_storage();
        let job = JobMetadata {
            id: "test-job-3".to_string(),
            repo: "https://github.com/test/repo".to_string(),
            path: "test/path".to_string(),
            script: "echo test".to_string(),
            packages: vec![],
            network_policy: None,
            nixpkgs_version: None,
            git_ref: None,
            hardening_profile: None,
            push: false,
            status: JobStatus::Running,
            created_at: SystemTime::now(),
            completed_at: None,
        };

        storage.save_job(&job).expect("Failed to save job");
        storage
            .update_job_status("test-job-3", JobStatus::Completed)
            .expect("Failed to update status");

        let retrieved = storage
            .get_job("test-job-3")
            .expect("Failed to get job")
            .expect("job should exist");
        assert_eq!(retrieved.status, JobStatus::Completed);
        assert!(retrieved.completed_at.is_some());
    }

    #[test]
    #[allow(clippy::panic)]
    fn test_update_nonexistent_job_status() {
        let storage = create_test_storage();
        let result = storage.update_job_status("nonexistent", JobStatus::Completed);
        assert!(result.is_err());
        match result {
            Err(StorageError::JobNotFound(id)) => assert_eq!(id, "nonexistent"),
            other => {
                panic!("expected jobnotfound error, got {:?}", other);
            }
        }
    }

    #[test]
    fn test_append_and_get_logs() {
        let storage = create_test_storage();
        let job = JobMetadata {
            id: "test-job-4".to_string(),
            repo: "https://github.com/test/repo".to_string(),
            path: "test/path".to_string(),
            script: "echo test".to_string(),
            packages: vec![],
            network_policy: None,
            nixpkgs_version: None,
            git_ref: None,
            hardening_profile: None,
            push: false,
            status: JobStatus::Running,
            created_at: SystemTime::now(),
            completed_at: None,
        };

        storage.save_job(&job).expect("Failed to save job");

        let log1 = LogEntry {
            timestamp: SystemTime::now(),
            message: "First log entry".to_string(),
            source: LogSource::System as i32,
        };
        let log2 = LogEntry {
            timestamp: SystemTime::now(),
            message: "Second log entry".to_string(),
            source: LogSource::System as i32,
        };

        storage
            .append_log("test-job-4", &log1)
            .expect("Failed to append log");
        storage
            .append_log("test-job-4", &log2)
            .expect("Failed to append log");

        let logs = storage.get_logs("test-job-4").expect("Failed to get logs");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].message, "First log entry");
        assert_eq!(logs[1].message, "Second log entry");
    }

    #[test]
    fn test_get_logs_empty() {
        let storage = create_test_storage();
        let job = JobMetadata {
            id: "test-job-5".to_string(),
            repo: "https://github.com/test/repo".to_string(),
            path: "test/path".to_string(),
            script: "echo test".to_string(),
            packages: vec![],
            network_policy: None,
            nixpkgs_version: None,
            git_ref: None,
            hardening_profile: None,
            push: false,
            status: JobStatus::Pending,
            created_at: SystemTime::now(),
            completed_at: None,
        };

        storage.save_job(&job).expect("Failed to save job");

        let logs = storage.get_logs("test-job-5").expect("Failed to get logs");
        assert_eq!(logs.len(), 0);
    }

    #[test]
    fn test_job_status_serialization() {
        assert_eq!(JobStatus::Pending.to_string(), "pending");
        assert_eq!(JobStatus::Running.to_string(), "running");
        assert_eq!(JobStatus::Completed.to_string(), "completed");
        assert_eq!(JobStatus::Failed.to_string(), "failed");

        assert_eq!(
            JobStatus::from_string("pending").expect("failed to parse pending status"),
            JobStatus::Pending
        );
        assert_eq!(
            JobStatus::from_string("running").expect("failed to parse running status"),
            JobStatus::Running
        );
        assert_eq!(
            JobStatus::from_string("completed").expect("failed to parse completed status"),
            JobStatus::Completed
        );
        assert_eq!(
            JobStatus::from_string("failed").expect("failed to parse failed status"),
            JobStatus::Failed
        );

        assert!(JobStatus::from_string("invalid").is_err());
    }
}
