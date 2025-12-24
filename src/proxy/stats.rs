use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Serializable proxy statistics for file output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatsSummary {
    pub approved: Vec<(String, u64)>,
    pub denied: Vec<(String, u64)>,
}

/// Thread-safe statistics tracking for proxy requests
#[derive(Debug, Default)]
pub struct ProxyStats {
    approved: Mutex<HashMap<String, u64>>,
    denied: Mutex<HashMap<String, u64>>,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an approved request for the given hostname.
    /// Increments the counter for this hostname.
    pub fn record_approved(&self, hostname: &str) {
        // Safety: mutex poisoning should panic - indicates another thread panicked
        #[allow(clippy::expect_used)]
        let mut map = self.approved.lock().expect("operation failed");
        *map.entry(hostname.to_string()).or_insert(0) += 1;
    }

    /// Record a denied request for the given hostname.
    /// Returns true if this is the first time this hostname was denied (should log),
    /// false otherwise (already logged, don't spam).
    pub fn record_denied(&self, hostname: &str) -> bool {
        // Safety: mutex poisoning should panic - indicates another thread panicked
        #[allow(clippy::expect_used)]
        let mut map = self.denied.lock().expect("operation failed");
        let entry = map.entry(hostname.to_string()).or_insert(0);
        let is_first = *entry == 0;
        *entry += 1;
        is_first
    }

    /// Get summary statistics as a serializable struct
    pub fn summary(&self) -> ProxyStatsSummary {
        #[allow(clippy::expect_used)]
        let approved = self.approved.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let denied = self.denied.lock().expect("operation failed");

        let mut approved_vec: Vec<_> = approved.iter().map(|(k, v)| (k.clone(), *v)).collect();
        approved_vec.sort_by(|a, b| b.1.cmp(&a.1));

        let mut denied_vec: Vec<_> = denied.iter().map(|(k, v)| (k.clone(), *v)).collect();
        denied_vec.sort_by(|a, b| b.1.cmp(&a.1));

        ProxyStatsSummary {
            approved: approved_vec,
            denied: denied_vec,
        }
    }

    /// Write stats to a JSON file for the orchestrator to read after job completes
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let summary = self.summary();
        let json = serde_json::to_string(&summary)?;
        std::fs::write(path, json)
    }
}
