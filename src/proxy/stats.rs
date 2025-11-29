use std::collections::HashMap;
use std::sync::Mutex;

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

    /// Log summary statistics as a structured log message.
    /// This should be called on shutdown (SIGTERM/SIGINT).
    pub fn log_summary(&self) {
        // Safety: mutex poisoning should panic - indicates another thread panicked
        #[allow(clippy::expect_used)]
        let approved = self.approved.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let denied = self.denied.lock().expect("operation failed");

        // Convert to sorted Vec for consistent output
        let mut approved_vec: Vec<_> = approved.iter().collect();
        approved_vec.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending

        let mut denied_vec: Vec<_> = denied.iter().collect();
        denied_vec.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending

        tracing::info!(
            approved_total = approved.len(),
            denied_total = denied.len(),
            approved = ?approved_vec,
            denied = ?denied_vec,
            "Proxy shutdown statistics"
        );
    }
}
