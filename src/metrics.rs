//! Prometheus metrics for nix-jail
//!
//! Exposes job execution, cache performance, and resource metrics.

use crate::proxy::llm::ToolCall;
use prometheus::{
    CounterVec, Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

/// Registry holding all Prometheus metrics for nix-jail
#[derive(Debug)]
pub struct MetricsRegistry {
    registry: Registry,

    // Job counters
    pub jobs_total: CounterVec,

    // Duration histograms
    pub job_duration_seconds: Histogram,
    pub phase_duration_seconds: HistogramVec,

    // Cache counters
    pub cache_hits_total: CounterVec,
    pub cache_misses_total: CounterVec,

    // Closure metrics
    pub closure_paths_total: Histogram,

    // Active jobs gauge
    pub active_jobs: Gauge,

    // Proxy request counters
    pub proxy_requests_total: CounterVec,

    // LLM API metrics
    /// Token usage by host, model, type (input/output/cache_read), and credential
    pub llm_tokens_total: CounterVec,
    /// Tool invocations by host, tool name, and credential
    pub llm_tool_calls_total: CounterVec,
    /// LLM API requests by host, model, and credential
    pub llm_requests_total: CounterVec,
}

impl MetricsRegistry {
    /// Create a new metrics registry with all metrics registered
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // Job counters
        let jobs_total = CounterVec::new(
            Opts::new("nix_jail_jobs_total", "Total number of jobs completed")
                .namespace("nix_jail"),
            &["status"],
        )?;
        registry.register(Box::new(jobs_total.clone()))?;

        // Job duration histogram
        // Buckets: 1s, 5s, 10s, 30s, 1m, 2m, 5m, 10m, 30m, 1h
        let job_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "nix_jail_job_duration_seconds",
                "Total job duration in seconds",
            )
            .namespace("nix_jail")
            .buckets(vec![
                1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0,
            ]),
        )?;
        registry.register(Box::new(job_duration_seconds.clone()))?;

        // Phase duration histogram
        // Buckets: 100ms, 500ms, 1s, 2s, 5s, 10s, 30s, 60s
        let phase_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "nix_jail_phase_duration_seconds",
                "Duration of job execution phases in seconds",
            )
            .namespace("nix_jail")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
            &["phase"],
        )?;
        registry.register(Box::new(phase_duration_seconds.clone()))?;

        // Cache hit counter
        let cache_hits_total = CounterVec::new(
            Opts::new("nix_jail_cache_hits_total", "Total number of cache hits")
                .namespace("nix_jail"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        // Cache miss counter
        let cache_misses_total = CounterVec::new(
            Opts::new(
                "nix_jail_cache_misses_total",
                "Total number of cache misses",
            )
            .namespace("nix_jail"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        // Closure paths histogram
        // Buckets: 10, 50, 100, 200, 500, 1000, 2000 paths
        let closure_paths_total = Histogram::with_opts(
            HistogramOpts::new(
                "nix_jail_closure_paths_total",
                "Number of store paths in job closures",
            )
            .namespace("nix_jail")
            .buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0]),
        )?;
        registry.register(Box::new(closure_paths_total.clone()))?;

        // Active jobs gauge
        let active_jobs = Gauge::new("nix_jail_active_jobs", "Number of currently running jobs")?;
        registry.register(Box::new(active_jobs.clone()))?;

        // Proxy request counter with dimensions
        let proxy_requests_total = CounterVec::new(
            Opts::new(
                "nix_jail_proxy_requests_total",
                "Total proxy requests by host, method, status, credential, and decision",
            )
            .namespace("nix_jail"),
            &["host", "method", "status", "credential", "decision"],
        )?;
        registry.register(Box::new(proxy_requests_total.clone()))?;

        // LLM API token usage counter
        let llm_tokens_total = CounterVec::new(
            Opts::new("nix_jail_llm_tokens_total", "LLM API token usage by type")
                .namespace("nix_jail"),
            &["host", "model", "token_type", "credential"],
        )?;
        registry.register(Box::new(llm_tokens_total.clone()))?;

        // LLM API tool call counter
        let llm_tool_calls_total = CounterVec::new(
            Opts::new("nix_jail_llm_tool_calls_total", "LLM API tool invocations")
                .namespace("nix_jail"),
            &["host", "tool_name", "credential"],
        )?;
        registry.register(Box::new(llm_tool_calls_total.clone()))?;

        // LLM API request counter
        let llm_requests_total = CounterVec::new(
            Opts::new("nix_jail_llm_requests_total", "LLM API requests by model")
                .namespace("nix_jail"),
            &["host", "model", "credential"],
        )?;
        registry.register(Box::new(llm_requests_total.clone()))?;

        // Register process collector for memory/CPU metrics (Linux only)
        #[cfg(target_os = "linux")]
        {
            let process_collector = prometheus::process_collector::ProcessCollector::for_self();
            registry.register(Box::new(process_collector))?;
        }

        Ok(Self {
            registry,
            jobs_total,
            job_duration_seconds,
            phase_duration_seconds,
            cache_hits_total,
            cache_misses_total,
            closure_paths_total,
            active_jobs,
            proxy_requests_total,
            llm_tokens_total,
            llm_tool_calls_total,
            llm_requests_total,
        })
    }

    /// Encode all metrics in Prometheus text format
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        let metric_families = self.registry.gather();
        let _ = encoder.encode(&metric_families, &mut buffer);
        String::from_utf8(buffer).unwrap_or_default()
    }

    /// Record a completed job
    pub fn record_job_completed(&self, status: &str, duration_secs: f64) {
        self.jobs_total.with_label_values(&[status]).inc();
        self.job_duration_seconds.observe(duration_secs);
    }

    /// Record a phase duration
    pub fn record_phase(&self, phase: &str, duration_secs: f64) {
        self.phase_duration_seconds
            .with_label_values(&[phase])
            .observe(duration_secs);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self, cache_type: &str) {
        self.cache_hits_total.with_label_values(&[cache_type]).inc();
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self, cache_type: &str) {
        self.cache_misses_total
            .with_label_values(&[cache_type])
            .inc();
    }

    /// Record closure size
    pub fn record_closure_size(&self, path_count: usize) {
        self.closure_paths_total.observe(path_count as f64);
    }

    /// Increment active jobs count
    pub fn job_started(&self) {
        self.active_jobs.inc();
    }

    /// Decrement active jobs count
    pub fn job_finished(&self) {
        self.active_jobs.dec();
    }

    /// Record a proxy request with all dimensions
    pub fn record_proxy_request(
        &self,
        host: &str,
        method: &str,
        status: u16,
        credential: &str,
        decision: &str,
        count: u64,
    ) {
        self.proxy_requests_total
            .with_label_values(&[host, method, &status.to_string(), credential, decision])
            .inc_by(count as f64);
    }

    /// Record LLM API usage metrics
    #[allow(clippy::too_many_arguments)]
    pub fn record_llm_usage(
        &self,
        host: &str,
        credential: &str,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_read_tokens: Option<u64>,
        tool_calls: &[ToolCall],
    ) {
        let model_str = model.unwrap_or("unknown");

        // Record request
        self.llm_requests_total
            .with_label_values(&[host, model_str, credential])
            .inc();

        // Record token usage
        if let Some(input) = input_tokens {
            self.llm_tokens_total
                .with_label_values(&[host, model_str, "input", credential])
                .inc_by(input as f64);
        }
        if let Some(output) = output_tokens {
            self.llm_tokens_total
                .with_label_values(&[host, model_str, "output", credential])
                .inc_by(output as f64);
        }
        if let Some(cache) = cache_read_tokens {
            self.llm_tokens_total
                .with_label_values(&[host, model_str, "cache_read", credential])
                .inc_by(cache as f64);
        }

        // Record tool calls (by name only for Prometheus labels)
        for tool in tool_calls {
            self.llm_tool_calls_total
                .with_label_values(&[host, &tool.name, credential])
                .inc();
        }
    }
}

/// Shared metrics registry type
pub type SharedMetrics = Arc<MetricsRegistry>;

/// Create a new shared metrics registry
pub fn create_registry() -> Result<SharedMetrics, prometheus::Error> {
    Ok(Arc::new(MetricsRegistry::new()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_creation() {
        let registry = MetricsRegistry::new().expect("failed to create registry");
        assert!(registry.active_jobs.get() == 0.0);
    }

    #[test]
    fn test_metrics_encoding() {
        let registry = MetricsRegistry::new().expect("failed to create registry");
        registry.job_started();
        registry.record_cache_hit("root");
        registry.record_phase("setup_workspace", 1.5);

        let output = registry.encode();
        assert!(output.contains("nix_jail_active_jobs 1"));
        assert!(output.contains("nix_jail_cache_hits_total"));
        assert!(output.contains("nix_jail_phase_duration_seconds"));
    }

    #[test]
    fn test_job_lifecycle() {
        let registry = MetricsRegistry::new().expect("failed to create registry");

        registry.job_started();
        assert!(registry.active_jobs.get() == 1.0);

        registry.job_finished();
        assert!(registry.active_jobs.get() == 0.0);

        registry.record_job_completed("success", 10.5);
        // Counter should have been incremented
    }
}
