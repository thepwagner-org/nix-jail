//! Manages alice proxy lifecycle for individual jobs
//!
//! Each job gets its own alice proxy instance on a unique port.
//! The proxy is automatically terminated when dropped.
//!
//! # Path conventions
//!
//! Alice writes its CA certificate to the configured path. Inside the sandbox
//! (chroot), this becomes a different path:
//!
//! - **Host path**: `{root_dir}/etc/ssl/certs/ca-certificates.crt`
//! - **Chroot path**: `/etc/ssl/certs/ca-certificates.crt` (inside sandbox)
//!
//! Environment variables like `SSL_CERT_FILE` must use the chroot path.

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::workspace::ProxyConfigResult;

/// Fallback proxy port used when parsing the listen address fails.
/// With dynamic port allocation (port 0), the real port is discovered
/// from alice's "listening for connections" log line after startup.
pub const DEFAULT_PROXY_PORT: u16 = 0;

/// Find the alice proxy binary.
///
/// Search order:
/// 1. `proxy_binary` from server config (set by NixOS module)
/// 2. `ALICE_PATH` environment variable
/// 3. `alice` on $PATH (via `which`)
/// 4. Sibling of current executable (for cargo dev builds)
fn find_alice_binary(configured_path: Option<&Path>) -> std::io::Result<PathBuf> {
    // 1. Explicit config path (from NixOS module)
    if let Some(path) = configured_path {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("configured proxy_binary not found: {:?}", path),
        ));
    }

    // 2. ALICE_PATH env var
    if let Ok(path) = std::env::var("ALICE_PATH") {
        let path = PathBuf::from(&path);
        if path.exists() {
            return Ok(path);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("ALICE_PATH binary not found: {:?}", path),
        ));
    }

    // 3. alice on $PATH
    if let Ok(path) = which::which("alice") {
        return Ok(path);
    }

    // 4. Sibling of current exe (cargo dev)
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(bin_dir) = current_exe.parent() {
            let sibling = bin_dir.join("alice");
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "alice binary not found (tried: config proxy_binary, ALICE_PATH env, PATH, exe sibling)",
    ))
}

/// CA certificate path inside the sandbox (chroot-relative)
///
/// Use this for environment variables like SSL_CERT_FILE that are
/// interpreted inside the sandbox.
pub const CA_CERT_CHROOT_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// CA certificate path relative to root_dir (host-relative)
///
/// Use this to construct the host filesystem path where the cert is written.
/// The full host path is `{root_dir}/{CA_CERT_HOST_SUBPATH}`.
pub const CA_CERT_HOST_SUBPATH: &str = "etc/ssl/certs/ca-certificates.crt";

/// Manages an alice proxy instance for a single job
#[derive(Debug)]
pub struct ProxyManager {
    /// Proxy process handle
    proxy_process: Option<Child>,

    /// Port the proxy is listening on
    pub port: u16,

    /// Host/IP the proxy is listening on (platform-specific)
    pub listen_host: String,

    /// Job ID this proxy belongs to
    job_id: String,

    /// Optional username for HTTP Basic Auth
    proxy_username: Option<String>,

    /// Optional password for HTTP Basic Auth
    proxy_password: Option<String>,

    /// Stdout channel for streaming proxy logs
    pub stdout: Option<mpsc::Receiver<String>>,

    /// Stderr channel for streaming proxy logs
    pub stderr: Option<mpsc::Receiver<String>>,

    /// Port for alice's observability metrics endpoint
    pub metrics_port: Option<u16>,

    /// Port for alice's reverse proxy listener (inbound traffic to sandbox)
    /// Set when alice is configured with [reverse_proxy] and reports its bound port.
    pub reverse_proxy_port: Option<u16>,
}

impl ProxyManager {
    /// Compute the CA certificate host path from a root directory
    pub fn ca_cert_host_path(root_dir: &Path) -> PathBuf {
        root_dir.join(CA_CERT_HOST_SUBPATH)
    }

    /// Start a new alice proxy instance for a job
    ///
    /// The proxy will listen on the configured port and write its CA certificate
    /// to the configured path (accessible inside the sandbox).
    ///
    /// # Arguments
    /// * `job_id` - Unique identifier for this job
    /// * `root_dir` - Path to the job's root directory (becomes / inside sandbox)
    /// * `config_result` - Result from write_proxy_config with config path, env vars, and port
    /// * `listen_host` - Host/IP the proxy connects from (e.g., "127.0.0.1" or "10.0.0.1")
    /// * `resolved_cred_env` - Pre-resolved credential values as env vars (for keychain/inline sources)
    /// * `configured_binary` - Optional explicit path to the alice binary (from server config)
    pub async fn start(
        job_id: String,
        root_dir: PathBuf,
        config_result: ProxyConfigResult,
        listen_host: String,
        resolved_cred_env: HashMap<String, String>,
        configured_binary: Option<&Path>,
    ) -> Result<Self, std::io::Error> {
        // CA cert host path — alice writes here, sandbox sees it at CA_CERT_CHROOT_PATH
        let ca_cert_host_path = Self::ca_cert_host_path(&root_dir);
        if let Some(cert_dir) = ca_cert_host_path.parent() {
            std::fs::create_dir_all(cert_dir)?;
        }

        let proxy_username = config_result.proxy_username.clone();
        let proxy_password = config_result.proxy_password.clone();

        tracing::debug!(job_id = %job_id, "starting alice proxy for job");

        let alice_bin = find_alice_binary(configured_binary)?;

        let (stdout_tx, stdout_rx) = mpsc::channel::<String>(128);
        let (stderr_tx, stderr_rx) = mpsc::channel::<String>(128);

        let mut proxy_cmd = Command::new(&alice_bin);
        let _ = proxy_cmd
            .arg("--config")
            .arg(&config_result.config_path)
            .arg("--json"); // JSON logs for readiness detection

        // Set environment variables from config (proxy password, etc.)
        for (key, value) in &config_result.env_vars {
            let _ = proxy_cmd.env(key, value);
        }

        // Set pre-resolved credential environment variables
        for (key, value) in &resolved_cred_env {
            let _ = proxy_cmd.env(key, value);
        }

        // Propagate trace context to child process for distributed tracing
        let propagator = TraceContextPropagator::new();
        let mut carrier: HashMap<String, String> = HashMap::new();
        let cx = tracing::Span::current().context();
        propagator.inject_context(&cx, &mut carrier);

        if let Some(traceparent) = carrier.get("traceparent") {
            let _ = proxy_cmd.env("TRACEPARENT", traceparent);
            tracing::debug!(traceparent = %traceparent, "propagating trace context to alice");
        }
        if let Some(tracestate) = carrier.get("tracestate") {
            let _ = proxy_cmd.env("TRACESTATE", tracestate);
        }

        tracing::debug!(
            job_id = %job_id,
            config_path = %config_result.config_path.display(),
            alice_binary = %alice_bin.display(),
            "alice will use config file"
        );

        let mut proxy_process = proxy_cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let proxy_stdout = proxy_process
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture alice stdout"))?;
        let proxy_stderr = proxy_process
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture alice stderr"))?;

        // Readiness info parsed from alice's stderr logs
        struct ReadinessInfo {
            /// Actual port alice bound for the forward proxy (OS-assigned when port 0 was configured)
            proxy_port: u16,
            reverse_proxy_port: Option<u16>,
            metrics_port: Option<u16>,
        }

        // Channel for readiness signal from stderr parser
        let (ready_tx, mut ready_rx) = mpsc::channel::<ReadinessInfo>(1);

        // Spawn stdout streaming task
        drop(tokio::spawn(async move {
            let reader = BufReader::new(proxy_stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if stdout_tx.send(line).await.is_err() {
                    break;
                }
            }
        }));

        // Spawn stderr streaming task with readiness detection
        // Alice outputs JSON logs to stderr with --json flag.
        // We detect readiness by looking for the "listening for connections" message.
        // We parse all three ports (forward proxy, reverse proxy, metrics) from startup
        // log messages since all use port 0 (OS-assigned) to avoid cross-job conflicts.
        drop(tokio::spawn(async move {
            let reader = BufReader::new(proxy_stderr);
            let mut lines = reader.lines();
            let mut ready_sent = false;
            let mut reverse_proxy_port: Option<u16> = None;
            let mut metrics_port: Option<u16> = None;

            while let Ok(Some(line)) = lines.next_line().await {
                // Parse reverse proxy port from alice log:
                // JSON log contains "reverse proxy started" with addr field
                // e.g., {"fields":{"addr":"127.0.0.1:12345",...},"message":"reverse proxy started",...}
                if line.contains("reverse proxy started") {
                    reverse_proxy_port = parse_addr_port(&line);
                    if let Some(port) = reverse_proxy_port {
                        tracing::debug!(port = port, "parsed reverse proxy port from alice log");
                    }
                }

                // Parse metrics port from alice log:
                // JSON log contains "metrics server started" with addr field
                // e.g., {"fields":{"addr":"127.0.0.1:54321",...},"message":"metrics server started",...}
                if line.contains("metrics server started") {
                    metrics_port = parse_addr_port(&line);
                    if let Some(port) = metrics_port {
                        tracing::debug!(port = port, "parsed metrics port from alice log");
                    }
                }

                // Detect alice readiness: JSON log line containing "listening for connections"
                // This is the forward proxy readiness signal (emitted after TCP bind).
                // The addr field contains the actual bound address (e.g., "0.0.0.0:54321")
                // which may differ from the configured address when port 0 was used.
                if !ready_sent && line.contains("listening for connections") {
                    let proxy_port = parse_addr_port(&line).unwrap_or(0);
                    let _ = ready_tx
                        .send(ReadinessInfo {
                            proxy_port,
                            reverse_proxy_port,
                            metrics_port,
                        })
                        .await;
                    ready_sent = true;
                }

                if stderr_tx.send(line).await.is_err() {
                    break;
                }
            }
        }));

        tracing::debug!(job_id = %job_id, "alice started, waiting for readiness");

        // Wait for readiness signal (alice logs "listening for connections" after TCP bind)
        let readiness_timeout = tokio::time::timeout(Duration::from_secs(30), async {
            // Check both the readiness signal and process exit
            tokio::select! {
                result = ready_rx.recv() => {
                    if let Some(info) = result {
                        return Ok(info);
                    }
                    // Channel closed without ready signal
                    Err(std::io::Error::other("alice stderr closed without readiness signal"))
                }
                status = proxy_process.wait() => {
                    Err(std::io::Error::other(format!(
                        "alice exited unexpectedly with status: {}",
                        status.map_or_else(|e| e.to_string(), |s| s.to_string())
                    )))
                }
            }
        })
        .await;

        let readiness_info = match readiness_timeout {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "alice did not become ready after 30 seconds",
                ));
            }
        };

        tracing::info!(
            job_id = %job_id,
            proxy_port = readiness_info.proxy_port,
            ca_cert = %ca_cert_host_path.display(),
            reverse_proxy_port = ?readiness_info.reverse_proxy_port,
            metrics_port = ?readiness_info.metrics_port,
            "alice proxy ready"
        );

        Ok(Self {
            proxy_process: Some(proxy_process),
            port: readiness_info.proxy_port,
            listen_host,
            job_id,
            proxy_username,
            proxy_password,
            stdout: Some(stdout_rx),
            stderr: Some(stderr_rx),
            metrics_port: readiness_info.metrics_port,
            reverse_proxy_port: readiness_info.reverse_proxy_port,
        })
    }

    /// Get proxy URL for environment variables using the listen host
    ///
    /// Returns URL with embedded credentials if proxy authentication is enabled:
    /// - With auth: `http://job-123:password@127.0.0.1:3128` (trufflehog:ignore)
    /// - Without auth: `http://127.0.0.1:3128`
    pub fn proxy_url(&self) -> String {
        self.proxy_url_with_host(&self.listen_host)
    }

    /// Get proxy URL with a specific host (for platform-specific connect addresses)
    ///
    /// Use this to build proxy URLs with the correct connect address:
    /// - Linux jobs connect via veth at 10.0.0.1
    /// - macOS jobs connect via localhost at 127.0.0.1
    pub fn proxy_url_with_host(&self, host: &str) -> String {
        match (&self.proxy_username, &self.proxy_password) {
            (Some(user), Some(pass)) => {
                format!("http://{}:{}@{}:{}", user, pass, host, self.port)
            }
            _ => {
                format!("http://{}:{}", host, self.port)
            }
        }
    }

    /// Take ownership of stdout channel for streaming
    pub fn take_stdout(&mut self) -> Option<mpsc::Receiver<String>> {
        self.stdout.take()
    }

    /// Take ownership of stderr channel for streaming
    pub fn take_stderr(&mut self) -> Option<mpsc::Receiver<String>> {
        self.stderr.take()
    }

    /// Collect stats from alice's metrics endpoints before shutdown.
    ///
    /// Alice exposes /metrics (Prometheus) and /llm/completions (JSON) endpoints.
    /// We query these before sending SIGTERM so the data isn't lost.
    ///
    /// Returns (approved_count, denied_count) as a simple summary.
    pub async fn collect_stats(&self) -> ProxyStats {
        let Some(metrics_port) = self.metrics_port else {
            return ProxyStats::default();
        };

        let base_url = format!("http://127.0.0.1:{}", metrics_port);
        let mut stats = ProxyStats::default();

        // Query /llm/completions for LLM usage data
        match reqwest::get(format!("{}/llm/completions", base_url)).await {
            Ok(resp) => {
                if let Ok(completions) = resp.json::<Vec<AliceLlmCompletion>>().await {
                    stats.llm_completions = completions;
                }
            }
            Err(e) => {
                tracing::debug!(job_id = %self.job_id, error = %e, "failed to query alice /llm/completions");
            }
        }

        // Query /metrics for prometheus text
        match reqwest::get(format!("{}/metrics", base_url)).await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    stats.prometheus_text = Some(text);
                }
            }
            Err(e) => {
                tracing::debug!(job_id = %self.job_id, error = %e, "failed to query alice /metrics");
            }
        }

        stats
    }

    /// Stop the proxy (called automatically on drop)
    pub async fn stop(&mut self) {
        if let Some(mut process) = self.proxy_process.take() {
            tracing::info!(job_id = %self.job_id, "stopping alice proxy");

            if let Some(pid) = process.id() {
                let pid = Pid::from_raw(pid as i32);
                if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
                    tracing::warn!(job_id = %self.job_id, "failed to send SIGTERM to alice: {}", e);
                } else {
                    tracing::debug!(job_id = %self.job_id, "sent SIGTERM to alice, waiting for graceful shutdown");

                    // Wait up to 2 seconds for graceful shutdown
                    match tokio::time::timeout(Duration::from_secs(2), process.wait()).await {
                        Ok(Ok(status)) => {
                            tracing::info!(job_id = %self.job_id, "alice exited gracefully with status: {}", status);
                            return;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(job_id = %self.job_id, "error waiting for alice: {}", e);
                        }
                        Err(_) => {
                            tracing::warn!(job_id = %self.job_id, "alice did not exit after SIGTERM, sending SIGKILL");
                        }
                    }
                }
            }

            let _ = process.kill().await;
            let _ = process.wait().await;
        }
    }
}

impl Drop for ProxyManager {
    fn drop(&mut self) {
        if let Some(mut process) = self.proxy_process.take() {
            if let Some(pid) = process.id() {
                let pid = Pid::from_raw(pid as i32);
                if signal::kill(pid, Signal::SIGTERM).is_ok() {
                    tracing::debug!(job_id = %self.job_id, "sent SIGTERM to alice on drop");
                    return;
                }
            }

            let _ = process.start_kill();
            tracing::debug!(job_id = %self.job_id, "alice process killed on drop");
        }
    }
}

/// Parse a port number from an alice JSON log line that contains an `addr` field.
///
/// Alice logs startup messages like `"reverse proxy started"` and `"metrics server started"`
/// with an `addr` field containing the bound address (e.g., `"127.0.0.1:12345"`).
/// With `--json`, the log is structured JSON.
///
/// Falls back to plain-text extraction if JSON parsing fails.
fn parse_addr_port(line: &str) -> Option<u16> {
    // Try JSON parsing first: {"fields":{"addr":"127.0.0.1:12345",...},...}
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(addr) = json
            .get("fields")
            .and_then(|f| f.get("addr"))
            .and_then(|v| v.as_str())
        {
            if let Some(port_str) = addr.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }

    // Fallback: extract port from "addr=127.0.0.1:12345" or similar patterns
    // This handles non-JSON log formats (e.g., human-readable tracing output)
    for segment in line.split_whitespace() {
        if segment.starts_with("addr=") || segment.starts_with("addr:") {
            let addr = segment.split_once(['=', ':'])?.1;
            let addr = addr.trim_matches('"').trim_matches(',');
            if let Some(port_str) = addr.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }

    None
}

/// Stats collected from alice before shutdown
#[derive(Debug, Default)]
pub struct ProxyStats {
    /// LLM completion metrics from /llm/completions endpoint
    pub llm_completions: Vec<AliceLlmCompletion>,
    /// Raw prometheus metrics text from /metrics endpoint
    pub prometheus_text: Option<String>,
}

impl ProxyStats {
    /// Parse request counts from prometheus text
    /// Returns (approved, denied) totals
    pub fn request_counts(&self) -> (u64, u64) {
        let Some(ref text) = self.prometheus_text else {
            return (0, 0);
        };

        let mut approved: u64 = 0;
        let mut denied: u64 = 0;

        for line in text.lines() {
            if line.starts_with("alice_requests_total{") {
                if line.contains("action=\"allow\"") {
                    if let Some(value) = line.rsplit(' ').next() {
                        approved += value.parse::<f64>().unwrap_or(0.0) as u64;
                    }
                } else if line.contains("action=\"deny\"") {
                    if let Some(value) = line.rsplit(' ').next() {
                        denied += value.parse::<f64>().unwrap_or(0.0) as u64;
                    }
                }
            }
        }

        (approved, denied)
    }
}

/// LLM completion entry from alice's /llm/completions endpoint
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AliceLlmCompletion {
    pub host: Option<String>,
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub tool_calls: Option<Vec<crate::metrics::LlmToolCall>>,
}
