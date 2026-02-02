//! Network proxy for intercepting and logging HTTP/HTTPS/WebSocket traffic
//!
//! This module implements a MITM (Man-in-the-Middle) proxy that:
//! - Intercepts HTTPS traffic via TLS termination with on-demand certificate generation
//! - Parses WebSocket frames to log individual messages
//! - Logs requests to Claude API and other services
//! - Provides full visibility into job network activity

pub mod certs;
pub mod llm;
pub mod mitm;
pub mod policy;
pub mod stats;

use std::sync::Arc;

pub use certs::CertificateAuthority;
pub use policy::{CompiledPolicy, PolicyDecision};
pub use stats::{ProxyStats, ProxyStatsSummary, RequestKey};

use crate::config::Credential;
use crate::jail::NetworkPolicy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:3128")
    pub listen_addr: String,

    /// Path to save CA certificate PEM file
    #[serde(default = "default_ca_cert_path")]
    pub ca_cert_path: PathBuf,

    /// Optional network policy for request filtering (None = deny all)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicy>,

    /// Credentials for token injection
    #[serde(default)]
    pub credentials: Vec<Credential>,

    /// Optional username for HTTP Basic Auth (prevents cross-job proxy access)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_username: Option<String>,

    /// Optional password for HTTP Basic Auth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,

    /// Optional path to log all requests as JSON lines (for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_log_path: Option<PathBuf>,

    /// Optional OpenTelemetry OTLP endpoint for exporting traces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
}

fn default_ca_cert_path() -> PathBuf {
    "/tmp/nix-jail-proxy-ca.pem".into()
}

impl ProxyConfig {
    /// Load from JSON file
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Start the proxy server
///
/// This function:
/// 1. Generates a CA certificate
/// 2. Saves it to the configured path
/// 3. Compiles network policy if provided (None = deny all)
/// 4. Starts listening for proxy connections
/// 5. Handles HTTP CONNECT requests with TLS MITM, policy enforcement, and token injection
pub async fn run_proxy(
    config: ProxyConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!("starting proxy on {}", config.listen_addr);

    // Generate CA certificate
    let ca = Arc::new(CertificateAuthority::generate()?);
    let ca_cert_pem = ca.ca_cert_pem()?;
    tracing::debug!("generated ca certificate");

    // Compile network policy if provided, otherwise use deny-all
    let compiled_policy = if let Some(policy) = config.network_policy {
        let compiled = CompiledPolicy::compile(policy, &config.credentials)
            .map_err(|e| format!("failed to compile network policy: {}", e))?;
        tracing::info!(
            "compiled network policy with {} rules and {} credentials",
            compiled.rules.len(),
            config.credentials.len()
        );
        Arc::new(compiled)
    } else {
        tracing::warn!("no network policy configured - using default deny-all policy");
        Arc::new(CompiledPolicy::deny_all())
    };

    // Create proxy state with CA and policy (always present, never None)
    let state = Arc::new(mitm::ProxyState {
        ca,
        policy: compiled_policy,
        stats: Arc::new(ProxyStats::new()),
        proxy_username: config.proxy_username,
        proxy_password: config.proxy_password,
        request_log_path: config.request_log_path,
        metrics: None, // LLM metrics disabled for standalone proxy
    });

    // Start MITM proxy server (CA cert is written after bind for reliable readiness signal)
    mitm::start_server(config.listen_addr, state, config.ca_cert_path, ca_cert_pem).await?;

    Ok(())
}
