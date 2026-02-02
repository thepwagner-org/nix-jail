use clap::Parser;
use nix_jail::proxy::{run_proxy, ProxyConfig};
use std::path::PathBuf;
use tracing::Instrument;

/// nix-jail MITM Proxy
///
/// Intercepts HTTP/HTTPS/WebSocket traffic for logging and inspection.
/// Generates a CA certificate on startup and issues per-host certificates on-demand.
///
/// Logging: Set RUST_LOG environment variable (e.g., RUST_LOG=debug)
#[derive(Parser, Debug)]
#[command(name = "nix-jail-proxy", version)]
#[command(about = "MITM proxy for nix-jail job network monitoring", long_about = None)]
struct Args {
    /// Path to proxy configuration file (JSON) - REQUIRED
    ///
    /// This file must contain listen_addr, ca_cert_path, network_policy, and credentials.
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Load config first to get OTLP endpoint (before tracing is initialized)
    let config = ProxyConfig::from_file(&args.config)?;

    // Initialize logging with optional OpenTelemetry export
    let _tracing_guard = nix_jail::init_tracing(
        "nix-jail-proxy",
        "info",
        false,
        config.otlp_endpoint.as_deref(),
    );

    // Initialize rustls crypto provider for MITM TLS connections
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Log diagnostic info about OTel configuration
    if let Ok(traceparent) = std::env::var("TRACEPARENT") {
        tracing::info!(traceparent = %traceparent, "received parent trace context");
    } else {
        tracing::debug!("no TRACEPARENT env var (proxy will create new trace)");
    }
    if config.otlp_endpoint.is_some() {
        tracing::info!(endpoint = ?config.otlp_endpoint, "opentelemetry export configured");
    } else {
        tracing::debug!("no otlp_endpoint configured (console logging only)");
    }

    tracing::debug!("loaded proxy config from: {}", args.config.display());
    tracing::debug!("starting nix-jail mitm proxy");
    tracing::debug!("listen address: {}", config.listen_addr);
    tracing::debug!("ca certificate: {}", config.ca_cert_path.display());
    if config.network_policy.is_some() {
        tracing::debug!("network policy: enabled");
    } else {
        tracing::debug!("network policy: none (deny all)");
    }
    tracing::debug!("credentials: {} configured", config.credentials.len());
    if config.proxy_username.is_some() && config.proxy_password.is_some() {
        tracing::debug!("proxy authentication: enabled");
    } else {
        tracing::debug!("proxy authentication: disabled");
    }

    // Wrap the proxy in a root span that will carry the parent trace context
    // This ensures all LLM completion spans are linked to the parent trace
    async { run_proxy(config).await }
        .instrument(tracing::info_span!("proxy"))
        .await?;

    Ok(())
}
