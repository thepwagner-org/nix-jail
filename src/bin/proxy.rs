use clap::Parser;
use nix_jail::proxy::{run_proxy, ProxyConfig};
use std::path::PathBuf;

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

    // Initialize logging from RUST_LOG environment variable
    let _tracing_guard = nix_jail::init_tracing("nix-jail-proxy", "info", false, None);

    // Initialize rustls crypto provider for MITM TLS connections
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing::debug!("loading proxy config from: {}", args.config.display());
    let config = ProxyConfig::from_file(&args.config)?;

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

    run_proxy(config).await?;

    Ok(())
}
