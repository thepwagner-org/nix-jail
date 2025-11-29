use clap::Parser;
use nix_jail::config::ServerConfig;
use nix_jail::executor::EXECUTOR_NAME;
use std::path::PathBuf;
use tonic::transport::Server;

#[derive(Parser, Debug)]
#[command(name = "nix-jail-server", version)]
#[command(about = "nix-jail gRPC server")]
struct Args {
    /// Path to TOML configuration file
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = if let Some(config_path) = args.config.as_ref() {
        ServerConfig::from_toml_file(config_path)?
    } else {
        ServerConfig::default()
    };

    // Initialize tracing with optional OTLP endpoint from config
    let _tracing_guard = nix_jail::init_tracing(
        "nix-jail-server",
        "nix_jail=info",
        false,
        config.otlp_endpoint.as_deref(),
    );
    let _ = rustls::crypto::ring::default_provider().install_default();

    if args.config.is_some() {
        tracing::info!(path = ?args.config, "loaded configuration from file");
    } else {
        tracing::warn!("no config file specified, using defaults (no credentials available)");
    }

    let addr = config.addr;
    let db_path = config.db_path.clone();
    let num_credentials = config.credentials.len();

    tracing::info!(database = ?db_path, "initializing storage");

    tracing::info!(
        address = %addr,
        executor = EXECUTOR_NAME,
        num_credentials = num_credentials,
        "Server started"
    );

    Server::builder()
        .add_service(nix_jail::service(&db_path, config)?)
        .serve(addr)
        .await?;

    Ok(())
}
