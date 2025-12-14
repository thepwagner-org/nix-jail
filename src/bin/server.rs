use clap::Parser;
use nix_jail::config::ServerConfig;
use nix_jail::executor::EXECUTOR_NAME;
use nix_jail::session::SessionRegistry;
use std::path::PathBuf;
use std::sync::Arc;
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

    // Create session registry for interactive sessions
    let session_registry = Arc::new(SessionRegistry::new());

    // Calculate WebSocket port (gRPC port + 1)
    let ws_port = addr.port() + 1;
    let ws_addr = std::net::SocketAddr::new(addr.ip(), ws_port);

    tracing::info!(
        grpc_address = %addr,
        ws_address = %ws_addr,
        executor = EXECUTOR_NAME,
        num_credentials = num_credentials,
        "starting servers"
    );

    // Start WebSocket server in background
    let ws_registry = session_registry.clone();
    let ws_handle = tokio::spawn(async move {
        if let Err(e) = run_websocket_server(ws_addr, ws_registry).await {
            tracing::error!(error = %e, "websocket server failed");
        }
    });

    // Start gRPC server
    let grpc_result = Server::builder()
        .add_service(nix_jail::service(&db_path, config, session_registry)?)
        .serve(addr)
        .await;

    // If gRPC server exits, abort WebSocket server
    ws_handle.abort();

    grpc_result?;
    Ok(())
}

/// Run WebSocket server for interactive TTY sessions
async fn run_websocket_server(
    addr: std::net::SocketAddr,
    session_registry: Arc<SessionRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "websocket server listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let registry = session_registry.clone();

        drop(tokio::spawn(async move {
            if let Err(e) = handle_websocket_connection(stream, peer_addr, registry).await {
                tracing::warn!(
                    peer = %peer_addr,
                    error = %e,
                    "websocket connection failed"
                );
            }
        }));
    }
}

/// Handle a single WebSocket connection
async fn handle_websocket_connection(
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    session_registry: Arc<SessionRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message;

    // Accept WebSocket upgrade
    let ws_stream = accept_async(stream).await?;
    tracing::debug!(peer = %peer_addr, "websocket connection accepted");

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // First message should be authentication: {"job_id": "...", "token": "..."}
    let auth_msg = ws_receiver
        .next()
        .await
        .ok_or("connection closed before auth")??;

    let auth_data: serde_json::Value = match auth_msg {
        Message::Text(text) => serde_json::from_str(&text)?,
        _ => return Err("expected text message for auth".into()),
    };

    let job_id = auth_data["job_id"]
        .as_str()
        .ok_or("missing job_id in auth")?
        .to_string();
    let token = auth_data["token"].as_str().ok_or("missing token in auth")?;

    // Validate session and token
    if !session_registry.validate_token(&job_id, token).await {
        let _ = ws_sender
            .send(Message::Text(
                r#"{"error": "invalid session or token"}"#.to_string(),
            ))
            .await;
        return Err("invalid session or token".into());
    }

    tracing::info!(
        job_id = %job_id,
        peer = %peer_addr,
        "authenticated websocket session"
    );

    // Send success message
    ws_sender
        .send(Message::Text(r#"{"status": "connected"}"#.to_string()))
        .await?;

    // Get PTY channels from session registry (poll until available)
    let channels = {
        let mut attempts = 0;
        loop {
            if let Some(ch) = session_registry.take_channels(&job_id).await {
                break ch;
            }
            attempts += 1;
            if attempts > 50 {
                // 5 second timeout
                let _ = ws_sender
                    .send(Message::Text(r#"{"error": "pty not ready"}"#.to_string()))
                    .await;
                return Err("PTY channels not available after timeout".into());
            }
            if attempts == 1 {
                tracing::debug!(job_id = %job_id, "pty channels not available yet, waiting...");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };

    let stdin_tx = channels.stdin_tx;
    let mut stdout_rx = channels.stdout_rx;

    tracing::info!(job_id = %job_id, "pty channels connected to websocket");

    // Spawn task to forward PTY output to WebSocket
    let job_id_out = job_id.clone();
    let output_task = tokio::spawn(async move {
        while let Some(data) = stdout_rx.recv().await {
            if ws_sender.send(Message::Binary(data)).await.is_err() {
                tracing::debug!(job_id = %job_id_out, "websocket send failed, client disconnected");
                break;
            }
        }
    });

    // Forward WebSocket input to PTY
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Binary(data)) => {
                tracing::debug!(job_id = %job_id, bytes = data.len(), "forwarding input to pty");
                if stdin_tx.send(data).await.is_err() {
                    tracing::debug!(job_id = %job_id, "pty stdin closed");
                    break;
                }
            }
            Ok(Message::Close(_)) => {
                tracing::info!(job_id = %job_id, "client closed connection");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(job_id = %job_id, error = %e, "websocket error");
                break;
            }
        }
    }

    output_task.abort();
    Ok(())
}
