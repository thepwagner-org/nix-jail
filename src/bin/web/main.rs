//! nj-web: HTTP reverse proxy with subdomain-based routing for nix-jail jobs.
//!
//! Routes `{subdomain}.{base_domain}` → alice's per-job reverse proxy port
//! by querying nixjaild's ListJobs gRPC endpoint.
//!
//! The reserved `home` subdomain serves a landing page with job list and
//! a submit form for running one-off sandboxed scripts.
//!
//! Designed to sit behind nginx which handles TLS termination. nj-web listens
//! on plain HTTP (default 127.0.0.1:3000).
//!
//! Traffic flow:
//! ```text
//! Browser → nginx :443 (TLS) → nj-web :3000 (subdomain routing)
//!        → alice :NNNNN (per-job reverse proxy) → job namespace
//! ```

mod api;
mod proxy;
mod sse;
mod templates;
mod util;

use api::{api_cancel_job, api_list_jobs, api_retry_job, api_submit_job};
use clap::Parser;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy::{
    handle_websocket_upgrade, lookup_job_backend, new_asset_cache, proxy_http, AssetCache,
};
use sse::api_stream_job;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use templates::{landing_page, log_page};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use util::{error_response, extract_subdomain, BoxedBody};

#[derive(Parser, Debug)]
#[command(name = "nj-web", about = "nix-jail web reverse proxy")]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// nixjaild gRPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    daemon: String,

    /// Base domain — subdomains are stripped from the left
    /// e.g. "myhost.example.com" means "foo.myhost.example.com" → subdomain "foo"
    #[arg(long)]
    base_domain: String,
}

/// Shared state threaded through all request handlers.
#[derive(Clone)]
struct AppState {
    daemon: Arc<String>,
    base_domain: Arc<String>,
    asset_cache: AssetCache,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let listen_addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, base_domain = %args.base_domain, "nj-web listening");

    let state = AppState {
        daemon: Arc::new(args.daemon),
        base_domain: Arc::new(args.base_domain),
        asset_cache: new_asset_cache(),
    };

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        drop(tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, state.clone(), peer_addr));
            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                debug!(peer = %peer_addr, error = %e, "connection error");
            }
        }));
    }
}

async fn handle(
    req: Request<Incoming>,
    state: AppState,
    peer_addr: SocketAddr,
) -> Result<Response<BoxedBody>, Infallible> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Strip port suffix if present (e.g. "foo.example.com:443" → "foo.example.com")
    let host = host.split(':').next().unwrap_or("");

    let subdomain = match extract_subdomain(host, &state.base_domain) {
        Some(s) => s,
        None => {
            warn!(host = %host, "no subdomain found in host header");
            return Ok(error_response(StatusCode::BAD_REQUEST, "missing subdomain"));
        }
    };

    if subdomain == "home" {
        return home_handler(req, &state.daemon).await;
    }

    debug!(subdomain = %subdomain, path = %req.uri().path(), peer = %peer_addr, "routing request");

    let backend = match lookup_job_backend(&state.daemon, subdomain).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            info!(subdomain = %subdomain, "no running job found for subdomain");
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                &format!("no running job for subdomain '{subdomain}'"),
            ));
        }
        Err(e) => {
            error!(subdomain = %subdomain, error = %e, "failed to query daemon");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "failed to query nix-jail daemon",
            ));
        }
    };

    let is_upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("websocket"))
        .unwrap_or(false);

    if is_upgrade {
        return handle_websocket_upgrade(req, backend.addr, peer_addr).await;
    }

    proxy_http(
        req,
        &backend.addr,
        subdomain,
        backend.path.as_deref(),
        &state.asset_cache,
    )
    .await
}

async fn home_handler(
    req: Request<Incoming>,
    daemon: &str,
) -> Result<Response<BoxedBody>, Infallible> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    match (method, path.as_str()) {
        (Method::GET, "/") => landing_page(daemon).await,
        (Method::GET, "/api/jobs") => api_list_jobs(daemon).await,
        (Method::POST, "/api/jobs") => api_submit_job(req, daemon).await,
        _ if path.starts_with("/api/jobs/") && path.ends_with("/stream") => {
            let job_id = path
                .trim_start_matches("/api/jobs/")
                .trim_end_matches("/stream")
                .to_owned();
            api_stream_job(daemon, &job_id).await
        }
        (Method::DELETE, _) if path.starts_with("/api/jobs/") => {
            let job_id = path.trim_start_matches("/api/jobs/").to_owned();
            api_cancel_job(daemon, &job_id).await
        }
        (Method::POST, _) if path.starts_with("/api/jobs/") && path.ends_with("/retry") => {
            let job_id = path
                .trim_start_matches("/api/jobs/")
                .trim_end_matches("/retry")
                .to_owned();
            api_retry_job(daemon, &job_id).await
        }
        (Method::GET, _) if path.starts_with("/logs/") => {
            let job_id = path.trim_start_matches("/logs/").to_owned();
            log_page(&job_id).await
        }
        _ => Ok(error_response(StatusCode::NOT_FOUND, "not found")),
    }
}
