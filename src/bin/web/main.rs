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
mod cache;
mod events;
mod proxy;
mod sse;
mod templates;
mod util;

use api::{api_cancel_job, api_list_jobs, api_retry_job, api_submit_job};
use cache::JobCache;
use clap::Parser;
use events::api_events;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy::{
    handle_websocket_upgrade, lookup_subdomain, new_asset_cache, proxy_http, AssetCache,
    SubdomainState,
};
use sse::api_stream_job;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use templates::{completed_page, failed_page, landing_page, loading_page, log_page};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use util::{error_response, extract_subdomain, json_ok, BoxedBody, LogLine};

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
    job_cache: Arc<JobCache>,
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

    let job_cache = Arc::new(JobCache::new());
    cache::spawn_cache_sync(args.daemon.clone(), job_cache.clone());

    let state = AppState {
        daemon: Arc::new(args.daemon),
        base_domain: Arc::new(args.base_domain),
        asset_cache: new_asset_cache(),
        job_cache,
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

/// Path on subdomain routes that returns a JSON status snapshot.
///
/// Polled by the loading page JS to detect when the job backend becomes ready.
const STATUS_PATH: &str = "/.well-known/nj/status";

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
        return home_handler(req, &state).await;
    }

    // Extract metadata from the request before it may be consumed.
    let path = req.uri().path().to_owned();
    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        .to_owned();
    let home_base = format!("{scheme}://home.{}", state.base_domain);

    debug!(subdomain = %subdomain, path = %path, peer = %peer_addr, "routing request");

    let subdomain_state = match lookup_subdomain(&state.job_cache, &state.daemon, subdomain).await {
        Ok(s) => s,
        Err(e) => {
            error!(subdomain = %subdomain, error = %e, "failed to query daemon");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "failed to query nix-jail daemon",
            ));
        }
    };

    match subdomain_state {
        SubdomainState::Ready(backend) => {
            // Intercept the status endpoint before proxying: return JSON directly.
            if path == STATUS_PATH {
                let j = backend.job_id.as_str();
                return Ok(json_ok(format!(r#"{{"state":"ready","job_id":"{j}"}}"#)));
            }

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

        SubdomainState::Loading { job_id } => {
            info!(subdomain = %subdomain, job_id = %job_id, "serving loading page");
            if path == STATUS_PATH {
                return Ok(json_ok(format!(
                    r#"{{"state":"loading","job_id":"{job_id}"}}"#
                )));
            }
            Ok(loading_page(subdomain, &job_id, &home_base))
        }

        SubdomainState::Failed { job_id } => {
            info!(subdomain = %subdomain, job_id = %job_id, "serving failed page");
            if path == STATUS_PATH {
                return Ok(json_ok(format!(
                    r#"{{"state":"failed","job_id":"{job_id}"}}"#
                )));
            }
            let logs = fetch_tail_logs(&state.daemon, &job_id, 80).await;
            Ok(failed_page(subdomain, &job_id, &logs, &home_base))
        }

        SubdomainState::Completed { job_id } => {
            info!(subdomain = %subdomain, job_id = %job_id, "serving completed page");
            if path == STATUS_PATH {
                return Ok(json_ok(format!(
                    r#"{{"state":"completed","job_id":"{job_id}"}}"#
                )));
            }
            let logs = fetch_tail_logs(&state.daemon, &job_id, 80).await;
            Ok(completed_page(subdomain, &job_id, &logs, &home_base))
        }

        SubdomainState::NotFound => {
            info!(subdomain = %subdomain, "no job found for subdomain");
            Ok(error_response(
                StatusCode::NOT_FOUND,
                &format!("no job for subdomain '{subdomain}'"),
            ))
        }
    }
}

/// Fetch the last `n` log lines for a finished job, for server-side rendering.
async fn fetch_tail_logs(daemon: &str, job_id: &str, n: u32) -> Vec<LogLine> {
    use nix_jail::jail::jail_service_client::JailServiceClient;
    use nix_jail::jail::{LogSource, StreamRequest};

    let mut client = match JailServiceClient::connect(daemon.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            warn!(job_id = %job_id, error = %e, "failed to connect to daemon for log fetch");
            return vec![];
        }
    };

    let mut stream = match client
        .stream_job(StreamRequest {
            job_id: job_id.to_owned(),
            tail_lines: Some(n),
            follow: false,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            warn!(job_id = %job_id, error = %e, "stream_job rpc failed for log fetch");
            return vec![];
        }
    };

    let mut lines = Vec::new();
    while let Ok(Some(entry)) = stream.message().await {
        let source = match entry.source {
            s if s == LogSource::JobStdout as i32 => "stdout",
            s if s == LogSource::JobStderr as i32 => "stderr",
            s if s == LogSource::ProxyStdout as i32 => "proxy",
            s if s == LogSource::ProxyStderr as i32 => "proxy",
            s if s == LogSource::System as i32 => "system",
            _ => "stdout",
        };
        lines.push(LogLine {
            source,
            content: entry.content,
        });
    }
    lines
}

async fn home_handler(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<BoxedBody>, Infallible> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let daemon = state.daemon.as_str();

    match (method, path.as_str()) {
        (Method::GET, "/") => landing_page(daemon).await,
        (Method::GET, "/api/jobs") => api_list_jobs(daemon).await,
        (Method::GET, "/api/events") => api_events(state.job_cache.clone()).await,
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
