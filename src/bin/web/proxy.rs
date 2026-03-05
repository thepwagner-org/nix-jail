//! Reverse proxy handlers: plain HTTP forwarding and WebSocket TCP splicing.
//!
//! Includes:
//! - Bootstrap system: seeds opencode's localStorage on first visit via a
//!   cookie + redirect + inline-JS HTML page (ported from meow-web).
//! - Asset cache: shares opencode's hashed `/assets/*` bundles across all
//!   subdomain requests so the backend is only hit once per asset.
//! - Response hop-by-hop header stripping.

use crate::util::{error_response, full_body, percent_decode, percent_encode, BoxedBody};
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::ListJobsRequest;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

// ---------------------------------------------------------------------------
// Asset cache
// ---------------------------------------------------------------------------

/// A cached static asset fetched from an opencode backend.
#[derive(Clone)]
pub struct CachedAsset {
    pub content_type: String,
    pub bytes: Bytes,
}

/// Shared in-process asset cache. Keyed by path (e.g. `/assets/index-abc123.js`).
///
/// opencode's assets are content-addressed (hashed filenames), so once
/// fetched from any backend they never change. Shared across all subdomains.
pub type AssetCache = Arc<RwLock<HashMap<String, CachedAsset>>>;

pub fn new_asset_cache() -> AssetCache {
    Arc::new(RwLock::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Backend lookup
// ---------------------------------------------------------------------------

/// Information about a job's backend, returned by [`lookup_job_backend`].
pub struct JobBackend {
    /// Host:port of alice's reverse proxy for this job.
    pub addr: String,
    /// The job's `path` field (e.g. `"projects/nix-jail"`), if any.
    pub path: Option<String>,
}

/// Query nixjaild for a running job with the given subdomain.
///
/// Returns `None` when the job exists but the reverse proxy port isn't ready yet,
/// or when no job matches the subdomain.
pub async fn lookup_job_backend(
    daemon: &str,
    subdomain: &str,
) -> anyhow::Result<Option<JobBackend>> {
    let mut client = JailServiceClient::connect(daemon.to_string()).await?;

    let resp = client
        .list_jobs(ListJobsRequest {
            status: Some("running".to_string()),
            limit: Some(100),
            offset: None,
        })
        .await?
        .into_inner();

    for job in resp.jobs {
        if job.subdomain.as_deref() == Some(subdomain) {
            if let Some(port) = job.reverse_proxy_port {
                return Ok(Some(JobBackend {
                    addr: format!("127.0.0.1:{port}"),
                    path: job.path,
                }));
            }
            // Job found but no reverse proxy port yet (still starting up)
            warn!(
                subdomain = %subdomain,
                job_id = %job.job_id,
                "job found but reverse_proxy_port not set yet"
            );
            return Ok(None);
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// Cookie name prefix. The subdomain is appended to scope the cookie per-job.
const BOOTSTRAP_COOKIE_PREFIX: &str = "nj-bootstrapped-";

/// Path served to seed localStorage and set the bootstrap cookie.
const BOOTSTRAP_PATH: &str = "/.well-known/nj/bootstrap";

/// Paths that must never trigger a bootstrap redirect (subresource fetches
/// that can't run JavaScript, or the bootstrap page itself).
fn is_bootstrap_exempt(path: &str) -> bool {
    path == BOOTSTRAP_PATH
        || path.starts_with("/assets/")
        || path == "/favicon.ico"
        || path == "/robots.txt"
        || path == "/site.webmanifest"
}

/// Derive the project directory inside the sandbox from the job's `path` field.
///
/// - No path  → `/workspace`
/// - `"projects/nix-jail"` → `/workspace/projects/nix-jail`
fn project_dir(job_path: Option<&str>) -> String {
    match job_path {
        None | Some("") => "/workspace".to_owned(),
        Some(p) => format!("/workspace/{p}"),
    }
}

/// Generate the bootstrap HTML page.
///
/// Seeds four opencode localStorage keys then redirects to `/`.
/// `origin` is the full URL origin the browser sees (e.g. `https://opencode.desktop-17.pwagner.net`).
/// `dir` is the project directory inside the sandbox (e.g. `/workspace/projects/nix-jail`).
fn bootstrap_page(origin: &str, dir: &str) -> String {
    // Escape for embedding in a JS string literal
    let origin_js = origin.replace('\\', "\\\\").replace('\'', "\\'");
    let dir_js = dir.replace('\\', "\\\\").replace('\'', "\\'");

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>setting up…</title></head>
<body>
<script>
(function() {{
  var origin = '{origin_js}';
  var dir    = '{dir_js}';

  // opencode.global.dat:server — project/worktree mapping (always written)
  var serverKey = 'opencode.global.dat:server';
  var server = JSON.parse(localStorage.getItem(serverKey) || 'null') || {{}};
  if (!server.projects)    server.projects    = {{}};
  if (!server.lastProject) server.lastProject = {{}};
  server.projects[origin]    = [{{ worktree: dir, expanded: true }}];
  server.lastProject[origin] = dir;
  localStorage.setItem(serverKey, JSON.stringify(server));

  // opencode.global.dat:model — default model (only if unset)
  if (!localStorage.getItem('opencode.global.dat:model')) {{
    localStorage.setItem('opencode.global.dat:model', JSON.stringify({{
      user: [{{ modelID: 'claude-sonnet-4-6', providerID: 'anthropic', visibility: 'show' }}],
      recent: [{{ modelID: 'claude-sonnet-4-6', providerID: 'anthropic' }}],
      variant: {{}}
    }}));
  }}

  // opencode.global.dat:layout — clean default layout (only if unset)
  if (!localStorage.getItem('opencode.global.dat:layout')) {{
    localStorage.setItem('opencode.global.dat:layout', JSON.stringify({{
      sidebar: {{ opened: false, width: 344, workspaces: {{}}, workspacesDefault: false }},
      terminal: {{ height: 280, opened: false }},
      review: {{ diffStyle: 'split', panelOpened: false }},
      fileTree: {{ opened: false, width: 344, tab: 'changes' }},
      session: {{ width: 600 }},
      mobileSidebar: {{ opened: false }},
      sessionTabs: {{}},
      sessionView: {{}},
      handoff: {{}}
    }}));
  }}

  // settings.v3 — base preferences (only if unset)
  if (!localStorage.getItem('settings.v3')) {{
    localStorage.setItem('settings.v3', JSON.stringify({{
      general: {{ autoSave: true, releaseNotes: true, showReasoningSummaries: true }},
      updates: {{ startup: true }},
      appearance: {{ fontSize: 14, font: 'fira-code' }},
      keybinds: {{}},
      permissions: {{ autoApprove: false }},
      notifications: {{ agent: false, permissions: false, errors: false }},
      sounds: {{
        agentEnabled: false, agent: 'staplebops-01',
        permissionsEnabled: false, permissions: 'staplebops-02',
        errorsEnabled: false, errors: 'nope-03'
      }}
    }}));
  }}

  localStorage.setItem('nj:bootstrapped', dir);
  setTimeout(function() {{ location.replace('/'); }}, 100);
}})();
</script>
<p style="font-family:monospace;color:#888">setting up opencode…</p>
</body>
</html>
"#
    )
}

/// Check the bootstrap cookie for this subdomain. Returns `Some(redirect_response)` if
/// the cookie is missing or stale, `None` if the cookie is valid and the request should
/// proceed to the normal proxy path.
fn check_bootstrap(
    req: &Request<Incoming>,
    subdomain: &str,
    dir: &str,
) -> Option<Response<BoxedBody>> {
    let cookie_name = format!("{BOOTSTRAP_COOKIE_PREFIX}{subdomain}");

    // Parse Cookie header
    let cookie_val = req
        .headers()
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|pair| {
                let pair = pair.trim();
                pair.strip_prefix(&format!("{cookie_name}="))
                    .map(str::trim)
                    .map(str::to_owned)
            })
        });

    let valid = cookie_val
        .as_deref()
        .map(|v| percent_decode(v) == dir)
        .unwrap_or(false);

    if valid {
        return None;
    }

    // Redirect to bootstrap page with a cache-busting query param
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let location = format!("{BOOTSTRAP_PATH}?t={epoch}");
    Some(
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(hyper::header::LOCATION, location)
            .header("Cache-Control", "no-store")
            .body(full_body("redirecting to bootstrap\n"))
            .unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "redirect failed")
            }),
    )
}

/// Serve the bootstrap page and set the bootstrap cookie.
fn serve_bootstrap(subdomain: &str, dir: &str, origin: &str) -> Response<BoxedBody> {
    let cookie_name = format!("{BOOTSTRAP_COOKIE_PREFIX}{subdomain}");
    let cookie_val = percent_encode(dir);
    let cookie = format!("{cookie_name}={cookie_val}; Path=/; Max-Age=86400; SameSite=Lax");
    let html = bootstrap_page(origin, dir);

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Set-Cookie", cookie)
        .body(full_body(html))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "bootstrap failed"))
}

/// Determine the origin the browser sees from the request headers.
///
/// Uses `X-Forwarded-Proto` (set by nginx) for the scheme, falls back to `https`.
/// Uses the `Host` header for the host (which includes the subdomain).
fn request_origin(req: &Request<Incoming>) -> String {
    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    format!("{scheme}://{host}")
}

// ---------------------------------------------------------------------------
// Hop-by-hop header stripping
// ---------------------------------------------------------------------------

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ] {
        let _ = headers.remove(name);
    }
}

// ---------------------------------------------------------------------------
// Asset cache fetch
// ---------------------------------------------------------------------------

/// Try to serve a `/assets/*` path from the cache, or fetch it from the backend,
/// cache it, and return it. Returns `None` if the backend returns a non-2xx status.
pub async fn serve_asset(
    path: &str,
    backend: &str,
    cache: &AssetCache,
) -> Option<Response<BoxedBody>> {
    // Cache hit
    if let Ok(map) = cache.read() {
        if let Some(asset) = map.get(path) {
            return Some(cached_asset_response(asset));
        }
    }

    // Cache miss: fetch from backend
    let stream = TcpStream::connect(backend).await.ok()?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .ok()?;
    drop(tokio::spawn(async move {
        let _ = conn.await;
    }));

    let fetch_req = Request::builder()
        .method("GET")
        .uri(path)
        .header(hyper::header::HOST, "localhost")
        .body(http_body_util::Empty::<Bytes>::new())
        .ok()?;

    let resp = sender.send_request(fetch_req).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let content_type = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    let bytes = resp.into_body().collect().await.ok()?.to_bytes();

    let asset = CachedAsset {
        content_type: content_type.clone(),
        bytes: bytes.clone(),
    };

    // Store in cache
    if let Ok(mut map) = cache.write() {
        let _ = map.insert(path.to_owned(), asset);
    }

    Some(cached_asset_response(&CachedAsset {
        content_type,
        bytes,
    }))
}

fn cached_asset_response(asset: &CachedAsset) -> Response<BoxedBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, asset.content_type.as_str())
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(full_body(asset.bytes.clone()))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "asset error"))
}

// ---------------------------------------------------------------------------
// Main proxy entry point
// ---------------------------------------------------------------------------

/// Forward a request to the job's opencode backend, handling bootstrap, asset
/// caching, and hop-by-hop header stripping.
///
/// `subdomain` is the DNS label for this job (used to scope the bootstrap cookie).
/// `job_path` is the job's `path` field from JobInfo (e.g. `"projects/nix-jail"`).
pub async fn proxy_http(
    req: Request<Incoming>,
    backend: &str,
    subdomain: &str,
    job_path: Option<&str>,
    asset_cache: &AssetCache,
) -> Result<Response<BoxedBody>, Infallible> {
    let path = req.uri().path().to_owned();
    let dir = project_dir(job_path);

    // Serve cached assets immediately, no bootstrap needed
    if path.starts_with("/assets/") {
        if let Some(resp) = serve_asset(&path, backend, asset_cache).await {
            return Ok(resp);
        }
        // Fall through on cache miss/backend error — let the normal proxy try
    }

    // Bootstrap check (skip for exempt paths)
    if !is_bootstrap_exempt(&path) {
        if let Some(redirect) = check_bootstrap(&req, subdomain, &dir) {
            return Ok(redirect);
        }
    }

    // Serve the bootstrap page
    if path == BOOTSTRAP_PATH {
        let origin = request_origin(&req);
        return Ok(serve_bootstrap(subdomain, &dir, &origin));
    }

    proxy_to_backend(req, backend).await
}

/// Low-level HTTP/1.1 proxy: forward `req` to `backend`, strip hop-by-hop
/// headers in both directions, and stream the response body without buffering.
async fn proxy_to_backend(
    req: Request<Incoming>,
    backend: &str,
) -> Result<Response<BoxedBody>, Infallible> {
    let stream = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(e) => {
            error!(backend = %backend, error = %e, "failed to connect to backend");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "backend unreachable",
            ));
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            error!(backend = %backend, error = %e, "HTTP handshake failed");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "backend handshake failed",
            ));
        }
    };

    drop(tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "backend connection closed");
        }
    }));

    // Strip hop-by-hop request headers before forwarding
    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let req = Request::from_parts(parts, body);

    match sender.send_request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            // Strip hop-by-hop response headers before forwarding to client
            strip_hop_by_hop(&mut parts.headers);
            // Stream the response body directly without buffering.
            // Buffering here would break SSE and other unbounded streaming responses.
            // If the backend errors mid-stream the connection drops, which is correct
            // proxy behaviour (we've already sent headers so can't send a 502 anyway).
            let streaming = body.map_err(|_: hyper::Error| -> Infallible {
                unreachable!("hyper::Error mapped to Infallible for BoxedBody compatibility")
            });
            Ok(Response::from_parts(parts, streaming.boxed()))
        }
        Err(e) => {
            error!(backend = %backend, error = %e, "backend request failed");
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "backend request failed",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket upgrade
// ---------------------------------------------------------------------------

/// Handle a WebSocket upgrade by splicing raw TCP between client and backend.
pub async fn handle_websocket_upgrade(
    req: Request<Incoming>,
    backend: String,
    peer_addr: SocketAddr,
) -> Result<Response<BoxedBody>, Infallible> {
    use hyper::upgrade::on;

    // Connect to backend first — fail fast if unreachable
    let backend_stream = match TcpStream::connect(&backend).await {
        Ok(s) => s,
        Err(e) => {
            error!(backend = %backend, error = %e, "ws backend unreachable");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                "backend unreachable",
            ));
        }
    };

    // Capture request parts for building the raw upgrade request to the backend
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    drop(tokio::spawn(async move {
        // Upgrade the client connection
        let upgraded_client = match on(req).await {
            Ok(u) => u,
            Err(e) => {
                error!(peer = %peer_addr, error = %e, "ws client upgrade failed");
                return;
            }
        };

        // Send the upgrade request to the backend over raw TCP
        let mut backend_stream = backend_stream;
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let mut request_line = format!("{method} {path} HTTP/1.1\r\n");
        for (name, value) in &headers {
            if let Ok(v) = value.to_str() {
                request_line.push_str(&format!("{name}: {v}\r\n"));
            }
        }
        request_line.push_str("\r\n");

        if let Err(e) = backend_stream.write_all(request_line.as_bytes()).await {
            error!(error = %e, "failed to write ws upgrade to backend");
            return;
        }

        // Splice the two streams
        let client_io = TokioIo::new(upgraded_client);
        let (mut client_r, mut client_w) = tokio::io::split(client_io);
        let (mut backend_r, mut backend_w) = backend_stream.into_split();

        let c2b = tokio::io::copy(&mut client_r, &mut backend_w);
        let b2c = tokio::io::copy(&mut backend_r, &mut client_w);

        let _ = tokio::join!(c2b, b2c);
        debug!(peer = %peer_addr, backend = %backend, "ws session ended");
    }));

    // Return 101 Switching Protocols to the client
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "Upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .body(full_body(Bytes::new()))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "upgrade failed")))
}
