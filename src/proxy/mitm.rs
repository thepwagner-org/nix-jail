use crate::proxy::CertificateAuthority;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use moka::future::Cache;
use rustls::ServerConfig;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

/// Global connection counter for generating unique connection IDs
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(1);

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Shared state for OAuth response redaction
///
/// When a request is sent to an OAuth token endpoint, the request handler sets this
/// to the credential name. The response handler checks this and redacts tokens if set.
type RedactionSignal = Arc<tokio::sync::Mutex<Option<String>>>;

/// Signal for LLM metrics extraction
///
/// When a request goes to an LLM API endpoint with metrics enabled, stores
/// the context needed for response parsing (host, credential name, provider).
#[derive(Debug, Clone)]
struct LlmMetricsContext {
    host: String,
    path: String,
    credential: String,
    provider: LlmProvider,
}

type LlmMetricsSignal = Arc<tokio::sync::Mutex<Option<LlmMetricsContext>>>;

use crate::config::{extract_access_token, CredentialType, LlmProvider};
use crate::metrics::SharedMetrics;
use crate::proxy::llm::{LlmMetrics, StreamingMetricsAccumulator};
use crate::proxy::policy::{CompiledPolicy, PolicyDecision};
use crate::proxy::stats::ProxyStats;

/// Emit an OpenTelemetry span for LLM API completion metrics.
///
/// Creates a span (not just an event) so it appears in distributed traces.
/// Uses gen_ai semantic conventions for attributes:
/// - gen_ai.system: The LLM provider (anthropic, openai)
/// - gen_ai.request.model: Model name
/// - gen_ai.usage.input_tokens: Input/prompt tokens
/// - gen_ai.usage.output_tokens: Output/completion tokens
/// - gen_ai.usage.cache_read_tokens: Cache read tokens (Anthropic)
/// - gen_ai.tool_calls: JSON array of tool calls with arguments
fn emit_llm_completion_span(ctx: &LlmMetricsContext, metrics: &LlmMetrics, conn_id: u64) {
    let provider_str = match ctx.provider {
        LlmProvider::Anthropic => "anthropic",
        LlmProvider::OpenAI => "openai",
    };

    let model_str = metrics.model.as_deref().unwrap_or("unknown");
    let input_tokens = metrics.input_tokens.unwrap_or(0);
    let output_tokens = metrics.output_tokens.unwrap_or(0);
    let cache_read_tokens = metrics.cache_read_tokens.unwrap_or(0);

    // Serialize tool calls to JSON for the span attribute
    let tool_calls_json = serde_json::to_string(&metrics.tool_calls).unwrap_or_default();

    // Create a span with all LLM metrics as attributes
    // The span is immediately entered and exited, recording a point-in-time event
    let span = tracing::info_span!(
        target: "gen_ai",
        "llm.completion",
        gen_ai_system = provider_str,
        gen_ai_request_model = model_str,
        gen_ai_usage_input_tokens = input_tokens,
        gen_ai_usage_output_tokens = output_tokens,
        gen_ai_usage_cache_read_tokens = cache_read_tokens,
        gen_ai_tool_calls = tool_calls_json,
        conn_id = conn_id,
        host = ctx.host.as_str(),
        path = ctx.path.as_str(),
        credential = ctx.credential.as_str(),
    );
    // Enter and immediately exit to record the span
    let _guard = span.enter();
}

/// Shared state for the proxy server
///
/// Contains the CA for certificate generation and the compiled network policy
/// for request filtering and credential injection.
#[derive(Debug)]
pub struct ProxyState {
    /// Certificate authority for generating per-host certificates
    pub ca: Arc<CertificateAuthority>,

    /// Compiled network policy for filtering requests and credential injection
    /// Always present - uses deny_all() when no policy configured
    pub policy: Arc<CompiledPolicy>,

    /// Statistics tracking for approved and denied requests
    pub stats: Arc<ProxyStats>,

    /// Optional username for HTTP Basic Auth
    pub proxy_username: Option<String>,

    /// Optional password for HTTP Basic Auth
    pub proxy_password: Option<String>,

    /// Optional path to log requests as JSON lines (for debugging)
    pub request_log_path: Option<std::path::PathBuf>,

    /// Optional Prometheus metrics registry for LLM metrics
    pub metrics: Option<SharedMetrics>,
}

/// Global cache for DNS blackhole detection results (60-second TTL)
static BLACKHOLE_CACHE: std::sync::OnceLock<Cache<String, bool>> = std::sync::OnceLock::new();

/// Get or initialize the global blackhole cache
fn get_blackhole_cache() -> &'static Cache<String, bool> {
    BLACKHOLE_CACHE.get_or_init(|| {
        Cache::builder()
            .time_to_live(Duration::from_secs(60))
            .max_capacity(1000)
            .build()
    })
}

/// Validate HTTP Basic Authentication
///
/// Checks the Authorization header for valid credentials.
/// Returns true if auth is disabled (no credentials configured) or if valid credentials provided.
fn validate_basic_auth(
    req: &Request<hyper::body::Incoming>,
    expected_username: &Option<String>,
    expected_password: &Option<String>,
) -> bool {
    // If no credentials configured, auth is disabled
    let (expected_user, expected_pass) = match (expected_username, expected_password) {
        (Some(u), Some(p)) => (u, p),
        _ => return true,
    };

    // Extract Authorization header
    if let Some(auth_header) = req.headers().get("Proxy-Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            // Parse "Basic base64(username:password)"
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded_bytes) = base64::prelude::BASE64_STANDARD.decode(encoded) {
                    if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                        if let Some((user, pass)) = decoded.split_once(':') {
                            return user == expected_user && pass == expected_pass;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Check if a hostname resolves to a blackhole IP address
///
/// Performs DNS lookup and checks if any resolved IP is:
/// - 0.0.0.0 (common DNS blackhole)
/// - 127.0.0.1 (localhost redirect)
///
/// Results are cached for 60 seconds to avoid repeated DNS lookups.
async fn is_hostname_blackholed(hostname: &str) -> bool {
    let cache = get_blackhole_cache();

    cache
        .try_get_with(hostname.to_string(), async {
            // Perform DNS lookup
            let lookup_result = tokio::net::lookup_host(format!("{}:443", hostname)).await;

            let is_blackholed = match lookup_result {
                Ok(addrs) => {
                    // Check if any resolved IP is a blackhole address
                    let blackholed = addrs.into_iter().any(|addr| {
                        let ip = addr.ip();
                        matches!(ip,
                            IpAddr::V4(ipv4) if ipv4.is_unspecified() || ipv4.is_loopback()
                        )
                    });

                    if blackholed {
                        tracing::debug!("DNS blackhole detected for {}", hostname);
                    }

                    blackholed
                }
                Err(e) => {
                    // DNS lookup failed - log and don't cache failures
                    tracing::debug!("DNS lookup failed for {}: {}", hostname, e);
                    return Err(format!("DNS lookup failed: {}", e));
                }
            };

            Ok(is_blackholed)
        })
        .await
        .unwrap_or(false)
}

/// Start the MITM proxy server
///
/// Listens on the specified address and handles incoming proxy connections.
/// For HTTPS (via HTTP CONNECT), performs TLS MITM with on-demand certificate generation.
/// If token injection is configured, automatically injects authentication headers for matching requests.
///
/// The `ca_cert_path` and `ca_cert_pem` are written AFTER the socket is bound, ensuring that
/// the CA cert file appearing is a reliable signal that the proxy is ready to accept connections.
pub async fn start_server(
    listen_addr: String,
    state: Arc<ProxyState>,
    ca_cert_path: std::path::PathBuf,
    ca_cert_pem: String,
) -> Result<(), BoxError> {
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::debug!("proxy listening on {}", listen_addr);

    // Write CA cert AFTER bind - this is the readiness signal for proxy_manager
    std::fs::write(&ca_cert_path, &ca_cert_pem)?;
    tracing::debug!("saved ca certificate to {}", ca_cert_path.display());

    tracing::debug!(
        "network policy enabled with {} rules",
        state.policy.rules.len()
    );

    // Set up signal handlers for graceful shutdown
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

    loop {
        tokio::select! {
            // Handle SIGTERM
            _ = sigterm.recv() => {
                tracing::debug!("received sigterm, shutting down proxy");
                // Write stats to file for orchestrator to read after job completes
                let stats_path = ca_cert_path.with_file_name("proxy-stats.json");
                if let Err(e) = state.stats.write_to_file(&stats_path) {
                    tracing::warn!("failed to write proxy stats: {}", e);
                }
                return Ok(());
            }
            // Handle SIGINT (Ctrl+C)
            _ = sigint.recv() => {
                tracing::debug!("received sigint, shutting down proxy");
                let stats_path = ca_cert_path.with_file_name("proxy-stats.json");
                if let Err(e) = state.stats.write_to_file(&stats_path) {
                    tracing::warn!("failed to write proxy stats: {}", e);
                }
                return Ok(());
            }
            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, peer_addr) = accept_result?;
                let state = state.clone();

                // Spawn task to handle connection independently - no need to await
                // Use in_current_span() to propagate trace context without creating a visible span
                drop(tokio::spawn(
                    async move {
                        if let Err(e) =
                            handle_connection(stream, state, peer_addr.to_string()).await
                        {
                            tracing::error!("connection error from {}: {}", peer_addr, e);
                        }
                    }
                    .in_current_span(),
                ));
            }
        }
    }
}

/// Handle a single proxy connection
async fn handle_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
    peer_addr: String,
) -> Result<(), BoxError> {
    let io = TokioIo::new(stream);

    // Serve the initial HTTP request to determine if it's CONNECT or regular HTTP
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let state = state.clone();
        let peer_addr = peer_addr.clone();
        async move { handle_request(req, state, peer_addr).await }
    });

    if let Err(e) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        tracing::debug!("connection serving error: {}", e);
    }

    Ok(())
}

/// Handle a single HTTP request
///
/// Routes to either:
/// - handle_connect() for HTTPS (HTTP CONNECT method)
/// - handle_http() for plain HTTP
///
/// For CONNECT requests:
/// 1. Enforces network policy (if configured)
/// 2. Performs DNS blackhole detection
/// 3. Logs at DEBUG level if blackholed, INFO level for normal connections
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
    _peer_addr: String,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Validate Basic Authentication if configured
    if !validate_basic_auth(&req, &state.proxy_username, &state.proxy_password) {
        tracing::warn!("proxy authentication failed for {}", req.uri());
        return Ok(Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header("Proxy-Authenticate", "Basic realm=\"nix-jail-proxy\"")
            .body(empty_body())
            .unwrap_or_else(|_| Response::new(empty_body())));
    }

    if req.method() == Method::CONNECT {
        // Extract hostname from URI
        let uri_str = req.uri().to_string();
        let hostname = uri_str.split(':').next().unwrap_or(&uri_str);

        // Enforce network policy (always present)
        // At CONNECT time, we can't see the HTTP path yet, so we evaluate with path=None
        // If the policy denies but the hostname matches a rule (that might need path),
        // we defer enforcement to HTTP inspection phase
        let policy_decision = match state.policy.evaluate(hostname, None).await {
            Ok(decision @ PolicyDecision::Allow { .. }) => {
                tracing::debug!("policy allows: {}", hostname);
                Some(decision)
            }
            Ok(PolicyDecision::Deny) => {
                // Check if hostname matches any rule (might be path-dependent)
                match state.policy.hostname_matches_any_rule(hostname).await {
                    Ok(true) => {
                        // Hostname matches a rule, but path might be required
                        // Defer enforcement to HTTP inspection phase
                        tracing::debug!(
                            "policy deferred for {} (path-based rule possible)",
                            hostname
                        );
                        None // Signal that we need to re-evaluate with path
                    }
                    Ok(false) => {
                        // Hostname doesn't match any rule, use default deny
                        if state.stats.record_denied(hostname) {
                            tracing::warn!("policy denies: {} - blocking at connect", hostname);
                        }
                        state
                            .stats
                            .record_request(hostname, "CONNECT", 403, None, false);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(empty_body())
                            .unwrap_or_else(|_| Response::new(empty_body())));
                    }
                    Err(e) => {
                        tracing::error!(
                            "policy evaluation error for {}: {} - denying",
                            hostname,
                            e
                        );
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(empty_body())
                            .unwrap_or_else(|_| Response::new(empty_body())));
                    }
                }
            }
            Err(e) => {
                tracing::error!("policy evaluation error for {}: {} - denying", hostname, e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(empty_body())
                    .unwrap_or_else(|_| Response::new(empty_body())));
            }
        };

        // Check DNS blackhole and reject early to avoid TLS handshake spam
        let is_blackholed = is_hostname_blackholed(hostname).await;
        if is_blackholed {
            let denied_key = format!("{} (blackholed)", hostname);
            if state.stats.record_denied(&denied_key) {
                tracing::debug!("connect {} (blackholed) - rejecting early", req.uri());
            }
            state
                .stats
                .record_request(hostname, "CONNECT", 502, None, false);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(empty_body())
                .unwrap_or_else(|_| Response::new(empty_body())));
        }

        tracing::debug!("CONNECT {}", req.uri());

        // HTTPS request - need to perform TLS MITM
        match handle_connect(req, state, policy_decision).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::error!("connect error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty_body())
                    .unwrap_or_else(|_| Response::new(empty_body())))
            }
        }
    } else {
        // Plain HTTP request - log at debug level
        tracing::debug!("{} {}", req.method(), req.uri());
        handle_http(req).await
    }
}

/// Handle HTTP CONNECT request (for HTTPS)
///
/// This function:
/// 1. Extracts the target hostname from the request
/// 2. Issues a forged certificate for that hostname
/// 3. Responds with "200 Connection Established"
/// 4. Hijacks the connection to perform TLS MITM
async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
    policy_decision: Option<PolicyDecision>,
) -> Result<Response<BoxBody>, BoxError> {
    // Extract hostname from CONNECT request (e.g., "api.anthropic.com:443")
    let host = req
        .uri()
        .authority()
        .ok_or("Missing authority in CONNECT request")?
        .as_str()
        .to_string(); // Convert to owned String

    // Parse hostname (remove port if present)
    let hostname = host
        .split(':')
        .next()
        .ok_or("Invalid hostname in CONNECT request")?
        .to_string(); // Convert to owned String

    tracing::debug!("connect to {}", hostname);

    // Issue certificate for this hostname
    let (cert_der, key_der) = state.ca.issue_for_host(&hostname)?;

    // Get CA certificate to include in the chain
    // TLS clients need the full chain to verify the server certificate
    let ca_cert_der = state.ca.ca_cert_der().clone();

    // Respond with 200 Connection Established
    let state_for_mitm = state.clone();
    let policy_decision_for_mitm = policy_decision;
    // Spawn task to handle WebSocket upgrade in background - no need to await
    // Instrument with span to inherit trace context from parent
    let mitm_span = tracing::info_span!("mitm", host = %hostname);
    drop(tokio::spawn(
        async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    // Wrap upgraded connection with TokioIo for AsyncRead/AsyncWrite traits
                    let io = TokioIo::new(upgraded);
                    if let Err(e) = handle_mitm(
                        io,
                        hostname,
                        cert_der,
                        ca_cert_der,
                        key_der,
                        state_for_mitm,
                        policy_decision_for_mitm,
                    )
                    .await
                    {
                        // Downgrade expected connection errors to debug level
                        let err_str = e.to_string();
                        if err_str.contains("close_notify") || err_str.contains("Connection reset")
                        {
                            tracing::debug!("connection closed: {}", e);
                        } else if err_str.contains("Connection refused") {
                            tracing::debug!("connection refused (likely dns-blocked): {}", e);
                        } else {
                            tracing::error!("mitm error: {}", e);
                        }
                    }
                }
                Err(e) => tracing::error!("upgrade error: {}", e),
            }
        }
        .instrument(mitm_span),
    ));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())?)
}

/// Handle MITM for an upgraded HTTPS connection
///
/// This function:
/// 1. Performs TLS handshake with client using forged certificate
/// 2. Connects to upstream server
/// 3. Performs TLS handshake with upstream server
/// 4. Proxies decrypted traffic between client and server
/// 5. Inspects traffic for logging
async fn handle_mitm<I>(
    client_stream: I,
    hostname: String,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
    state: Arc<ProxyState>,
    policy_decision: Option<PolicyDecision>,
) -> Result<(), BoxError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Generate unique connection ID for tracing
    let conn_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Configure TLS for client connection (with forged cert)
    // Send the full certificate chain: [host cert, CA cert]
    // This allows clients to verify the chain without needing the CA pre-installed
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der, ca_cert_der], key_der)?;

    // Only support HTTP/1.1 for now
    // HTTP/2 MITM implementation exists but has FRAME_SIZE_ERROR issues
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Perform TLS handshake with client
    let client_tls = acceptor.accept(client_stream).await?;

    // Detect negotiated protocol (convert to owned String before moving client_tls)
    let protocol = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .and_then(|p| std::str::from_utf8(p).ok())
        .unwrap_or("unknown")
        .to_string(); // Convert to owned String

    tracing::debug!(protocol = %protocol, "client tls handshake complete");

    // Connect to upstream server
    let upstream_addr = format!("{}:443", hostname);
    let upstream_stream = TcpStream::connect(&upstream_addr).await?;

    // Configure TCP keepalive to prevent connection resets on long-running streams
    upstream_stream.set_nodelay(true)?;
    let sock_ref = socket2::SockRef::from(&upstream_stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        tracing::warn!(conn_id, error = %e, "failed to set tcp keepalive");
    }

    // Configure TLS for upstream connection
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let upstream_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(upstream_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.clone())?;

    let upstream_tls = connector.connect(server_name, upstream_stream).await?;

    tracing::debug!(conn_id, "upstream connection established");

    // HTTP/1.1: Use stream-based bidirectional relay
    let (client_reader, client_writer) = tokio::io::split(client_tls);
    let (upstream_reader, upstream_writer) = tokio::io::split(upstream_tls);

    // Share client_writer between both tasks (for error responses and normal relay)
    use tokio::sync::Mutex;
    let client_writer = Arc::new(Mutex::new(client_writer));
    let client_writer_for_upstream = client_writer.clone();

    // Shared signal for OAuth response redaction
    // Set by request handler when request goes to a redact path
    let redaction_signal: RedactionSignal = Arc::new(Mutex::new(None));
    let redaction_signal_for_upstream = redaction_signal.clone();

    // Shared signal for LLM metrics extraction
    let llm_metrics_signal: LlmMetricsSignal = Arc::new(Mutex::new(None));
    let llm_metrics_signal_for_upstream = llm_metrics_signal.clone();

    let hostname_clone = hostname.clone();
    let state_clone = state.clone();
    let state_for_upstream = state.clone();
    let policy_decision_clone = policy_decision;

    let client_to_upstream = async move {
        proxy_with_http1_inspection(
            client_reader,
            client_writer,
            upstream_writer,
            hostname_clone,
            state_clone,
            policy_decision_clone,
            conn_id,
            redaction_signal,
            llm_metrics_signal,
        )
        .await
    };

    let upstream_to_client = async move {
        relay_upstream_to_client(
            upstream_reader,
            client_writer_for_upstream,
            state_for_upstream,
            redaction_signal_for_upstream,
            llm_metrics_signal_for_upstream,
            conn_id,
        )
        .await
    };

    // Run both directions concurrently
    tokio::try_join!(client_to_upstream, upstream_to_client)?;

    Ok(())
}

/// Proxy client to upstream with HTTP/1.1 request inspection and token injection
#[allow(clippy::too_many_arguments)]
async fn proxy_with_http1_inspection<R, CW, UW>(
    mut reader: R,
    client_writer: Arc<tokio::sync::Mutex<CW>>,
    mut upstream_writer: UW,
    hostname: String,
    state: Arc<ProxyState>,
    policy_decision: Option<PolicyDecision>,
    conn_id: u64,
    redaction_signal: RedactionSignal,
    llm_metrics_signal: LlmMetricsSignal,
) -> Result<(), BoxError>
where
    R: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UW: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut accumulated = Vec::new();
    // Track remaining request body bytes to forward (for POST requests with Content-Length)
    let mut body_bytes_remaining: usize = 0;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // If we're in body forwarding mode, forward data directly
        if body_bytes_remaining > 0 {
            let to_forward = n.min(body_bytes_remaining);
            upstream_writer.write_all(&buf[..to_forward]).await?;
            body_bytes_remaining -= to_forward;

            // If we forwarded less than we read, the rest is the next request
            if to_forward < n {
                accumulated.extend_from_slice(&buf[to_forward..n]);
            }

            // If more body expected, continue reading
            if body_bytes_remaining > 0 {
                continue;
            }
            // Body complete - flush to ensure data is transmitted
            upstream_writer.flush().await?;
            // Fall through to parse next request from accumulated
        } else {
            // Accumulate data for parsing
            accumulated.extend_from_slice(&buf[..n]);
        }

        // Try to parse HTTP requests from accumulated data
        loop {
            // Prepare buffer for httparse (need to convert to slice of headers)
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);

            match req.parse(&accumulated) {
                Ok(httparse::Status::Complete(bytes_parsed)) => {
                    // Successfully parsed a request
                    if let (Some(method), Some(path), Some(version)) =
                        (req.method, req.path, req.version)
                    {
                        // Re-evaluate policy if it was deferred at CONNECT time
                        let final_policy_decision = if policy_decision.is_none() {
                            // Policy was deferred - re-evaluate with path
                            match state.policy.evaluate(&hostname, Some(path)).await {
                                Ok(decision @ PolicyDecision::Allow { .. }) => {
                                    tracing::debug!(
                                        "policy allows: {} {} (path-based)",
                                        hostname,
                                        path
                                    );
                                    Some(decision)
                                }
                                Ok(PolicyDecision::Deny) => {
                                    // Denied after path evaluation - send 403 response to client
                                    let denied_key = format!("{}:{}", hostname, path);
                                    if state.stats.record_denied(&denied_key) {
                                        tracing::warn!(
                                            "policy denies: {} {} - blocking at http",
                                            hostname,
                                            path
                                        );
                                    }
                                    state
                                        .stats
                                        .record_request(&hostname, method, 403, None, false);

                                    // Construct HTTP/1.1 403 Forbidden response
                                    let response = format!(
                                        "HTTP/1.{} 403 Forbidden\r\n\
                                         Content-Length: 0\r\n\
                                         Connection: close\r\n\
                                         \r\n",
                                        version
                                    );

                                    let mut client_writer = client_writer.lock().await;
                                    client_writer.write_all(response.as_bytes()).await?;
                                    client_writer.shutdown().await?;
                                    accumulated.clear();
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "policy re-evaluation error for {} {}: {}",
                                        hostname,
                                        path,
                                        e
                                    );

                                    // Construct HTTP/1.1 500 Internal Server Error response
                                    let response = format!(
                                        "HTTP/1.{} 500 Internal Server Error\r\n\
                                         Content-Length: 0\r\n\
                                         Connection: close\r\n\
                                         \r\n",
                                        version
                                    );

                                    let mut client_writer = client_writer.lock().await;
                                    client_writer.write_all(response.as_bytes()).await?;
                                    client_writer.shutdown().await?;
                                    accumulated.clear();
                                    break;
                                }
                            }
                        } else {
                            policy_decision.clone()
                        };

                        // Extract policy info and credential name for logging
                        let (rule_index, credential_from_policy) = match &final_policy_decision {
                            Some(PolicyDecision::Allow {
                                rule_index,
                                credential,
                            }) => (*rule_index, credential.as_deref()),
                            _ => (None, None),
                        };

                        // Track approved request in statistics (legacy + detailed)
                        state.stats.record_approved(&hostname);
                        state.stats.record_request(
                            &hostname,
                            method,
                            0, // status not tracked yet
                            credential_from_policy,
                            true, // approved
                        );

                        // Log request with enhanced metadata
                        match (rule_index, credential_from_policy) {
                            (Some(idx), Some(cred)) => {
                                tracing::debug!(
                                    conn_id,
                                    rule_index = idx,
                                    credential = cred,
                                    "{} {}{}",
                                    method,
                                    hostname,
                                    path
                                );
                            }
                            (Some(idx), None) => {
                                tracing::debug!(
                                    conn_id,
                                    rule_index = idx,
                                    "{} {}{}",
                                    method,
                                    hostname,
                                    path
                                );
                            }
                            (None, Some(cred)) => {
                                tracing::debug!(
                                    conn_id,
                                    credential = cred,
                                    "{} {}{}",
                                    method,
                                    hostname,
                                    path
                                );
                            }
                            (None, None) => {
                                tracing::debug!(conn_id, "{} {}{}", method, hostname, path);
                            }
                        }

                        // JSON request logging for debugging
                        {
                            use std::collections::HashMap;
                            let headers: HashMap<String, String> = req
                                .headers
                                .iter()
                                .map(|h| {
                                    (
                                        h.name.to_lowercase(),
                                        String::from_utf8_lossy(h.value).to_string(),
                                    )
                                })
                                .collect();
                            let log_entry = serde_json::json!({
                                "ts": chrono::Utc::now().to_rfc3339(),
                                "conn_id": conn_id,
                                "method": method,
                                "host": hostname,
                                "path": path,
                                "headers": headers,
                                "rule_index": rule_index,
                                "credential": credential_from_policy,
                            });
                            if let Some(ref log_path) = state.request_log_path {
                                if let Ok(json) = serde_json::to_string(&log_entry) {
                                    if let Ok(mut f) = std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(log_path)
                                    {
                                        use std::io::Write;
                                        let _ = writeln!(f, "{}", json);
                                    }
                                }
                            }
                        }

                        // Extract Content-Length for body tracking (needed for all paths)
                        let req_content_length: Option<usize> = req
                            .headers
                            .iter()
                            .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                            .and_then(|h| std::str::from_utf8(h.value).ok())
                            .and_then(|v| v.parse().ok());

                        // Policy-based credential injection
                        if let Some(credential_name) = credential_from_policy {
                            // Fetch token with 5-minute caching
                            match state.policy.fetch_token(credential_name).await {
                                Ok(token) => {
                                    let credential = match state
                                        .policy
                                        .get_credential(credential_name)
                                    {
                                        Some(c) => c,
                                        None => {
                                            tracing::error!(
                                                credential = credential_name,
                                                "credential not found after successful token fetch"
                                            );
                                            return Err(Box::new(std::io::Error::other(format!(
                                                "credential not found: {}",
                                                credential_name
                                            ))));
                                        }
                                    };

                                    // Check Authorization header for dummy token replacement
                                    let client_auth = req
                                        .headers
                                        .iter()
                                        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
                                        .map(|h| String::from_utf8_lossy(h.value).to_string());

                                    let dummy_token = credential.dummy_token.as_deref();

                                    // For Claude credentials, extract accessToken from JSON
                                    // For other credentials, use token directly
                                    let inject_token =
                                        if credential.credential_type == CredentialType::Claude {
                                            extract_access_token(&token)
                                        } else {
                                            Some(token.clone())
                                        };

                                    // Set LLM metrics signal early (before any early returns)
                                    // This ensures metrics are captured even if no token injection occurs
                                    // Only track actual LLM endpoints (not health checks, OAuth, etc.)
                                    let is_llm_endpoint = path.starts_with("/v1/messages")
                                        || path.starts_with("/v1/chat/completions");
                                    if credential.extract_llm_metrics && is_llm_endpoint {
                                        let provider = credential.llm_provider.or_else(|| {
                                            if hostname.contains("anthropic") {
                                                Some(crate::config::LlmProvider::Anthropic)
                                            } else if hostname.contains("openai") {
                                                Some(crate::config::LlmProvider::OpenAI)
                                            } else {
                                                None
                                            }
                                        });
                                        if let Some(provider) = provider {
                                            let mut signal = llm_metrics_signal.lock().await;
                                            *signal = Some(LlmMetricsContext {
                                                host: hostname.clone(),
                                                path: path.to_string(),
                                                credential: credential_name.to_string(),
                                                provider,
                                            });
                                            tracing::debug!(
                                                credential = credential_name,
                                                path = path,
                                                provider = ?provider,
                                                "signaling llm metrics extraction"
                                            );
                                        }
                                    }
                                    tracing::debug!(
                                        credential = credential_name,
                                        host = %hostname,
                                        method = method,
                                        path = path,
                                        "credentialed request"
                                    );

                                    let header_value = match (
                                        &client_auth,
                                        dummy_token,
                                        inject_token,
                                    ) {
                                        (Some(sent), Some(dummy), Some(real_token)) => {
                                            let expected_dummy =
                                                credential.header_format.replace("{token}", dummy);
                                            if sent == &expected_dummy {
                                                tracing::debug!(
                                                    "client sent expected dummy, will replace"
                                                );
                                                Some(
                                                    credential
                                                        .header_format
                                                        .replace("{token}", &real_token),
                                                )
                                            } else {
                                                // Check if the sent token is a redacted OAuth token
                                                // Extract the token from the Authorization header
                                                let sent_token = extract_bearer_token(sent);
                                                if let Some(token_str) = sent_token {
                                                    if let Some(real_oauth_token) = state
                                                        .policy
                                                        .get_real_oauth_token(token_str)
                                                        .await
                                                    {
                                                        tracing::debug!(
                                                            "client sent redacted oauth token, will replace"
                                                        );
                                                        Some(
                                                            credential.header_format.replace(
                                                                "{token}",
                                                                &real_oauth_token,
                                                            ),
                                                        )
                                                    } else {
                                                        tracing::debug!(
                                                            "client auth does not match dummy or oauth cache, forwarding unchanged for {} {}",
                                                            method, path
                                                        );
                                                        None
                                                    }
                                                } else {
                                                    tracing::debug!(
                                                        "client auth does not match dummy, forwarding unchanged for {} {}",
                                                        method, path
                                                    );
                                                    None
                                                }
                                            }
                                        }
                                        (Some(sent), None, Some(_)) => {
                                            // No static dummy configured, but check OAuth cache
                                            let sent_token = extract_bearer_token(sent);
                                            if let Some(token_str) = sent_token {
                                                if let Some(real_oauth_token) = state
                                                    .policy
                                                    .get_real_oauth_token(token_str)
                                                    .await
                                                {
                                                    tracing::debug!(
                                                        "client sent redacted oauth token (no static dummy), will replace"
                                                    );
                                                    Some(
                                                        credential
                                                            .header_format
                                                            .replace("{token}", &real_oauth_token),
                                                    )
                                                } else {
                                                    tracing::debug!(
                                                        "client sent auth but no dummy configured and not in oauth cache, forwarding unchanged for {} {}",
                                                        method, path
                                                    );
                                                    None
                                                }
                                            } else {
                                                tracing::warn!(
                                                    "client sent auth but no dummy configured, forwarding unchanged for {} {}",
                                                    method, path
                                                );
                                                None
                                            }
                                        }
                                        (None, _, _) => {
                                            tracing::debug!(
                                                "no client auth header, forwarding unchanged for {} {}",
                                                method, path
                                            );
                                            None
                                        }
                                        (Some(_), None, None) => {
                                            tracing::error!(
                                                "failed to extract token for injection"
                                            );
                                            None
                                        }
                                        (_, _, None) => {
                                            tracing::error!(
                                                "failed to extract token for injection"
                                            );
                                            None
                                        }
                                    };

                                    // If no injection needed, forward unchanged
                                    let header_value = match header_value {
                                        Some(v) => v,
                                        None => {
                                            upstream_writer.write_all(&accumulated).await?;
                                            accumulated.clear();
                                            continue;
                                        }
                                    };

                                    // Check if this response needs redaction (for OAuth token responses)
                                    let redact_credential =
                                        state.policy.should_redact_response(&hostname, path);
                                    let needs_response_redaction = redact_credential.is_some();

                                    // Signal response handler to redact this response
                                    if let Some(cred_name) = redact_credential {
                                        let mut signal = redaction_signal.lock().await;
                                        *signal = Some(cred_name.to_string());
                                        tracing::debug!(
                                            credential = cred_name,
                                            "signaling response redaction for oauth path"
                                        );
                                    }

                                    // Build new headers list, replacing Authorization in place
                                    // If response redaction is needed, strip Accept-Encoding to
                                    // force uncompressed responses we can parse
                                    let mut new_headers: Vec<(&str, String)> = Vec::new();
                                    for header in req.headers.iter() {
                                        let header_value_str =
                                            std::str::from_utf8(header.value).unwrap_or("");

                                        if header.name.eq_ignore_ascii_case("authorization") {
                                            new_headers.push((header.name, header_value.clone()));
                                        } else if needs_response_redaction
                                            && header.name.eq_ignore_ascii_case("accept-encoding")
                                        {
                                            // Skip Accept-Encoding to force plaintext response
                                            tracing::debug!(
                                                "stripping accept-encoding for response redaction"
                                            );
                                        } else {
                                            new_headers
                                                .push((header.name, header_value_str.to_string()));
                                        }
                                    }

                                    // Reconstruct the HTTP/1.1 request with modified headers
                                    let mut reconstructed = Vec::new();

                                    // Request line
                                    reconstructed.extend_from_slice(method.as_bytes());
                                    reconstructed.push(b' ');
                                    reconstructed.extend_from_slice(path.as_bytes());
                                    reconstructed.extend_from_slice(b" HTTP/1.");
                                    reconstructed.push(b'0' + version);
                                    reconstructed.extend_from_slice(b"\r\n");

                                    // Headers
                                    for (name, value) in new_headers {
                                        reconstructed.extend_from_slice(name.as_bytes());
                                        reconstructed.extend_from_slice(b": ");
                                        reconstructed.extend_from_slice(value.as_bytes());
                                        reconstructed.extend_from_slice(b"\r\n");
                                    }

                                    // End of headers
                                    reconstructed.extend_from_slice(b"\r\n");

                                    // Body (everything after the headers in this chunk)
                                    let body_in_chunk = accumulated.len() - bytes_parsed;
                                    reconstructed.extend_from_slice(&accumulated[bytes_parsed..]);

                                    // Write the reconstructed request to upstream
                                    upstream_writer.write_all(&reconstructed).await?;

                                    // Track remaining body bytes to forward
                                    if let Some(total_body) = req_content_length {
                                        if body_in_chunk < total_body {
                                            body_bytes_remaining = total_body - body_in_chunk;
                                        } else {
                                            // Body complete in first chunk - flush
                                            upstream_writer.flush().await?;
                                        }
                                    } else {
                                        // No Content-Length (e.g., GET request) - flush
                                        upstream_writer.flush().await?;
                                    }

                                    // Clear accumulated buffer since we've processed everything
                                    accumulated.clear();
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "failed to fetch token for {}: {}",
                                        credential_name,
                                        e
                                    );
                                    // Forward entire request (headers + body in chunk)
                                    upstream_writer.write_all(&accumulated).await?;
                                    // Track remaining body
                                    let body_in_chunk = accumulated.len() - bytes_parsed;
                                    if let Some(cl) = req_content_length {
                                        if body_in_chunk < cl {
                                            body_bytes_remaining = cl - body_in_chunk;
                                        } else {
                                            upstream_writer.flush().await?;
                                        }
                                    } else {
                                        upstream_writer.flush().await?;
                                    }
                                    accumulated.clear();
                                }
                            }
                        } else {
                            // No credential injection - forward as-is
                            upstream_writer.write_all(&accumulated).await?;
                            let body_in_chunk = accumulated.len() - bytes_parsed;
                            if let Some(cl) = req_content_length {
                                if body_in_chunk < cl {
                                    body_bytes_remaining = cl - body_in_chunk;
                                } else {
                                    upstream_writer.flush().await?;
                                }
                            } else {
                                upstream_writer.flush().await?;
                            }
                            accumulated.clear();
                        }
                    } else {
                        // Failed to parse completely - forward as-is
                        upstream_writer.write_all(&accumulated).await?;
                        upstream_writer.flush().await?;
                        accumulated.clear();
                    }
                }
                Ok(httparse::Status::Partial) => {
                    // Need more data to complete parsing
                    break;
                }
                Err(e) => {
                    // Parse error - forward raw data
                    tracing::debug!(
                        error = %e,
                        buffer_len = accumulated.len(),
                        "http/1.1 parse error for {}",
                        hostname
                    );
                    upstream_writer.write_all(&accumulated).await?;
                    accumulated.clear();
                    break;
                }
            }
        }
    }

    upstream_writer.shutdown().await?;
    Ok(())
}

/// Relay responses from upstream to client, with optional OAuth token redaction and LLM metrics
///
/// When the redaction signal is set, this function:
/// 1. Buffers the complete HTTP response
/// 2. Parses the JSON body
/// 3. Replaces real OAuth tokens with dummy tokens
/// 4. Caches the token mapping for future request injection
/// 5. Sends the redacted response to the client
///
/// When the LLM metrics signal is set:
/// 1. For streaming (SSE), parses events as they arrive
/// 2. For non-streaming, parses the complete response body
/// 3. Records token usage and tool calls to Prometheus metrics
async fn relay_upstream_to_client<R, W>(
    mut upstream_reader: R,
    client_writer: Arc<tokio::sync::Mutex<W>>,
    state: Arc<ProxyState>,
    redaction_signal: RedactionSignal,
    llm_metrics_signal: LlmMetricsSignal,
    conn_id: u64,
) -> Result<(), BoxError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut accumulated = Vec::new();
    const MAX_REDACT_SIZE: usize = 1024 * 1024; // 1MB limit for redaction

    // LLM metrics state
    let mut llm_context: Option<LlmMetricsContext> = None;
    let mut llm_accumulator: Option<StreamingMetricsAccumulator> = None;
    let mut llm_is_streaming: Option<bool> = None;
    let mut llm_is_gzip: Option<bool> = None;
    let mut llm_response_body: Vec<u8> = Vec::new();
    let mut llm_headers_parsed = false;
    let mut llm_metrics_recorded = false; // Track if we've already recorded metrics

    loop {
        let n = match upstream_reader.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(conn_id, error = %e, "upstream read error");
                return Err(e.into());
            }
        };
        if n == 0 {
            break;
        }

        // Check if we need to redact this response
        let credential_name = {
            let signal = redaction_signal.lock().await;
            signal.clone()
        };

        // Check if we need LLM metrics extraction (only on first check)
        if llm_context.is_none() {
            let signal = llm_metrics_signal.lock().await;
            llm_context = signal.clone();
            if llm_context.is_some() {
                tracing::debug!(conn_id, "llm_context acquired from signal");
            }
        }

        if credential_name.is_none() && llm_context.is_none() {
            // No special handling needed - relay directly
            tracing::trace!("upstream -> client: {} bytes", n);
            let mut client_writer = client_writer.lock().await;
            client_writer.write_all(&buf[..n]).await?;
            client_writer.flush().await?;
            continue;
        }

        // Handle LLM metrics extraction (forward while parsing - no modification)
        if credential_name.is_none() && llm_context.is_some() {
            tracing::trace!(
                conn_id,
                n,
                headers_parsed = llm_headers_parsed,
                "processing llm response chunk"
            );
            // Accumulate data for header parsing
            accumulated.extend_from_slice(&buf[..n]);

            // Detect streaming on first header parse
            if !llm_headers_parsed {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut resp = httparse::Response::new(&mut headers);

                if let Ok(httparse::Status::Complete(header_len)) = resp.parse(&accumulated) {
                    llm_headers_parsed = true;

                    // Check Content-Type for streaming
                    let is_sse = resp.headers.iter().any(|h| {
                        h.name.eq_ignore_ascii_case("content-type")
                            && std::str::from_utf8(h.value)
                                .map(|v| v.contains("text/event-stream"))
                                .unwrap_or(false)
                    });

                    // Check Content-Encoding for gzip
                    let is_gzip = resp.headers.iter().any(|h| {
                        h.name.eq_ignore_ascii_case("content-encoding")
                            && std::str::from_utf8(h.value)
                                .map(|v| v.contains("gzip"))
                                .unwrap_or(false)
                    });
                    llm_is_gzip = Some(is_gzip);

                    llm_is_streaming = Some(is_sse);

                    if is_sse {
                        // Create streaming accumulator
                        if let Some(ref ctx) = llm_context {
                            llm_accumulator = Some(StreamingMetricsAccumulator::new(ctx.provider));
                            tracing::debug!(conn_id, path = %ctx.path, "detected sse streaming llm response");
                        }
                    } else {
                        tracing::debug!(conn_id, "detected non-streaming llm response");
                    }

                    // For streaming, process the body portion already received
                    if is_sse {
                        if let Some(ref mut acc) = llm_accumulator {
                            acc.process_chunk(&accumulated[header_len..]);
                        }
                    } else {
                        // Store body for non-streaming
                        llm_response_body.extend_from_slice(&accumulated[header_len..]);
                    }

                    // Forward accumulated data to client
                    let mut client_writer = client_writer.lock().await;
                    client_writer.write_all(&accumulated).await?;
                    client_writer.flush().await?;
                    accumulated.clear();
                    continue;
                }
            } else {
                // Headers already parsed - process based on streaming mode
                if llm_is_streaming == Some(true) {
                    if let Some(ref mut acc) = llm_accumulator {
                        acc.process_chunk(&buf[..n]);

                        // Record metrics immediately when complete (don't wait for EOF)
                        // SSE streams may be interrupted by proxy shutdown before EOF
                        if !llm_metrics_recorded && acc.is_complete() {
                            if let Some(ref ctx) = llm_context {
                                let metrics = acc.metrics();

                                // Record to stats for file output
                                state.stats.record_llm_metrics(
                                    metrics.model.as_deref(),
                                    metrics.input_tokens,
                                    metrics.output_tokens,
                                    metrics.cache_read_tokens,
                                    &metrics.tool_calls,
                                );

                                // Record to Prometheus if available
                                if let Some(ref registry) = state.metrics {
                                    registry.record_llm_usage(
                                        &ctx.host,
                                        &ctx.credential,
                                        metrics.model.as_deref(),
                                        metrics.input_tokens,
                                        metrics.output_tokens,
                                        metrics.cache_read_tokens,
                                        &metrics.tool_calls,
                                    );
                                }

                                // Emit OpenTelemetry event for distributed tracing
                                emit_llm_completion_span(ctx, metrics, conn_id);

                                llm_metrics_recorded = true;
                            }
                        }
                    }
                } else {
                    // Non-streaming: accumulate body for final parsing
                    llm_response_body.extend_from_slice(&buf[..n]);
                }

                // Forward immediately (no modification needed for metrics)
                let mut client_writer = client_writer.lock().await;
                client_writer.write_all(&buf[..n]).await?;
                client_writer.flush().await?;
                accumulated.clear();
                continue;
            }

            // Headers not yet complete - wait for more data but still forward
            let mut client_writer = client_writer.lock().await;
            client_writer.write_all(&buf[..n]).await?;
            client_writer.flush().await?;
            // Don't clear accumulated - we need it for header parsing
            continue;
        }

        // OAuth redaction is needed - credential_name.is_some()

        // Redaction mode: buffer the response
        accumulated.extend_from_slice(&buf[..n]);

        // Enforce size limit
        if accumulated.len() > MAX_REDACT_SIZE {
            tracing::warn!(
                conn_id,
                size = accumulated.len(),
                "response too large for redaction, forwarding as-is"
            );
            // Clear signal and forward what we have
            {
                let mut signal = redaction_signal.lock().await;
                *signal = None;
            }
            let mut client_writer = client_writer.lock().await;
            client_writer.write_all(&accumulated).await?;
            accumulated.clear();
            continue;
        }

        // Try to parse HTTP response to see if we have the complete body
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&accumulated) {
            Ok(httparse::Status::Complete(header_len)) => {
                // Find Content-Length to determine body size
                let content_length: Option<usize> = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|v| v.parse().ok());

                let body_received = accumulated.len() - header_len;

                // Check if we have the complete body
                let body_complete = match content_length {
                    Some(len) => body_received >= len,
                    None => {
                        // No Content-Length - check for chunked encoding or assume complete
                        let is_chunked = resp.headers.iter().any(|h| {
                            h.name.eq_ignore_ascii_case("transfer-encoding")
                                && std::str::from_utf8(h.value)
                                    .map(|v| v.contains("chunked"))
                                    .unwrap_or(false)
                        });
                        if is_chunked {
                            // Look for final chunk marker
                            accumulated.ends_with(b"0\r\n\r\n")
                        } else {
                            // No length indicator - can't reliably determine completeness
                            // Forward as-is to avoid hanging
                            true
                        }
                    }
                };

                if body_complete {
                    // We have the complete response - redact it
                    // Safety: credential_name is Some based on check at line 1021
                    let Some(cred_name) = credential_name else {
                        unreachable!("credential_name was checked to be Some above");
                    };

                    // Clear signal for next request
                    {
                        let mut signal = redaction_signal.lock().await;
                        *signal = None;
                    }

                    let body = &accumulated[header_len..];
                    let redacted = redact_oauth_response(body, &cred_name, &state, conn_id).await;

                    match redacted {
                        Ok(new_body) => {
                            // Reconstruct response with new body
                            let mut response = Vec::new();

                            // Status line
                            response.extend_from_slice(b"HTTP/1.");
                            response.push(b'0' + resp.version.unwrap_or(1));
                            response.push(b' ');
                            response
                                .extend_from_slice(resp.code.unwrap_or(200).to_string().as_bytes());
                            response.push(b' ');
                            response.extend_from_slice(resp.reason.unwrap_or("OK").as_bytes());
                            response.extend_from_slice(b"\r\n");

                            // Headers (update Content-Length)
                            for header in resp.headers.iter() {
                                if header.name.is_empty() {
                                    continue;
                                }
                                if header.name.eq_ignore_ascii_case("content-length") {
                                    response.extend_from_slice(b"Content-Length: ");
                                    response
                                        .extend_from_slice(new_body.len().to_string().as_bytes());
                                    response.extend_from_slice(b"\r\n");
                                } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                                    // Skip chunked encoding - we're sending fixed length
                                    continue;
                                } else {
                                    response.extend_from_slice(header.name.as_bytes());
                                    response.extend_from_slice(b": ");
                                    response.extend_from_slice(header.value);
                                    response.extend_from_slice(b"\r\n");
                                }
                            }
                            response.extend_from_slice(b"\r\n");

                            // New body
                            response.extend_from_slice(&new_body);

                            tracing::debug!(
                                conn_id,
                                original_size = body.len(),
                                redacted_size = new_body.len(),
                                "oauth response redacted"
                            );

                            let mut client_writer = client_writer.lock().await;
                            client_writer.write_all(&response).await?;
                            client_writer.flush().await?;
                        }
                        Err(e) => {
                            tracing::warn!(
                                conn_id,
                                error = %e,
                                "failed to redact oauth response, forwarding as-is"
                            );
                            let mut client_writer = client_writer.lock().await;
                            client_writer.write_all(&accumulated).await?;
                            client_writer.flush().await?;
                        }
                    }

                    accumulated.clear();
                }
                // else: keep buffering until body is complete
            }
            Ok(httparse::Status::Partial) => {
                // Keep buffering
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "failed to parse response for redaction");
                // Clear signal and forward as-is
                {
                    let mut signal = redaction_signal.lock().await;
                    *signal = None;
                }
                let mut client_writer = client_writer.lock().await;
                client_writer.write_all(&accumulated).await?;
                accumulated.clear();
            }
        }
    }

    // Send any remaining buffered data
    if !accumulated.is_empty() {
        let mut client_writer = client_writer.lock().await;
        client_writer.write_all(&accumulated).await?;
    }

    // Record LLM metrics at stream end (unless already recorded for streaming)
    tracing::debug!(
        conn_id,
        has_llm_context = llm_context.is_some(),
        already_recorded = llm_metrics_recorded,
        "relay loop ended"
    );
    if let Some(ctx) = llm_context {
        let _had_accumulator = llm_accumulator.is_some();

        // For streaming responses, metrics may have already been recorded when complete
        // For non-streaming, we always record here
        let should_record = !llm_metrics_recorded;

        let metrics = if let Some(acc) = llm_accumulator {
            // Streaming response - finalize accumulator
            acc.finalize()
        } else if !llm_response_body.is_empty() {
            // Non-streaming response - parse the buffered body
            // May need to decompress gzip and decode chunked encoding
            let body = decode_response_body(&llm_response_body, llm_is_gzip == Some(true));
            crate::proxy::llm::parse_llm_response(&body, ctx.provider).unwrap_or_default()
        } else {
            crate::proxy::llm::LlmMetrics::default()
        };

        // Only record if not already recorded during streaming
        if should_record {
            // Record to Prometheus if registry available
            if let Some(ref registry) = state.metrics {
                registry.record_llm_usage(
                    &ctx.host,
                    &ctx.credential,
                    metrics.model.as_deref(),
                    metrics.input_tokens,
                    metrics.output_tokens,
                    metrics.cache_read_tokens,
                    &metrics.tool_calls,
                );
            }

            // Record to stats for file output (for local execution mode)
            state.stats.record_llm_metrics(
                metrics.model.as_deref(),
                metrics.input_tokens,
                metrics.output_tokens,
                metrics.cache_read_tokens,
                &metrics.tool_calls,
            );

            // Emit OpenTelemetry event for distributed tracing
            emit_llm_completion_span(&ctx, &metrics, conn_id);
        } else {
            tracing::debug!(
                conn_id,
                "skipping duplicate llm metrics recording (already recorded during stream)"
            );
        }

        // Clear signal for next request
        {
            let mut signal = llm_metrics_signal.lock().await;
            *signal = None;
        }
    }

    let mut client_writer = client_writer.lock().await;
    client_writer.shutdown().await?;
    Ok(())
}

/// Redact OAuth tokens from a JSON response body
///
/// Replaces access_token and refresh_token with dummy values,
/// caching the mapping for future request injection.
async fn redact_oauth_response(
    body: &[u8],
    credential_name: &str,
    state: &ProxyState,
    conn_id: u64,
) -> Result<Vec<u8>, String> {
    // Parse JSON
    let mut json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("failed to parse oauth response as json: {}", e))?;

    let mut redacted_count = 0;

    // Redact access_token
    if let Some(access_token) = json.get("access_token").and_then(|v| v.as_str()) {
        let dummy = generate_dummy_token("access");
        state
            .policy
            .cache_oauth_token(dummy.clone(), access_token.to_string())
            .await;
        json["access_token"] = serde_json::Value::String(dummy);
        redacted_count += 1;
        tracing::info!(
            conn_id,
            credential = credential_name,
            "redacted access_token in oauth response"
        );
    }

    // Redact refresh_token
    if let Some(refresh_token) = json.get("refresh_token").and_then(|v| v.as_str()) {
        let dummy = generate_dummy_token("refresh");
        state
            .policy
            .cache_oauth_token(dummy.clone(), refresh_token.to_string())
            .await;
        json["refresh_token"] = serde_json::Value::String(dummy);
        redacted_count += 1;
        tracing::info!(
            conn_id,
            credential = credential_name,
            "redacted refresh_token in oauth response"
        );
    }

    if redacted_count == 0 {
        tracing::debug!(
            conn_id,
            credential = credential_name,
            "no tokens found to redact in oauth response"
        );
    }

    serde_json::to_vec(&json).map_err(|e| format!("failed to serialize redacted json: {}", e))
}

/// Extract the token from a Bearer authorization header value
///
/// Given "Bearer sk-xxx" returns Some("sk-xxx")
/// Given "token sk-xxx" returns Some("sk-xxx")
fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    // Handle common formats: "Bearer TOKEN" or "token TOKEN"
    let auth_header = auth_header.trim();

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Some(token.trim())
    } else if let Some(token) = auth_header.strip_prefix("bearer ") {
        Some(token.trim())
    } else if let Some(token) = auth_header.strip_prefix("token ") {
        Some(token.trim())
    } else {
        // Unknown format - maybe just the token itself
        None
    }
}

/// Generate a dummy token that looks similar to a real OAuth token
fn generate_dummy_token(token_type: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    // Generate a random-looking suffix
    let random_part: u64 = timestamp as u64 ^ 0xDEADBEEF;

    format!(
        "REDACTED_{}_{:016x}_{:08x}",
        token_type.to_uppercase(),
        timestamp,
        random_part
    )
}

/// Handle plain HTTP request
///
/// For now, just return 501 Not Implemented.
/// We could forward these requests if needed in the future.
async fn handle_http(
    _req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(empty_body())
        .unwrap_or_else(|_| Response::new(empty_body())))
}

/// Create an empty HTTP body
fn empty_body() -> BoxBody {
    http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Decode HTTP response body, handling chunked transfer encoding and gzip compression
fn decode_response_body(raw_body: &[u8], is_gzip: bool) -> Vec<u8> {
    // First, try to decode chunked transfer encoding
    // Chunked format: <size_hex>\r\n<data>\r\n...<size_hex>\r\n<data>\r\n0\r\n\r\n
    let decoded_chunks = decode_chunked(raw_body).unwrap_or_else(|| raw_body.to_vec());

    // Then decompress gzip if needed
    if is_gzip {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(&decoded_chunks[..]);
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_ok() {
            decompressed
        } else {
            tracing::warn!("failed to decompress gzip response body");
            decoded_chunks
        }
    } else {
        decoded_chunks
    }
}

/// Decode chunked transfer encoding
/// Returns None if the body doesn't appear to be chunked
fn decode_chunked(raw: &[u8]) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < raw.len() {
        // Find the end of the size line (CRLF)
        let size_end = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p)?;

        // Parse the hex size
        let size_str = std::str::from_utf8(&raw[pos..size_end]).ok()?;
        let size_str = size_str.split(';').next()?; // Handle chunk extensions
        let chunk_size = usize::from_str_radix(size_str.trim(), 16).ok()?;

        // Move past the size line and CRLF
        pos = size_end + 2;

        // Size 0 means end of chunks
        if chunk_size == 0 {
            break;
        }

        // Extract chunk data
        if pos + chunk_size > raw.len() {
            return None; // Incomplete chunk
        }
        result.extend_from_slice(&raw[pos..pos + chunk_size]);

        // Move past chunk data and CRLF
        pos += chunk_size + 2;
    }

    if result.is_empty() {
        None // Doesn't look like valid chunked encoding
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        // Standard Bearer format
        assert_eq!(
            extract_bearer_token("Bearer sk-ant-abc123"),
            Some("sk-ant-abc123")
        );

        // Lowercase bearer
        assert_eq!(
            extract_bearer_token("bearer sk-ant-abc123"),
            Some("sk-ant-abc123")
        );

        // GitHub token format
        assert_eq!(extract_bearer_token("token ghp_xxxx"), Some("ghp_xxxx"));

        // With extra whitespace
        assert_eq!(
            extract_bearer_token("  Bearer   sk-ant-abc123  "),
            Some("sk-ant-abc123")
        );

        // Unknown format
        assert_eq!(extract_bearer_token("Basic dXNlcjpwYXNz"), None);

        // Just the token (no prefix)
        assert_eq!(extract_bearer_token("sk-ant-abc123"), None);
    }

    #[test]
    fn test_generate_dummy_token() {
        let token1 = generate_dummy_token("access");
        let token2 = generate_dummy_token("refresh");

        // Should have correct prefix
        assert!(token1.starts_with("REDACTED_ACCESS_"));
        assert!(token2.starts_with("REDACTED_REFRESH_"));

        // Should be different due to timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let token3 = generate_dummy_token("access");
        assert_ne!(token1, token3);
    }

    #[test]
    fn test_dummy_token_format() {
        let token = generate_dummy_token("test");

        // Should start with expected prefix
        assert!(token.starts_with("REDACTED_TEST_"));

        // Should be long enough to be unique
        assert!(token.len() > 30);

        // Should contain only valid characters
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }
}
