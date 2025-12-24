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
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio_rustls::TlsAcceptor;

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

use crate::proxy::policy::{CompiledPolicy, PolicyDecision};
use crate::proxy::stats::ProxyStats;

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
                return Ok(());
            }
            // Handle SIGINT (Ctrl+C)
            _ = sigint.recv() => {
                tracing::debug!("received sigint, shutting down proxy");
                return Ok(());
            }
            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, peer_addr) = accept_result?;
                let state = state.clone();

                // Spawn task to handle connection independently - no need to await
                drop(tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state, peer_addr.to_string()).await {
                        tracing::error!("connection error from {}: {}", peer_addr, e);
                    }
                }));
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
    drop(tokio::spawn(async move {
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
                    if err_str.contains("close_notify") || err_str.contains("Connection reset") {
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
    }));

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
#[tracing::instrument(
    level = "debug",
    skip(client_stream, cert_der, ca_cert_der, key_der, state, policy_decision)
)]
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

    // Configure TLS for upstream connection
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let upstream_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(upstream_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.clone())?;

    let upstream_tls = connector.connect(server_name, upstream_stream).await?;

    tracing::debug!("upstream connection established");

    // HTTP/1.1: Use stream-based bidirectional relay
    let (client_reader, client_writer) = tokio::io::split(client_tls);
    let (upstream_reader, upstream_writer) = tokio::io::split(upstream_tls);

    // Share client_writer between both tasks (for error responses and normal relay)
    use tokio::sync::Mutex;
    let client_writer = Arc::new(Mutex::new(client_writer));
    let client_writer_for_upstream = client_writer.clone();

    let hostname_clone = hostname.clone();
    let state_clone = state.clone();
    let policy_decision_clone = policy_decision;

    let client_to_upstream = async move {
        proxy_with_http1_inspection(
            client_reader,
            client_writer,
            upstream_writer,
            hostname_clone,
            state_clone,
            policy_decision_clone,
        )
        .await
    };

    let upstream_to_client = async move {
        // For now, just relay responses without inspection
        let mut buf = vec![0u8; 8192];
        let mut upstream_reader = upstream_reader;
        loop {
            let n = upstream_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            tracing::trace!("upstream -> client: {} bytes", n);
            let mut client_writer = client_writer_for_upstream.lock().await;
            client_writer.write_all(&buf[..n]).await?;
            client_writer.flush().await?;
        }
        let mut client_writer = client_writer_for_upstream.lock().await;
        client_writer.shutdown().await?;
        Ok::<(), BoxError>(())
    };

    // Run both directions concurrently
    tokio::try_join!(client_to_upstream, upstream_to_client)?;

    Ok(())
}

/// Proxy client to upstream with HTTP/1.1 request inspection and token injection
async fn proxy_with_http1_inspection<R, CW, UW>(
    mut reader: R,
    client_writer: Arc<tokio::sync::Mutex<CW>>,
    mut upstream_writer: UW,
    hostname: String,
    state: Arc<ProxyState>,
    policy_decision: Option<PolicyDecision>,
) -> Result<(), BoxError>
where
    R: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UW: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut accumulated = Vec::new();

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Accumulate data for parsing
        accumulated.extend_from_slice(&buf[..n]);

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

                        // Track approved request in statistics
                        state.stats.record_approved(&hostname);

                        // Log request with enhanced metadata
                        match (rule_index, credential_from_policy) {
                            (Some(idx), Some(cred)) => {
                                tracing::debug!(
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
                                    rule_index = idx,
                                    "{} {}{}",
                                    method,
                                    hostname,
                                    path
                                );
                            }
                            (None, Some(cred)) => {
                                tracing::debug!(
                                    credential = cred,
                                    "{} {}{}",
                                    method,
                                    hostname,
                                    path
                                );
                            }
                            (None, None) => {
                                tracing::debug!("{} {}{}", method, hostname, path);
                            }
                        }

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

                                    // Format header value using credential's header_format
                                    let header_value =
                                        credential.header_format.replace("{token}", &token);

                                    // Build new headers list
                                    let mut new_headers = Vec::new();

                                    // Determine the expected dummy for comparison
                                    let expected_dummy =
                                        credential.dummy_token.as_ref().map(|token| {
                                            credential.header_format.replace("{token}", token)
                                        });

                                    // Copy all existing headers, skipping ALL Authorization headers
                                    // (we'll inject the correct one below)
                                    for header in req.headers.iter() {
                                        let header_value_str =
                                            std::str::from_utf8(header.value).unwrap_or("");

                                        // Skip ALL Authorization headers - we're injecting the correct one
                                        if header.name.eq_ignore_ascii_case("authorization") {
                                            if let Some(ref dummy) = expected_dummy {
                                                if header_value_str == dummy {
                                                    tracing::debug!("removing dummy authorization header (matches expected dummy)");
                                                } else {
                                                    tracing::warn!(
                                                        actual = %header_value_str,
                                                        expected = %dummy,
                                                        "removing authorization header that does not match configured dummy"
                                                    );
                                                }
                                            } else {
                                                tracing::debug!("removing authorization header (no dummy configured)");
                                            }
                                            continue;
                                        }

                                        new_headers.push((header.name, header_value_str));
                                    }

                                    // Add the authorization header
                                    new_headers.push(("Authorization", header_value.as_str()));

                                    tracing::debug!(
                                        "injected authorization header for {} {}",
                                        method,
                                        path
                                    );

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

                                    // Body (everything after the headers)
                                    reconstructed.extend_from_slice(&accumulated[bytes_parsed..]);

                                    // Write the reconstructed request to upstream
                                    upstream_writer.write_all(&reconstructed).await?;

                                    // Clear accumulated buffer since we've processed everything
                                    accumulated.clear();
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "failed to fetch token for {}: {}",
                                        credential_name,
                                        e
                                    );
                                    // Forward request without modification on error
                                    upstream_writer
                                        .write_all(&accumulated[..bytes_parsed])
                                        .await?;
                                    let _ = accumulated.drain(..bytes_parsed);
                                }
                            }
                        } else {
                            // No credential injection - just forward the raw bytes
                            upstream_writer
                                .write_all(&accumulated[..bytes_parsed])
                                .await?;
                            let _ = accumulated.drain(..bytes_parsed);
                        }
                    } else {
                        // Failed to parse completely - forward as-is
                        upstream_writer
                            .write_all(&accumulated[..bytes_parsed])
                            .await?;
                        let _ = accumulated.drain(..bytes_parsed);
                    }
                }
                Ok(httparse::Status::Partial) => {
                    // Need more data to complete parsing
                    break;
                }
                Err(e) => {
                    // Parse error - log and forward raw data
                    tracing::debug!("http/1.1 parse error for {}: {}", hostname, e);
                    // Forward the data we couldn't parse
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
