use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{
    fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

pub mod cache;
pub mod config;
pub mod executor;
pub mod hashbang;
pub mod job_dir;
pub mod job_registry;
pub mod job_workspace;
pub mod log_sink;
pub mod networkpolicy;
pub mod orchestration;
pub mod proxy;
pub mod proxy_manager;
pub mod root;
pub mod service;
pub mod session;
pub mod storage;
pub mod streaming;
pub mod validation;
pub mod workspace;

pub mod jail {
    tonic::include_proto!("jail");
}

pub use jail::jail_service_server::JailServiceServer;
pub use service::JailServiceImpl;

/// Guard that ensures OpenTelemetry spans are flushed on shutdown.
/// Drop this guard when the application exits to ensure all traces are exported.
#[derive(Debug)]
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Force flush any pending spans before shutdown
            // This is important for short-lived processes like the client
            let _ = provider.force_flush();
            let _ = provider.shutdown();
        }
    }
}

/// Initialize tracing with compact formatter and optional OpenTelemetry export.
///
/// # Arguments
/// * `service_name` - Service name for OpenTelemetry (e.g., "nix-jail-server")
/// * `default_filter` - Default filter level (e.g., "info", "nix_jail=debug")
/// * `use_stderr` - If true, log to stderr instead of stdout (useful for clients that output to stdout)
/// * `otlp_endpoint` - Optional OTLP endpoint for distributed tracing (e.g., "http://localhost:4317")
///
/// # Returns
/// A guard that must be kept alive for the duration of the program.
/// Dropping the guard will flush pending traces.
///
/// # Panics
/// Panics if tracing has already been initialized
pub fn init_tracing(
    service_name: &str,
    default_filter: &str,
    use_stderr: bool,
    otlp_endpoint: Option<&str>,
) -> TracingGuard {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    // Use provided endpoint or fall back to environment variable
    let otlp_endpoint: Option<String> = otlp_endpoint
        .map(String::from)
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    // Try to initialize OpenTelemetry if endpoint is configured
    let (provider, otel_init_error) = if let Some(endpoint) = &otlp_endpoint {
        match init_otlp_tracer(service_name, endpoint) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e.to_string())),
        }
    } else {
        (None, None)
    };

    // Build the subscriber - create otel layer inside each branch to satisfy type system
    if use_stderr {
        let fmt_layer = fmt::layer()
            .compact()
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(std::io::stderr);

        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        let fmt_layer = fmt::layer().compact().with_span_events(FmtSpan::CLOSE);

        let otel_layer = provider.as_ref().map(|p| {
            tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_string()))
        });

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    }

    // Log OTel status now that tracing is initialized
    if let Some(error) = otel_init_error {
        tracing::warn!(error = %error, "failed to initialize opentelemetry, using console only");
    } else if let Some(endpoint) = otlp_endpoint {
        if provider.is_some() {
            tracing::info!(endpoint = %endpoint, "opentelemetry export enabled");
        }
    }

    TracingGuard { provider }
}

fn init_otlp_tracer(
    service_name: &str,
    endpoint: &str,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder_empty()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    Ok(provider)
}

/// Create a new JailServiceServer with the given database path and config
pub fn service(
    db_path: impl AsRef<std::path::Path>,
    config: config::ServerConfig,
    session_registry: std::sync::Arc<session::SessionRegistry>,
) -> Result<JailServiceServer<JailServiceImpl>, storage::StorageError> {
    let path_str = db_path.as_ref().to_str().ok_or_else(|| {
        storage::StorageError::InvalidPath("Database path contains invalid UTF-8".to_string())
    })?;
    let storage = storage::JobStorage::new(path_str)?;

    // Recover any orphaned jobs from previous server instances
    // (jobs left in "running" state when the server crashed/was killed)
    let recovered_count = storage.recover_orphaned_jobs()?;
    if recovered_count > 0 {
        tracing::info!(
            count = recovered_count,
            "recovered orphaned jobs from previous server instance"
        );
    }

    // Initialize cache manager for closure caching
    let cache_dir = config.cache_dir();
    let cache_manager = cache::CacheManager::new(cache_dir, storage.clone()).map_err(|e| {
        storage::StorageError::InvalidPath(format!("failed to initialize cache manager: {}", e))
    })?;

    // Create job root based on configured strategy
    let job_root = root::get_job_root(config.store_strategy, cache_manager.clone());
    tracing::info!(strategy = ?job_root, "initialized job root");

    // Create job workspace based on cache availability
    let job_workspace = job_workspace::get_job_workspace(Some(cache_manager.clone()));
    tracing::info!(strategy = ?job_workspace, "initialized job workspace");

    let registry = job_registry::JobRegistry::new();
    Ok(JailServiceServer::new(JailServiceImpl::new(
        storage,
        config,
        registry,
        cache_manager,
        job_root,
        job_workspace,
        session_registry,
    )))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ulid_generation() {
        use ulid::Ulid;

        let job_id = Ulid::new().to_string();

        // ULID should be exactly 26 characters
        assert_eq!(job_id.len(), 26);

        // ULID should only contain Base32 characters (A-Z, 0-9)
        assert!(job_id
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_ulid_uniqueness() {
        use ulid::Ulid;

        // Generate multiple ULIDs and verify they're unique
        let id1 = Ulid::new().to_string();
        let id2 = Ulid::new().to_string();
        let id3 = Ulid::new().to_string();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_ulid_sortability() {
        use ulid::Ulid;

        // ULIDs generated later should sort after earlier ones
        let id1 = Ulid::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = Ulid::new();

        assert!(id2 > id1, "Later ULID should be greater than earlier one");
    }
}
