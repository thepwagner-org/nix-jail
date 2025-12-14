use std::sync::Arc;

use clap::{Parser, Subcommand};
use nix_jail::config::ClientConfig;
use nix_jail::executor::HardeningProfile;
use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::{
    GcRequest, HostPattern, IpPattern, JobRequest, LogSource, NetworkAction, NetworkPattern,
    NetworkPolicy, NetworkRule, StreamRequest,
};
use nix_jail::log_sink::StdioLogSink;
use nix_jail::networkpolicy::ClientNetworkPolicy;
use nix_jail::orchestration::{execute_local, LocalExecutionConfig};
use tonic::Request;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Inject OpenTelemetry trace context into a tonic request
fn inject_trace_context<T>(mut request: Request<T>) -> Request<T> {
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    let context = tracing::Span::current().context();
    let propagator = TraceContextPropagator::new();

    let mut injector = MetadataInjector(request.metadata_mut());
    propagator.inject_context(&context, &mut injector);

    request
}

/// Helper to inject trace context into tonic metadata
struct MetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);

impl opentelemetry::propagation::Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = value.parse() {
                let _ = self.0.insert(key, val);
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "nix-jail", version)]
#[command(about = "A secure jail for Nix derivations", long_about = None)]
struct Cli {
    /// Server address to connect to
    #[arg(short, long)]
    server: Option<String>,

    /// OpenTelemetry OTLP endpoint for distributed tracing (e.g., "http://localhost:4317")
    #[arg(long)]
    otlp_endpoint: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
struct OutputOptions {
    /// Only show job output (hide proxy logs)
    #[arg(long)]
    job_only: bool,

    /// Only show proxy output (hide job logs)
    #[arg(long)]
    proxy_only: bool,

    /// Don't add source prefixes (useful for piping)
    #[arg(long)]
    no_prefix: bool,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Execute a script with specified Nix packages
    Exec {
        /// Nix packages to make available (can be specified multiple times)
        #[arg(short, long)]
        package: Vec<String>,

        /// Path to script file to execute
        #[arg(short, long)]
        script: std::path::PathBuf,

        /// Path to network policy JSON file
        #[arg(long)]
        policy: Option<std::path::PathBuf>,

        /// Allow access to specific hosts (can be specified multiple times)
        #[arg(long)]
        allow_host: Vec<String>,

        /// Allow access to specific CIDR ranges (can be specified multiple times)
        #[arg(long)]
        allow_cidr: Vec<String>,

        /// Git repository URL (optional, for git workspace mode)
        #[arg(long)]
        repo: Option<String>,

        /// Path within repository (optional, defaults to ".")
        #[arg(long)]
        path: Option<String>,

        /// Git ref to checkout: branch, tag, or commit SHA (optional, uses default branch if omitted)
        #[arg(long, alias = "ref")]
        git_ref: Option<String>,

        /// Nixpkgs version to use for package resolution
        ///
        /// Supported formats:
        ///   - "nixos-24.05"                    - release branch (hash auto-discovered)
        ///   - "nixos-24.05#sha256:abc..."      - release with explicit hash
        ///   - "nixos-unstable"                 - unstable branch
        ///   - "ae2fc9e0...f068c1bfdc11c71"     - 40-char commit SHA
        #[arg(long, alias = "nixpkgs", default_value = "nixos-25.05")]
        nixpkgs_version: String,

        /// Hardening profile for systemd execution (Linux only)
        ///
        /// If omitted, defaults to "default" (maximum security).
        ///
        /// Supported profiles:
        ///   - "default"     - All 33 hardening properties (blocks JIT compilation)
        ///   - "jit-runtime" - 32 hardening properties (allows JIT for Node.js, Python, etc.)
        ///
        /// SECURITY WARNING: The jit-runtime profile removes MemoryDenyWriteExecute=true
        /// to allow JIT compilation. Use only when running JIT-based runtimes.
        #[arg(long)]
        hardening_profile: Option<String>,

        /// Enable automatic pull request creation for git repositories
        /// After successful execution, commits will be pushed to a new branch (job-${jobID})
        /// and a pull request will be created to the original branch.
        /// Requires: --repo to be set and GitHub credential in server config
        #[arg(long)]
        push: bool,

        #[command(flatten)]
        output: OutputOptions,
    },
    /// Attach to an existing job and stream its output
    Attach {
        /// Job ID to attach to
        job_id: String,

        /// Number of historical log lines to show before live streaming
        /// If omitted, only shows live output from "now"
        #[arg(long)]
        tail: Option<u32>,

        #[command(flatten)]
        output: OutputOptions,
    },
    /// Attach to an interactive job via WebSocket TTY
    AttachInteractive {
        /// WebSocket URL for the interactive session
        /// Format: ws://host:port/session/{job_id}?token={token}
        websocket_url: String,
    },
    /// List jobs with optional filtering
    List {
        /// Filter by job status (Running, Completed, Failed, Pending)
        #[arg(long)]
        status: Option<String>,

        /// Maximum number of jobs to return
        #[arg(long, default_value = "50")]
        limit: u32,

        /// Number of jobs to skip for pagination
        #[arg(long, default_value = "0")]
        offset: u32,

        /// Output as JSON instead of table format
        #[arg(long)]
        json: bool,
    },
    /// Run garbage collection to clear the cache
    Gc,

    /// Execute a command locally without a server (serverless mode)
    Run {
        /// Nix packages to make available (can be specified multiple times)
        #[arg(short, long)]
        package: Vec<String>,

        /// Path to network policy TOML file
        #[arg(long)]
        policy: Option<std::path::PathBuf>,

        /// Allow access to specific hosts (can be specified multiple times)
        #[arg(long)]
        allow_host: Vec<String>,

        /// Allow access to specific CIDR ranges (can be specified multiple times)
        #[arg(long)]
        allow_cidr: Vec<String>,

        /// Working directory (defaults to current directory)
        #[arg(long)]
        workdir: Option<std::path::PathBuf>,

        /// Nixpkgs version to use for package resolution
        #[arg(long, alias = "nixpkgs", default_value = "nixos-25.05")]
        nixpkgs_version: String,

        /// Hardening profile for systemd execution (Linux only)
        #[arg(long)]
        hardening_profile: Option<String>,

        /// Path to config file (same format as server config)
        #[arg(long)]
        config: Option<std::path::PathBuf>,

        /// Show output prefixes for log sources
        #[arg(long)]
        show_prefix: bool,

        /// Command to execute (everything after --)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let _tracing_guard = nix_jail::init_tracing(
        "nix-jail-client",
        "info",
        true,
        cli.otlp_endpoint.as_deref(),
    );
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Handle Run command separately (doesn't need server connection)
    if let Commands::Run {
        package,
        policy,
        allow_host,
        allow_cidr,
        workdir,
        nixpkgs_version,
        hardening_profile,
        config,
        show_prefix,
        command,
    } = cli.command
    {
        let exit_code = run_local(
            package,
            policy,
            allow_host,
            allow_cidr,
            workdir,
            nixpkgs_version,
            hardening_profile,
            config,
            show_prefix,
            command,
        )
        .await?;
        std::process::exit(exit_code);
    }

    let server = cli
        .server
        .unwrap_or_else(|| ClientConfig::default().server_url);

    // Create root span that encompasses the entire client operation
    let root_span = tracing::info_span!("client", server = %server);
    let _root_guard = root_span.enter();

    let mut client = {
        let _span = tracing::info_span!("connect").entered();
        JailServiceClient::connect(server).await?
    };

    match cli.command {
        Commands::Exec {
            package,
            script,
            policy,
            allow_host,
            allow_cidr,
            repo,
            path,
            git_ref,
            nixpkgs_version,
            hardening_profile,
            push,
            output,
        } => {
            exec_job(
                &mut client,
                package,
                script,
                policy,
                allow_host,
                allow_cidr,
                repo,
                path,
                git_ref,
                nixpkgs_version,
                hardening_profile,
                push,
                output,
            )
            .await?;
        }
        Commands::Attach {
            job_id,
            tail,
            output,
        } => {
            attach_job(&mut client, job_id, tail, output).await?;
        }
        Commands::AttachInteractive { websocket_url } => {
            attach_interactive(websocket_url).await?;
        }
        Commands::List {
            status,
            limit,
            offset,
            json,
        } => {
            list_jobs(&mut client, status, limit, offset, json).await?;
        }
        Commands::Gc => {
            gc_cache(&mut client).await?;
        }
        Commands::Run { .. } => unreachable!(), // Handled above
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(client, output, script_path, policy_path, allow_hosts, allow_cidrs, path, hardening_profile), fields(packages = ?packages, repo = ?repo))]
async fn exec_job(
    client: &mut JailServiceClient<tonic::transport::Channel>,
    mut packages: Vec<String>,
    script_path: std::path::PathBuf,
    policy_path: Option<std::path::PathBuf>,
    allow_hosts: Vec<String>,
    allow_cidrs: Vec<String>,
    repo: Option<String>,
    path: Option<String>,
    git_ref: Option<String>,
    nixpkgs_version: String,
    hardening_profile: Option<String>,
    push: bool,
    output: OutputOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        nixpkgs_version = %nixpkgs_version,
        "executing job"
    );

    let script = std::fs::read_to_string(&script_path).map_err(|e| {
        format!(
            "Failed to read script file {}: {}",
            script_path.display(),
            e
        )
    })?;

    // Auto-detect interpreter from hashbang
    if let Some(interpreter) = detect_hashbang(&script) {
        if !packages.contains(&interpreter) {
            tracing::info!(
                "auto-detected interpreter '{}' from hashbang, adding to packages",
                interpreter
            );
            packages.push(interpreter);
        }
    }

    let mut network_policy = if let Some(ref path) = policy_path {
        let policy_toml = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
        let policy_file: ClientNetworkPolicy = toml::from_str(&policy_toml)
            .map_err(|e| format!("Failed to parse policy TOML: {}", e))?;
        let policy = policy_file.to_proto();
        tracing::info!(
            "loaded network policy from {} with {} rules",
            path.display(),
            policy.rules.len()
        );
        Some(policy)
    } else {
        None
    };

    // Apply CLI overrides for allowed hosts/CIDRs
    if !allow_hosts.is_empty() || !allow_cidrs.is_empty() {
        let mut rules = vec![];

        for host in allow_hosts {
            rules.push(NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(nix_jail::jail::network_pattern::Pattern::Host(
                        HostPattern {
                            host: host.clone(),
                            path: None,
                        },
                    )),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            });
            tracing::info!("added allow rule for host: {}", host);
        }

        for cidr in allow_cidrs {
            rules.push(NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(nix_jail::jail::network_pattern::Pattern::Ip(IpPattern {
                        cidr: cidr.clone(),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            });
            tracing::info!("added allow rule for CIDR: {}", cidr);
        }

        // If policy exists, prepend CLI rules (they take precedence)
        // If no policy, create a new one with just the CLI rules
        network_policy = Some(if let Some(mut policy) = network_policy {
            rules.append(&mut policy.rules);
            NetworkPolicy { rules }
        } else {
            NetworkPolicy { rules }
        });
    }

    let request = Request::new(JobRequest {
        packages,
        script,
        repo: repo.unwrap_or_default(),
        path: path.unwrap_or_default(),
        git_ref,
        network_policy,
        nixpkgs_version: Some(nixpkgs_version),
        hardening_profile,
        push: Some(push),
        interactive: None, // Not interactive for exec mode
    });

    let job_id = {
        let _span = tracing::info_span!("submit_job").entered();
        let response = client.submit_job(inject_trace_context(request)).await?;
        let job_id = response.into_inner().job_id;
        tracing::info!(job_id = %job_id, "job submitted");
        job_id
    };

    // Immediately start streaming the job output (no tail, just live from beginning)
    stream_job_output(client, &job_id, None, output).await
}

/// Detect hashbang from script content and return interpreter_name
/// Only supports: sh, bash, python3
fn detect_hashbang(script: &str) -> Option<String> {
    let interpreter = nix_jail::hashbang::detect_interpreter(script)?;

    // Only allow specific interpreters
    match interpreter.as_str() {
        "sh" | "bash" => Some("bash".to_string()),
        "python3" => Some("python3".to_string()),
        _ => None,
    }
}

#[tracing::instrument(skip(client, output), fields(job_id = %job_id))]
async fn attach_job(
    client: &mut JailServiceClient<tonic::transport::Channel>,
    job_id: String,
    tail: Option<u32>,
    output: OutputOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    // Trim "job_id=" prefix if present (convenience for copy-paste from logs)
    let job_id = job_id
        .strip_prefix("job_id=")
        .unwrap_or(&job_id)
        .to_string();

    tracing::info!(tail = ?tail, "attaching to job");
    stream_job_output(client, &job_id, tail, output).await
}

#[allow(clippy::print_stdout)] // Intentional: user-facing output to terminal
async fn list_jobs(
    client: &mut JailServiceClient<tonic::transport::Channel>,
    status: Option<String>,
    limit: u32,
    offset: u32,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use nix_jail::jail::ListJobsRequest;
    use nu_ansi_term::Color;
    use std::io::IsTerminal;

    let request = Request::new(ListJobsRequest {
        status,
        limit: Some(limit),
        offset: Some(offset),
    });

    let response = client
        .list_jobs(inject_trace_context(request))
        .await?
        .into_inner();

    if json {
        // JSON output
        let json_output = serde_json::to_string_pretty(&response)?;
        println!("{}", json_output);
    } else {
        // Table output
        if response.jobs.is_empty() {
            println!("No jobs found");
            return Ok(());
        }

        // Detect if we should use colors (TTY + no NO_COLOR env var)
        let use_color = std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err();

        // Print header
        let header = format!(
            "{:<26} {:<10} {:<19} {:<10} {:<30}",
            "JOB ID", "STATUS", "CREATED", "RUNTIME", "REPO"
        );
        println!(
            "{}",
            if use_color {
                Color::White.bold().paint(header).to_string()
            } else {
                header
            }
        );
        let separator = "-".repeat(100);
        println!(
            "{}",
            if use_color {
                Color::DarkGray.paint(separator).to_string()
            } else {
                separator
            }
        );

        // Print each job
        for job in &response.jobs {
            let created = job
                .created_at
                .as_ref()
                .map(|t| {
                    use chrono::{DateTime, Local, TimeZone, Utc};
                    let secs = t.seconds;
                    let utc = Utc.timestamp_opt(secs, 0).unwrap();
                    let local: DateTime<Local> = utc.into();
                    local.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let runtime = format_duration(job.runtime_seconds);

            let repo = job
                .repo
                .as_ref()
                .map(|r| {
                    // Strip https://github.com/ prefix if present
                    let stripped = r.strip_prefix("https://github.com/").unwrap_or(r);

                    if stripped.len() > 28 {
                        format!("{}...", &stripped[..25])
                    } else {
                        stripped.to_string()
                    }
                })
                .unwrap_or_else(String::new);

            // Format each field with proper width, then apply colors
            // This ensures ANSI codes don't mess up column alignment
            let job_id_formatted = format!("{:<26}", job.job_id);
            let status_formatted = format!("{:<10}", job.status);
            let created_formatted = format!("{:<19}", created);
            let runtime_formatted = format!("{:<10}", runtime);
            let repo_formatted = format!("{:<30}", repo);

            if use_color {
                let job_id_colored = Color::DarkGray.paint(job_id_formatted);
                let status_colored = match job.status.as_str() {
                    "completed" => Color::Green.paint(status_formatted),
                    "running" => Color::Yellow.paint(status_formatted),
                    "failed" => Color::Red.paint(status_formatted),
                    _ => Color::White.paint(status_formatted),
                };
                println!(
                    "{} {} {} {} {}",
                    job_id_colored,
                    status_colored,
                    created_formatted,
                    runtime_formatted,
                    repo_formatted
                );
            } else {
                println!(
                    "{} {} {} {} {}",
                    job_id_formatted,
                    status_formatted,
                    created_formatted,
                    runtime_formatted,
                    repo_formatted
                );
            }
        }

        // Print summary
        println!();
        println!(
            "Showing {} jobs (total: {})",
            response.jobs.len(),
            response.total_count
        );
    }

    Ok(())
}

#[allow(clippy::print_stdout)] // Intentional: user-facing output to terminal
async fn gc_cache(
    client: &mut JailServiceClient<tonic::transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("running garbage collection");

    let request = Request::new(GcRequest {});
    let response = client.gc(inject_trace_context(request)).await?.into_inner();

    println!(
        "Cleared {} cache entries ({} bytes freed)",
        response.deleted_count, response.bytes_freed
    );

    Ok(())
}

/// Execute a command locally without a server
#[allow(clippy::too_many_arguments)]
async fn run_local(
    packages: Vec<String>,
    policy_path: Option<std::path::PathBuf>,
    allow_hosts: Vec<String>,
    allow_cidrs: Vec<String>,
    workdir: Option<std::path::PathBuf>,
    nixpkgs_version: String,
    hardening_profile: Option<String>,
    config_path: Option<std::path::PathBuf>,
    show_prefix: bool,
    command: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    tracing::info!(packages = ?packages, "running locally");

    // Determine working directory
    let working_dir = match workdir {
        Some(dir) => dir.canonicalize()?,
        None => std::env::current_dir()?,
    };

    // Load network policy if provided
    let mut network_policy = if let Some(ref path) = policy_path {
        let policy_toml = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
        let policy_file: ClientNetworkPolicy = toml::from_str(&policy_toml)
            .map_err(|e| format!("Failed to parse policy TOML: {}", e))?;
        tracing::info!(
            "loaded network policy from {} with {} rules",
            path.display(),
            policy_file.rules.len()
        );
        Some(policy_file.to_proto())
    } else {
        None
    };

    // Apply CLI overrides for allowed hosts/CIDRs
    if !allow_hosts.is_empty() || !allow_cidrs.is_empty() {
        let mut rules = vec![];

        for host in allow_hosts {
            rules.push(NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(nix_jail::jail::network_pattern::Pattern::Host(
                        HostPattern { host, path: None },
                    )),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            });
        }

        for cidr in allow_cidrs {
            rules.push(NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(nix_jail::jail::network_pattern::Pattern::Ip(IpPattern {
                        cidr,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            });
        }

        // Merge with existing policy or create new
        if let Some(ref mut policy) = network_policy {
            policy.rules.extend(rules);
        } else {
            network_policy = Some(NetworkPolicy { rules });
        }
    }

    // Parse hardening profile
    let profile = match hardening_profile.as_deref() {
        Some(s) => s.parse::<HardeningProfile>()?,
        None => HardeningProfile::Default,
    };

    // Load credentials from config file if provided
    let credentials = if let Some(ref path) = config_path {
        let config = nix_jail::config::ServerConfig::from_toml_file(path)?;
        config.credentials
    } else {
        vec![]
    };

    // Determine state directory
    let state_dir = std::env::temp_dir().join("nix-jail-local");
    std::fs::create_dir_all(&state_dir)?;

    // Create log sink
    let log_sink = Arc::new(StdioLogSink::new(show_prefix));

    // Build execution config
    let exec_config = LocalExecutionConfig {
        packages,
        command,
        working_dir,
        network_policy,
        credentials,
        hardening_profile: profile,
        state_dir,
        nixpkgs_version: Some(nixpkgs_version),
    };

    // Execute
    let exit_code = execute_local(exec_config, log_sink).await?;

    Ok(exit_code)
}

/// Format duration in seconds to human-readable format
fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        format!("{}m {}s", mins, secs)
    } else {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

#[allow(clippy::print_stdout)] // Intentional: user-facing output to terminal
#[tracing::instrument(skip(client, output))]
async fn stream_job_output(
    client: &mut JailServiceClient<tonic::transport::Channel>,
    job_id: &str,
    tail: Option<u32>,
    output: OutputOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = Request::new(StreamRequest {
        job_id: job_id.to_string(),
        tail_lines: tail,
    });

    let mut stream = client
        .stream_job(inject_trace_context(request))
        .await?
        .into_inner();

    while let Some(entry) = stream.message().await? {
        let source = LogSource::try_from(entry.source).unwrap_or(LogSource::Unspecified);

        // Apply filtering
        let is_job = matches!(source, LogSource::JobStdout | LogSource::JobStderr);
        let is_proxy = matches!(source, LogSource::ProxyStdout | LogSource::ProxyStderr);

        if output.job_only && !is_job {
            continue;
        }
        if output.proxy_only && !is_proxy {
            continue;
        }

        // Format output with prefix if requested
        if output.no_prefix {
            print!("{}", entry.content);
        } else {
            const GUTTER_WIDTH: usize = 6; // "proxy" (5 chars) + 1 space
            let source_name = match source {
                LogSource::JobStdout => "job",
                LogSource::JobStderr => "job",
                LogSource::ProxyStdout => "proxy",
                LogSource::ProxyStderr => "proxy",
                LogSource::System => "sys",
                LogSource::Unspecified => "",
            };
            let prefix = format!("{:>width$} | ", source_name, width = GUTTER_WIDTH);

            // Print each line with prefix
            for line in entry.content.lines() {
                println!("{}{}", prefix, line);
            }
        }
    }

    tracing::info!(job_id = %job_id, "job finished streaming");

    Ok(())
}

/// Attach to an interactive job via WebSocket
#[tracing::instrument(skip(websocket_url), fields(url = %websocket_url))]
async fn attach_interactive(websocket_url: String) -> Result<(), Box<dyn std::error::Error>> {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    tracing::info!("connecting to interactive session");

    // Connect to WebSocket
    let (ws_stream, _) = connect_async(&websocket_url).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Extract job_id and token from URL
    let url_parts: Vec<&str> = websocket_url.split('/').collect();
    let session_part = url_parts
        .last()
        .ok_or("invalid websocket url")?
        .split('?')
        .collect::<Vec<&str>>();
    let job_id = session_part.first().ok_or("missing job_id")?;
    let token = session_part
        .get(1)
        .and_then(|s| s.strip_prefix("token="))
        .ok_or("missing token")?;

    // Send authentication
    let auth_msg = serde_json::json!({
        "job_id": job_id,
        "token": token,
    });
    ws_sender.send(Message::Text(auth_msg.to_string())).await?;

    // Wait for auth response
    let auth_response = ws_receiver.next().await.ok_or("connection closed")??;
    match auth_response {
        Message::Text(text) => {
            let response: serde_json::Value = serde_json::from_str(&text)?;
            if response.get("error").is_some() {
                return Err(format!("authentication failed: {}", text).into());
            }
            tracing::info!("authenticated successfully");
        }
        _ => return Err("unexpected auth response".into()),
    }

    // Put terminal in raw mode
    let _raw_guard = enable_raw_mode()?;

    // Spawn task to read from stdin and send to WebSocket
    let stdin_handle = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 1024];

        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if ws_sender
                        .send(Message::Binary(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "stdin read error");
                    break;
                }
            }
        }
    });

    // Read from WebSocket and write to stdout
    let mut stdout = tokio::io::stdout();
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Binary(data)) => {
                stdout.write_all(&data).await?;
                stdout.flush().await?;
            }
            Ok(Message::Close(_)) => {
                tracing::info!("server closed connection");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "websocket error");
                break;
            }
        }
    }

    // Clean up
    stdin_handle.abort();

    Ok(())
}

/// Enable raw mode for terminal (disable line buffering and echo)
fn enable_raw_mode() -> Result<RawModeGuard, Box<dyn std::error::Error>> {
    use std::io::stdin;

    // Get current terminal attributes
    let original_termios = nix::sys::termios::tcgetattr(stdin())?;

    // Create new termios with raw mode settings
    let mut raw_termios = original_termios.clone();
    nix::sys::termios::cfmakeraw(&mut raw_termios);

    // Apply raw mode
    nix::sys::termios::tcsetattr(stdin(), nix::sys::termios::SetArg::TCSANOW, &raw_termios)?;

    Ok(RawModeGuard { original_termios })
}

/// Guard that restores terminal mode on drop
struct RawModeGuard {
    original_termios: nix::sys::termios::Termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        use std::io::stdin;
        // Restore original terminal settings
        let _ = nix::sys::termios::tcsetattr(
            stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            &self.original_termios,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hashbang() {
        // Supported interpreters (sh maps to bash since no sh package in nix)
        assert_eq!(detect_hashbang("#!/bin/bash\n"), Some("bash".to_string()));
        assert_eq!(
            detect_hashbang("#!/usr/bin/env sh\n"),
            Some("bash".to_string())
        );
        assert_eq!(
            detect_hashbang("#!/usr/bin/python3 -u\n"),
            Some("python3".to_string())
        );

        // Unsupported interpreters
        assert_eq!(detect_hashbang("#!/usr/bin/ruby\n"), None);
        assert_eq!(detect_hashbang("#!/usr/bin/env node\n"), None);

        // No hashbang
        assert_eq!(detect_hashbang("echo hello"), None);
    }
}
