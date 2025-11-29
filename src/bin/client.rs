use clap::{Parser, Subcommand};
use nix_jail::config::ClientConfig;
use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::{
    GcRequest, HostPattern, IpPattern, JobRequest, LogSource, NetworkAction, NetworkPattern,
    NetworkPolicy, NetworkRule, StreamRequest,
};
use nix_jail::networkpolicy::ClientNetworkPolicy;
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
    let first_line = script.lines().next()?;
    if !first_line.starts_with("#!") {
        return None;
    }

    let shebang = first_line.trim_start_matches("#!").trim();
    let binary = if shebang.contains("/env ") || shebang.contains("/env\t") {
        // Handle "#!/usr/bin/env bash" or "#!/usr/bin/env python3"
        shebang.split_whitespace().last()?
    } else {
        // Handle "#!/bin/bash" or "#!/usr/bin/python3"
        shebang.split('/').next_back()?.split_whitespace().next()?
    };

    // Only allow specific interpreters
    match binary {
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
