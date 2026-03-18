//! REST API handlers for job management.
//!
//! Endpoints:
//! - `GET  /api/jobs`           — list all jobs as JSON
//! - `POST /api/jobs`           — submit a new job
//! - `DELETE /api/jobs/{id}`    — cancel a running job
//! - `POST /api/jobs/{id}/retry`— re-submit a job with its original parameters

use crate::util::{error_response, full_body, json_error, BoxedBody};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::{
    CancelJobRequest, HostPattern, JobRequest, ListJobsRequest, ListJobsResponse, NetworkAction,
    NetworkPattern, NetworkPolicy, NetworkRule,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// GET /api/jobs
// ---------------------------------------------------------------------------

pub async fn api_list_jobs(daemon: &str) -> Result<Response<BoxedBody>, Infallible> {
    match fetch_jobs_json(daemon).await {
        Ok(body) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(full_body(format!(r#"{{"jobs":{body}}}"#)))
            .unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
            })),
        Err(e) => {
            error!(error = %e, "api list_jobs failed");
            Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "failed to query daemon",
            ))
        }
    }
}

/// Fetch all jobs and return them as a JSON array string (serialised manually
/// to avoid pulling in a derive macro for a one-off proto → JSON mapping).
pub async fn fetch_jobs_json(daemon: &str) -> anyhow::Result<String> {
    let mut client = JailServiceClient::connect(daemon.to_string()).await?;
    let resp = client
        .list_jobs(ListJobsRequest {
            status: None,
            limit: Some(50),
            offset: None,
        })
        .await?
        .into_inner();

    let items: Vec<String> = resp
        .jobs
        .iter()
        .map(|j| {
            let created_at = j
                .created_at
                .as_ref()
                .map(|t| t.seconds)
                .unwrap_or_default();
            let packages: Vec<String> = j.packages.iter().map(|p| format!(r#""{p}""#)).collect();
            let packages_json = format!("[{}]", packages.join(","));
            let repo = j
                .repo
                .as_deref()
                .map(|r| format!(r#""{}""#, r.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            let path = j
                .path
                .as_deref()
                .map(|p| format!(r#""{}""#, p.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            let subdomain = j
                .subdomain
                .as_deref()
                .map(|s| format!(r#""{}""#, s.replace('"', "\\\"")))
                .unwrap_or_else(|| "null".to_string());
            let script = j
                .script
                .as_deref()
                .map(|s| {
                    // Use serde_json to produce a correctly-escaped JSON string
                    serde_json::to_string(s).unwrap_or_else(|_| "null".to_string())
                })
                .unwrap_or_else(|| "null".to_string());
            let service_port = j
                .service_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "null".to_string());
            let hosts: Vec<String> = j
                .allowed_hosts
                .iter()
                .map(|h| format!(r#""{}""#, h.replace('"', "\\\"")))
                .collect();
            let hosts_json = format!("[{}]", hosts.join(","));
            format!(
                r#"{{"job_id":"{}","status":"{}","created_at":{},"runtime_seconds":{},"packages":{},"repo":{},"path":{},"subdomain":{},"script":{},"service_port":{},"hosts":{}}}"#,
                j.job_id,
                j.status,
                created_at,
                j.runtime_seconds,
                packages_json,
                repo,
                path,
                subdomain,
                script,
                service_port,
                hosts_json
            )
        })
        .collect();

    Ok(format!("[{}]", items.join(",")))
}

// ---------------------------------------------------------------------------
// POST /api/jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SubmitRequest {
    /// Script content.  Optional when `profile` is set — the profile supplies the script.
    #[serde(default)]
    script: String,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    subdomain: Option<String>,
    service_port: Option<u32>,
    /// Job profile names to apply in order (e.g. `["opencode", "cargo"]`).
    /// The server loads each profile from `{profile_dir}/{name}.toml` and merges
    /// them sequentially. Additive fields (packages, network rules) accumulate;
    /// singular fields (script, hardening) are set by the first profile that
    /// supplies them.
    #[serde(default)]
    profiles: Vec<String>,
    /// Git repository URL to clone (e.g. `"https://git.example.com/org/repo"`).
    /// When set, the server clones the repo and makes it available at `/workspace`.
    repo: Option<String>,
    /// Path within the repository (for monorepo support, e.g. `"projects/foo"`).
    #[serde(default)]
    path: String,
    /// Git ref to check out (branch, tag, or commit SHA).  Defaults to HEAD.
    git_ref: Option<String>,
    /// After successful execution, push commits to a new branch and open a PR.
    push: Option<bool>,
    /// Additional paths to include in sparse checkout (for multi-project sessions).
    #[serde(default)]
    extra_paths: Vec<String>,
    /// Environment variables to set for this job.
    #[serde(default)]
    env: HashMap<String, String>,
    /// Working directory relative to the workspace root (e.g. `"projects/meow"`).
    cwd: Option<String>,
    /// Skip filesystem cleanup after job exits (preserves root/ and workspace/ for inspection).
    no_cleanup: Option<bool>,
}

pub async fn api_submit_job(
    req: Request<Incoming>,
    daemon: &str,
) -> Result<Response<BoxedBody>, Infallible> {
    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!(error = %e, "failed to read submit request body");
            return Ok(json_error(StatusCode::BAD_REQUEST, "failed to read body"));
        }
    };

    let parsed: SubmitRequest = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                &format!("invalid json: {e}"),
            ));
        }
    };

    // A script, profiles, or repo is required.
    if parsed.script.is_empty() && parsed.profiles.is_empty() && parsed.repo.is_none() {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "script, profiles, or repo is required",
        ));
    }

    let network_policy = build_network_policy(&parsed.hosts);
    let base_subdomain = parsed.subdomain.clone();

    let job_req = JobRequest {
        script: parsed.script,
        packages: parsed.packages,
        network_policy,
        subdomain: parsed.subdomain,
        service_port: parsed.service_port,
        profiles: parsed.profiles,
        repo: parsed.repo.unwrap_or_default(),
        path: parsed.path,
        git_ref: parsed.git_ref,
        push: parsed.push,
        extra_paths: parsed.extra_paths,
        env: parsed.env,
        cwd: parsed.cwd,
        no_cleanup: parsed.no_cleanup,
        ..Default::default()
    };

    submit_job_request(daemon, job_req, None, base_subdomain).await
}

// ---------------------------------------------------------------------------
// DELETE /api/jobs/{id}
// ---------------------------------------------------------------------------

pub async fn api_cancel_job(daemon: &str, job_id: &str) -> Result<Response<BoxedBody>, Infallible> {
    let mut client = match JailServiceClient::connect(daemon.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to connect to daemon for cancel");
            return Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "failed to connect to daemon",
            ));
        }
    };

    match client
        .cancel_job(CancelJobRequest {
            job_id: job_id.to_owned(),
        })
        .await
    {
        Ok(resp) => {
            let cancelled = resp.into_inner().cancelled;
            info!(job_id = %job_id, cancelled, "cancel_job rpc returned");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(full_body(format!(r#"{{"cancelled":{cancelled}}}"#)))
                .unwrap_or_else(|_| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                }))
        }
        Err(e) => {
            let status = e.code();
            error!(job_id = %job_id, error = %e, "cancel_job rpc failed");
            let http_status = if status == tonic::Code::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(json_error(http_status, e.message()))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/jobs/{id}/retry
// ---------------------------------------------------------------------------

pub async fn api_retry_job(daemon: &str, job_id: &str) -> Result<Response<BoxedBody>, Infallible> {
    let mut client = match JailServiceClient::connect(daemon.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to connect to daemon for retry");
            return Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "failed to connect to daemon",
            ));
        }
    };

    let resp: ListJobsResponse = match client
        .list_jobs(ListJobsRequest {
            status: None,
            limit: Some(200),
            offset: None,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!(job_id = %job_id, error = %e, "list_jobs rpc failed for retry");
            return Ok(json_error(StatusCode::BAD_GATEWAY, "failed to list jobs"));
        }
    };

    let original = match resp.jobs.into_iter().find(|j| j.job_id == job_id) {
        Some(j) => j,
        None => return Ok(json_error(StatusCode::NOT_FOUND, "job not found")),
    };

    let script = match original.script {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "job has no script to retry",
            ));
        }
    };

    let network_policy = build_network_policy(&original.allowed_hosts);

    let job_req = JobRequest {
        script,
        packages: original.packages,
        network_policy,
        subdomain: original.subdomain,
        service_port: original.service_port,
        ..Default::default()
    };

    submit_job_request(daemon, job_req, Some(job_id), None).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a `NetworkPolicy` that allows the given host patterns (deny-by-default).
/// Returns `None` if the list is empty (meaning: no network rules / blocked).
fn build_network_policy(hosts: &[String]) -> Option<NetworkPolicy> {
    if hosts.is_empty() {
        return None;
    }
    let rules = hosts
        .iter()
        .map(|h| NetworkRule {
            pattern: Some(NetworkPattern {
                pattern: Some(nix_jail::jail::network_pattern::Pattern::Host(
                    HostPattern {
                        host: h.clone(),
                        path: None,
                    },
                )),
            }),
            action: NetworkAction::Allow as i32,
            credential: None,
        })
        .collect();
    Some(NetworkPolicy { rules })
}

/// Submit a `JobRequest` and return a JSON response with `job_id` and, when a
/// base subdomain was requested, the server-assigned suffixed `subdomain`.
///
/// `original_job_id` is used only for log context (retry path).
/// `base_subdomain` is the subdomain value from the HTTP request *before* the
/// server appends its job-ID suffix — used to reconstruct the final name.
async fn submit_job_request(
    daemon: &str,
    job_req: JobRequest,
    original_job_id: Option<&str>,
    base_subdomain: Option<String>,
) -> Result<Response<BoxedBody>, Infallible> {
    let mut client = match JailServiceClient::connect(daemon.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to connect to daemon for submit");
            return Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "failed to connect to daemon",
            ));
        }
    };

    match client.submit_job(job_req).await {
        Ok(resp) => {
            let new_job_id = resp.into_inner().job_id;
            if let Some(orig) = original_job_id {
                info!(
                    original_job_id = %orig,
                    new_job_id = %new_job_id,
                    "retried job via web ui"
                );
            } else {
                info!(job_id = %new_job_id, "submitted job via web ui");
            }
            // Reconstruct the final subdomain.  service.rs appends the last 6
            // characters of the job ID (lowercased) to prevent collisions:
            //   "{base}-{job_id[-6..].to_lowercase()}"
            let subdomain_json = base_subdomain
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|base| {
                    let n = new_job_id.len();
                    let suffix = new_job_id[n.saturating_sub(6)..].to_ascii_lowercase();
                    format!(",\"subdomain\":\"{base}-{suffix}\"")
                })
                .unwrap_or_default();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(full_body(format!(
                    r#"{{"job_id":"{new_job_id}"{subdomain_json}}}"#
                )))
                .unwrap_or_else(|_| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                }))
        }
        Err(e) => {
            error!(error = %e, "submit_job rpc failed");
            Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("submit failed: {e}"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_request_parses_with_serde() {
        let body =
            r#"{"script":"curl https://example.com","packages":["curl"],"hosts":["example.com"]}"#;
        let req: SubmitRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.script, "curl https://example.com");
        assert_eq!(req.packages, vec!["curl"]);
        assert_eq!(req.hosts, vec!["example.com"]);
        assert_eq!(req.subdomain, None);
        assert_eq!(req.service_port, None);
    }

    #[test]
    fn test_submit_request_escape_in_script() {
        let body = r#"{"script":"echo \"hi\"\nworld","packages":[]}"#;
        let req: SubmitRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.script, "echo \"hi\"\nworld");
    }

    #[test]
    fn test_submit_request_empty_arrays_default() {
        let body = r#"{"script":"ls"}"#;
        let req: SubmitRequest = serde_json::from_str(body).unwrap();
        assert!(req.packages.is_empty());
        assert!(req.hosts.is_empty());
    }

    #[test]
    fn test_build_network_policy_empty() {
        assert!(build_network_policy(&[]).is_none());
    }

    #[test]
    fn test_build_network_policy_nonempty() {
        let hosts = vec!["example.com".to_string(), "*.github.com".to_string()];
        let policy = build_network_policy(&hosts).unwrap();
        assert_eq!(policy.rules.len(), 2);
    }
}
