# nix-jail Roadmap

This document explores future possibilities for nix-jail. For current implementation and design decisions, see [SANDBOX.md](SANDBOX.md) and [CLAUDE.md](CLAUDE.md).

## Resource Limits (macOS)

macOS SandboxExecutor could enforce resource limits using ulimit-based restrictions.
**Possible approaches:**
- `ulimit -t` for CPU time limits
- `ulimit -v` for virtual memory caps
- `ulimit -u` for max process limits
- Workspace size monitoring with periodic checks
- Job termination when disk quota exceeded
- Per-job configurable limits via gRPC
- Default limits in server config
**Example limits:**
- CPU time: 1 hour
- Memory: 4 GB
- Disk: 10 GB workspace
- Processes: 100
Linux SystemdExecutor already has these via systemd properties (CPUQuota, MemoryMax, TasksMax, RuntimeMaxSec).

## Testing & Validation

Rigorous security testing to validate the sandbox.
**Penetration testing scenarios:**
- Malicious npm/PyPI package attempts:
   - Direct HTTPS exfiltration
   - Reading `~/.ssh/id_rsa`
   - Reading `~/.aws/credentials`
   - Reverse shell via netcat
   - Process injection attacks
   - Privilege escalation attempts
**Verify threat model:**
- Confirm all attack vectors are blocked (see [CLAUDE.md](CLAUDE.md) for threat model)
- Document what escapes are possible
**Performance benchmarking:**
- Job spawn time distribution
- Proxy overhead measurement
- Disk I/O impact
- Memory footprint
- Concurrent job scaling
**Security audit:**
- Token injection system review
- Credential storage analysis
- Network policy bypass attempts
- Sandbox escape research
**Load testing:**
- Hundreds of concurrent jobs
- Long-running jobs (hours/days)
- Resource exhaustion scenarios

## Advanced Caching

Beyond btrfs snapshots, explore multi-level caching strategies.
**Remote caching:**
- S3-backed closure cache
- HTTP cache server
- Cache sharing across machines
**Cache warming:**
- Pre-populate common closures (nodejs, python, rust toolchains)
- Async background cache refresh
**Deduplication:**
- Shared base layers across closures
- Content-addressed storage
- Minimal delta transfers
**Compression:**
- zstd compression for remote cache
- Transparent decompression on access
**Smart invalidation:**
- Nix derivation-based expiry
- Automatic refresh when nixpkgs updates

## Prometheus Metrics

Expose `/metrics` endpoint for Prometheus scraping with job execution and cache performance data.

### Proposed Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nix_jail_jobs_total` | Counter | `status` | Jobs completed (success/failure/cancelled) |
| `nix_jail_job_duration_seconds` | Histogram | - | Total job duration |
| `nix_jail_phase_duration_seconds` | Histogram | `phase` | Duration by execution phase |
| `nix_jail_cache_hits_total` | Counter | `cache_type` | Cache hits |
| `nix_jail_cache_misses_total` | Counter | `cache_type` | Cache misses |
| `nix_jail_closure_paths_total` | Histogram | - | Number of store paths per closure |
| `nix_jail_closure_size_bytes` | Histogram | - | Closure size distribution |
| `nix_jail_active_jobs` | Gauge | - | Currently running jobs |
**Label values:**
- `status`: `success`, `failure`, `cancelled`
- `phase`: `closure_resolution`, `root_prepare`, `workspace_prepare`, `proxy_setup`, `execution`
- `cache_type`: `workspace` (git sparse checkout), `root` (nix closure btrfs snapshot)

### Implementation Pattern

**Where to instrument** (existing tracing spans already mark these):
- `orchestration.rs`: `setup_workspace`, `resolve_packages`, `compute_closure`, `prepare_root`, `start_proxy`
- `cache/mod.rs`: `prepare_root()` returns cache hit/miss
- `job_workspace.rs`: sparse checkout cache hit/miss at lines 477-523
**Data flow option 1 - gRPC extension:**
```protobuf
message JobMetrics {
  bool workspace_cache_hit = 1;
  bool root_cache_hit = 2;
  uint32 closure_resolution_ms = 3;
  uint32 root_prepare_ms = 4;
  uint32 workspace_prepare_ms = 5;
  uint32 proxy_setup_ms = 6;
  uint32 execution_ms = 7;
  uint64 closure_size_bytes = 8;
  uint32 closure_path_count = 9;
}

message JobInfo {
  // ...existing fields...
  optional JobMetrics metrics = 10;
}
```
Clients (forgejo-nix-ci) can fetch `JobInfo` after completion and record metrics locally.
**Data flow option 2 - native /metrics endpoint:**
Add HTTP server to nix-jail daemon exposing Prometheus metrics directly. Requires:
- `prometheus` crate
- `axum` or `hyper` for HTTP
- Config: `metrics_port = 9091`
**Recommended:** Option 2 (native endpoint) for simplicity. Option 1 useful if clients need per-job breakdown.

### Storage Schema Extension

Add columns to `jobs` table:
```sql
ALTER TABLE jobs ADD COLUMN workspace_cache_hit BOOLEAN;
ALTER TABLE jobs ADD COLUMN root_cache_hit BOOLEAN;
ALTER TABLE jobs ADD COLUMN closure_resolution_ms INTEGER;
ALTER TABLE jobs ADD COLUMN root_prepare_ms INTEGER;
ALTER TABLE jobs ADD COLUMN workspace_prepare_ms INTEGER;
ALTER TABLE jobs ADD COLUMN proxy_setup_ms INTEGER;
ALTER TABLE jobs ADD COLUMN execution_ms INTEGER;
ALTER TABLE jobs ADD COLUMN closure_size_bytes INTEGER;
ALTER TABLE jobs ADD COLUMN closure_path_count INTEGER;
```
Populate during job execution in `orchestration.rs`.

## Debugging

**Debugging mode:**
- Interactive shell in failed job workspaces
- Preserve failed job environments

## Non-Goals

Explicitly out of scope to keep the project focused:
- **Multi-tenancy** - Single-user focus, no user isolation
- **Windows support** - Unix-only (macOS/Linux)
- **GUI application sandboxing** - CLI/headless workloads only
- **General-purpose container runtime** - Nix-specific, not Docker replacement
- **SLSA Level 3+ compliance** - Personal automation, not supply chain hardening
- **Real-time guarantees** - Best-effort scheduling
- **Compliance frameworks** - No PCI-DSS, FedRAMP, SOC2, etc.
- **Web UI** - CLI-first, use external tools for dashboards
- **Shell completions** - Not worth the maintenance

## See Also

- [SANDBOX.md](SANDBOX.md) - Current implementation (what exists today)
- [CLAUDE.md](CLAUDE.md) - Development guidelines, security rules, and design decisions
