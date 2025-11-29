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

## Filesystem Caching with btrfs

On Linux systems with btrfs, we could use copy-on-write snapshots for O(1) workspace creation.

**Cache structure:**
```
cache/
  derivations/{hash}/     # Nix closure as root filesystem
  repos/{hash}/           # Git repository state
```

**Closure caching:**
- Compute closure with `nix-store -qR`
- Copy with reflinks: `cp --reflink=always`
- O(1) snapshots for new jobs
- Metadata tracking in SQLite (last used, reference counts, disk usage)

**Repo caching:**
- Hash git state (HEAD + tree hash)
- Snapshot for each job
- Reuse common base states

**Garbage collection:**
- LRU eviction based on last used time
- Configurable disk quota
- Manual `nix-jail gc` command

**Performance target:** <25ms job spawn time from cache hits

## Platform Abstraction

Formalize platform abstractions to make adding new isolation backends easier.

**Trait design:**
```rust
trait IsolationProvider {
    fn spawn(&self, job: Job) -> Result<Process>;
    fn cleanup(&self, job_id: String) -> Result<()>;
}

trait FilesystemProvider {
    fn prepare_workspace(&self, closure: &[Path]) -> Result<Workspace>;
}

trait NetworkProvider {
    fn setup_network(&self, job_id: String) -> Result<NetworkConfig>;
}
```

**Benefits:**
- Easier to add new platforms (FreeBSD, NixOS-specific optimizations)
- Conditional compilation with feature flags
- Shared core logic (workspace, proxy, storage)
- Clear platform capabilities matrix

## Deployment Tooling

Make nix-jail easier to deploy and operate in production.

**systemd service:**
- `nix-jail.service` for daemon
- Socket activation
- Automatic restarts
- Log integration with journald

**Installation:**
- Nix flake for reproducible builds
- NixOS module for system-wide deployment
- Home Manager integration for user services

**Configuration:**
- TOML/YAML config files
- Environment variable overrides
- Per-user vs system-wide settings

**Observability:**
- Metrics collection (Prometheus exporter?)
- Structured logging (JSON)
- Health check endpoints

**Permissions:**
- `nix-jail` group for access control
- Per-user resource quotas
- Audit logging

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

## Observability & Debugging

Rich introspection and debugging capabilities.

**Web UI:**
- Job status dashboard
- Real-time logs
- Resource usage graphs (CPU/memory/disk over time)
- Network traffic visualization

**Distributed tracing:**
- OpenTelemetry integration
- Trace job execution through all components
- Performance bottleneck identification

**Audit trails:**
- Complete history of job executions
- Who ran what, when
- What network connections were made
- What files were accessed

**Debugging mode:**
- Interactive shell in failed job workspaces
- Preserve failed job environments
- Step-through execution
- Breakpoint support (for supported runtimes)

**Structured logging:**
- JSON logs for easy parsing
- Log aggregation (Loki, CloudWatch, etc.)
- Log-based alerting

## Developer Experience

Tools to make nix-jail easier to use and debug.

**CLI improvements:**
- Interactive job selection: `nix-jail attach`
- Job history browsing
- Log filtering and search
- Config file validation
- Shell completions (bash, zsh, fish)

**IDE integration:**
- VS Code extension (syntax highlighting for config, job status)
- Language Server Protocol for config validation
- Debugging integration

**Template library:**
- Common job patterns (CI/CD, data processing, builds)
- Pre-configured environments
- Example repositories
- Quick-start templates

**Documentation:**
- Interactive tutorials
- Best practices guide
- Security hardening guide
- Performance tuning guide

## Non-Goals

Explicitly out of scope to keep the project focused:

- **Multi-tenancy** - Single-user focus, no user isolation
- **Windows support** - Unix-only (macOS/Linux)
- **GUI application sandboxing** - CLI/headless workloads only
- **General-purpose container runtime** - Nix-specific, not Docker replacement
- **SLSA Level 3+ compliance** - Personal automation, not supply chain hardening
- **Real-time guarantees** - Best-effort scheduling
- **Compliance frameworks** - No PCI-DSS, FedRAMP, SOC2, etc.

## See Also

- [SANDBOX.md](SANDBOX.md) - Current implementation (what exists today)
- [CLAUDE.md](CLAUDE.md) - Development guidelines, security rules, and design decisions
