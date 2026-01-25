# nix-jail Roadmap

This document explores future possibilities for nix-jail. For current implementation and design decisions, see [SANDBOX.md](SANDBOX.md) and [CLAUDE.md](CLAUDE.md).

## Resource Limits (macOS)

macOS SandboxExecutor could enforce resource limits using ulimit-based restrictions.

### Possible Approaches

- `ulimit -t` for CPU time limits
- `ulimit -v` for virtual memory caps
- `ulimit -u` for max process limits
- Workspace size monitoring with periodic checks
- Job termination when disk quota exceeded
- Per-job configurable limits via gRPC
- Default limits in server config

### Example Limits

- CPU time: 1 hour
- Memory: 4 GB
- Disk: 10 GB workspace
- Processes: 100
Linux SystemdExecutor already has these via systemd properties (CPUQuota, MemoryMax, TasksMax, RuntimeMaxSec).

## Testing & Validation

Rigorous security testing to validate the sandbox.

### Penetration Testing Scenarios

- Malicious npm/PyPI package attempts:
   - Direct HTTPS exfiltration
   - Reading `~/.ssh/id_rsa`
   - Reading `~/.aws/credentials`
   - Reverse shell via netcat
   - Process injection attacks
   - Privilege escalation attempts

### Verify Threat Model

- Confirm all attack vectors are blocked (see [CLAUDE.md](CLAUDE.md) for threat model)
- Document what escapes are possible

### Performance Benchmarking

- Job spawn time distribution
- Proxy overhead measurement
- Disk I/O impact
- Memory footprint
- Concurrent job scaling

### Security Audit

- Token injection system review
- Credential storage analysis
- Network policy bypass attempts
- Sandbox escape research

### Load Testing

- Hundreds of concurrent jobs
- Long-running jobs (hours/days)
- Resource exhaustion scenarios

## Advanced Caching

Beyond btrfs snapshots, explore multi-level caching strategies.

### Remote Caching

- S3-backed closure cache
- HTTP cache server
- Cache sharing across machines

### Cache Warming

- Pre-populate common closures (nodejs, python, rust toolchains)
- Async background cache refresh

### Deduplication

- Shared base layers across closures
- Content-addressed storage
- Minimal delta transfers

### Compression

- zstd compression for remote cache
- Transparent decompression on access

### Smart Invalidation

- Nix derivation-based expiry
- Automatic refresh when nixpkgs updates

## Debugging

### Debugging Mode

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
