# nix-jail

Sandboxed execution for Nix packages with network policy enforcement and credential injection.

## What it does

Run scripts in isolated environments where:
- Only the packages you specify are available (minimal Nix closure)
- Network access is denied by default, allowed by policy
- Credentials are injected by the proxy, never visible to the sandbox

```bash
# Run curl in a sandbox - network blocked by default
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh
# Connection refused

# Allow specific host with policy
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --policy examples/network-policies/httpbin-allow.toml
# Works, but only httpbin.org
```

## How it works

The server spawns jobs through a pipeline: resolve Nix packages, set up workspace, start a per-job MITM proxy, execute in platform sandbox, cleanup.

**macOS:** Apple sandbox-exec with SBPL profiles. Localhost-only network forces proxy usage.

**Linux:** systemd transient units with 33 hardening properties. Network namespaces with veth pairs provide kernel-enforced proxy-only communication.

The proxy intercepts HTTPS traffic, enforces host+path policies, and injects credentials from the host keychain. Code in the sandbox cannot access the real tokens.

## Features

- **Network policies** - Regex matching on host and path, default deny, ordered rule matching
- **Credential injection** - Tokens injected by proxy, sandbox only sees dummy values
- **Git workspaces** - Clone repos as job workspaces with shallow clones and auth support
- **Nixpkgs versions** - Pin to releases, unstable, or specific commits
- **Hardening profiles** - Weaken specific protections when needed (e.g., JIT runtimes)

## Requirements

- Nix
- macOS or Linux with systemd
- Root access (daemon manages network namespaces and sandboxing)

## Getting started

```bash
# Build and start server
cargo build && cargo run --bin server -- --config server.toml

# Run a script with bash and coreutils
cargo run --bin client -- exec -p bash -p coreutils -s examples/scripts/bash-env.sh

# Run with network access to specific hosts
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --allow-host "httpbin.org"

# Use Claude Code in a sandbox (with credential injection)
cargo run --bin client -- exec -p claude-code --nixpkgs nixos-unstable \
  -s examples/scripts/claude.sh \
  --policy examples/network-policies/anthropic-allow.toml \
  --hardening-profile jit-runtime
```

## Documentation

- [TESTING.md](TESTING.md) - More examples and testing workflows
- [SANDBOX.md](SANDBOX.md) - Architecture, security model, implementation details
- [ROADMAP.md](ROADMAP.md) - Future directions

## Status

Early development (v0.1.0). The core works but APIs may change.
