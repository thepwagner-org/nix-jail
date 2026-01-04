# nix-jail Overview

## Slide 1: Job = Sandbox + Proxy

```mermaid
flowchart LR
    subgraph Sandbox
        direction TB
        Agent["Agent<br/>(e.g. Claude Code)"]
        Shell["Shell"]
        MCP["stdio mcp"]
    end

    subgraph Host["Host (outside sandbox)"]
        Proxy["MITM Proxy"]
        Creds["Credentials<br/>(keychain, env, files)"]
    end

    subgraph Internet
        Anthropic["api.anthropic.com"]
        Wikipedia["wikipedia.org"]
    end

    Sandbox -->|"HTTPS"| Proxy
    Proxy -.->|"read"| Creds
    Proxy -->|"HTTPS+inject"| Anthropic
    Proxy -->|"HTTPS"| Wikipedia

    Sandbox -.-x|"❌"| Internet
    Sandbox -.-x|"❌"| Creds
```

**Key points:**
- Sandbox has NO direct internet access - must go through proxy
- Sandbox has NO access to credentials (keychain, env vars, files)
- Sandbox backends: sandbox-exec (macOS), systemd (Linux), Docker (both)

---

## Slide 2: Sandbox Contents from Nix Expression

The sandbox environment is derived **at job time** from a Nix expression.

**Option 1: Nixpkgs branch + packages**
```bash
nix-jail run --nixpkgs nixos-24.11 -p cargo -p rustfmt -p clippy -- cargo build
```

**Option 2: Flake with mkShell**
```nix
# shell.nix
pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustfmt
    clippy
    protobuf
    pkg-config
    openssl.dev
  ];
}
```
```bash
nix-jail run -- cargo build  # uses flake.nix/shell.nix from workspace
```

**Key point:** Only the packages you specify (+ their dependencies) are available in the sandbox.

---

## Slide 3: Dummy Token Injection

```mermaid
sequenceDiagram
    box Sandbox
    participant Agent
    end

    box Host
    participant Proxy as MITM Proxy
    participant Creds as Credentials
    end

    participant API as api.anthropic.com

    Agent->>Proxy: Authorization: dummy-token-AAAA

    Note over Proxy: Verify dummy matches pattern
    Proxy->>Creds: Fetch real token
    Creds-->>Proxy: sk-ant-oat01-real...

    Note over Proxy: Replace dummy → real
    Proxy->>API: Authorization: Bearer sk-ant-oat01-real...
    API-->>Proxy: 200 OK
    Proxy-->>Agent: 200 OK
```

**Key insight:** Real tokens never enter the sandbox.

Compromised code in sandbox only sees `dummy-token-AAAA` - useless outside.
