# nix-jail Overview

## Slide 1: Job = Sandbox + Proxy

```mermaid
flowchart LR
    subgraph Sandbox
        Agent["Agent<br/>(e.g. Claude Code)"]
        Shell["Shell"]
        MCP["MCP Servers"]
    end

    subgraph Host["Host (outside sandbox)"]
        Proxy["MITM Proxy"]
        Creds["Credentials<br/>(keychain, env, files)"]
    end

    Internet["api.anthropic.com"]

    Sandbox -->|"HTTPS"| Proxy
    Proxy -.->|"read"| Creds
    Proxy -->|"inject"| Internet

    Sandbox -.-x|"❌"| Internet
    Sandbox -.-x|"❌"| Creds
```

**Key points:**
- Sandbox has NO direct internet access - must go through proxy
- Sandbox has NO access to credentials (keychain, env vars, files)
- Proxy injects real tokens into requests, sandbox only sees dummies

---

## Slide 2: Nix Expression → Minimal Closure

```mermaid
flowchart TD
    CLI["-p bash -p curl"]

    CLI --> Resolve["nix-instantiate<br/>(resolve packages)"]
    Resolve --> Closure["Closure Computation<br/>(transitive deps only)"]
    Closure --> Store["/nix/store<br/>(minimal set)"]

    subgraph Sandbox
        Store --> Agent["Agent sees only<br/>requested packages"]
    end

    NixStore["Host /nix/store<br/>(thousands of packages)"] -.-x|"❌"| Agent
```

**Key points:**
- `-p bash -p curl` → only those packages + dependencies
- Flake support: `flake.nix` → `nix develop` shell automatically
- No access to host's full `/nix/store`

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
