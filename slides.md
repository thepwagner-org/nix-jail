# nix-jail Overview

## Slide 1: Job = Sandbox + Proxy

```mermaid
flowchart LR
    subgraph Sandbox["Sandbox (kernel-isolated)"]
        Agent["Agent<br/>(Claude Code)"]
    end

    subgraph Host["Host (outside sandbox)"]
        Proxy["MITM Proxy"]
        Keychain["Keychain<br/>Credentials"]
    end

    Internet["Internet<br/>(api.anthropic.com)"]

    Agent -->|"HTTP_PROXY"| Proxy
    Proxy -.->|"fetch tokens"| Keychain
    Proxy -->|"inject real tokens"| Internet

    style Sandbox fill:#ffe0e0
    style Host fill:#e0ffe0
```

**Key points:**
- Jobs run in platform sandboxes (macOS sandbox-exec, Linux systemd, Docker)
- Each job gets its own MITM proxy controlling all network
- Sandbox cannot bypass proxy (kernel-enforced)

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

    NixStore["Host /nix/store<br/>(thousands of packages)"] -.->|"excluded"| X["❌"]

    style Sandbox fill:#ffe0e0
```

**Key points:**
- `-p bash -p curl` → only those packages + dependencies
- Flake support: `flake.nix` → `nix develop` shell automatically
- No access to host's full `/nix/store`

---

## Slide 3: Dummy Token Injection

```mermaid
sequenceDiagram
    box rgba(255,200,200,0.3) Sandbox
    participant Agent as Agent
    end

    box rgba(200,255,200,0.3) Host
    participant Proxy as MITM Proxy
    participant Keychain as Keychain
    end

    participant API as api.anthropic.com

    Agent->>Proxy: Authorization: dummy-token-AAAA

    Note over Proxy: Verify dummy matches pattern
    Proxy->>Keychain: Fetch real token
    Keychain-->>Proxy: sk-ant-oat01-real...

    Note over Proxy: Replace dummy → real
    Proxy->>API: Authorization: Bearer sk-ant-oat01-real...
    API-->>Proxy: 200 OK
    Proxy-->>Agent: 200 OK
```

**Key insight:** Real tokens never enter the sandbox.

Compromised code in sandbox only sees `dummy-token-AAAA` - useless outside.
