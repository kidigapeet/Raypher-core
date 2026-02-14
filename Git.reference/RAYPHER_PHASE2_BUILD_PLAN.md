# RAYPHER PHASE 2: THE GHOST PROTOCOL — COMPLETE BUILD PLAN

> **Codename:** Ghost Protocol — Invisibility & Persistence
> **Objective:** Transform `raypher.exe` from a CLI tool into an invisible, unkillable **System Service** that starts on boot, protects itself from termination, manages API keys through a local proxy, and delivers professional installers with automated CI/CD.
> **Timeline:** 4 Weeks (Week 5–8)
> **Prerequisite:** Phase 1 complete (scanner, heuristics, terminator, safety, watchtower, panic, database, identity, CLI — all verified ✅)

---

## Table of Contents

1. [The Architecture Shift](#the-architecture-shift)
2. [Technology Stack](#technology-stack)
3. [Week 5: The Daemon — Service Refactor](#week-5-the-daemon--service-refactor)
4. [Week 6: The Vault — Localhost Proxy & Secret Manager](#week-6-the-vault--localhost-proxy--secret-manager)
5. [Week 7: The Factory — Installers & CI/CD](#week-7-the-factory--installers--cicd)
6. [Week 8: The Immortal — Self-Update & Watchdog](#week-8-the-immortal--self-update--watchdog)
7. [Enhancement: Health & Telemetry Endpoint](#enhancement-health--telemetry-endpoint)
8. [Enhancement: Structured Logging for Service Mode](#enhancement-structured-logging-for-service-mode)
9. [Enhancement: Configuration File System](#enhancement-configuration-file-system)
10. [The Ghost User Experience](#the-ghost-user-experience)
11. [Phase 2 Final Checklist](#phase-2-final-checklist)

---

## The Architecture Shift

Phase 2 is the transition from **User Mode** (a tool you run) to **System Mode** (a living sentinel):

| Feature | **Phase 1 (Current)** | **Phase 2 (Target)** |
|---|---|---|
| **Visibility** | Terminal Window Open | **Invisible Background Process** |
| **Lifespan** | Dies when you close window | **Starts on Boot / Restarts on Crash** |
| **Identity** | Runs as your user account | **Runs as `SYSTEM` / `root`** |
| **API Keys** | Hardcoded in `.env` or plaintext | **Intercepted via Local Proxy, sealed in TPM** |
| **Updates** | `git pull && cargo run` | **Auto-Update from GitHub Releases** |
| **Delivery** | `cargo build` + copy binary | **Professional MSI installer, one-click** |

### The Split Brain Architecture

After Phase 2, the `raypher` binary has a **dual personality**:

- **Personality A — CLI (User Mode):** Triggered by `raypher scan`, `raypher seal`, `raypher logs`, etc. It prints to the console and exits when done.
- **Personality B — Service (System Mode):** Triggered **only** by the OS Service Control Manager (SCM). It has **no console** — `println!` goes nowhere. It must "check in" with the OS within 30 seconds or be killed.

```
┌──────────────────────────────────────────────┐
│              raypher.exe BINARY               │
├──────────────────┬───────────────────────────┤
│   CLI MODE       │      SERVICE MODE         │
│                  │                           │
│ raypher scan     │ SCM Start Signal          │
│ raypher seal     │  ├── Register Dispatcher  │
│ raypher logs     │  ├── Report "RUNNING"     │
│ raypher identity │  ├── Launch Watchtower    │
│ raypher panic    │  ├── Launch Proxy :8888   │
│                  │  └── Wait for Stop Signal │
│ (exits after)    │  (runs forever)           │
└──────────────────┴───────────────────────────┘
```

---

## Technology Stack

### New Dependencies (Phase 2)

| Crate | Purpose | Why This One |
|---|---|---|
| `windows-service` | Windows Service dispatcher & SCM communication | Only Rust crate that handles the 30-second SCM handshake properly |
| `axum` | HTTP server for the localhost proxy | Tokio-native, zero-copy, production-grade. Same stack as Cloudflare. |
| `reqwest` | HTTP client to forward requests to real APIs | Async, supports connection pooling (Keep-Alive), rustls-native |
| `rustls` | TLS implementation | Pure Rust — no OpenSSL DLL Hell on Windows cross-compilation |
| `tokio` | Async runtime | Required by axum. Industry standard. |
| `self_update` | Auto-update from GitHub Releases | Handles download, checksum, and binary swap |
| `cargo-wix` | MSI installer generation | Reads Cargo.toml metadata, auto-generates WiX XML |
| `rpassword` | Secure password/key input from terminal | Hides keystrokes when entering API keys via `raypher seal` |

### Carried From Phase 1

| Crate | Continued Use |
|---|---|
| `sysinfo` | PID verification for proxy allow-list |
| `sha2` + `hex` | Process fingerprinting for proxy verification |
| `rusqlite` | Storing sealed secrets, events, identity |
| `clap` | CLI subcommands (seal, unseal, status) |
| `windows` (NCrypt) | TPM key operations for sealing/unsealing API keys |
| `tracing` + `tracing-subscriber` | Structured logging (upgraded to file output in service mode) |
| `ctrlc` | Graceful shutdown in CLI mode |

---

## Week 5: The Daemon — Service Refactor

### Philosophy

> *"A security tool that requires a terminal window to stay open is not a security tool; it is a toy."*

This week transforms Raypher into a background daemon that starts before the user even logs in.

---

### Founder (Cybersecurity) — Windows Service Implementation

#### Objective

Make `raypher.exe` run as a proper Windows Service using the `windows-service` crate.

#### New File: `src/service.rs`

This is the largest new module. It contains:

**1. The Service Dispatcher**

```rust
// The ENTRY POINT when Windows starts Raypher as a service.
// This is NOT main(). Windows calls this function directly.
fn service_main(arguments: Vec<OsString>) {
    // 1. Register the event handler (for Stop/Pause signals)
    // 2. Report status: SERVICE_RUNNING (CRITICAL: within 30 seconds!)
    // 3. Launch the Watchtower loop
    // 4. Launch the Proxy server
    // 5. Wait for shutdown signal
}
```

**2. The Event Handler**

```rust
// Windows sends signals through this function.
// We MUST handle ServiceControl::Stop gracefully.
fn event_handler(control_event: ServiceControl) -> ServiceControlHandlerResult {
    match control_event {
        ServiceControl::Stop => {
            // Set AtomicBool shutdown flag (same pattern as Phase 1)
            // Report status: SERVICE_STOP_PENDING
            // Allow Watchtower and Proxy to drain connections
            // Report status: SERVICE_STOPPED
        }
        ServiceControl::Interrogate => {
            // SCM checking if we're alive — just report current status
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}
```

**3. The Critical 30-Second Window**

When the SCM starts a service, it gives it exactly **30 seconds** to report `SERVICE_RUNNING`. If Raypher is stuck (e.g., database locked, TPM timeout), Windows kills it and marks the install as failed.

**Mitigation strategy:**

- Report `SERVICE_START_PENDING` immediately with checkpoints
- Initialize database in a separate thread
- Only report `SERVICE_RUNNING` after core systems are confirmed ready
- Set a startup timeout alarm — if initialization exceeds 25 seconds, report running anyway and initialize remaining systems lazily

**4. The Privilege Level: `LocalSystem`**

Raypher runs as `LocalSystem`, not as a regular admin account.

| Capability | Admin | LocalSystem |
|---|---|---|
| Kill other admin processes | ❌ | ✅ |
| Access TPM hardware directly | ⚠️ Limited | ✅ Full |
| Listen on port 8888 without firewall popup | ❌ | ✅ |
| Survive user logout | ❌ | ✅ |
| Start before user login | ❌ | ✅ |

#### Modified File: `src/main.rs`

The `main()` function needs split logic:

```rust
fn main() {
    // Detect: are we running as a service or CLI?
    if std::env::args().any(|a| a == "--service") {
        // SERVICE MODE — called by SCM
        service::run_service();
    } else {
        // CLI MODE — normal user interaction
        let cli = Cli::parse();
        match cli.command { ... }
    }
}
```

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Add `windows-service` crate to `Cargo.toml`. Create `src/service.rs` skeleton. Implement `service_main` with `SERVICE_START_PENDING` → `SERVICE_RUNNING` lifecycle. | Service starts and reports running to SCM |
| **Day 2** | Implement `event_handler` for `Stop`, `Interrogate`, `Pause/Continue`. Add `--service` detection to `main.rs`. Wire up the `AtomicBool` shutdown flag from Phase 1's Watchtower. | Service can be started and stopped cleanly |
| **Day 3** | Test: Install manually with `sc create RaypherService binPath="C:\path\raypher.exe --service"`. Verify with `sc query RaypherService`. Check `Event Viewer` for errors. | Service runs in background, survives logout |

**TRAP WARNING:** If Raypher panics in service mode, there is NO console to see the error. You MUST implement the logging fix (see Enhancement: Structured Logging) first, otherwise debugging will be blind.

---

### Co-Founder (Data/Ops) — Linux Daemon (`systemd`)

#### Objective

Create a `systemd` unit file so Raypher runs as a daemon on Linux servers.

#### New File: `deploy/raypher.service`

```ini
[Unit]
Description=Raypher AI Safety Agent
Documentation=https://github.com/kidigapeet/raypherweb
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/raypher monitor
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=raypher

# CRITICAL: Prevent restart loops from burning CPU
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=/var/lib/raypher /home

[Install]
WantedBy=multi-user.target
```

#### Key Decisions Explained

| Setting | Value | Why |
|---|---|---|
| `Restart=always` | Auto-restart after crash | But with `StartLimitBurst=5` to prevent infinite restart loops — max 5 restarts per 60 seconds |
| `User=root` | Root privileges | Required to kill other processes and access TPM |
| `After=network-online.target` | Wait for network | The proxy needs network access to forward API calls |
| `StandardOutput=journal` | Log to journalctl | `println!` output goes to system logs, not `/dev/null` |
| `ProtectSystem=strict` | Read-only filesystem | Prevents Raypher from accidentally modifying system files. Only `ReadWritePaths` are writable |

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Create `deploy/raypher.service` unit file. Create `deploy/install-linux.sh` script that copies binary to `/usr/local/bin/` and enables the service. | Installable on any Linux system |
| **Day 2** | Test on GitHub Codespaces or a VPS: `sudo systemctl start raypher`, `systemctl status raypher`, `journalctl -u raypher -f`. | Service runs, logs visible via journalctl |
| **Day 3** | Kill the process manually (`kill -9 $(pidof raypher)`) and verify it auto-restarts. Kill it 6 times rapidly and verify the rate limiter kicks in. | Restart behavior is validated |

---

## Week 6: The Vault — Localhost Proxy & Secret Manager

### Philosophy

> *"The user's Python script should never touch a real API key. Raypher is the bouncer at the door — it checks your ID, holds the VIP pass, and escorts you in."*

This is the **Man-in-the-Middle** feature. Raypher sits between the AI agent and the internet, intercepting requests at `127.0.0.1:8888` to inject real API keys from the TPM vault.

---

### Founder (Cybersecurity) — The Proxy Server

#### New File: `src/proxy.rs`

This module implements a high-performance HTTP reverse proxy using `axum`.

**The Complete Request Flow:**

```
Step 1: Agent sends request
  python agent.py → POST http://localhost:8888/v1/chat/completions
                     Header: X-Raypher-Token: dummy-token
                     Body: {"model": "gpt-4", "messages": [...]}

Step 2: Raypher intercepts
  axum server on 127.0.0.1:8888 receives request
  ├── Extract X-Raypher-Token header
  ├── Identify calling process PID from TCP socket
  ├── Look up PID in sysinfo → get executable path
  └── SHA-256 hash the executable

Step 3: The CSI Investigation (Verification)
  ├── Query data.db allow_list table
  ├── Compare exe_hash against registered hashes
  ├── IF MATCH → proceed to Step 4
  └── IF NO MATCH → drop connection, log CRITICAL event

Step 4: The Key Injection
  ├── Ask TPM to unseal the real API key
  ├── Replace X-Raypher-Token with: Authorization: Bearer sk-REAL-KEY
  ├── Forward request to https://api.openai.com/v1/chat/completions
  └── Stream response back to the agent

Step 5: Audit
  └── Log event: {pid, exe_hash, endpoint, status, latency_ms}
```

#### The Proxy Architecture

```rust
// proxy.rs — core structure

pub struct ProxyConfig {
    /// The address to listen on (default: 127.0.0.1:8888)
    pub listen_addr: SocketAddr,
    /// The target API base URL (default: https://api.openai.com)
    pub target_base_url: String,
    /// Connection pool — reuse TCP connections to the API
    pub http_client: reqwest::Client,
}

// Route handlers
async fn handle_chat_completions(
    State(config): State<Arc<ProxyConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    // 1. Extract X-Raypher-Token
    // 2. Identify caller PID (platform-specific)
    // 3. Verify against allow list
    // 4. Unseal real API key from TPM
    // 5. Forward with real key
    // 6. Log the event
}
```

#### PID Identification from TCP Socket

This is the "Hard Part" — figuring out WHICH process made the HTTP request.

**On Windows:**

```rust
// Use GetExtendedTcpTable or GetTcpTable2 from iphlpapi
// These functions return a table of all TCP connections with their owning PIDs
// Match the source port of the incoming connection to find the PID
```

**On Linux:**

```rust
// Parse /proc/net/tcp or /proc/net/tcp6
// Each line contains: local_address:port remote_address:port ... inode
// Then scan /proc/*/fd/ to find which PID owns that socket inode
```

#### Key Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **HTTP Framework** | `axum` | Tokio-native, zero-copy, same performance tier as Go's stdlib. No macro magic. |
| **HTTP Client** | `reqwest` with connection pooling | Keep-Alive connections to OpenAI reduce latency by ~100ms per request |
| **TLS** | `rustls` (not openssl) | Pure Rust — no DLL Hell on Windows, no cross-compilation nightmares |
| **Proxy Binding** | `127.0.0.1` only | NEVER bind to `0.0.0.0` — this would expose the proxy to the network and leak API keys |
| **Auth Check** | PID + exe hash verification | PID alone is spoofable. exe hash ensures the EXACT binary is authorized |

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Add `axum`, `reqwest`, `tokio`, `hyper` to `Cargo.toml`. Create `src/proxy.rs` skeleton. Implement basic echo server on `127.0.0.1:8888`. Test with `curl localhost:8888/health`. | Proxy server starts and responds |
| **Day 2** | Implement the forwarding logic. Accept POST to `/v1/chat/completions`. Hardcode a test API key. Forward to OpenAI. Return the response. Test end-to-end with a Python script. | Proxy forwards requests successfully |
| **Day 3** | Implement PID verification. Use `GetExtendedTcpTable` (Windows) or `/proc/net/tcp` (Linux) to identify the calling PID. Hash the executable. Check against `allow_list` table. | Only authorized processes can use the proxy |
| **Day 4** | Wire up TPM unsealing. Replace hardcoded key with real key from TPM vault. Add rate limiting (max 100 req/min per PID). | Production-ready proxy with TPM integration |
| **Day 5** | Integration test: Python script → proxy → OpenAI → response. Unauthorized script → connection dropped. All events logged to audit ledger. | Complete proxy verification |

**PERFORMANCE WARNING:** The proxy adds latency. Ensure `reqwest` uses a persistent connection pool:

```rust
let client = reqwest::Client::builder()
    .pool_idle_timeout(Duration::from_secs(90))
    .pool_max_idle_per_host(10)
    .use_rustls_tls()
    .build()?;
```

---

### Co-Founder (Data/Ops) — The Secret Manager

#### Objective

Build CLI commands to seal (encrypt) and manage API keys using the TPM.

#### Modified File: `src/main.rs` — New Subcommands

```rust
enum Commands {
    // ... existing commands ...

    /// Seal an API key into the TPM vault
    Seal {
        /// Provider name (e.g., "openai", "anthropic", "google")
        #[arg(short, long)]
        provider: String,
    },

    /// Unseal and display a stored API key (admin only)
    Unseal {
        /// Provider name to retrieve
        #[arg(short, long)]
        provider: String,
    },

    /// List all sealed providers
    Secrets,

    /// Register a process in the proxy allow list
    Allow {
        /// Full path to the executable to authorize
        #[arg(short, long)]
        exe_path: String,
    },

    /// Show Raypher service status
    Status,
}
```

#### New File: `src/secrets.rs`

This module handles the encryption/decryption lifecycle:

**The Seal Flow:**

```
User: raypher seal --provider openai
  ├── Prompt: "Enter API Key: " (hidden input via rpassword)
  ├── Read key: "sk-proj-abc123..."
  ├── Encrypt with TPM public key (NCryptEncrypt)
  ├── Store encrypted blob in data.db → secrets table
  └── Print: "✅ Key sealed for provider 'openai'"
```

**The Unseal Flow (internal, used by proxy):**

```
Proxy needs key for "openai"
  ├── Query data.db → secrets table → get encrypted blob
  ├── Decrypt with TPM private key (NCryptDecrypt)
  ├── Return plaintext key (NEVER log this!)
  └── Key exists only in memory, zeroized after use
```

#### New Database Table: `secrets`

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT NOT NULL UNIQUE,
    encrypted_blob  BLOB NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
```

#### New Database Table: `allow_list`

```sql
CREATE TABLE IF NOT EXISTS allow_list (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exe_path        TEXT NOT NULL,
    exe_hash        TEXT NOT NULL,
    friendly_name   TEXT,
    added_at        TEXT NOT NULL,
    added_by        TEXT NOT NULL DEFAULT 'manual'
);
```

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Add `rpassword` crate. Create `src/secrets.rs`. Implement `seal()` function that encrypts using TPM and stores in DB. Add `Seal` subcommand to CLI. | `raypher seal --provider openai` works |
| **Day 2** | Implement `unseal()` function using `NCryptDecrypt`. Add `Secrets` subcommand (list all providers). Add `Unseal` subcommand (admin display with confirmation prompt). | Keys can be stored and retrieved |
| **Day 3** | Create `allow_list` table in `database.rs`. Implement `Allow` subcommand that hashes an exe and registers it. Test: `raypher allow --exe-path "C:\Python\python.exe"`. | Process authorization system works |

---

## Week 7: The Factory — Installers & CI/CD

### Philosophy

> *"You cannot ask a lawyer to install Rust. You need a file they can double-click."*

This week creates professional installers and automated build pipelines.

---

### Founder (Cybersecurity) — Windows MSI Installer

#### Tool: `cargo-wix`

WiX (Windows Installer XML) is the "C++ of installers." It uses XML configuration to describe exactly:

- Where files go
- What registry keys to create
- What services to install
- How to uninstall everything cleanly

`cargo-wix` bridges Rust and WiX — it reads `Cargo.toml` metadata and auto-generates the XML scaffolding.

#### The Installer Flow

```
User downloads: RaypherSetup-v0.2.0.msi
User double-clicks → "Next, Next, Finish"

Behind the scenes:
  ├── Copy raypher.exe to C:\Program Files\Raypher\
  ├── Register RaypherService with SCM
  ├── Set startup type: Automatic
  ├── Set recovery: Restart on failure (1st, 2nd, subsequent)
  ├── Set service account: LocalSystem
  ├── Create Start Menu shortcut
  ├── Create uninstaller entry in Programs & Features
  └── Start the service immediately
```

#### Modified WiX Configuration: `wix/main.wxs`

Key additions beyond the auto-generated template:

```xml
<!-- Service Installation -->
<ServiceInstall
    Id="RaypherServiceInstall"
    Name="RaypherService"
    DisplayName="Raypher AI Safety Agent"
    Description="Silicon-native sovereign security for AI agents"
    Start="auto"
    Type="ownProcess"
    ErrorControl="normal"
    Account="LocalSystem"
    Arguments="--service" />

<!-- Service Control (Start on install, Stop on uninstall) -->
<ServiceControl
    Id="RaypherServiceControl"
    Name="RaypherService"
    Start="install"
    Stop="both"
    Remove="uninstall"
    Wait="yes" />

<!-- Failure Recovery Actions -->
<util:ServiceConfig
    ServiceName="RaypherService"
    FirstFailureActionType="restart"
    SecondFailureActionType="restart"
    ThirdFailureActionType="restart"
    RestartServiceDelayInSeconds="1"
    ResetPeriodInDays="1" />
```

#### Code Signing

| Stage | Approach |
|---|---|
| **Development** | Self-signed certificate (`makecert`) — triggers Windows SmartScreen warning |
| **Beta** | Let's Encrypt code signing or cheap certificate (~$50/year) |
| **Production** | EV Code Signing Certificate (~$400/year) — instant trust, no SmartScreen |

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Install `cargo-wix`: `cargo install cargo-wix`. Run `cargo wix init` to generate `wix/main.wxs`. Update `Cargo.toml` metadata (description, homepage, license). | WiX scaffold generated |
| **Day 2** | Edit `main.wxs` to add `<ServiceInstall>`, `<ServiceControl>`, and recovery actions. Add custom action for firewall rule if needed. | MSI template with service registration |
| **Day 3** | Build: `cargo wix --nocapture`. Test on a fresh Windows VM (or Windows Sandbox). Verify: service appears in `services.msc`, starts automatically, proxy responds on 8888. | Working MSI installer verified on clean machine |

---

### Co-Founder (Data/Ops) — Build Pipeline Upgrade

#### Modified File: `.github/workflows/release.yml`

The existing release workflow is upgraded to:

1. Build **both** the raw binary AND the MSI installer
2. Build for **3 targets**: Windows (MSI), Linux (binary), ARM64 Linux (binary)
3. Run tests before release
4. Generate checksums for security

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --no-default-features

  build-linux:
    needs: test
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            artifact: raypher-linux-amd64
          - target: aarch64-unknown-linux-gnu
            artifact: raypher-linux-arm64
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Install cross
        run: cargo install cross
      - name: Build
        run: cross build --release --target ${{ matrix.target }} --no-default-features
      - name: Rename & Upload
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: target/${{ matrix.target }}/release/raypher

  build-windows:
    needs: test
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build binary
        run: cargo build --release
      - name: Install cargo-wix
        run: cargo install cargo-wix
      - name: Build MSI
        run: cargo wix --nocapture
      - name: Upload binary
        uses: actions/upload-artifact@v4
        with:
          name: raypher-windows.exe
          path: target/release/raypher.exe
      - name: Upload MSI
        uses: actions/upload-artifact@v4
        with:
          name: RaypherSetup.msi
          path: target/wix/*.msi

  release:
    needs: [build-linux, build-windows]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: artifacts
      - name: Generate checksums
        run: |
          cd artifacts
          find . -type f -exec sha256sum {} \; > SHA256SUMS.txt
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          name: Raypher ${{ github.ref_name }}
          body: |
            ## Raypher ${{ github.ref_name }} — Ghost Protocol

            ### Downloads
            | Platform | File | Notes |
            |---|---|---|
            | Windows (Installer) | `RaypherSetup.msi` | Recommended. Auto-installs as service. |
            | Windows (Binary) | `raypher-windows.exe` | Manual installation. |
            | Linux (AMD64) | `raypher-linux-amd64` | For x86_64 servers. |
            | Linux (ARM64) | `raypher-linux-arm64` | For Raspberry Pi, AWS Graviton. |

            ### Verify Integrity
            ```bash
            sha256sum -c SHA256SUMS.txt
            ```
          files: |
            artifacts/**/*
          draft: false
          prerelease: false
```

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Update `release.yml` with the new multi-platform build matrix. Add the `test` job as a gate before building. | CI/CD pipeline upgraded |
| **Day 2** | Add MSI build step for Windows. Add SHA256 checksum generation. Test by pushing a `v0.2.0-rc1` tag. | Automated MSI generation in CI |
| **Day 3** | Verify all artifacts appear in the GitHub Release page. Download and test on a clean machine. | End-to-end release pipeline verified |

---

## Week 8: The Immortal — Self-Update & Watchdog

### Philosophy

> *"A good security agent doesn't just refuse to die — it evolves while running."*

This week makes Raypher self-healing and self-updating.

---

### Founder (Cybersecurity) — The Watchdog

#### Windows Service Recovery Configuration

After the MSI installer registers the service, we configure recovery via `sc.exe`:

```powershell
# Configure the service to restart on ANY failure
sc failure RaypherService reset=86400 actions=restart/1000/restart/1000/restart/1000

# Translation:
#   reset=86400    → After 24 hours of running fine, reset the crash counter
#   actions=       → On 1st failure: restart after 1 second
#                    On 2nd failure: restart after 1 second
#                    On 3rd failure: restart after 1 second
```

**Why this is superior to `loop { run() }` in Rust:**

- If Rust panics, the entire process crashes. A `loop` around `run()` won't catch panics on other threads
- The OS restarter gives a **clean slate** — fresh memory, fresh file handles
- The OS logs the crash in Event Viewer — you get forensics for free

#### Watchdog Process Monitoring

In addition to OS-level recovery, implement a lightweight watchdog within the service:

```rust
// src/watchdog.rs
pub struct Watchdog {
    /// Maximum time without a successful scan cycle
    pub heartbeat_timeout: Duration,
    /// Last successful heartbeat
    last_heartbeat: Instant,
}

impl Watchdog {
    /// Called by the Watchtower after each successful scan cycle
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Returns true if the system is healthy
    pub fn is_healthy(&self) -> bool {
        self.last_heartbeat.elapsed() < self.heartbeat_timeout
    }
}
```

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Add `sc failure` command to MSI post-install script. Create `src/watchdog.rs` with heartbeat tracking. Wire heartbeat into Watchtower loop. | Self-healing service with internal health monitoring |
| **Day 2** | Test: Kill `raypher.exe` via Task Manager. Verify it restarts within 2 seconds. Kill it 10 times rapidly. Verify the restart rate limit works. | Validated resurrection behavior |

---

### Co-Founder (Data/Ops) — The Auto-Updater

#### How Auto-Update Works

```
Every 6 hours (configurable):
  ├── Check GitHub Releases API for latest version tag
  ├── Compare with current version (from Cargo.toml)
  ├── IF newer version exists:
  │   ├── Download new binary to temp directory
  │   ├── Verify SHA-256 checksum
  │   ├── THE SWAP (Windows):
  │   │   ├── Rename current: raypher.exe → raypher.exe.old
  │   │   ├── Move new binary: temp/raypher.exe → raypher.exe
  │   │   └── Request service restart from SCM
  │   ├── THE SWAP (Linux):
  │   │   ├── mv /usr/local/bin/raypher /usr/local/bin/raypher.old
  │   │   ├── mv /tmp/raypher-new /usr/local/bin/raypher
  │   │   ├── chmod +x /usr/local/bin/raypher
  │   │   └── systemctl restart raypher
  │   └── Log UPDATE event to audit ledger
  └── IF same version: sleep until next check
```

#### New File: `src/updater.rs`

```rust
use self_update::backends::github::Update;

pub struct UpdateConfig {
    /// GitHub repo owner
    pub repo_owner: String,
    /// GitHub repo name
    pub repo_name: String,
    /// Current version (from Cargo.toml)
    pub current_version: String,
    /// How often to check (default: 6 hours)
    pub check_interval: Duration,
}

pub async fn check_and_update(config: &UpdateConfig) -> Result<bool, Box<dyn Error>> {
    let status = Update::configure()
        .repo_owner(&config.repo_owner)
        .repo_name(&config.repo_name)
        .bin_name("raypher")
        .current_version(&config.current_version)
        .no_confirm(true)  // Don't prompt — we're a service, there's no user
        .build()?
        .update()?;

    Ok(status.updated())
}
```

#### Security — The Update Chain of Trust

| Check | How |
|---|---|
| **Source verification** | Only accept updates from the configured GitHub repo (hardcoded owner/name) |
| **Integrity check** | SHA-256 checksum verification of downloaded binary |
| **Rollback** | Keep `.old` binary for 24 hours in case new version crashes |
| **Audit** | Log every update attempt (success or failure) to the audit ledger |

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | Add `self_update` crate. Create `src/updater.rs`. Implement `check_and_update()`. Add update check to the service startup and on a timer (every 6 hours). | Auto-update mechanism implemented |
| **Day 2** | Test: Create a `v0.2.0-test` release on GitHub with a dummy binary. Run the updater. Verify it downloads, verifies checksum, and swaps the binary. Verify the `.old` file exists as rollback. | Update lifecycle verified end-to-end |
| **Day 3** | Implement rollback logic: if the new binary crashes within 5 minutes of update, auto-revert to `.old`. Add `raypher update --check` CLI command to manually trigger update check. | Rollback safety net + manual update trigger |

---

## Enhancement: Health & Telemetry Endpoint

> **Not in the original plan — Added because it makes Raypher significantly more operationally useful.**

### New File: `src/health.rs`

When running in service mode, expose a health endpoint on the proxy server:

```
GET http://127.0.0.1:8888/health

Response:
{
  "status": "healthy",
  "version": "0.2.0",
  "uptime_secs": 86400,
  "silicon_id": "345318b3ab82f55...",
  "watchtower": {
    "scan_cycles": 43200,
    "avg_scan_ms": 12.3,
    "active_threats": 0,
    "last_scan": "2026-02-14T15:00:00Z"
  },
  "proxy": {
    "requests_served": 1847,
    "requests_blocked": 3,
    "avg_latency_ms": 45.2
  },
  "database": {
    "total_events": 2094,
    "db_size_bytes": 524288
  }
}
```

**Why this matters:**

- Enterprise IT teams need to monitor Raypher's health across 1,000 machines
- This endpoint can be scraped by Prometheus/Datadog/Grafana
- It's the building block for Phase 10's Unified Dashboard

---

## Enhancement: Structured Logging for Service Mode

> **Critical enhancement — Without this, debugging the service is impossible.**

### Problem

In CLI mode, `println!` works fine. In service mode, there is **no console** — `println!` goes to `/dev/null` (or crashes on Windows).

### Solution

Upgrade `tracing-subscriber` to output to **a log file** when in service mode:

```rust
// In service mode, log to file instead of stdout
fn init_service_logging() {
    let log_dir = dirs_next().unwrap().join(".raypher").join("logs");
    fs::create_dir_all(&log_dir).unwrap();

    let file = File::create(log_dir.join("raypher.log")).unwrap();

    tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)       // No color codes in log files
        .with_target(true)      // Show module path
        .with_level(true)       // Show INFO/WARN/ERROR
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .init();
}
```

**Log rotation:** Use `tracing-appender` for daily log rotation with 7-day retention:

```rust
let file_appender = tracing_appender::rolling::daily(&log_dir, "raypher.log");
let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
```

---

## Enhancement: Configuration File System

> **Not in the original plan — Added because hardcoding configuration is not enterprise-ready.**

### New File: `config/raypher.toml`

Instead of hardcoding proxy port, update interval, scan frequency, etc., use a TOML configuration file:

```toml
[service]
# How the service identifies itself
name = "RaypherService"
display_name = "Raypher AI Safety Agent"

[proxy]
# Localhost proxy settings
listen_addr = "127.0.0.1"
listen_port = 8888
# Default upstream API
default_upstream = "https://api.openai.com"
# Max requests per PID per minute
rate_limit = 100
# Connection pool settings
pool_idle_timeout_secs = 90
pool_max_idle_per_host = 10

[watchtower]
# Scan interval in seconds
scan_interval_secs = 2
# Minimum risk level to alert on
alert_threshold = "Medium"
# Show verbose output
verbose = false

[updater]
# Auto-update settings
enabled = true
check_interval_hours = 6
repo_owner = "kidigapeet"
repo_name = "raypherweb"

[logging]
# Log level: trace, debug, info, warn, error
level = "info"
# Log directory (relative to ~/.raypher/)
log_dir = "logs"
# Number of days to keep log files
retention_days = 7
```

### New File: `src/config.rs`

```rust
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct RaypherConfig {
    pub service: ServiceConfig,
    pub proxy: ProxyConfig,
    pub watchtower: WatchtowerConfig,
    pub updater: UpdaterConfig,
    pub logging: LoggingConfig,
}

impl RaypherConfig {
    pub fn load() -> Self {
        let config_path = Self::config_path();
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path).unwrap();
            toml::from_str(&content).unwrap()
        } else {
            Self::default()  // Use hardcoded defaults if no config file
        }
    }

    fn config_path() -> PathBuf {
        let home = dirs_next().unwrap();
        home.join(".raypher").join("config.toml")
    }
}
```

---

## The Ghost User Experience

When Phase 2 is complete, this is the end-to-end experience:

### 1. Installation (One-Time)

```
User downloads: RaypherSetup-v0.2.0.msi
Double-clicks → "Next, Next, Finish"
Result: Raypher is now running. No window opens. No tray icon. Invisible.
```

### 2. Configuration (One-Time)

```powershell
# Seal the OpenAI API key into the TPM vault
PS> raypher seal --provider openai
  Enter API Key: ████████████████████
  ✅ Key sealed for provider 'openai'

# Register the Python interpreter as an authorized caller
PS> raypher allow --exe-path "C:\Python312\python.exe"
  ✅ python.exe registered (hash: a3b8d1...)

# Check status
PS> raypher status
  ╔══════════════════════════════════════╗
  ║   RAYPHER — System Status            ║
  ╠══════════════════════════════════════╣
  ║ Service:    RUNNING                  ║
  ║ Uptime:     3h 42m                   ║
  ║ Proxy:      127.0.0.1:8888 (active)  ║
  ║ Sealed Keys: 1 (openai)             ║
  ║ Allow List:  1 process               ║
  ║ Silicon ID:  345318b3ab82...         ║
  ╚══════════════════════════════════════╝
```

### 3. Operation (Daily)

```python
# agent.py — The developer's code doesn't change!
import requests

response = requests.post(
    "http://localhost:8888/v1/chat/completions",  # ← Points to Raypher, not OpenAI
    headers={"X-Raypher-Token": "agent-1"},       # ← Dummy token, Raypher handles the real key
    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}
)
print(response.json())
```

### 4. Persistence

```
User reboots laptop.
Raypher is already running before the user logs in.
The proxy is ready. The watchtower is scanning. The ghost is awake.
```

### 5. Self-Healing

```
Malware runs: taskkill /f /im raypher.exe
1 second later: Raypher is back. The event is logged. The IT team is alerted.
```

---

## Phase 2 Final Checklist

### Week 5 — The Daemon

- [ ] `windows-service` crate added and `src/service.rs` implemented
- [ ] Service reports `RUNNING` to SCM within 30 seconds
- [ ] `--service` flag detection in `main.rs`
- [ ] Service survives user logout
- [ ] Service starts on boot
- [ ] `systemd` unit file created and tested on Linux
- [ ] Restart rate-limiting works (`StartLimitBurst`)

### Week 6 — The Vault

- [ ] `axum` proxy server running on `127.0.0.1:8888`
- [ ] `POST /v1/chat/completions` forwards to OpenAI
- [ ] PID verification: calling process identified from TCP socket
- [ ] Exe hash verification: process checked against allow list
- [ ] TPM-sealed API key injection into forwarded request
- [ ] `raypher seal --provider <name>` encrypts and stores key
- [ ] `raypher unseal --provider <name>` decrypts and displays key
- [ ] `raypher secrets` lists all sealed providers
- [ ] `raypher allow --exe-path <path>` registers authorized process
- [ ] All proxy events logged to audit ledger

### Week 7 — The Factory

- [ ] `cargo-wix` generates working MSI installer
- [ ] MSI installs service, starts it, configures recovery
- [ ] MSI works on fresh Windows VM / Windows Sandbox
- [ ] CI/CD builds all 4 artifacts (Linux AMD64, Linux ARM64, Windows exe, Windows MSI)
- [ ] SHA-256 checksums generated and included in release
- [ ] GitHub Release page populated automatically on tag push

### Week 8 — The Immortal

- [ ] Service restarts within 2 seconds of being killed
- [ ] Restart rate limiter prevents CPU burn from crash loops
- [ ] `self_update` checks for new versions every 6 hours
- [ ] Binary swap works on Windows (rename + replace + restart)
- [ ] Binary swap works on Linux (mv + chmod + systemctl restart)
- [ ] Update events logged to audit ledger
- [ ] Rollback to `.old` binary if new version crashes within 5 minutes

### Enhancements

- [ ] `/health` endpoint returns JSON status
- [ ] Structured logging to file in service mode (with rotation)
- [ ] TOML configuration file system (`~/.raypher/config.toml`)
- [ ] `raypher status` CLI command shows service health

---

## New Files Summary (Phase 2)

| File | Purpose | Estimated Lines |
|---|---|---|
| `src/service.rs` | Windows Service dispatcher, SCM communication | ~150 |
| `src/proxy.rs` | HTTP reverse proxy on localhost:8888 | ~250 |
| `src/secrets.rs` | TPM seal/unseal for API keys | ~120 |
| `src/updater.rs` | Auto-update from GitHub Releases | ~80 |
| `src/watchdog.rs` | Internal heartbeat monitoring | ~50 |
| `src/health.rs` | Health endpoint for operational monitoring | ~60 |
| `src/config.rs` | TOML configuration loader | ~80 |
| `deploy/raypher.service` | systemd unit file for Linux | ~25 |
| `deploy/install-linux.sh` | Linux install script | ~30 |
| `wix/main.wxs` | Windows MSI installer configuration | ~100 |
| `config/raypher.toml` | Default configuration template | ~40 |

**Total new code: ~985 lines across 11 files**

---

> **You have built the Engine (Phase 1). Now you are building the Vehicle.**
> **When Phase 2 is complete, Raypher is not a tool you run — it is a force that runs itself.**
