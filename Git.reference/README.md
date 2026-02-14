<![CDATA[# RAYPHER — The Operating System for AI Security

> **"No other platform on earth connects hardware identity to kernel enforcement to enterprise governance in one binary."**

Raypher is a silicon-native, sovereign security platform that monitors, controls, and governs autonomous AI agents at the hardware and OS level. It runs as an invisible background service, binds its identity to physical TPM silicon, and sits between AI agents and the outside world — intercepting, auditing, and enforcing policy on every action.

**Repository:** [github.com/kidigapeet/Raypher-core](https://github.com/kidigapeet/Raypher-core)
**Version:** `v0.2.0`
**Language:** Rust
**License:** MIT

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Feature Map — All 10 Phases](#feature-map--all-10-phases)
  - [Phase 1 — The Foundation (Silicon Sentinel)](#phase-1--the-foundation-silicon-sentinel)
  - [Phase 2 — The Ghost Protocol (Invisibility & Persistence)](#phase-2--the-ghost-protocol-invisibility--persistence)
  - [Phase 3 — The Local Guard (Kernel-Level Enforcement)](#phase-3--the-local-guard-kernel-level-enforcement)
  - [Phase 4 — The Network Proxy (Air Traffic Controller)](#phase-4--the-network-proxy-air-traffic-controller)
  - [Phase 5 — The Policy Engine (The Constitution)](#phase-5--the-policy-engine-the-constitution)
  - [Phase 6 — Shadow AI Discovery (The Sonar)](#phase-6--shadow-ai-discovery-the-sonar)
  - [Phase 7 — Data Loss Prevention (The Content Filter)](#phase-7--data-loss-prevention-the-content-filter)
  - [Phase 8 — The Trust Score (FICO Score for AI)](#phase-8--the-trust-score-fico-score-for-ai)
  - [Phase 9 — The Audit Ledger (The Flight Recorder)](#phase-9--the-audit-ledger-the-flight-recorder)
  - [Phase 10 — The Unified Dashboard (God Mode)](#phase-10--the-unified-dashboard-god-mode)
- [Source File Map](#source-file-map)
- [CLI Reference](#cli-reference)
- [Installation](#installation)
- [Build From Source](#build-from-source)
- [Completion Checklist — Where We Are](#completion-checklist--where-we-are)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER / AI AGENT LAYER                         │
│    python agent.py  ·  OpenClaw  ·  LangChain  ·  CrewAI        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP to localhost:8888
┌──────────────────────────▼──────────────────────────────────────┐
│                     RAYPHER PROXY LAYER                          │
│  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ PID      │ │ EXE Hash     │ │ Secret   │ │ Audit Logger  │  │
│  │ Resolver │ │ Verification │ │ Injector │ │ (DB Ledger)   │  │
│  └──────────┘ └──────────────┘ └──────────┘ └───────────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS (real API key injected)
┌──────────────────────────▼──────────────────────────────────────┐
│                  EXTERNAL API PROVIDERS                          │
│    api.openai.com  ·  api.anthropic.com  ·  huggingface.co      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    RAYPHER CORE ENGINE                           │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Scanner  │ │ Heuristics │ │ Killer / │ │ Watchdog        │  │
│  │ (sysinfo)│ │ (3-Level)  │ │ Terminat.│ │ (Auto-Restart)  │  │
│  └──────────┘ └────────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Identity │ │ Secrets    │ │ Database │ │ Watchtower      │  │
│  │ (TPM 2.0)│ │ (Vault)    │ │ (SQLite) │ │ (Monitor Loop)  │  │
│  └──────────┘ └────────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Updater  │ │ Config     │ │ Safety   │ │ Panic Protocol  │  │
│  │ (GitHub) │ │ (TOML)     │ │ (Filter) │ │ (Dead Man's SW) │  │
│  └──────────┘ └────────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          Windows Service (SCM) / Linux Daemon (systemd)  │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    HARDWARE LAYER                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  TPM 2.0 Chip — Endorsement Key (EK) — Machine DNA      │   │
│  │  SHA-256 Fingerprint · Seal/Unseal · Hardware Binding    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Language** | Rust | Memory-safe, zero-cost abstractions, native binary |
| **Process Discovery** | `sysinfo` crate | Cross-platform process enumeration |
| **Hardware Identity** | Windows CNG / `tss-esapi` | TPM 2.0 chip communication |
| **CLI Framework** | `clap` (derive) | Structured CLI parsing |
| **Serialization** | `serde` + `serde_json` + `toml` | JSON output, TOML config |
| **Logging** | `tracing` + `tracing-subscriber` + `tracing-appender` | Structured, production-grade logging |
| **HTTP Server** | `axum` (async) | High-speed localhost proxy |
| **HTTP Client** | `reqwest` (rustls) | Forwards proxied API calls |
| **Database** | `rusqlite` (bundled SQLite) | Local secrets, policies, audit events |
| **Windows Service** | `windows-service` crate | SCM integration, auto-start on boot |
| **Linux Daemon** | `systemd` unit file | Auto-start, restart on failure |
| **Installer** | `cargo-wix` (WiX MSI) | Professional Windows installer |
| **CI/CD** | GitHub Actions | Automated cross-platform releases |
| **TLS** | `rustls` (pure Rust) | No OpenSSL "DLL Hell" |
| **Auto-Update** | `self_update` crate | Binary hot-swap from GitHub Releases |
| **Cross-Compile** | `cross` crate | Docker-based cross-compilation |
| **Async Runtime** | `tokio` (full) | Async I/O for proxy and service |
| **Hashing** | `sha2` + `hex` | SHA-256 for fingerprints and integrity |

---

## Feature Map — All 10 Phases

### Phase 1 — The Foundation (Silicon Sentinel)

> **Goal:** Build the Rust engine that sees, identifies, judges, and kills rogue AI processes. Bind the binary to physical silicon so it cannot be cloned.

#### 1.1 — Process Scanner (`scanner.rs`)

The **Hunter**. Enumerates every running process using `sysinfo`:

- `ProcessData` struct capturing: PID, name, command-line args, memory, CPU usage, parent PID, exe path, confidence level, risk level, risk reason, scan timestamp
- `DataConfidence` enum: `Full` / `Partial` / `Low` — degrades gracefully when OS denies access to process details
- Outputs structured JSON via `serde_json` for downstream consumption
- Handles elevated process visibility (System processes return empty command lines → falls back to process name with `Low` confidence)

#### 1.2 — Heuristic Risk Engine (`heuristics.rs`)

The **Judge**. Three-level escalating risk analysis:

| Level | Method | Trigger → Risk |
|---|---|---|
| **Level 1** | Binary Name Match | `ollama`, `uvicorn`, `torchserve`, `llama.cpp` → **MEDIUM** |
| **Level 2** | Argument Analysis | `python` + args containing `langchain`, `openai`, `autogpt`, `crewai`, `--model`, `--api-key` → **HIGH** |
| **Level 3** | Environment Inspection | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HUGGINGFACE_TOKEN` present → **CRITICAL** |

#### 1.3 — Silicon-Bound Identity (`identity.rs`)

The **Passport**. Binds the binary to the physical TPM 2.0 chip:

- Reads the Endorsement Key (EK) public portion from the TPM
- Computes SHA-256 hash → **Machine Fingerprint** (persistent across reboots)
- Fingerprint stored in database for hardware verification
- **Cloning defense:** Stolen database files are useless on different hardware — the TPM EK is different, decryption fails

**Windows Implementation:** Uses Windows CNG (`Win32_Security_Cryptography`) to access TPM via the platform crypto provider.

#### 1.4 — Process Terminator (`terminator.rs` + `killer.rs`)

The **Executioner**. Recursive process tree kill:

1. Discovers all child processes using `parent_pid` mapping
2. Builds a full process tree (children → grandchildren → ...)
3. Kills **bottom-up** (leaves first, trunk last) to prevent orphan zombies
4. Multi-stage kill chain: Freeze (SIGSTOP) → Tree Hunt (PGID) → Resource Sever (close file descriptors + sockets)

#### 1.5 — Safety Filter (`safety.rs`)

The **Guardrail**. Hard whitelist prevents accidental system kills:

- PIDs < 100 are protected (system processes)
- Suicide check (won't kill its own PID)
- Critical process whitelist: `explorer.exe`, `csrss.exe`, `svchost.exe`, `systemd`, `kernel_task`, `launchd`

#### 1.6 — Panic Protocol (`panic.rs`)

The **Dead Man's Switch**. Emergency shutdown when an agent goes rogue:

- Forensic snapshot of the last 60 seconds of activity
- Context dump: what the agent was doing when Panic triggered
- Immutable audit log entry with timestamp
- Triggered via CLI: `raypher panic --pid <PID>`

#### 1.7 — Watchtower (`watchtower.rs`)

The **Sentry**. Efficient continuous monitoring loop:

- Initializes `System` once, calls `refresh_processes()` incrementally (not `new_all()`)
- 2-second scan interval → < 1% CPU usage
- Graceful `Ctrl+C` handling via `AtomicBool` shutdown flag
- Runs via: `raypher monitor`

---

### Phase 2 — The Ghost Protocol (Invisibility & Persistence)

> **Goal:** Transform `raypher-core.exe` from a CLI tool into an invisible, unkillable System Service that runs on boot, self-updates, and manages API keys through a localhost proxy.

#### 2.1 — Windows Service (`service.rs` + `main.rs`)

The **Split Brain**. Single binary with two personalities:

- **CLI Mode:** Triggered by user (`raypher scan`, `raypher seal`). Prints to console, exits when done.
- **Service Mode:** Triggered by Windows SCM. No console. Reports status within 30 seconds or OS kills it.
- Runs as `LocalSystem` (higher than Admin) — can kill malware, access TPM, bind to ports without firewall popups
- Graceful stop handling via SCM event callbacks
- Service event loop integrates: Watchtower scanning, auto-update checks, watchdog heartbeat

#### 2.2 — Linux Daemon (`deploy/install-linux.sh`)

Systemd unit file with:
- `Restart=always` — instant restart on crash
- `User=root` — permission to kill other processes
- `StartLimitIntervalSec=60` — prevents restart-loop CPU burn

#### 2.3 — Localhost Proxy (`proxy.rs`)

The **Vault Flow**. Man-in-the-middle for API key injection:

1. `axum` HTTP server on `127.0.0.1:8888`
2. Accepts requests to `/v1/chat/completions` (OpenAI-compatible)
3. **The Intercept Chain:**
   - Resolves the calling **PID** from the TCP socket metadata
   - Scans the PID using `sysinfo` → gets exe path
   - Computes **SHA-256 hash** of the calling binary
   - Checks the hash against the **Allow List** in `data.db`
   - ✅ **Match:** Decrypts the real API key from TPM vault, injects `Authorization: Bearer sk-REAL-KEY`, forwards to real API
   - ❌ **No Match:** Drops the connection. Agent gets "Connection Reset"
4. Supports multiple providers: OpenAI, Anthropic, and custom endpoints
5. Connection pooling via `reqwest` Keep-Alive for low latency

#### 2.4 — Secret Manager (`secrets.rs`)

The **Vault**. Hardware-bound secret storage:

- `raypher seal --provider openai` — prompts for API key, encrypts with TPM public key, stores encrypted blob in SQLite `secrets` table
- `raypher unseal --provider openai` — decrypts and displays (only works on same hardware)
- `raypher allow --exe-path <path>` — adds a binary's SHA-256 hash to the proxy allow list
- Secrets never exist in plaintext on disk — TPM-sealed at rest, decrypted only in memory during proxy forwarding

#### 2.5 — Database & Audit Ledger (`database.rs`)

The **Black Box**. SQLite database with structured schema:

- **Tables:** `machine_info`, `secrets`, `allowed_exes`, `events`, `scan_results`
- **Event logging:** Every significant action logged with: timestamp, event_type, details_json, severity
- **Event types:** `MACHINE_REGISTERED`, `SECRET_STORED`, `EXE_ALLOWED`, `SCAN_COMPLETE`, `AUTO_UPDATE`, `UPDATE_ERROR`, `PROCESS_KILLED`
- Auto-initialization: database and tables created on first run

#### 2.6 — Windows Installer (`wix/main.wxs`)

Professional MSI installer via WiX Toolset:
- Service Name: `RaypherService`
- Start Type: `Automatic` (starts on boot)
- Custom Actions: register service with SCM, start immediately after install
- Auto-updating ProductCode UUID for clean upgrades

#### 2.7 — CI/CD Pipeline (`.github/workflows/release.yml`)

GitHub Actions release workflow:
- Triggers on tag push (`v*`)
- Builds Linux binary (`x86_64-unknown-linux-gnu`)
- Builds Windows binary
- Creates GitHub Release with downloadable artifacts

#### 2.8 — Auto-Updater (`updater.rs`)

The **Immortal**. Self-updating binary:

- Checks GitHub Releases for newer version tags
- Downloads new binary in background
- **Binary swap:** Renames current exe → `.old`, moves new binary into place, restarts service
- **5-minute auto-rollback safety net:**
  - After update, writes a timestamped marker file
  - If service restarts within 5 minutes → assumes new binary is bad → restores `.old` binary
  - If service runs > 5 minutes → update deemed stable → cleans up `.old` and `.failed` binaries
- All update events (success, error, stability) logged to DB audit ledger

#### 2.9 — Watchdog (`watchdog.rs`)

The **Guardian**. Unkillable service protection:

- Windows Service Recovery Actions: Restart on every failure (1st, 2nd, subsequent)
- 1-second restart delay
- 24-hour crash counter reset
- OS-level restart (fresh memory) > code-level loop (panic kills everything)

#### 2.10 — TOML Configuration (`config.rs` + `config/raypher.toml`)

The **Brain**. Flexible configuration system:

- Loads settings from `~/.raypher/config.toml`
- Falls back to compiled defaults if file missing
- **Sections:** Service (name, display_name, description), Proxy (host, port, timeout), Watchtower (scan_interval, auto_kill), Updater (enabled, check_interval, repo), Logging (level, file, max_size)
- `write_defaults()` generates a commented default config file

---

### Phase 3 — The Local Guard (Kernel-Level Enforcement)

> **Goal:** Kernel-level interception that blocks dangerous actions *before* they execute.

- **Linux:** eBPF probes (KProbes) attached to system calls: `sys_execve`, `sys_connect`, `sys_unlink`, `sys_open`
- **Windows:** Kernel Callback Drivers (`PsSetCreateProcessNotifyRoutine`) + WFP (Windows Filtering Platform)
- **Cross-platform abstraction:** Developer writes one policy → compiled to eBPF bytecode (Linux) or WFP filter (Windows)
- Identity-aware: Maps Hardware Identity (TPM) to Kernel Enforcement

**Attack Prevention:**

| Scenario | Attack | Hook | Outcome |
|---|---|---|---|
| Sleepy Developer | Agent deletes `production.db` | `sys_unlink` | Deletion blocked |
| Reverse Shell | Agent spawns `/bin/bash` piped to network | `sys_socket` + `sys_execve` | Process killed before connection opens |
| Data Exfiltration | Agent uploads `customer_emails.txt` to `pastebin.com` | `sys_connect` | Connection reset, data never leaves |

---

### Phase 4 — The Network Proxy (Air Traffic Controller)

> **Goal:** Transparent local proxy with TLS termination. No code changes required from the developer.

- **Local MITM:** Generates a unique Root CA on install, installs into OS Trust Store
- **TLS Termination:** Raypher presents certificates signed by its local CA → decrypts traffic → inspects → re-encrypts → forwards
- **Zero code changes:** Catches traffic at OS level (`iptables` / WFP), not via `base_url` changes

**Four Defense Layers:**

| Layer | Defense | Mechanism |
|---|---|---|
| **SSRF Prevention** | Block all private IP ranges (`10.0.0.0/8`, `192.168.x.x`, `169.254.x.x`) | Prevents AWS metadata access |
| **Domain Whitelisting** | Policy: "Finance Agent ONLY talks to `api.openai.com` + `stripe.com`" | Any other domain → dropped |
| **Data Loss Prevention** | Regex scan on body payload (Visa cards, API keys, SSNs) | Match → BLOCK, request never leaves |
| **Budget Enforcement** | Track token usage + cost per agent. Daily limit = $50.00 | At $50.01 → return `429 Too Many Requests` |

---

### Phase 5 — The Policy Engine (The Constitution)

> **Goal:** Transform vague business intent into binary machine logic. Policy as Code.

**The Four Pillars:**

| Pillar | What It Controls | Example |
|---|---|---|
| **Operational** | File system, process spawning, hardware access | `Block Write: /system/*`, `Block Spawn: /bin/bash` |
| **Financial** | Cost limits, model restrictions | `Daily Limit: $20`, `Block: gpt-4-32k unless Senior Engineer` |
| **Network** | Domain allowlists, DLP rules | `Allow: *.openai.com`, `Block if body contains sk-...` |
| **Temporal** | Time-fencing | `Allow: Mon-Fri 09:00-18:00`, `Block: Weekends` |

**Cascading Hierarchy:**
1. **Global Policy (CISO)** → Cannot be overridden
2. **Team Policy (Manager)** → "Backend can access AWS. Frontend cannot."
3. **Local Policy (Developer)** → "Stop if agent spends > $5."

Conflict resolution: **Most Restrictive** rule always wins.

**Dynamic Trust-Based Policies:** Rules adapt based on Trust Score:
- Score > 900 → Allow file deletion (auto)
- Score 700-899 → Require human approval (pop-up)
- Score < 700 → Block file deletion

---

### Phase 6 — Shadow AI Discovery (The Sonar)

> **Goal:** Find every AI model, agent process, and vector database running in the dark — before you install a policy.

**Multi-Layer Reconnaissance:**

| Layer | Method | What It Finds |
|---|---|---|
| **Process Scanning** | Binary names + args + loaded DLLs | `ollama`, `python (running langchain)`, GPU-accelerated AI even if renamed |
| **Port Listening** | Monitor known AI ports | 11434 (Ollama), 8000 (ChromaDB), 6333 (Qdrant), 5000 (Flask) |
| **Network Inspection** | DNS cache + payload shape analysis | API calls to `api.anthropic.com`, LLM chat completion protocol patterns |
| **mDNS Discovery** | Multicast DNS queries | `_ollama._tcp.local`, rogue AI servers on same network |

---

### Phase 7 — Data Loss Prevention (The Content Filter)

> **Goal:** Automatic redaction engine scanning every byte of outbound data. Sanitize at the source.

**Hybrid Inspection Engine:**

| Layer | Speed | Technology | Coverage |
|---|---|---|---|
| **Regex Engine** | Microseconds | Optimized Rust (ripgrep-style) | Credit cards, SSNs, API keys (OpenAI, GitHub PAT, AWS), crypto wallets, emails |
| **Contextual NER** | Milliseconds | Local Named Entity Recognition | Names, addresses, phone numbers, proprietary code |
| **Presidio Integration** | — | Microsoft Presidio | Industry-standard PII detection (trusted by banks) |

**Actions:** Redact (sanitize in-flight: SSN → `[REDACTED]`) or Block (HTTP 403, quarantine).

**Compliance:** GDPR (PII stays on device), HIPAA (patient IDs blocked), PCI-DSS (card numbers never transmitted).

---

### Phase 8 — The Trust Score (FICO Score for AI)

> **Goal:** Dynamic, real-time reputation system. Score 0-1000 governing agent privileges.

| Score | Status | Privileges |
|---|---|---|
| **900+** | Autonomous | Deploy code, move money |
| **700-899** | Probationary | Human approval for sensitive actions |
| **< 500** | Restricted | Read-only, sandboxed |

**The Algorithm — Three Pillars:**

| Pillar | Weight | Factors |
|---|---|---|
| **Behavioral History** | 60% | Violation rate (-50/violation), crash rate (-10/crash), cost efficiency, hallucination rate |
| **Identity & Provenance** | 20% | TPM binding (+100), code signature verification, developer reputation tier |
| **Community Intelligence** | 20% | Global blocklist (500+ blocks → toxic), CVE vulnerability alerts (-200 until patched) |

**Score decay:** Idle for 30 days → score drops (halflife). Agent must "prove" itself again.

---

### Phase 9 — The Audit Ledger (The Flight Recorder)

> **Goal:** Cryptographically signed, immutable record of every agent action. Legally admissible chain of custody.

**Merkle Chain (Blockchain-Lite):**

1. **Atomic Entry:** Actor (Agent_ID + TPM Signature), Action (syscall + target), Policy (ID + result), Context (Trust Score), Timestamp (NTP atomic clock)
2. **SHA-256 Hash:** Each entry hashed → tamper detection
3. **Chain Link:** Each entry includes previous entry's hash → breaking the chain flags `CORRUPTED` → alerts CISO

**Tiered Storage:**

| Layer | Location | Retention | Purpose |
|---|---|---|---|
| **Local Buffer** | Developer's laptop (encrypted) | 24 hours (Free) | Instant debugging |
| **Cloud Sync** | Raypher Cloud (S3 Immutable) | 30 days (Team) | Centralized reporting |
| **Cold Storage** | Customer's own archive (Glacier/Splunk) | **7 years** (Enterprise) | Legal defense |

---

### Phase 10 — The Unified Dashboard (God Mode)

> **Goal:** Single visual interface where all features converge. The reason CISOs sign the $100,000 check.

**Three "God Mode" Views:**

| View | Question It Answers | Key Feature |
|---|---|---|
| **API Watchtower** | "Who is using our OpenAI key right now?" | Live streaming connections + "Kill Connection" button |
| **Database X-Ray** | "Which agents touch the customer DB?" | Visualized data flow lines, `DROP TABLE` → RED alert |
| **Trust Leaderboard** | "Which of my 5,000 agents is about to go rogue?" | Ranked by risk, CISO focuses on Bottom 10 |

**Control Plane:**
- **Global Policy Push:** CISO creates rule → clicks "Deploy Global" → all agents receive in < 2 seconds
- **Global Freeze:** Zero-day in LangChain → "Freeze" → all 2,000 agents suspended in RAM instantly
- **Compliance Report Generator:** SOC2 / ISO 27001 PDF with inventory, access control proof, incident log, cryptographic integrity proofs

**Architecture:** gRPC heartbeats (edge → cloud), WebSocket dashboard (live, no page refresh), Rust/Go ingestor (millions of events/second).

---

## Source File Map

| File | Lines | Size | Purpose |
|---|---|---|---|
| `main.rs` | ~500 | 18 KB | CLI entry point (`clap`), Windows Service dispatcher, module wiring |
| `scanner.rs` | ~280 | 9 KB | Process discovery via `sysinfo`, `ProcessData` struct, JSON output |
| `heuristics.rs` | ~250 | 9 KB | 3-level risk scoring engine (binary name → args → env vars) |
| `identity.rs` | ~180 | 6 KB | TPM 2.0 identity: EK reading, SHA-256 fingerprint, hardware binding |
| `terminator.rs` | ~110 | 4 KB | Recursive process tree kill (bottom-up) |
| `killer.rs` | ~160 | 6 KB | Process kill orchestration, multi-stage kill chain |
| `safety.rs` | ~40 | 1 KB | Hard whitelist: critical process protection |
| `panic.rs` | ~40 | 1 KB | Dead Man's Switch: forensic snapshot + emergency shutdown |
| `watchtower.rs` | ~150 | 5 KB | Efficient monitoring loop, incremental refresh, Ctrl+C handling |
| `proxy.rs` | ~440 | 15 KB | Localhost proxy (axum), PID resolution, secret injection, API forwarding |
| `secrets.rs` | ~170 | 6 KB | TPM-sealed secret storage, seal/unseal commands, allow list management |
| `database.rs` | ~330 | 11 KB | SQLite schema, event logging, CRUD for secrets/allowed exes/scan results |
| `service.rs` | ~400 | 14 KB | Windows Service implementation, SCM integration, main service event loop |
| `watchdog.rs` | ~140 | 5 KB | Service recovery configuration, unkillable service setup |
| `updater.rs` | ~330 | 11 KB | GitHub Releases auto-update, binary swap, 5-min rollback safety net |
| `config.rs` | ~240 | 9 KB | TOML configuration loader, defaults, config file generation |
| `monitor.rs` | ~150 | 5 KB | Real-time monitoring display, process tracking |

**Total: 17 source files · ~3,900 lines · ~135 KB of Rust**

---

## CLI Reference

```
raypher-core — Silicon-native sovereign security for AI agents

USAGE:
    raypher-core <COMMAND>

COMMANDS:
    scan           Scan all running processes and score AI risk levels
    monitor        Run the Watchtower continuous monitoring loop
    seal           Encrypt and store an API key in the TPM-bound vault
    unseal         Decrypt and display a stored API key (same hardware only)
    allow          Add a binary's SHA-256 hash to the proxy allow list
    proxy          Start the localhost API proxy on 127.0.0.1:8888
    kill           Kill a process and its entire child tree
    panic          Emergency shutdown: kill + forensic snapshot
    identity       Display the machine's TPM fingerprint
    update         Check for and apply binary updates from GitHub Releases
    install        Install as a Windows Service (LocalSystem)
    service        Run in Windows Service mode (called by SCM only)
    query          Query the local database (events, scan results, secrets)
    status         Display service status and health
```

---

## Installation

### Windows (MSI Installer)
```powershell
# Download the MSI from GitHub Releases
# Double-click → Next → Next → Finish
# Raypher is now running as a Windows Service (invisible)
```

### Windows (Manual)
```powershell
# Build from source
cargo build --release

# Install as Windows Service
.\target\release\raypher-core.exe install

# Seal your API key
.\target\release\raypher-core.exe seal --provider openai

# Allow your Python runtime
.\target\release\raypher-core.exe allow --exe-path "C:\Python312\python.exe"

# Start the proxy
.\target\release\raypher-core.exe proxy
```

### Linux (systemd)
```bash
curl -fsSL https://github.com/kidigapeet/Raypher-core/releases/latest/download/raypher-linux-amd64 -o /usr/local/bin/raypher
chmod +x /usr/local/bin/raypher
sudo ./deploy/install-linux.sh
```

---

## Build From Source

**Prerequisites:** Rust 1.75+ (with `cargo`), Git

```bash
git clone https://github.com/kidigapeet/Raypher-core.git
cd Raypher-core
cargo build --release
```

**Cross-Compilation:**
```bash
# Install cross
cargo install cross

# Build for Linux from Windows (or vice versa)
cross build --target x86_64-unknown-linux-gnu --release
```

**Release Profile:** LTO enabled, debug symbols stripped, single codegen unit for maximum optimization.

---

## Completion Checklist — Where We Are

### ✅ Phase 1 — The Foundation (Silicon Sentinel) — **100% COMPLETE**

- [x] Process scanner with `ProcessData`, `DataConfidence`, `RiskLevel` enums (`scanner.rs`)
- [x] Graceful fallback when OS denies access to process details
- [x] 3-level heuristic risk engine: binary name → arguments → environment (`heuristics.rs`)
- [x] TPM 2.0 identity: EK reading, SHA-256 machine fingerprint (`identity.rs`)
- [x] Recursive process tree kill (bottom-up, children-first) (`terminator.rs`, `killer.rs`)
- [x] Critical process safety whitelist (`safety.rs`)
- [x] Panic Protocol: emergency shutdown + forensic snapshot (`panic.rs`)
- [x] Watchtower: efficient monitoring loop with < 1% CPU (`watchtower.rs`)
- [x] CLI entry point with `clap` subcommands (`main.rs`)
- [x] Structured JSON output via `serde_json`
- [x] `tracing` structured logging
- [x] Cross-compilation support via `cross` crate
- [x] Release profile: LTO, stripped, single codegen unit

### ✅ Phase 2 — The Ghost Protocol (Invisibility & Persistence) — **100% COMPLETE**

- [x] Windows Service implementation with SCM handshake (`service.rs`, `main.rs`)
- [x] Service runs as `LocalSystem` (higher than Admin)
- [x] Linux daemon systemd unit file (`deploy/install-linux.sh`)
- [x] Localhost proxy on `127.0.0.1:8888` with PID resolution + EXE hash verification (`proxy.rs`)
- [x] Secret injection: TPM-decrypted API key injected into `Authorization` header
- [x] Secret Manager: `seal`, `unseal`, `allow` commands (`secrets.rs`)
- [x] SQLite database with events, secrets, allowed_exes, scan_results tables (`database.rs`)
- [x] Audit event logging: `MACHINE_REGISTERED`, `SECRET_STORED`, `EXE_ALLOWED`, `AUTO_UPDATE`, `UPDATE_ERROR`
- [x] Windows MSI installer via WiX Toolset (`wix/main.wxs`)
- [x] GitHub Actions CI/CD pipeline (`.github/workflows/release.yml`)
- [x] Auto-updater from GitHub Releases with binary swap (`updater.rs`)
- [x] 5-minute auto-rollback safety net with marker file system (`updater.rs`)
- [x] Watchdog: OS-level service recovery on crash (`watchdog.rs`)
- [x] TOML configuration system with defaults (`config.rs`, `config/raypher.toml`)
- [x] All update events (success, error, stability) logged to DB audit ledger

### ⬜ Phase 3 — The Local Guard (Kernel-Level Enforcement) — **NOT STARTED**

- [ ] eBPF probes attached to `sys_execve`, `sys_connect`, `sys_unlink`, `sys_open` on Linux
- [ ] WFP (Windows Filtering Platform) filters functional on Windows
- [ ] Identity-aware interception: maps TPM identity to kernel enforcement
- [ ] Policy checks return correct ALLOW/DENY verdicts
- [ ] No false positives on critical system processes
- [ ] Blocked actions logged with full context to audit ledger

### ⬜ Phase 4 — The Network Proxy (Air Traffic Controller) — **NOT STARTED**

- [ ] Local Root CA certificate generated and installed in OS Trust Store
- [ ] Transparent TLS termination and re-encryption
- [ ] SSRF blocking for all private IP ranges (`10.0.0.0/8`, `192.168.x.x`, `169.254.x.x`)
- [ ] Domain whitelisting enforcement
- [ ] Regex-based DLP scanning on outbound payload bodies
- [ ] Budget tracking and enforcement per agent (daily cost cap)
- [ ] Zero code changes required from the developer (OS-level intercept)

### ⬜ Phase 5 — The Policy Engine (The Constitution) — **NOT STARTED**

- [ ] Policy file format defined (YAML/JSON schema)
- [ ] All four pillars: Operational, Financial, Network, Temporal
- [ ] Cascading hierarchy with "Most Restrictive Wins" conflict resolution
- [ ] Dynamic Trust-Based policies linked to Trust Score
- [ ] Policy hot-reload (no service restart required)
- [ ] Policies external to code (CISO can update without developer involvement)
- [ ] Global Policy Push to all endpoints in < 2 seconds

### ⬜ Phase 6 — Shadow AI Discovery (The Sonar) — **NOT STARTED**

- [ ] Process scanning detects known AI binaries and runtimes
- [ ] Library/DLL analysis detects GPU-accelerated AI (even if binary is renamed)
- [ ] Port monitoring for all known AI service ports
- [ ] Network inspection for LLM API patterns
- [ ] mDNS network discovery for neighboring AI services
- [ ] Discovery Dashboard displays live asset inventory
- [ ] "Silent Mode" (discovery-only, no blocking) for POC deployments

### ⬜ Phase 7 — Data Loss Prevention (The Content Filter) — **NOT STARTED**

- [ ] High-speed Regex engine scanning all outbound payloads
- [ ] All major secret patterns covered (API keys, CC numbers, SSN, crypto wallets, emails)
- [ ] NER model running locally for contextual PII detection
- [ ] Microsoft Presidio integration functional
- [ ] Redaction mode: modify payload in-flight without breaking agent workflow
- [ ] Block mode: return HTTP 403 with clear explanation + audit log
- [ ] Sub-millisecond latency impact on API calls

### ⬜ Phase 8 — The Trust Score (FICO Score for AI) — **NOT STARTED**

- [ ] Trust Score API endpoint returning real-time scores (0-1000)
- [ ] All three pillars contributing: Behavioral (60%), Identity (20%), Community (20%)
- [ ] Score decay over inactivity periods (halflife)
- [ ] Policy Engine consuming Trust Score for dynamic decisions
- [ ] Global Blocklist fed by Free Tier telemetry
- [ ] Vulnerability alert integration (CVE feeds)
- [ ] Score change events logged to Audit Ledger

### ⬜ Phase 9 — The Audit Ledger (The Flight Recorder) — **NOT STARTED**

- [ ] Atomic log entries: Actor (TPM-signed), Action, Policy, Context, Timestamp
- [ ] SHA-256 hash chain linking every entry (Merkle Chain)
- [ ] Tamper detection: broken chain → CORRUPTED flag → CISO alert
- [ ] Local buffer with encryption at rest
- [ ] Cloud sync to immutable object storage (S3 Object Lock)
- [ ] Cold storage export (JSON + cryptographic proofs) for 7-year retention
- [ ] TPM-signed entries (cannot be forged)

### ⬜ Phase 10 — The Unified Dashboard (God Mode) — **NOT STARTED**

- [ ] API Watchtower view with live connection streaming
- [ ] Database X-Ray: visualized agent-to-database data flows
- [ ] Trust Score Leaderboard with ranked risk display
- [ ] Global Policy Push with < 2 second propagation
- [ ] Global Freeze ("Panic Center") for library-specific agent suspension
- [ ] gRPC heartbeat architecture (edge → cloud)
- [ ] WebSocket-powered live dashboard (no page refresh)
- [ ] SOC2 / ISO 27001 Compliance Report generator (PDF)
- [ ] Platform agnostic: Azure, AWS, local laptop agents side-by-side

---

## Overall Progress

```
Phase 1  ████████████████████ 100%  The Foundation (Silicon Sentinel)
Phase 2  ████████████████████ 100%  The Ghost Protocol (Invisibility & Persistence)
Phase 3  ░░░░░░░░░░░░░░░░░░░░   0%  The Local Guard (Kernel-Level Enforcement)
Phase 4  ░░░░░░░░░░░░░░░░░░░░   0%  The Network Proxy (Air Traffic Controller)
Phase 5  ░░░░░░░░░░░░░░░░░░░░   0%  The Policy Engine (The Constitution)
Phase 6  ░░░░░░░░░░░░░░░░░░░░   0%  Shadow AI Discovery (The Sonar)
Phase 7  ░░░░░░░░░░░░░░░░░░░░   0%  Data Loss Prevention (The Content Filter)
Phase 8  ░░░░░░░░░░░░░░░░░░░░   0%  The Trust Score (FICO Score for AI)
Phase 9  ░░░░░░░░░░░░░░░░░░░░   0%  The Audit Ledger (The Flight Recorder)
Phase 10 ░░░░░░░░░░░░░░░░░░░░   0%  The Unified Dashboard (God Mode)
─────────────────────────────────
Overall  ████░░░░░░░░░░░░░░░░  20%  (2 of 10 phases complete)
```

**Current Binary:** 17 source files · ~3,900 lines of Rust · Compiles to single native executable
**Current Status:** Phases 1 & 2 are production-ready. The ENGINE + GHOST are built. Next: The GUARD.

---

*Built by Raypher Labs · Powered by Rust · Anchored to Silicon*
*Last updated: 2026-02-14*
]]>
