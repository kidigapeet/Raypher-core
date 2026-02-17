# RAYPHER: THE COMPLETE BUILD PLAN

## From Zero to Enterprise AI Security Platform — All Phases, All Details

> **"You are not building a tool. You are building a Platform."**

This document is the **single source of truth** for every phase of Raypher's development. It unifies the Founder (Cybersecurity) and Co-Founder (Data/Ops) paths into one sequential, phase-by-phase execution blueprint. Every detail from the Git.reference files is captured here—the philosophy, the code, the architecture, and the strategy.

---

## Table of Contents

1. [Phase 1: The Foundation (Silicon Sentinel)](#phase-1-the-foundation-silicon-sentinel)
2. [Phase 2: The Ghost Protocol (Invisibility & Persistence)](#phase-2-the-ghost-protocol-invisibility--persistence)
3. [Phase 3: The Local Guard (Kernel-Level Enforcement)](#phase-3-the-local-guard-kernel-level-enforcement)
4. [Phase 4: The Network Proxy (Air Traffic Controller)](#phase-4-the-network-proxy-air-traffic-controller)
5. [Phase 5: The Policy Engine (The Constitution)](#phase-5-the-policy-engine-the-constitution)
6. [Phase 6: Shadow AI Discovery (The Sonar)](#phase-6-shadow-ai-discovery-the-sonar)
7. [Phase 7: Data Loss Prevention (The Content Filter)](#phase-7-data-loss-prevention-the-content-filter)
8. [Phase 8: The Trust Score (FICO Score for AI)](#phase-8-the-trust-score-fico-score-for-ai)
9. [Phase 9: The Audit Ledger (The Flight Recorder)](#phase-9-the-audit-ledger-the-flight-recorder)
10. [Phase 10: The Unified Dashboard (God Mode)](#phase-10-the-unified-dashboard-god-mode)

---

## Technology Stack (Core)

| Component | Technology | Why |
|---|---|---|
| **Language** | Rust | Memory-safe, zero-cost abstractions, compiles to native binary |
| **Process Discovery** | `sysinfo` crate | Cross-platform process enumeration |
| **Hardware Identity** | `tss-esapi` crate | Talks to TPM 2.0 chip via C FFI |
| **CLI Framework** | `clap` | Standard Rust CLI parsing |
| **Serialization** | `serde` + `serde_json` | Structured output for downstream consumption |
| **Logging** | `tracing` + `tracing-subscriber` | Structured, production-grade logging |
| **HTTP Server** | `axum` | High-speed async HTTP framework |
| **HTTP Client** | `reqwest` | Forwards proxied API calls |
| **Database** | `rusqlite` | Local SQLite for secrets, policies, logs |
| **Windows Service** | `windows-service` crate | SCM integration for Windows |
| **Linux Daemon** | `systemd` unit file | Auto-start, restart on failure |
| **Installer** | `cargo-wix` (Windows MSI) | Professional Windows installer |
| **CI/CD** | GitHub Actions | Automated cross-platform builds |
| **TLS** | `rustls` | Pure-Rust TLS (avoids OpenSSL "DLL Hell") |
| **Auto-Update** | `self_update` crate | Binary hot-swap from GitHub Releases |
| **Cross-Compile** | `cross` crate | Docker-based cross-compilation |

---

# Phase 1: The Foundation (Silicon Sentinel)

**Goal:** Build the Rust engine that sees, identifies, judges, and kills rogue AI processes. Bind the binary to physical silicon so it cannot be cloned.

**Timeline:** 4 Weeks

**Philosophy:** "Actions do not lie." — We don't analyze text or prompts. We monitor system calls, process trees, and hardware identity. We block the Physics, not the Semantics.

---

## Week 1: The "Hunter" (Process Discovery)

**Objective:** Build a Rust module that sees everything running on the OS, including processes trying to hide.

### Day 1–2: The `sysinfo` Foundation (Scanner Module)

**File:** `src/scanner.rs`

**What You Build:**

- A `ProcessData` struct that captures every running process:

  ```rust
  pub struct ProcessData {
      pid: u32,
      name: String,
      cmd: Vec<String>,
      memory: u64,
      cpu_usage: f32,
      parent_pid: Option<u32>,
      exe_path: Option<String>,
      confidence: DataConfidence,
      risk_level: RiskLevel,
      risk_reason: String,
      scanned_at: DateTime<Utc>,
  }
  ```

- A `DataConfidence` enum: `Full`, `Partial`, `Low`
- A `RiskLevel` enum: `None`, `Low`, `Medium`, `High`, `Critical`
- A `scan_all_processes(system: &System) -> Vec<ProcessData>` function

**The Trap:** When you run `process.cmd()` on a System Process (like Antivirus or Root), it returns an empty list because you lack permissions.

**The Fix:**

```rust
// If cmd is empty, fall back to process name.
// Log a "Low Confidence" warning internally.
let cmd_line = if process.cmd().is_empty() {
    vec![process.name().to_string()] // Fallback
} else {
    process.cmd().to_vec()
};
```

**Senior Review Checklist:**

- [ ] `scan_all_processes()` returns valid data for all processes
- [ ] Graceful fallback when permissions deny access to process details
- [ ] Confidence tagging works correctly (Full/Partial/Low)
- [ ] Output formatted as structured JSON via `serde_json`

### Day 3–5: The Heuristic Engine (Risk Scoring)

**File:** `src/heuristics.rs`

**What You Build:** A `RiskScore` function that classifies every discovered process through three escalating levels of analysis.

**Level 1 — Binary Name Match (→ Risk: MEDIUM):**

- Match known AI binary names: `ollama`, `uvicorn`, `torchserve`, `llama.cpp`
- Match known AI runtime names: `python`, `node`, `ruby` (escalate to Level 2)

**Level 2 — Argument Analysis (→ Risk: HIGH):**

- If binary is `python`, scan the command-line arguments for keywords:
  - `langchain`, `openai`, `api_key`, `huggingface`, `autogpt`, `crewai`
  - `--model`, `--api-key`, `--temperature`
- If any keyword matches → Risk escalates to HIGH

**Level 3 — Environment Variable Inspection (→ Risk: CRITICAL):**

- Try to read `process.environ()`
- Look for: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HUGGINGFACE_TOKEN`
- **Warning:** This often fails on Windows/Mac due to OS protections. Don't rely on it, but log it if you see it.
- If found → Risk escalates to CRITICAL

**Senior Review Checklist:**

- [ ] Level 1 (binary name), Level 2 (arguments), and Level 3 (environment) all functional
- [ ] Unit tests cover all scoring levels including edge cases
- [ ] False positive rate is acceptable (e.g., a normal Python script shouldn't flag HIGH)

### Day 5: CLI Entry Point

**File:** `src/main.rs`

**What You Build:**

- Wire `scanner.rs` and `heuristics.rs` together
- Initialize `tracing` for structured logging
- Create a `System` instance, scan all processes, score them, output JSON
- Basic `clap` CLI with `scan` subcommand

---

## Week 2: The "Hardware Handshake" (TPM Identity)

**Objective:** Bind the binary to the physical silicon so it cannot be cloned. This is the hardest part of Phase 1.

**Philosophy (Silicon-Bound Identity / Digital DNA):**

- Current security = "What You Know" (Passwords, API Keys) — like a $100 bill, anyone can spend it
- Raypher security = "What You Are" (Physical Hardware) — like a retinal scan, you cannot steal it without the physical device

### Day 1–2: Setup FFI (Foreign Function Interface)

**File:** `src/identity.rs`

**Context:** The library `tss-esapi` talks to C code (`tpm2-tss`).

**The Build Trap:** You need the C libraries installed on your machine to compile this.

- **Linux:** `sudo apt install libtss2-dev`
- **Windows:** Download the pre-compiled DLLs for `tpm2-tss`

**What You Build:**

- A function that connects to the TPM context:

  ```rust
  let context = Context::new(TctiNameConf::from_environment_variable())?;
  ```

- A simple test function that proves connection works

### Day 3–4: Read the EK (Endorsement Key)

**What You Build:**

1. Create the EK Handle (`0x81010001` is the standard persistent handle)
2. Read the public part of the Endorsement Key
3. Serialize it to bytes
4. Hash it with SHA-256 → This is the **Machine Fingerprint**

**The Security Check:**

- Run the code. Note the Hash.
- Reboot. Run it again.
- **If the Hash changes, you failed.** It must be persistent across reboots.

**Why This Matters (The "Cloning" Defense):**

- If a hacker steals the entire `data.db` file, they can't decrypt it because the decryption key is burned into the TPM silicon of *that specific laptop*
- If a hacker copies the Docker container to a new server, the TPM on the hacker's machine has a different EK → Decryption fails → API keys remain garbage → Agent crashes → **Theft Impossible**

### Day 5: The "Seal" and "Unseal" Commands

**What You Build:**

- `raypher seal`: Encrypt a secret (e.g., API Key) using the TPM public key, store the encrypted blob in `data.db`
- `raypher unseal`: Decrypt and print the secret (only works on the same hardware)

**TPM Technology Deep Dive:**

- **Endorsement Key (EK):** Factory-burned, unique per chip, never leaves silicon — the "Birth Certificate"
- **Platform Configuration Registers (PCRs):** Stores measurement hashes of the boot chain (BIOS→Bootloader→Kernel→Agent Code). If any component is tampered with, hashes change, and secrets are locked.
- **Sealing:** Encrypt data and bind decryption to specific PCR values. Only this exact hardware in this exact software state can decrypt.

---

## Week 3: The "Terminator" (Panic Protocol)

**Objective:** Kill a process and its children safely. Build the "Dead Man's Switch."

**Philosophy:** AI operates at machine speed (milliseconds). Humans operate at biological speed (seconds). When an agent goes rogue, it can cause millions in damage before a human finds the "Close Window" button. The Panic Protocol is not a "request" to stop — it is a kernel-level mandate.

### Day 1–2: The Recursive Process Tree

**File:** `src/terminator.rs`

**What You Build:**

1. Use `sysinfo` to get the `parent_id` of every running process
2. Build a Map of `Parent → [Children]`
3. Implement recursive tree traversal:

   ```
   Input: Target_PID
   → Find children of Target_PID
   → Find children of those children (Recursion)
   → Collect ALL PIDs into a list
   → Kill them Bottom-Up (Children first, then Parent)
   ```

**Why Bottom-Up Kill Order:** If you kill the parent first, children become "orphans" (zombies). They keep running with no parent to control them. Kill leaves first, then branches, then trunk.

**Multi-Stage Kill Chain:**

1. **Stage 1 — The "Freeze" (SIGSTOP):** Instantaneously suspend the agent and all threads. Preserves RAM state for debugging. Happens in < 1 millisecond.
2. **Stage 2 — The "Tree Hunt" (PGID):** Issue kill signal to the entire Process Group ID. No orphan processes left behind. (`kill -9 -PGID` on Linux)
3. **Stage 3 — The "Resource Sever":** Forcibly close all open File Descriptors and Network Sockets. Even if the process takes 2 seconds to die, its hands are already cut off — no more disk writes or API requests.

### Day 3–4: The "Safety" Filter

**File:** `src/safety.rs`

**The Risk:** You accidentally kill `csrss.exe` (Windows) or `systemd` (Linux) and blue-screen the user.

**What You Build:** A Hard Whitelist.

```rust
fn is_safe_to_kill(pid: u32) -> bool {
    if pid < 100 { return false; }       // System PIDs
    if pid == my_own_pid { return false; } // Suicide check
    let critical = vec!["explorer.exe", "kernel_task", "launchd",
                        "csrss.exe", "systemd", "svchost.exe"];
    // ... check names against critical list ...
}
```

### Day 5: Forensic "Black Box" Dump

**What You Build:** When the Panic Protocol triggers:

1. **Snapshot:** Save the last 60 seconds of API calls and system logs to a sealed file
2. **Memory Dump:** Dump the frozen RAM state to disk (optional)
3. **Context:** Log what the agent was doing when Panic was triggered
4. **Audit Log:** Write immutable event: "Panic Triggered by User at [timestamp]"

---

## Week 4: The "Watchtower" (Automation & Cross-Compilation)

**Objective:** Run the scanner in a loop without eating 100% CPU. Ship the binary to other OSes.

### Day 1–2: The Efficient Monitoring Loop

**File:** `src/watchtower.rs`

**The Trap:** `sysinfo::System::new_all()` is expensive. It scans everything.

**What You Build:**

1. Initialize `System` **once** outside the loop
2. Inside the loop, call `system.refresh_processes()` (incremental update)
3. Add `std::thread::sleep(Duration::from_secs(2))` delay
4. **Result:** < 1% CPU usage

**CLI Integration:**

- `raypher monitor` — runs the watchtower loop
- Graceful `Ctrl+C` handling via `AtomicBool` shutdown flag

### Day 3–5: Cross-Compilation

**What You Build:**

- Use the `cross` crate (Docker-based cross-compilation tool)
- Command: `cross build --target x86_64-pc-windows-gnu --release`
- This compiles a Windows `.exe` from a Linux machine
- **Senior Review:** Use `rustls` instead of `openssl` to avoid "DLL Hell" on Windows

**Release Profile (`Cargo.toml`):**

```toml
[profile.release]
opt-level = 3
lto = true          # Link-Time Optimization
strip = true         # Strip debug symbols
codegen-units = 1    # Maximum optimization
```

### Phase 1 Completion Checklist

- [ ] Can I print my TPM Hash?
- [ ] Can I detect a Python script running `langchain`?
- [ ] Can I kill a process tree without crashing my own laptop?
- [ ] Does my binary run on a different OS than the one I built it on?
- [ ] Does `cargo run -- monitor` handle `Ctrl+C` gracefully?

**If all 5 boxes are checked, Phase 1 is complete. You have built the ENGINE.**

---

# Phase 2: The Ghost Protocol (Invisibility & Persistence)

**Goal:** Transform `raypher.exe` from a CLI tool into a **System Service** that runs automatically on boot, protects itself from termination, and manages API keys securely.

**Timeline:** 4 Weeks (Weeks 5–8)

**Philosophy:** A security tool that requires a terminal window to stay open is not a security tool; it is a toy. To be "Enterprise Ready," Raypher must be invisible, unkillable, and omnipresent.

### The Architecture Shift

| Feature | **Phase 1 (Current)** | **Phase 2 (Target)** |
|---|---|---|
| **Visibility** | Terminal Window Open | **Invisible Background Process** |
| **Lifespan** | Dies when you close window | **Starts on Boot / Restarts on Crash** |
| **Identity** | "Kidigapeet's Process" | **"SYSTEM" / "ROOT" User** |
| **API Keys** | Hardcoded in `.env` | **Intercepted via Local Proxy** |
| **Updates** | `git pull && cargo run` | **Auto-Update via Cloud** |

---

## Week 5: The "Daemon" (Service Refactor)

**Objective:** Make the code capable of running as a Windows Service and a Linux Daemon. The binary now has a "Split Personality."

### The "Split Brain" Architecture

**Personality A: The CLI (User Mode)**

- Triggered when you type `raypher scan` or `raypher seal`
- It prints text to the console (`stdout`)
- It exits when the task is done

**Personality B: The Service (System Mode)**

- Triggered *only* by the Windows Service Control Manager (SCM)
- **It has no console.** If you try `println!("Hello")`, it goes nowhere (or crashes)
- **The "Handshake":** When it starts, it has ~30 seconds to send a "Status Report" to the SCM saying "I am running!" If it fails, Windows kills it
- This is why we need the `windows-service` crate — it handles the heartbeat "ping" to the OS

### Task 5.1: Windows Service Implementation

**File:** `src/main.rs` (refactored)

**What You Build:**

1. Add `windows-service` crate to `Cargo.toml`
2. Create a function `run_service()` that registers the service dispatcher
3. Implement the event handler to catch `ServiceControl::Stop` and trigger the `AtomicBool` shutdown flag
4. **Critical:** Ensure the service reports its status as `Running` to the OS within 30 seconds, or the install will fail
5. The main function detects: "Am I being called by SCM or by a user?" and branches accordingly

**Privilege Level Deep Dive:**

- When you run a terminal as "Admin," you are still a user
- **`LocalSystem`** is a pseudo-account used by the OS kernel. It has higher privileges than Admin. It acts as the computer itself
- **Why Raypher needs LocalSystem:**
  - To kill malware running as Admin
  - To access the TPM chip (raw hardware access)
  - To listen on Port 8888 without triggering Windows Firewall popup

### Task 5.2: Linux Daemon (systemd Unit File)

**File:** `raypher.service`

**What You Build:**

```ini
[Unit]
Description=Raypher AI Security Service
After=network.target

[Service]
ExecStart=/usr/local/bin/raypher monitor
Restart=always
User=root
StartLimitIntervalSec=60

[Install]
WantedBy=multi-user.target
```

**Key Configuration:**

- `ExecStart=/usr/local/bin/raypher monitor` — Run the watchtower
- `Restart=always` — If it crashes, restart it instantly
- `User=root` — We need permission to kill other processes
- `WantedBy=multi-user.target` — Start when the OS boots
- **Senior Review:** `StartLimitIntervalSec=60` — If Raypher crashes in a loop (e.g., DB is locked), `Restart=always` will cause a "Restart Loop" burning 100% CPU. This rate-limits restarts.

---

## Week 6: The "Vault" (Localhost Proxy)

**Objective:** Build the "Man-in-the-Middle" feature. Raypher sits between the Agent and the Internet to inject secrets. No API key ever touches disk in plaintext.

### Task 6.1: The Proxy Server

**File:** `src/proxy.rs`

**What You Build:**

1. Start an `axum` HTTP server on `127.0.0.1:8888`
2. Accept POST requests to `/v1/chat/completions` (OpenAI compatible endpoint)
3. **The Intercept Chain — "The Vault Flow":**
   - **Step 1 — The Trigger:** The user's Python script sends:

     ```python
     requests.post("http://localhost:8888/v1/chat/completions",
                   headers={"X-Raypher-Token": "dummy"})
     ```

   - **Step 2 — The Pause:** Raypher receives the request. It does NOT forward it yet.
   - **Step 3 — The CSI Investigation (The Hard Part):**
     - Raypher looks at the TCP connection metadata
     - Asks the OS Kernel: "Which Process ID (PID) owns the other end of this TCP socket?"
     - OS responds: "PID 4512"
   - **Step 4 — The Verification:**
     - Raypher scans PID 4512 using `sysinfo`
     - Calculates SHA-256 hash of the `.exe`
     - Compares it to the "Allow List" in `data.db`
   - **Step 5 — The Action:**
     - **Match:** Raypher asks TPM to decrypt the *real* OpenAI key, injects `Authorization: Bearer sk-REAL-KEY` into the header, forwards request to `api.openai.com`
     - **No Match:** Raypher drops the connection. The script gets a "Connection Reset" error.

**Senior Review:**

- **Latency:** The proxy adds latency. Ensure `reqwest` reuses connections (Keep-Alive / Connection Pooling) or agents will be slow.

### Task 6.2: The Secret Manager CLI

**What You Build:**

1. `raypher seal` command:
   - Prompt user: "Enter API Key"
   - Encrypt the key using the TPM public key (from Phase 1)
   - Store the encrypted blob in `data.db` under a new `secrets` table
2. The proxy reads from this `secrets` table at runtime

---

## Week 7: The "Factory" (Installers & CI/CD)

**Objective:** You cannot ask a lawyer to install Rust. You need a `.msi` file.

### Task 7.1: The Windows Installer (MSI)

**What You Build:**

1. Install `cargo-wix`: `cargo install cargo-wix`
2. Initialize: `cargo wix init` — Generates `main.wxs` from `Cargo.toml`
3. Edit `main.wxs` to include a `<ServiceInstall>` tag:
   - Service Name: `RaypherService`
   - Start Type: `Automatic` (starts on boot)
4. Sign the binary (self-signed for now, purchase code-signing certificate later)

**WiX Toolset Deep Dive:**

- WiX is the "C++ of Installers" — XML-based configuration for Windows Installer packages
- **Why WiX is critical:** Allows "Custom Actions" — e.g., "After copying files, immediately register 'RaypherService' with SCM and start it"
- **Alternative (bad):** Batch scripts are fragile, trigger antivirus warnings, and look unprofessional
- **The UUID Magic:** Every MSI needs a unique "ProductCode" UUID. `cargo-wix` auto-updates this UUID on version bumps so Windows knows it's an *upgrade*, not a new app

### Task 7.2: The Build Pipeline (GitHub Actions)

**File:** `.github/workflows/release.yml`

**What You Build:**

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Linux Binary
        run: cargo build --release --target x86_64-unknown-linux-gnu
      - name: Upload Linux Artifact
        uses: actions/upload-artifact@v4
        with:
          name: raypher-linux-amd64
          path: target/x86_64-unknown-linux-gnu/release/raypher

  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install cargo-wix
        run: cargo install cargo-wix
      - name: Build Windows MSI
        run: cargo wix
      - name: Upload Windows MSI
        uses: actions/upload-artifact@v4
        with:
          name: raypher-windows.msi
          path: target/wix/*.msi

  release:
    needs: [build-linux, build-windows]
    runs-on: ubuntu-latest
    steps:
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            raypher-linux-amd64
            raypher-windows.msi
```

**Senior Review:**

- **Cross-Compilation:** Rust makes this easy, but `openssl` is painful. Use `rustls` instead of `openssl` (native Rust TLS) to avoid "DLL Hell" on Windows.

---

## Week 8: The "Immortal" (Self-Update & Watchdog)

**Objective:** Raypher must update itself and refuse to die.

### Task 8.1: The Watchdog (Unkillable Service)

**The Challenge:** A virus will try to `taskkill raypher.exe`.

**What You Build:**

- Configure Windows Service Recovery Actions:
  - First Failure: **Restart the Service**
  - Second Failure: **Restart the Service**
  - Subsequent Failures: **Restart the Service**
  - `Restart/1000` — Wait 1 second, then restart
  - `Reset=86400` — If running fine for 24 hours, reset crash counter to zero

**Why OS-Level Restart > Code-Level Loop:**

- If you write `loop { run() }` inside Rust, a panic still kills the whole process
- By letting the *OS* handle the restart, you get a clean slate (fresh memory) every time

### Task 8.2: The Auto-Updater

**What You Build:**

1. Integrate `self_update` crate into `main.rs`
2. On startup, check GitHub Releases for a newer version tag (e.g., `v0.2.0`)
3. If found, download the binary in the background
4. **The Swap (Windows-specific):**
   - You can't replace a running `.exe`
   - Rename current exe to `raypher.exe.old`
   - Move new binary to `raypher.exe`
   - Restart the service
5. Old binary is cleaned up on next boot

---

### Phase 2: The "Ghost" User Experience

**What the user sees after Phase 2 is complete:**

1. **Installation:**
   - Download `RaypherSetup.msi`
   - Double-click. "Next, Next, Finish."
   - *Result:* Raypher is now running. No window opens.

2. **Configuration:**
   - Open PowerShell: `raypher seal` → Enter OpenAI Key
   - *Result:* Key is locked in TPM.

3. **Operation:**
   - Run agent: `python agent.py`
   - Agent tries to hack something → **Raypher blocks it silently.**
   - Check logs: `raypher logs` → See the block event.

4. **Persistence:**
   - Reboot the laptop
   - Raypher is already running before the user logs in.

### Phase 2 Completion Checklist

- [ ] Does `cargo run -- monitor` handle `Ctrl+C` gracefully? (Done in Phase 1)
- [ ] Can you install it as a Windows Service?
- [ ] Does the Proxy (`:8888`) successfully forward to OpenAI?
- [ ] Does the MSI installer work on a fresh Windows VM?
- [ ] Does the GitHub Action produce a downloadable release?
- [ ] Does the auto-updater download and swap binaries correctly?
- [ ] Does the Watchdog restart the service on crash?

---

# Phase 3: The Local Guard (Kernel-Level Enforcement)

**Goal:** Build the "Reflex System" — kernel-level interception that blocks dangerous actions *before* they execute. This is the most technically complex feature and the primary reason an Enterprise CISO will pay $100k+.

**Philosophy:** "Actions do not lie." We do not care what the prompt was. We do not care if the agent "meant well." We only care that a `syscall` was made to delete a protected file. We block the Physics, not the Semantics.

---

## The Technology: eBPF (The "God Mode" Hook)

**What is eBPF?** A programmable sandbox inside the Linux Kernel.

- **Speed:** JIT-compiled into native machine code. Runs in nanoseconds.
- **Safety:** The OS verifies the code before running it.
- **Invisibility:** The AI Agent (User Space) cannot see or stop the eBPF program (Kernel Space).

## The Architecture: The "Kernel Sandwich"

### Layer 1: The Trap (The Hook)

Attach "probes" (KProbes) to specific System Calls:

- **`sys_execve`:** "Run a new program" (e.g., spawn a shell)
- **`sys_connect`:** "Open a network connection" (e.g., talk to a server)
- **`sys_unlink`:** "Delete a file"
- **`sys_open`:** "Read a file"

### Layer 2: The Filter (The Decision)

When the Agent tries to execute `os.remove('/etc/shadow')`:

1. CPU pauses the Agent, runs Raypher's eBPF code
2. **Context Lookup:** "Who is calling this? PID 992 (The AI Agent)."
3. **Policy Check:** "Does PID 992 have permission to write to `/etc/`?" → **NO.**
4. **Verdict:** Returns error code `EPERM: Operation not permitted`

### Layer 3: The Result (The Block)

The OS tells the Agent: "Access Denied."

- **Crucially:** The command **never executed**. The file was never touched. The network packet was never sent.

## The Windows Challenge

eBPF is native to Linux. For Windows, Raypher uses **Kernel Callback Drivers**:

- `PsSetCreateProcessNotifyRoutine` — Process creation monitoring
- `WFP` (Windows Filtering Platform) — Network filtering

**The Abstraction Strategy:**

- Developer writes one policy: "Block File Deletion"
- Raypher compiles it into **eBPF bytecode** for Linux servers
- Raypher compiles it into a **WFP Filter** for Windows laptops
- The user never knows the difference

## Real-World Attack Scenarios

| Scenario | Attack | Raypher Hook | Policy | Outcome |
|---|---|---|---|---|
| **Sleepy Developer** | Agent thinks `production.db` is a log, tries `rm production.db` | `sys_unlink` | Critical File Protection | File deletion fails instantly |
| **Reverse Shell** | Hacker tricks agent into spawning `/bin/bash` piped to network socket | `sys_socket` + `sys_execve` | Agents cannot spawn Shells | Process killed before connection opens |
| **Data Exfiltration** | Agent reads `customer_emails.txt` and uploads to `pastebin.com` | `sys_connect` | Whitelist: only `api.openai.com` | Connection reset. Data never leaves laptop |

### Phase 3 Completion Checklist

- [ ] eBPF probes attached to `sys_execve`, `sys_connect`, `sys_unlink`, `sys_open` on Linux
- [ ] WFP Filters functional on Windows
- [ ] Identity-Aware Interception working (maps Hardware Identity to Kernel Enforcement)
- [ ] Policy checks return correct ALLOW/DENY verdicts
- [ ] No false positives on critical system processes
- [ ] Blocked actions logged with full context

---

# Phase 4: The Network Proxy (Air Traffic Controller)

**Goal:** Build a Transparent Local Proxy with TLS Termination. Intercept, inspect, and control every network request the agent makes. No code changes required from the developer.

**Philosophy:** "Trust No Outbound." We treat every network request as a potential data leak. We intercept the call, read the letter, and *then* decide if we should mail it.

---

## The Technology: Local MITM (Man-in-the-Middle)

### The "Wiretap" Flow

1. **Certificate Generation:** On install, Raypher generates a unique Root Certificate Authority (CA) and installs it into the OS Trust Store
2. **Interception:** When the Agent connects to `https://api.openai.com`, Raypher intercepts locally (using `iptables` or WFP)
3. **TLS Handshake:** Raypher pretends to be OpenAI, presents a certificate signed by its own Local CA. The Agent trusts the OS store and accepts.
4. **Inspection:** Raypher decrypts the traffic. Raw JSON payload in plain text: prompt, API key, file content — all visible.
5. **Forwarding:** If checks pass, Raypher re-encrypts and sends to the real server.

**Why this is unique:** Cloud proxies (Helicone) require code changes (`base_url="https://helicone.ai"`). Raypher requires NO code changes. We catch traffic at the OS level.

## The Four Defense Layers

### A. SSRF Prevention (Internal Spy Defense)

- Block all traffic to Private IP ranges (`10.0.0.0/8`, `192.168.x.x`, `169.254.x.x`)
- Prevents agents from reading AWS Metadata IP (`169.254.169.254/latest/meta-data/`)

### B. Domain Whitelisting (Walled Garden)

- Policy: "Finance Agent ONLY talks to `api.openai.com` and `stripe.com`"
- Any request to `evil-server.ru` is dropped instantly

### C. Data Loss Prevention (Secret Filter)

- Scan Body Payload before sending
- Regex Match: `\b4[0-9]{12}(?:[0-9]{3})?\b` (Visa Card)
- Regex Match: `sk-proj-[a-zA-Z0-9]{48}` (OpenAI Key)
- **Action:** BLOCK. Request never leaves laptop. API provider never sees sensitive data.

### D. Budget Enforcement (Wallet Guard)

- Track Token Usage and Cost per agent
- Policy: "Max Daily Spend = $50.00"
- At $50.01: Return `429 Too Many Requests`. Agent pauses, bank account saved.

### Phase 4 Completion Checklist

- [ ] Local CA certificate generated and installed in OS Trust Store
- [ ] TLS termination and re-encryption working
- [ ] SSRF blocking for all private IP ranges
- [ ] Domain whitelisting enforcement functional
- [ ] Regex-based DLP scanning on payload bodies
- [ ] Budget tracking and enforcement per agent
- [ ] Zero code changes required from the developer

---

# Phase 5: The Policy Engine (The Constitution)

**Goal:** Build the "brain" that decides when to use the handcuffs, when to pull the brake, and when to apply the gag. Transform vague business intent into binary machine logic.

**Philosophy:** "Policy as Code." Security rules are written in YAML/JSON, version-controlled in Git, and deployed instantly to thousands of agents.

---

## The Technology: Dynamic Decision Trees

### The "Millisecond Trial" Workflow

Every agent action triggers a mini-trial:

1. **Evidence Gathering:** Who (Agent ID + TPM), What (syscall + target), Where (device), Score (Trust Score)
2. **Law Loading:** Fetch active Policy File
3. **Judgment:** Evaluate rules → ALLOW or DENY
4. **Feedback:** Agent receives `403 Forbidden` or proceeds. Manager receives alert.

## The Four Pillars of Control

### A. Operational Policies (What can you touch?)

- **File System:** `Allow Read: /project/data/*`, `Block Write: /system/*`, `*.pem`, `*.db`
- **Process Control:** `Block Spawn: /bin/bash`, `powershell.exe`, `curl`, `wget`
- **Hardware Access:** `Block Camera/Mic`

### B. Financial Policies (What can you spend?)

- **Cost Limits:** Daily Limit: $20.00, Per-Request Limit: $0.50
- **Model Restrictions:** Allow: `gpt-3.5-turbo` (cheap), Block: `gpt-4-32k` (expensive) unless Senior Engineer

### C. Network Policies (Who can you talk to?)

- **Domain Whitelisting:** Allow: `*.openai.com`, `*.github.com`. Block: Everything Else.
- **DLP Rules:** Block If Body Contains: `"sk-..."` (API Keys), Pattern(SSN)

### D. Temporal Policies (When can you work?)

- **Time-Fencing:** Allow: Mon-Fri, 09:00–18:00. Block: Weekends.
- Why: A finance agent moving money at 3 AM on Sunday is suspicious → Block it.

## The Hierarchy: Cascading Inheritance (Enterprise Feature)

1. **Global Policy (The Constitution):** Set by CISO → "No Agent can ever send PII to the internet" → Applies to everyone. **Cannot be overridden.**
2. **Team Policy (The Department):** Set by Engineering Manager → "Backend can access AWS. Frontend cannot."
3. **Local Policy (The Developer):** Set by the User → "Stop my agent if it spends >$5."

**Conflict Resolution:** The **Most Restrictive** rule always wins.

## Dynamic Trust-Based Policies (The Secret Weapon)

Rules based on the Trust Score (Feature 8):

- `IF TrustScore > 900: Allow File Deletion (Auto)`
- `IF TrustScore 700-899: Require Human Approval (Pop-up)`
- `IF TrustScore < 700: Block File Deletion`

**Value:** As the agent proves reliability (score up), handcuffs loosen. As it crashes (score down), handcuffs tighten. Automatic, dynamic governance.

### Phase 5 Completion Checklist

- [ ] Policy file format defined (YAML/JSON schema)
- [ ] All four policy pillars implemented (Operational, Financial, Network, Temporal)
- [ ] Cascading hierarchy with "Most Restrictive Wins" conflict resolution
- [ ] Dynamic Trust-Based policies linked to Trust Score
- [ ] Policy hot-reload (no restart required)
- [ ] Policies are external to code (CISO can update without developer involvement)
- [ ] Global Policy Push to all endpoints in < 2 seconds

---

# Phase 6: Shadow AI Discovery (The Sonar)

**Goal:** Build the "Searchlight" that scans devices and networks to find every AI model, agent process, and vector database running in the dark — before you even install a policy.

**Philosophy:** "Illumination precedes Control." You cannot secure what you cannot see.

---

## Multi-Layered Reconnaissance

### Layer A: Process Scanning (The "Fingerprint")

Scan the OS active process list every 30 seconds for known AI signatures:

- **Binary Names:** `ollama`, `llama.cpp`, `python (running langchain)`, `uvicorn`, `torchserve`
- **Command Line Arguments:** `python app.py --model gpt-4`, `docker run -p 8000:8000 chromadb`
- **Library Loading:** Check loaded DLLs/Shared Libraries:
  - If process loads `cudart64_110.dll` (NVIDIA CUDA) + `pytorch_python.dll` → **This is an AI Model** — even if renamed to `calculator.exe`

### Layer B: Port Listening (The "Traffic Cop")

Monitor local TCP/UDP for listeners on known AI ports:

- **11434:** Ollama (Local LLM)
- **8000:** ChromaDB / FastAPI
- **6333:** Qdrant (Vector DB)
- **5000:** Flask (older AI demos)

If Raypher sees Port 11434 open → Flag: "Unmanaged LLM Detected."

### Layer C: Network Packet Inspection (The "Wiretap")

Feature 4 (Proxy) feeds data to Feature 6:

- Look for API Hostnames in DNS cache: `api.anthropic.com`, `huggingface.co`, `api.deepseek.com`
- Look for Payload Shapes: JSON POST containing `{"messages": [{"role": "user", "content": "..."}]}`
- **Verdict:** This is an LLM Chat Completion Protocol → Flag as "Shadow Agent"

### Layer D: mDNS Discovery (Finding Neighbors) — Enterprise Feature

Use Multicast DNS to ask the local network: "Is anyone running an AI service?"

- Query for `_ollama._tcp.local` or `_chromadb._tcp.local`
- Other machines (even without Raypher) may respond
- A single Raypher agent can detect "Rogue Servers" nearby on the same WiFi

## The Discovery Dashboard

The "Oh Sh*t" moment for CISOs:

**The Rouge List:**

| User | Process | Activity | Risk Level |
|---|---|---|---|
| `dev-sarah` | `python3` (PID: 9921) | Sending 5GB to `huggingface.co` | **CRITICAL** |

**The Local LLM List:**

| Device | Model | Status | Risk Level |
|---|---|---|---|
| `lab-pc-04` | `Llama-3-70b` | Running Unsecured (No Auth) | **HIGH** |

### Phase 6 Completion Checklist

- [ ] Process scanning detects known AI binaries and runtimes
- [ ] Library/DLL analysis detects GPU-accelerated AI (even if binary is renamed)
- [ ] Port monitoring for all known AI service ports
- [ ] Network inspection for LLM API patterns
- [ ] mDNS network discovery for neighboring AI services
- [ ] Discovery Dashboard displays live asset inventory
- [ ] "Silent Mode" (discovery-only, no blocking) for POC deployments

---

# Phase 7: Data Loss Prevention (The Content Filter)

**Goal:** Build the automatic redaction engine that scans every byte of outbound data and removes secrets, PII, and sensitive content before it leaves the device.

**Philosophy:** "Sanitize at the Source." We do not trust the Agent to know what is sensitive. We inspect every single byte before it leaves the device.

---

## The Technology: Hybrid Inspection Engine

### Layer A: High-Speed Regex (The "Pattern Matcher")

First pass — runs in microseconds using optimized Rust engine (based on `ripgrep`):

| Pattern | Target | Regex |
|---|---|---|
| **Credit Cards (Visa)** | Card Numbers | `\b(?:\d[ -]*?){13,16}\b` + Luhn check |
| **SSN (US)** | Social Security | `\b\d{3}-\d{2}-\d{4}\b` |
| **OpenAI API Key** | API Secrets | `sk-proj-[a-zA-Z0-9]{48}` |
| **GitHub PAT** | API Secrets | `ghp_[a-zA-Z0-9]{36}` |
| **AWS Access Key** | Cloud Secrets | `AKIA[0-9A-Z]{16}` |
| **Ethereum Wallet** | Crypto Addresses | `0x[a-fA-F0-9]{40}` |
| **Email Addresses** | PII | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |

### Layer B: Contextual NER (The "Smart Filter") — Enterprise Tier

Lightweight, local Named Entity Recognition model running on CPU:

- **PII Detection:** Names, Addresses, Phone Numbers, Dates of Birth
- **Code Detection:** Proprietary code snippets, internal variable names

### Microsoft Presidio Integration

Raypher integrates with Microsoft Presidio (industry-standard open-source PII detection):

- "We use the same PII detection engine as Microsoft, but we run it locally on your laptop."
- Banks trust Presidio → Raypher inherits that trust

## Actions: Redact vs. Block

### Option A: The Redaction (Sanitize)

- Agent sends: "User 42 (SSN: 123-45-6789) is late on payment."
- Raypher modifies in-flight: "User 42 (SSN: [REDACTED]) is late on payment."
- LLM gets context, secret never leaves laptop.

### Option B: The Block (Quarantine)

- Agent uploads `database_dump.csv` (10,000 rows of PII)
- Raypher: **BLOCK REQUEST** (HTTP 403 Forbidden)
- Audit Log: "Attempted Exfiltration of PII"

## Compliance Alignment

| Regulation | Raypher Value |
|---|---|
| **GDPR (Europe)** | "PII never leaves the EU — Raypher blocks at device level" |
| **HIPAA (Healthcare)** | "Patient IDs never sent to non-compliant LLMs" |
| **PCI-DSS (Finance)** | "Credit card numbers never logged or transmitted" |

### Phase 7 Completion Checklist

- [ ] High-speed Regex engine scanning all outbound payloads
- [ ] All major secret patterns covered (API keys, CC numbers, SSN, etc.)
- [ ] NER model running locally for contextual PII detection
- [ ] Presidio integration functional
- [ ] Redaction mode modifies payload in-flight without breaking agent workflow
- [ ] Block mode returns HTTP 403 with clear explanation
- [ ] Sub-millisecond latency impact on API calls

---

# Phase 8: The Trust Score (FICO Score for AI)

**Goal:** Build a dynamic, real-time reputation system for every AI agent. Assign a living score between 0 and 1000 that governs what each agent can and cannot do.

**Philosophy:** "Dynamic Reputation." Traditional security is binary (Allow/Block). AI agents are probabilistic. You need a gradient that captures nuance.

---

## Score Ranges

| Score | Status | Privileges |
|---|---|---|
| **900+** | **Autonomous** | Can deploy code, move money |
| **700–899** | **Probationary** | Needs human approval for sensitive actions |
| **< 500** | **Restricted** | Read-only access, sandboxed |

## The Algorithm: The "Raypher 360" Calculation

### Pillar A: Behavioral History (60% Weight — The "Credit Report")

1. **Policy Violation Rate:** (Blocked Actions / Total Actions) → `-50 points` per violation
2. **Crash/Error Rate:** How often does the process exit non-zero? → `-10 points/crash`
3. **Resource Efficiency:** API Cost per Task → `-20 points` for wasteful spending
4. **Hallucination Rate:** Did the human accept or reject the agent's output? Rejections → score drops

### Pillar B: Identity & Provenance (20% Weight — The "Background Check")

1. **Hardware Binding (Feature 1):** Valid TPM → `+100 points`. No TPM → `-50 points`
2. **Code Signature:** If `agent.py` hash changes since last audit → score resets until re-verified
3. **Developer Reputation:** Senior Architect → starts at `800`. Intern → starts at `400`

### Pillar C: Community Intelligence (20% Weight — The "Network Effect")

1. **Global Blocklist:** If 500 Free Tier users block a plugin → hash marked "Toxic" → score drops to `0` for all Enterprise customers
2. **Vulnerability Alerts:** New CVE in `langchain` version → `-200 points` until updated

## The Real-Time Feedback Loop

1. **Query:** Agent tries to access `Production_DB` → Gateway calls `GET /trust-score?agent_id=Ag-99`
2. **Calculate:** Base 800 (Senior Dev) - 50 (tried to delete file) + 100 (Valid TPM) + 0 (no community flags) = **850**
3. **Enforce:** Rule says "DB Write requires > 900" → **DENY** (850 < 900)
4. **Decay:** Agent idle for 30 days → score slowly drops (halflife). Must "prove" itself again.

## The Strategic Moat

- **Data Gravity:** If Microsoft launches a competitor tomorrow, they have 0 data. Raypher has thousands of Free Tier users feeding behavior data every second.
- **Business Enabler:** CISOs don't have to block everything. "If Score > 900, let it run at machine speed."
- **Universal Passport:** In the future, Agent-to-Agent communication uses Raypher Scores for mutual trust verification. Raypher becomes the "VISA credit check for APIs."

### Phase 8 Completion Checklist

- [ ] Trust Score API endpoint returning real-time scores
- [ ] All three pillars (Behavioral, Identity, Community) contributing to calculation
- [ ] Score decay over inactivity periods
- [ ] Policy Engine (Phase 5) consuming Trust Score for dynamic decisions
- [ ] Global Blocklist fed by Free Tier telemetry
- [ ] Vulnerability alert integration (CVE feeds)
- [ ] Score change events logged to Audit Ledger

---

# Phase 9: The Audit Ledger (The Flight Recorder)

**Goal:** Build a cryptographically signed, immutable record of every action every agent takes. This is what transforms Raypher from "Dev Tool" into "Enterprise Infrastructure." It is the only reason a regulated industry can legally use autonomous agents.

**Philosophy:** "Cryptographic Evidence." We do not just "log" events. We create a legally admissible chain of custody.

---

## The Technology: The "Merkle Chain" (Blockchain-Lite)

### Step A: The Atomic Entry (The "Block")

Every agent action captures:

1. **The Actor:** `Agent_ID` + TPM Signature (Feature 1)
2. **The Action:** `syscall: WRITE`, `target: s3://bucket/data`
3. **The Policy:** `Policy_ID: v4.2`, `Result: ALLOW`
4. **The Context:** `Trust_Score: 850`
5. **The Timestamp:** Atomic Clock Time (NTP)

### Step B: The Hash (The "Fingerprint")

Run the JSON through SHA-256 → unique hash `a1b2c3d4...`

- Change *one character* → hash changes completely → tamper detected

### Step C: The Chain (The "Link")

Each entry includes the hash of the previous entry:

```
Entry #1 Hash: H1
Entry #2 Hash: SHA-256(Data_2 + H1)
Entry #3 Hash: SHA-256(Data_3 + H2)
```

- If a hacker deletes Entry #2, the math for Entry #3 no longer matches
- Chain is broken → Raypher flags log as **"CORRUPTED"** → alerts CISO

## Tiered Storage Architecture

| Layer | Location | Format | Retention | Purpose |
|---|---|---|---|---|
| **Local Buffer** | Developer's Laptop (RAM/Disk) | Encrypted Binary (`raypher.log.enc`) | 24 hours (Free) | Instant debugging |
| **Cloud Sync** | Raypher Cloud (S3 Immutable Object Lock) | Hash Chain | 30 Days (Team) | Centralized reporting |
| **Cold Storage** | Customer's Own Archive (AWS Glacier/Splunk) | Raw JSON + Crypto Proofs | **7 Years** (Enterprise) | Legal Defense |

## Real-World Use Cases

| Case | Scenario | Without Raypher | With Raypher |
|---|---|---|---|
| **Bias Lawsuit** | Hiring Agent rejects candidate, gets sued | Generic log: "Candidate Rejected" (Lose) | Full ledger: Score = 40/100, Policy: Reject if < 60, Hardware Verified (Case Dismissed) |
| **Rogue Admin** | IT admin uses agent to delete backups, then deletes local logs | Evidence destroyed | Cloud Vault has instant copy. Integrity check flags missing heartbeat. Crime preserved. |
| **Forensic Debug** | Agent deploys bad code update, takes down website | "Which line broke it?" (Guessing) | Ledger shows exact POST to GitHub API with exact diff content. Revert in seconds. |

### Phase 9 Completion Checklist

- [ ] Atomic log entries capturing Actor, Action, Policy, Context, Timestamp
- [ ] SHA-256 hash chain linking every entry
- [ ] Tamper detection (broken chain → CORRUPTED flag → alert)
- [ ] Local buffer with encryption at rest
- [ ] Cloud sync to immutable object storage
- [ ] Cold storage export (JSON + cryptographic proofs)
- [ ] TPM-signed entries (cannot be forged)

---

# Phase 10: The Unified Dashboard (God Mode)

**Goal:** Build the "Mission Control" — a single visual interface where all features converge. This is the only thing the CISO looks at, and the specific reason they sign the $100,000 check.

**Philosophy:** "Single Pane of Glass." Treat every agent—laptop script or Kubernetes pod—as a single dot on a global map. Aggregate Identity, Behavior, and Risk into one real-time screen.

---

## The Three "God Mode" Views

### View A: The API Watchtower (The "Wallet Guard")

**Question:** "Who is using our OpenAI Enterprise Key right now?"

**Display:** Live, streaming list of every active API connection:

- **Source:** `Agent-007` (Laptop: `Mac-14`)
- **Destination:** `api.anthropic.com`
- **Payload:** "Analyze this customer contract..."
- **Cost:** `$0.04` (accumulating live)
- **Action:** "Kill Connection" button — Cut the cord without finding the developer

### View B: The Database X-Ray (The "Data Guard")

**Question:** "Which agents are touching the Customer Database?"

**Display:** Visualized Data Flow lines connecting agents to databases:

- `Agent-Marketing-Bot` → `SQL-Database-Prod`
- Action: `SELECT * FROM users WHERE email LIKE '%@gmail.com'`
- **Alert:** `DROP TABLE` or `DELETE FROM` → screen flashes RED, line turns solid red (Blocked)

### View C: The Trust Score Leaderboard (The "Risk Radar")

**Question:** "Which of my 5,000 agents is about to go rogue?"

**Display:** Ranked list by Risk Level:

- **Top Risky:** `Dev-Test-Bot-v2` (Score: 350) — Crashed 4 times, tried to access `/etc/shadow`
- **Top Trusted:** `Finance-Reconciler` (Score: 990) — 99.9% uptime, zero violations
- CISO focuses only on Bottom 10

## The Control Plane: Push-Button Governance

### Global Policy Push

- Scenario: DeepSeek banned by regulation
- CISO creates rule: `Block Domain: *.deepseek.com` → Clicks "Deploy Global"
- **Result:** Within 2 seconds, every agent on every device receives the rule. DeepSeek is dead instantly.

### The "Panic" Center

- Scenario: Zero-day in `LangChain` library
- CISO hits "Global Freeze" for LangChain group
- **Result:** All 2,000 agents using that library are suspended in RAM (memory saved, communication stopped). CISO patches safely.

## The Architecture: Scaling to Millions

- **Agent (Edge):** Lightweight binary buffers logs locally, sends compressed heartbeats every 5 seconds via **gRPC**
- **Ingestor (Cloud):** High-performance Rust/Go backend receives millions of events per second
- **Frontend (Stream):** Dashboard uses **WebSockets** — charts animate live, no page refreshes. Agent deletes file in Tokyo → pixel lights up in New York in 200ms.

## The Compliance Report Generator

The boring feature that makes the most money.

**Button:** "Generate SOC2 / ISO 27001 AI Report"

**Output PDF:**

1. **Inventory:** Every AI model used in the reporting period
2. **Access Control:** Proof that only Authorized Agents touched PII
3. **Incident Log:** Every blocked attack and remediation
4. **Integrity Proof:** Cryptographic hashes from Audit Ledger (Phase 9)

**Result:** Auditor stamps "Approved" and leaves. Bank saves $500,000 in consulting fees.

### Phase 10 Completion Checklist

- [ ] API Watchtower view with live connection streaming
- [ ] Database X-Ray visualization of agent-to-database data flows
- [ ] Trust Score Leaderboard with ranked risk display
- [ ] Global Policy Push with < 2 second propagation
- [ ] Global Freeze ("Panic Center") for library-specific agent suspension
- [ ] gRPC heartbeat architecture for edge-to-cloud communication
- [ ] WebSocket-powered live dashboard (no page refresh)
- [ ] SOC2/ISO 27001 Compliance Report generator
- [ ] Platform agnostic: shows Azure, AWS, local laptop agents side-by-side

---

# ⚠️ CRITICAL GAP ANALYSIS — "Voluntary" vs "Mandatory" Security

> **Phases 1 & 2 built the BODY (Binary/Service) and the IDENTITY (TPM).**
> **What is missing is the FORCE.**
>
> Right now, Raypher is **Voluntary Security** — the developer must *choose* to route through us.
> Enterprise security is **Mandatory Security** — we intercept whether they like it or not.

---

## Enterprise Maturity Matrix

| Capability | Current Status | Required For Enterprise | Gap Severity |
|:---|:---|:---|:---|
| Binary Identity (TPM) | ✅ Phase 1 Complete | ✅ | None |
| Process Scanning | ✅ Phase 1 Complete | ✅ | None |
| Kill/Panic Protocol | ✅ Phase 1 Complete | ✅ | None |
| Service Persistence | ✅ Phase 2 Complete | ✅ | None |
| Proxy + Secret Injection | ✅ Phase 2 Complete | ✅ | None |
| Auto-Update + MSI | ✅ Phase 2 Complete | ✅ | None |
| Status Dashboard | ✅ Phase 2.5 Complete | ✅ | None |
| **Kernel-Level Interception** | ❌ **MISSING** | ✅ Required | 🔴 **CRITICAL** |
| **Dynamic Policy Engine** | ❌ **MISSING** | ✅ Required | 🔴 **CRITICAL** |
| **Cloud Connectivity (gRPC)** | ❌ **MISSING** | ✅ Required | 🟡 **HIGH** |
| **Data Loss Prevention** | ❌ **MISSING** | ✅ Required | 🟡 **HIGH** |

---

## Gap 1: The "Transparent" Interception (The Traffic Cop)

**Status:** ❌ **MISSING** — Planned for Phase 3 & 4
**Severity:** 🔴 CRITICAL — Without this, Raypher can be bypassed entirely

### The Problem

Currently, the README says: *"Point your agent to `http://localhost:8888`"*.

This requires the developer to **willingly change their code**. If a rogue agent (or a lazy developer) simply ignores Raypher and calls `api.openai.com` directly, **Raypher is bypassed entirely**. The entire security model collapses.

### The Fix: Kernel-Level Redirection

Raypher must be a **transparent MITM** (Man-in-the-Middle), not just a configured proxy.

**Linux — iptables/nftables + eBPF:**

```bash
# Force ALL outbound HTTPS traffic from specific PIDs through Raypher
iptables -t nat -A OUTPUT -m owner --uid-owner $AGENT_UID \
  -p tcp --dport 443 \
  -j REDIRECT --to-port 8888

# eBPF alternative: attach to sys_connect() and rewrite destination
# Advantage: per-PID granularity without iptables rules
```

**Windows — Windows Filtering Platform (WFP):**

```
WFP Callout Driver → Intercept connect() calls → Redirect to localhost:8888
- Register FWPM_LAYER_ALE_AUTH_CONNECT_V4 filter
- Match by PID / application path
- Transparently redirect to Raypher proxy
```

### Key Implementation Notes

- **Local CA Certificate:** Raypher must generate a machine-local root CA, install it in the OS Trust Store, and do TLS termination + re-encryption (Phase 4)
- **PID Filtering:** Only intercept traffic from monitored processes, not system services
- **Fallback:** If kernel module fails to load → fall back to configured proxy mode with WARNING log
- **SSRF Protection:** Block all connections to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local)

### Success Criteria

- [ ] Agent calling `api.openai.com:443` directly is transparently redirected through Raypher
- [ ] Agent calling any HTTPS endpoint is visible in the audit log
- [ ] Zero code changes required from the developer
- [ ] No visible difference to the agent — requests succeed, just routed through Raypher
- [ ] Works on both Windows (WFP) and Linux (iptables/eBPF)

---

## Gap 2: The "Constitution" (Dynamic Policy Engine)

**Status:** ❌ **MISSING** — Planned for Phase 5
**Severity:** 🔴 CRITICAL — Without this, Raypher is binary (Allow/Deny only)

### The Problem

Currently, the proxy verifies the binary hash and injects a key. That is **binary logic**: Allow or Deny.

Enterprises need **nuance**:

- *"Can I allow this agent to spend $50/day but block it at $51?"*
- *"Can I block this agent from running on weekends?"*
- *"Can I allow file reads but block file deletes?"*
- *"Can I auto-approve trusted agents but require human approval for new ones?"*

### The Fix: Dynamic Policy Engine

**Policy File Format (YAML):**

```yaml
# /etc/raypher/policy.yaml — dynamically reloaded (no restart)
version: "1.0"

rules:
  - name: "Budget Limit - Junior Agents"
    match:
      trust_score: { lt: 700 }
    action: DENY
    conditions:
      - daily_spend: { gt: 50.00 }
      - model: { in: ["gpt-4-32k", "gpt-4-turbo"] }
    message: "Budget exceeded for low-trust agent"

  - name: "After-Hours Block"
    match:
      time: { after: "18:00", before: "06:00" }
      day: { in: ["Saturday", "Sunday"] }
    action: DENY
    message: "AI agents blocked outside business hours"

  - name: "High-Trust Auto-Approve"
    match:
      trust_score: { gte: 900 }
      action_type: "file_delete"
    action: ALLOW
    audit: true

  - name: "Medium-Trust Human Approval"
    match:
      trust_score: { gte: 700, lt: 900 }
      action_type: "file_delete"
    action: PROMPT  # Pop-up requiring human approval
    timeout: 30s
    default_on_timeout: DENY
```

**Engine Architecture:**

```
                    ┌──────────────────┐
 Request ──────────►│  Policy Engine   │──── ALLOW ────► Forward
                    │  (in-process)    │
                    │                  │──── DENY ─────► Block + Log
                    │  Evaluates:      │
                    │  - Trust Score   │──── PROMPT ───► Human Approval
                    │  - Time/Day      │
                    │  - Budget Used   │
                    │  - Model Type    │
                    │  - Action Type   │
                    └──────────────────┘
                           ▲
                           │ Hot-reload (fsnotify)
                    ┌──────┴──────┐
                    │ policy.yaml │
                    └─────────────┘
```

### Key Implementation Notes

- **Hot-Reload:** Use `notify` crate to watch `policy.yaml` — apply changes without restarting the service
- **Evaluation Order:** Rules evaluated top-to-bottom, first match wins (like iptables)
- **Default Policy:** If no rule matches → DENY (fail-closed)
- **Budget Tracking:** Per-agent daily/monthly spend stored in `data.db`
- **OPA Option:** For enterprise customers, support OPA/Rego as an alternative engine

### Success Criteria

- [ ] Policy file format defined (YAML schema)
- [ ] Hot-reload without service restart
- [ ] Trust-score-based dynamic rules functional
- [ ] Budget tracking and enforcement per agent
- [ ] Time-based and day-based restrictions
- [ ] Human approval flow for medium-trust agents
- [ ] Default-deny on no matching rule

---

## Gap 3: The "Nervous System" (Cloud Connectivity / gRPC)

**Status:** ❌ **MISSING** — Planned for Phase 10
**Severity:** 🟡 HIGH — Without this, CISOs cannot manage 1,000 laptops

### The Problem

Right now, Raypher logs to a **local SQLite database** (`data.db`). Two critical failures:

1. **"The Rogue Admin" Attack:** If a hacker gets root access, they can just `DELETE FROM events` or `rm data.db` to cover their tracks. The entire audit trail is gone.
2. **"The Fleet Blind Spot":** A CISO cannot see the status of 1,000 laptops from a single screen. Each machine is an island.

### The Fix: gRPC Heartbeat + Off-Site Immutable Logging

**Architecture:**

```
 ┌─────────────────┐     gRPC (TLS + mTLS)     ┌──────────────────┐
 │  raypher.exe    │ ──────────────────────────► │  Raypher Cloud   │
 │  (Edge Agent)   │   Heartbeat every 30s      │  (Command Center)│
 │                 │   + Event Stream            │                  │
 │  - Local SQLite │ ◄────────────────────────── │  - Policy Push   │
 │  - Policy Cache │   Policy Updates            │  - Fleet View    │
 │                 │   + Global Freeze           │  - Immutable Log │
 └─────────────────┘                             └──────────────────┘
```

**Heartbeat Payload (every 30 seconds):**

```json
{
  "agent_id": "tpm_fingerprint_hash",
  "timestamp": "2026-02-14T23:30:00Z",
  "status": "running",
  "uptime_seconds": 86400,
  "version": "0.2.0",
  "os": "windows_11_23H2",
  "stats": {
    "total_events": 1247,
    "events_since_last_heartbeat": 3,
    "active_agents": 2,
    "blocked_requests": 0,
    "trust_score_avg": 847
  }
}
```

**Event Stream (real-time):**

- Every audit event is streamed to the cloud server within 1 second
- Events are stored in an append-only, immutable log (hash-chained)
- Even if local `data.db` is deleted, the cloud has the full history

### Key Implementation Notes

- **Offline Resilience:** If cloud is unreachable, queue events locally and flush when reconnected
- **mTLS Authentication:** Each agent authenticates with its TPM-bound certificate — no API keys
- **Policy Push:** Cloud can push policy updates to all agents simultaneously (< 2 second propagation)
- **Global Freeze:** "Panic button" that suspends ALL agents across the fleet in < 5 seconds
- **Bandwidth:** Heartbeats are tiny (~500 bytes). Event stream is batched. Minimal network overhead

### Success Criteria

- [ ] gRPC client in `raypher.exe` streaming heartbeats every 30s
- [ ] Event stream with < 1 second latency to cloud
- [ ] Offline queue with automatic flush on reconnection
- [ ] mTLS authentication using TPM-bound certificates
- [ ] Cloud can push policy updates to individual agents or fleet-wide
- [ ] Global Freeze command functional (< 5 second propagation)
- [ ] Immutable, hash-chained event log on cloud side

---

## Gap 4: The "Content Filter" (Data Loss Prevention)

**Status:** ❌ **MISSING** — Planned for Phase 7
**Severity:** 🟡 HIGH — Without this, authorized agents can leak secrets

### The Problem

Raypher injects API keys but doesn't read the **payload** of the messages. An authorized agent with a valid TPM key can still send:

```
"Here is the CEO's password: hunter2"
"Credit card: 4532-1234-5678-9012"
"SSN: 123-45-6789"
"Internal API key: sk-proj-abc123..."
```

These go straight through to OpenAI. Raypher sees nothing, blocks nothing.

### The Fix: Regex/NER Scanning Inside the Proxy

**Scanning Pipeline:**

```
  Agent Request                                          OpenAI
      │                                                     ▲
      ▼                                                     │
 ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──┴──┐
 │ Intercept │───►│ Policy Check │───►│  DLP Scanner  │───►│ FWD │
 └──────────┘    └──────────────┘    │              │    └─────┘
                                     │ 1. Regex     │
                                     │ 2. NER       │
                                     │ 3. Entropy   │
                                     │ 4. Custom    │
                                     │              │
                                     │ ──► CLEAN ───┤──► Forward
                                     │ ──► DETECT ──┤──► Redact or Block
                                     └──────────────┘
```

**Detection Layers:**

| Layer | What It Catches | Method |
|:---|:---|:---|
| **Regex** | Credit Cards, SSNs, Phone Numbers, IBANs | Pattern matching (`\b4[0-9]{12}(?:[0-9]{3})?\b`) |
| **NER** | Person Names, Company Names, Addresses | Named Entity Recognition (Presidio or custom) |
| **Entropy** | API Keys, Tokens, Passwords | Shannon entropy > 4.5 on alphanumeric strings |
| **Custom** | Internal project names, codenames, domains | User-defined blocklist in `policy.yaml` |

**Example Regex Patterns:**

```rust
lazy_static! {
    static ref CREDIT_CARD: Regex = Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b").unwrap();
    static ref SSN: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    static ref API_KEY: Regex = Regex::new(r"\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b").unwrap();
    static ref HIGH_ENTROPY: fn(&str) -> bool = |s| shannon_entropy(s) > 4.5 && s.len() > 16;
}
```

**Actions on Detection:**

1. **REDACT:** Replace detected content with `[REDACTED-CC]`, `[REDACTED-SSN]`, etc. — request still goes through
2. **BLOCK:** Return 403 to the agent with reason — request never leaves the laptop
3. **ALERT:** Forward the request but emit a `CRITICAL` severity audit event + cloud alert
4. **PROMPT:** Pause and ask a human: *"Agent is trying to send a credit card number. Allow?"*

### Key Implementation Notes

- **Performance:** Regex scanning adds ~1-2ms per request. NER adds ~10-20ms. Keep it fast
- **False Positives:** Start with high-confidence patterns only (credit cards, SSNs). Tune over time
- **Bi-directional:** Scan BOTH the request (outbound to OpenAI) AND the response (inbound from OpenAI)
- **Custom Patterns:** Enterprises define their own patterns in `policy.yaml` (internal codenames, secret project names)

### Success Criteria

- [ ] Regex scanning for credit cards, SSNs, API keys, phone numbers
- [ ] Entropy-based detection for unknown token/password patterns
- [ ] Configurable action per pattern (Redact / Block / Alert / Prompt)
- [ ] Bi-directional scanning (request + response)
- [ ] Custom pattern support in policy file
- [ ] < 5ms latency overhead for regex-only scanning
- [ ] Zero false positives on standard test suite

---

## Immediate Action Plan — "The Bridge to Phase 3"

> **The shift from "Tool" to "Platform" requires one change in philosophy:**
> **Stop asking permission. Start seizing control.**

### Sprint Priority Order

| Priority | Feature | Why First | Estimated Effort |
|:---|:---|:---|:---|
| **P0** | Kernel-Level Interception | Everything else depends on seeing traffic | 3-4 weeks |
| **P1** | DLP Content Scanning | Quick win — regex scanning in existing proxy | 1-2 weeks |
| **P2** | Dynamic Policy Engine | Enables enterprise-grade governance | 2-3 weeks |
| **P3** | gRPC Cloud Connectivity | Enables fleet management + immutable logs | 3-4 weeks |

### Phase 3 Immediate Start Checklist

- [ ] Research `aya` crate (Rust eBPF framework) for Linux kernel hooks
- [ ] Research Windows Filtering Platform (WFP) API for Windows interception
- [ ] Prototype: attach eBPF probe to `sys_connect()` and log all outbound connections
- [ ] Prototype: redirect a specific PID's HTTPS traffic to `localhost:8888`
- [ ] Generate local CA certificate and install in OS Trust Store
- [ ] TLS termination in proxy (accept HTTPS, decrypt, inspect, re-encrypt, forward)

### The Enterprise Readiness Gate

**Raypher is NOT enterprise-ready until all 4 gaps are closed.**

```
 Current State: "Please use our proxy" ──────────────► Voluntary (Developer Chooses)
 Target State:  "We see everything"     ──────────────► Mandatory (Kernel Enforces)
```

**When all 4 gaps are closed, Raypher transforms from a *tool developers install* into a *platform CISOs deploy*.**

---

## The Complete Feature Map Summary

| # | Feature | Codename | Analogy | Core Technology |
|---|---|---|---|---|
| 1 | Silicon-Bound Identity | The Passport | Digital DNA | TPM 2.0 / EK / PCRs / Sealing |
| 2 | The Local Guard | The Handcuffs | Reflex System | eBPF / KProbes / WFP |
| 3 | The Panic Protocol | The Emergency Brake | Dead Man's Switch | SIGKILL / PGID / Process Trees |
| 4 | The Network Proxy | The Gag Order | Air Traffic Controller | Local MITM / TLS Termination |
| 5 | The Policy Engine | The Constitution | Rulebook | Dynamic Decision Trees / YAML |
| 6 | Shadow AI Discovery | The Searchlight | Sonar / X-Ray | Process + Port + DLL + mDNS |
| 7 | Data Loss Prevention | The Censor | Content Filter | Regex + NER / Presidio |
| 8 | The Trust Score | The Reputation | FICO Score for AI | 3-Pillar Algorithm / Decay |
| 9 | The Audit Ledger | The Black Box | Flight Recorder | SHA-256 Hash Chain / Merkle |
| 10 | Unified Dashboard | Mission Control | God Mode | gRPC + WebSocket + Live Views |

---

## The "Kill Shot" Pitch

> **"Raypher is the Operating System for AI Security.**
> **We anchor the Agent's soul to silicon (Feature 1), control its hands with kernel hooks (Feature 2), give it an emergency brake (Feature 3), filter its mouth (Feature 4), govern it with dynamic policies (Feature 5), discover Shadow AI (Feature 6), redact secrets automatically (Feature 7), assign reputation scores (Feature 8), record everything in an immutable ledger (Feature 9), and display it all on a single screen (Feature 10).**
> **No other platform on earth connects hardware identity to kernel enforcement to enterprise governance in one binary.**
> **This is not a tool. This is a Platform."**

---

*Document generated from Git.reference sources only. No external resources used.*
*Date: 2026-02-14*
*Gap Analysis added: 2026-02-14 — Based on Phase 1 & 2 completion review*
