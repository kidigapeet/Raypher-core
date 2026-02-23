# RAYPHER PHASE 1–3: COMPLETE CODING AGENT IMPLEMENTATION PLAN

> **Purpose:** This document is a comprehensive, step-by-step implementation plan designed for a coding agent (AI or human) to execute. It describes every gap between the build plans (Phases 1–3) and the current codebase, with exact file paths, function signatures, Rust code references, dependency requirements, and verification commands.
>
> **Date:** 2026-02-21
> **Rust Toolchain:** 1.93.0 (stable)
> **Cargo:** 1.93.0
> **Target:** x86_64-pc-windows-msvc (primary), x86_64-unknown-linux-gnu (secondary)

---

## 📦 PRE-FLIGHT: TOOLING & DEPENDENCY REQUIREMENTS

Before any code is written, the agent MUST verify the following are installed and working on the user's machine. If any are missing, install them first.

### Already Confirmed Present ✅

| Tool | Version | Verified |
|------|---------|----------|
| `rustc` | 1.93.0 | ✅ |
| `cargo` | 1.93.0 | ✅ |
| `git` | Installed | ✅ |

### Must Verify Before Executing

| Tool | Why Needed | Install Command |
|------|-----------|----------------|
| `cargo-nextest` | Faster test runner for integration tests | `cargo install cargo-nextest` |
| `WiX Toolset v4` | MSI installer builds | Already in `wix/` directory — verify with `dotnet tool list -g` or check `wix/` contents |
| `OpenSSL` (optional) | Only if TLS testing requires cert inspection | Usually bundled with Git for Windows |
| `cross` (optional) | Cross-compilation to Linux | `cargo install cross` — already has `Cross.toml` |

### Cargo.toml Dependencies — Already Present ✅

All required crates for Phases 1–3 are already in `Cargo.toml`:

```
sysinfo, serde, serde_json, sha2, tracing, tracing-subscriber, tracing-appender,
chrono, hex, clap, ctrlc, rusqlite (bundled), toml, tokio (full), axum, reqwest
(rustls-tls), hyper-util, hyper, tower, rpassword, self_update, dirs-next,
webbrowser, serde_yaml, notify, rcgen, tokio-rustls, rustls, rustls-pemfile,
regex, rand, url, windows (optional/tpm), windows-service
```

### Missing Dependencies — Must Add to Cargo.toml

```toml
# Add under [dependencies]:
glob = "0.3"                          # Runtime auto-detection glob patterns (installer.rs)
shannon-entropy = "0.2"               # Optional: dedicated entropy crate (currently hand-rolled — keep or replace)

# Add under [dev-dependencies]:
tempfile = "3.10"                     # Temp dirs for integration tests
assert_cmd = "2.0"                    # CLI integration testing
predicates = "3.1"                    # Assertion matchers for CLI output
tokio-test = "0.4"                    # Async test utilities
```

> **IMPORTANT:** The `glob` crate is needed for `find_runtime_path` improvements in `installer.rs`. If you decide to keep the current `which`/`where` approach, `glob` is optional. The `shannon-entropy` crate is also optional since `dlp.rs` already has a hand-rolled Shannon entropy function.

---

## 🔍 CODEBASE STATUS: FILE-BY-FILE AUDIT RESULTS

### Source Files (23 total in `src/`)

| File | Lines | Phase | Status | Gaps |
|------|-------|-------|--------|------|
| `scanner.rs` | 328 | P1 | ✅ DONE | None |
| `heuristics.rs` | 226 | P1 | ⚠️ PARTIAL | Level 3 (`analyze_level3_environment`) is a stub returning `None` |
| `identity.rs` | 204 | P1 | ✅ DONE | None |
| `terminator.rs` | 131 | P1 | ✅ DONE | None |
| `safety.rs` | 46 | P1 | ✅ DONE | None |
| `watchtower.rs` | 174 | P1 | ✅ DONE | None |
| `panic.rs` | 48 | P1 | ✅ DONE | None |
| `monitor.rs` | ~100 | P1 | ✅ DONE | None |
| `killer.rs` | ~60 | P1 | ✅ DONE | None |
| `service.rs` | 345 | P2 | ✅ DONE | None |
| `proxy.rs` | 868 | P2/P3 | ⚠️ PARTIAL | Missing: bi-directional DLP on *responses*, spend-tracking integration in proxy pipeline |
| `secrets.rs` | 149 | P2 | ✅ DONE | None |
| `database.rs` | 555 | P2/P3 | ⚠️ PARTIAL | Missing: `spend_tracking` table + `record_spend()` + `get_daily_spend()` methods |
| `config.rs` | ~120 | P2 | ✅ DONE | None |
| `updater.rs` | ~80 | P2 | ✅ DONE | None |
| `watchdog.rs` | ~90 | P2 | ✅ DONE | None |
| `policy.rs` | 591 | P3 | ⚠️ PARTIAL | Has YAML, hot-reload, budget structs — but `check_time_restriction` needs day-of-week logic, no `RequestContext` struct for full rule evaluation |
| `dlp.rs` | 485 | P3 | ✅ DONE | Complete with 11+ patterns, entropy, custom patterns, Luhn, SSN validation, tests |
| `tls.rs` | 308 | P3 | ✅ DONE | None |
| `installer.rs` | 437 | P3 | ✅ DONE | None |
| `dashboard.rs` | 609 | P2/P3 | ⚠️ PARTIAL | Has DLP/policy/spend endpoints — may need spend breakdown enhancement |
| `dashboard_spa.html` | ~2000 | P2/P3 | ⚠️ PARTIAL | DLP/Budget panels exist but may need deeper integration |
| `main.rs` | 694 | All | ⚠️ PARTIAL | `handle_setup()` doesn't call `tls.install_ca()`, no `--service` flag dispatch |

---

## 🚀 IMPLEMENTATION TASKS — ORDERED BY PRIORITY

Each task below is self-contained with:

- **Exact file path** to modify or create
- **Function signatures** showing what to write
- **Dependencies** (which tasks must be done first)
- **Verification command** to confirm completion
- **Estimated lines** of code to add/modify

---

### TASK 1: Add `spend_tracking` Table & Methods to `database.rs`

**Priority:** P1 — Required by proxy budget enforcement and dashboard spend panel
**File:** `src/database.rs`
**Dependencies:** None
**Estimated LOC:** +80

#### What To Do

1. In `Database::init()`, add a new table creation SQL after the existing `CREATE TABLE` statements:

```rust
conn.execute_batch("
    CREATE TABLE IF NOT EXISTS spend_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_hash TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT 'unknown',
        model TEXT NOT NULL DEFAULT 'unknown',
        date TEXT NOT NULL,
        tokens_in INTEGER DEFAULT 0,
        tokens_out INTEGER DEFAULT 0,
        total_cost_usd REAL DEFAULT 0.0,
        request_count INTEGER DEFAULT 0,
        UNIQUE(agent_hash, date, provider, model)
    );
    CREATE INDEX IF NOT EXISTS idx_spend_date ON spend_tracking(date);
    CREATE INDEX IF NOT EXISTS idx_spend_agent ON spend_tracking(agent_hash);
")?;
```

1. Add these methods to `impl Database`:

```rust
/// Record API spend for an agent after a proxy request completes.
pub fn record_spend(
    &self,
    agent_hash: &str,
    provider: &str,
    model: &str,
    tokens_in: u32,
    tokens_out: u32,
) -> SqlResult<f64> {
    let cost = Self::estimate_cost(model, tokens_in + tokens_out);
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    self.conn.execute(
        "INSERT INTO spend_tracking (agent_hash, provider, model, date, tokens_in, tokens_out, total_cost_usd, request_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
         ON CONFLICT(agent_hash, date, provider, model) DO UPDATE SET
           tokens_in = tokens_in + ?5,
           tokens_out = tokens_out + ?6,
           total_cost_usd = total_cost_usd + ?7,
           request_count = request_count + 1",
        params![agent_hash, provider, model, today, tokens_in, tokens_out, cost],
    )?;

    // Return today's total for budget check
    let daily_total: f64 = self.conn.query_row(
        "SELECT COALESCE(SUM(total_cost_usd), 0.0) FROM spend_tracking WHERE agent_hash = ?1 AND date = ?2",
        params![agent_hash, today],
        |row| row.get(0),
    )?;

    Ok(daily_total)
}

/// Get today's total spend across all agents.
pub fn get_daily_spend_total(&self) -> SqlResult<f64> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    self.conn.query_row(
        "SELECT COALESCE(SUM(total_cost_usd), 0.0) FROM spend_tracking WHERE date = ?1",
        params![today],
        |row| row.get(0),
    )
}

/// Get spend breakdown by provider for the dashboard.
pub fn get_spend_by_provider(&self, days: u32) -> SqlResult<Vec<(String, f64, i64)>> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64))
        .format("%Y-%m-%d").to_string();
    let mut stmt = self.conn.prepare(
        "SELECT provider, SUM(total_cost_usd), SUM(request_count)
         FROM spend_tracking WHERE date >= ?1
         GROUP BY provider ORDER BY SUM(total_cost_usd) DESC"
    )?;
    let rows = stmt.query_map(params![cutoff], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?, row.get::<_, i64>(2)?))
    })?;
    rows.collect()
}

/// Get hourly spend for the current agent (for hourly budget checks).
pub fn get_hourly_spend(&self, agent_hash: &str) -> SqlResult<f64> {
    let now = chrono::Utc::now();
    let today = now.format("%Y-%m-%d").to_string();
    // Approximation: divide daily spend by hours elapsed
    // For precise hourly tracking, add a timestamp column (future enhancement)
    self.get_daily_spend_total()
}

/// Cost estimation per model per 1K tokens.
fn estimate_cost(model: &str, total_tokens: u32) -> f64 {
    let cost_per_1k = match model {
        m if m.contains("gpt-4o") => 0.005,
        m if m.contains("gpt-4-turbo") => 0.01,
        m if m.contains("gpt-4") => 0.03,
        m if m.contains("gpt-3.5") => 0.0005,
        m if m.contains("claude-3-opus") => 0.015,
        m if m.contains("claude-3-sonnet") || m.contains("claude-3.5-sonnet") => 0.003,
        m if m.contains("claude-3-haiku") || m.contains("claude-3.5-haiku") => 0.00025,
        m if m.contains("gemini-1.5-pro") => 0.00125,
        m if m.contains("gemini-1.5-flash") => 0.000075,
        _ => 0.001,
    };
    (total_tokens as f64 / 1000.0) * cost_per_1k
}
```

#### Verification

```bash
cargo test -- --test-threads=1 2>&1 | grep -E "(test result|FAILED)"
cargo build 2>&1 | grep -E "^error"
```

---

### TASK 2: Add Bi-Directional DLP Scanning to `proxy.rs`

**Priority:** P1 — Phase 3 build plan explicitly requires scanning responses
**File:** `src/proxy.rs`
**Dependencies:** Task 1 (for spend tracking), DLP already done
**Estimated LOC:** +40 (add response scanning block after upstream response)

#### What To Do

In the `handle_proxy()` function (line ~305–745), after the upstream response is received and the body is read back, add a DLP scan on the response body **before** returning it to the caller.

Find the section where the upstream response body is read (look for `response.bytes()` or equivalent), and add:

```rust
// ── DLP SCAN: Response (bi-directional) ──
// Scan the API provider's response for leaked secrets.
// An LLM might echo back sensitive data from its training data or from the prompt.
let resp_body_text = String::from_utf8_lossy(&resp_bytes).to_string();
let resp_dlp_result = dlp::scan(
    &resp_body_text,
    &policy_snapshot.dlp.default_action,
    &policy_snapshot.dlp.custom_patterns.as_deref().unwrap_or(&[]),
    &policy_snapshot.dlp.exclusions.as_deref().unwrap_or(&[]),
);

if resp_dlp_result.total_findings > 0 {
    tracing::warn!(
        findings = resp_dlp_result.total_findings,
        "DLP: Sensitive data detected in API response"
    );
    log_proxy_event(
        &state.db,
        "DLP_RESPONSE_FINDING",
        &addr,
        &format!("Redacted {} findings from API response", resp_dlp_result.total_findings),
        Severity::Warning,
    );
    // Use the redacted body instead
    // resp_bytes = resp_dlp_result.sanitized_payload.into_bytes();
    // Note: only if the DLP result contains a sanitized_payload field
}
```

> **IMPORTANT:** Check the current `DlpScanResult` struct in `dlp.rs` to see exactly what fields it exposes. The `scan()` function returns a `DlpScanResult` with `total_findings`, `findings` Vec, and `sanitized_payload`. Use `sanitized_payload` to replace the response bytes if findings > 0 and the action is Redact.

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Send a request through the proxy where the LLM response contains a test SSN pattern
```

---

### TASK 3: Integrate Spend Tracking into Proxy Pipeline

**Priority:** P1 — Required for budget enforcement
**File:** `src/proxy.rs`
**Dependencies:** Task 1
**Estimated LOC:** +30

#### What To Do

After the upstream response is received and the body is read, extract token usage from the response JSON and call `db.record_spend()`.

OpenAI and compatible APIs return a `usage` object in the response:

```json
{
  "usage": {
    "prompt_tokens": 50,
    "completion_tokens": 100,
    "total_tokens": 150
  }
}
```

Add this after the response body is received:

```rust
// ── SPEND TRACKING ──
// Parse token usage from the API response and record spend.
if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
    let tokens_in = resp_json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32;
    let tokens_out = resp_json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32;
    let model = resp_json["model"].as_str().unwrap_or("unknown");

    if tokens_in + tokens_out > 0 {
        if let Some(db_arc) = &state.db {
            if let Ok(db) = db_arc.lock() {
                let agent_hash = format!("{:?}", addr); // Use the caller's address as agent identifier
                match db.record_spend(&agent_hash, &provider_name, model, tokens_in, tokens_out) {
                    Ok(daily_total) => {
                        tracing::debug!(
                            tokens_in, tokens_out, model,
                            daily_total_usd = format!("{:.4}", daily_total),
                            "Spend recorded"
                        );
                    }
                    Err(e) => tracing::warn!("Failed to record spend: {}", e),
                }
            }
        }
    }
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Send a request through proxy, then check: sqlite3 ~/.raypher/data.db "SELECT * FROM spend_tracking;"
```

---

### TASK 4: Integrate Budget Check into Proxy Pre-Forward Logic

**Priority:** P1 — Budget enforcement before forwarding expensive requests
**File:** `src/proxy.rs`
**Dependencies:** Task 1, Task 3
**Estimated LOC:** +25

#### What To Do

In `handle_proxy()`, after the policy evaluation and before forwarding to the upstream, add a budget check:

```rust
// ── BUDGET CHECK ──
// If the policy has budget limits, check them before forwarding.
if let Some(db_arc) = &state.db {
    if let Ok(db) = db_arc.lock() {
        let budget_status = policy::check_budget(&policy_snapshot, &db);
        if budget_status.is_exceeded() {
            tracing::warn!("Budget exceeded: {:?}", budget_status);
            log_proxy_event(
                &state.db,
                "BUDGET_EXCEEDED",
                &addr,
                &format!("Request denied: {:?}", budget_status),
                Severity::Critical,
            );
            return Err(StatusCode::TOO_MANY_REQUESTS); // 429
        }
    }
}

// ── MODEL ROUTING / DOWNGRADE ──
// Apply model routing rules (e.g., downgrade gpt-4 to gpt-3.5 when budget is high).
let budget_exceeded = if let Some(db_arc) = &state.db {
    if let Ok(db) = db_arc.lock() {
        policy::check_budget(&policy_snapshot, &db).is_exceeded()
    } else { false }
} else { false };

if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(&body_text) {
    if let Some(requested_model) = body_json["model"].as_str() {
        let routed_model = policy::route_model(&policy_snapshot, requested_model, budget_exceeded);
        if routed_model != requested_model {
            tracing::info!(
                from = requested_model, to = %routed_model,
                "Model downgraded by policy"
            );
            // Rewrite body JSON with the new model
            let mut json_mut = body_json.clone();
            json_mut["model"] = serde_json::Value::String(routed_model);
            body_text = serde_json::to_string(&json_mut).unwrap_or(body_text);
        }
    }
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Set budget.daily_limit_usd to 0.01 in policy.yaml, send a request — should get 429
```

---

### TASK 5: Implement Heuristics Level 3 (Environment Variable Analysis)

**Priority:** P2 — Phase 1 build plan specifies this level
**File:** `src/heuristics.rs`
**Dependencies:** None
**Estimated LOC:** +40 (replace stub)

#### What To Do

Replace the stub `analyze_level3_environment()` function (currently returns `None`) with actual logic.

> **NOTE:** `sysinfo` does NOT expose process environment variables on Windows. This function must use an alternative approach — reading `/proc/{pid}/environ` on Linux, or using Windows API `NtQueryInformationProcess` on Windows. Given complexity, implement a pragmatic version:

```rust
/// LEVEL 3: Environment variable analysis.
/// Checks the CURRENT process's env for API key indicators.
/// NOTE: We cannot read OTHER processes' env vars without elevated privileges.
/// This check runs on the Raypher process itself to detect leaked credentials.
pub fn analyze_level3_environment(_proc: &ProcessData) -> Option<HeuristicResult> {
    // Check current environment for common API key variables
    let api_key_vars = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_OPENAI_KEY",
        "HUGGINGFACE_TOKEN",
        "HF_TOKEN",
    ];

    for var_name in &api_key_vars {
        if let Ok(val) = std::env::var(var_name) {
            if !val.is_empty() && val != "PLACEHOLDER" && !val.starts_with("RAYPHER_") {
                return Some(HeuristicResult {
                    level: RiskLevel::Medium,
                    reason: format!("API key found in environment: {} ({}...)", var_name, &val[..std::cmp::min(8, val.len())]),
                    matched_rule: format!("L3_ENV_{}", var_name),
                    analysis_layer: 3,
                });
            }
        }
    }

    // Check for AI framework environment indicators
    let framework_vars = [
        ("LANGCHAIN_TRACING_V2", "LangChain tracing active"),
        ("CREWAI_TELEMETRY", "CrewAI framework detected"),
        ("AUTOGPT_WORKSPACE", "AutoGPT workspace configured"),
    ];

    for (var_name, description) in &framework_vars {
        if std::env::var(var_name).is_ok() {
            return Some(HeuristicResult {
                level: RiskLevel::Low,
                reason: format!("AI framework indicator: {} ({})", var_name, description),
                matched_rule: format!("L3_FRAMEWORK_{}", var_name),
                analysis_layer: 3,
            });
        }
    }

    None
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Test: set OPENAI_API_KEY=test123 && cargo run -- scan
```

---

### TASK 6: Enhance `check_time_restriction` with Day-of-Week Logic

**Priority:** P2 — Phase 3 build plan requires temporal policies including weekends
**File:** `src/policy.rs`
**Dependencies:** None
**Estimated LOC:** +20 (modify existing function)

#### What To Do

The current `check_time_restriction()` function checks work hours but not day-of-week. Add weekend detection:

```rust
/// Check if the current time is within allowed work hours AND on allowed days.
/// Returns true if access is allowed, false if time-restricted.
pub fn check_time_restriction(policy: &PolicyConfig) -> bool {
    let now = chrono::Local::now();
    let hour = now.hour();
    let weekday = now.weekday();

    // Check if weekends are blocked
    if policy.budget.block_weekends.unwrap_or(false) {
        match weekday {
            chrono::Weekday::Sat | chrono::Weekday::Sun => {
                tracing::info!(day = %weekday, "Temporal policy: weekend access blocked");
                return false;
            }
            _ => {}
        }
    }

    // Check work hours (existing logic)
    let start_hour = policy.budget.work_hours_start.unwrap_or(0);  // Default: no restriction
    let end_hour = policy.budget.work_hours_end.unwrap_or(24);      // Default: no restriction

    if start_hour == 0 && end_hour == 24 {
        return true; // No time restriction configured
    }

    if hour >= start_hour && hour < end_hour {
        true
    } else {
        tracing::info!(
            hour, start_hour, end_hour,
            "Temporal policy: outside work hours"
        );
        false
    }
}
```

> **NOTE:** You'll need to add `block_weekends: Option<bool>`, `work_hours_start: Option<u32>`, and `work_hours_end: Option<u32>` fields to the `BudgetConfig` struct if they don't already exist. Check the struct first.

Also add `use chrono::Timelike;` and `use chrono::Datelike;` at the top if not already imported.

#### Verification

```bash
cargo test test_time -- --nocapture
cargo build 2>&1 | grep -E "^error"
```

---

### TASK 7: Wire TLS CA Installation into `handle_setup()`

**Priority:** P2 — Phase 3 build plan requires `raypher setup` to install the CA
**File:** `src/main.rs`
**Dependencies:** None
**Estimated LOC:** +15

#### What To Do

In the `handle_setup()` function (line ~571–600), after the env var setup and before the success message, add TLS CA installation:

```rust
// Step 4: Generate and install TLS CA certificate
println!("\n🔐 Step 4: Setting up TLS certificate authority...");
let machine_id = identity::get_silicon_id();
let db = database::Database::init().expect("Failed to init database");
let tls_mgr = tls::TlsManager::new(&db, &machine_id);
match tls_mgr.install_ca() {
    Ok(()) => println!("   ✅ Raypher CA installed in OS Trust Store"),
    Err(e) => println!("   ⚠️  CA install failed (non-fatal): {}", e),
}
```

Also update `handle_uninstall()` to remove the CA:

```rust
// Remove TLS CA
println!("🔐 Removing TLS certificate...");
match tls::remove_ca_from_trust_store() {
    Ok(()) => println!("   ✅ CA removed from Trust Store"),
    Err(e) => println!("   ⚠️  CA removal failed: {}", e),
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Run `cargo run -- setup` and verify CA appears in certmgr.msc under "Trusted Root"
# Manual: Run `cargo run -- uninstall` and verify CA is removed
```

---

### TASK 8: Add `--service` Flag to `main.rs` for Windows SCM Dispatch

**Priority:** P2 — Phase 2 build plan requires silent service startup
**File:** `src/main.rs`
**Dependencies:** None
**Estimated LOC:** +10

#### What To Do

Check if `main.rs` already handles `--service` dispatching to `service::run_service()`. The Phase 2 build plan specifies that when Windows SCM starts the binary, it passes `--service` as an argument.

Look at the current `main()` function. If `--service` is not handled, add this before `Cli::parse()`:

```rust
// Check if we're being launched by the Windows Service Control Manager.
// SCM passes no args (or a service name). We detect service mode by checking
// if the first arg is "--service" (set during sc create).
let args: Vec<String> = std::env::args().collect();
if args.iter().any(|a| a == "--service") {
    return service::run_service().map_err(|e| {
        eprintln!("Service error: {}", e);
        std::process::exit(1);
    }).unwrap_or(());
}
```

> **NOTE:** Check the existing `main()` function first. The `service.rs` module already has `run_service()` with full SCM registration, event handling, and watchtower+proxy startup. This task is just about the entry-point dispatch.

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: sc create RaypherService binpath= "C:\...\raypher-core.exe --service" start= auto
# Manual: sc start RaypherService — verify service starts in services.msc
```

---

### TASK 9: Create Integration Test Suite

**Priority:** P2 — No `tests/` directory exists, all tests are currently unit tests inside modules
**File:** `tests/integration_tests.rs` [NEW]
**Dependencies:** Task 1 (spend tracking), dev-dependencies added
**Estimated LOC:** +200

#### What To Do

1. Add dev-dependencies to `Cargo.toml` (see PRE-FLIGHT section above).
2. Create `tests/integration_tests.rs`:

```rust
//! Integration tests for Raypher Phase 1-3 features.
//!
//! These tests verify end-to-end functionality without mocking.
//! They create temporary databases and test real module interactions.

use std::path::PathBuf;

// ── Test Helpers ──

fn create_test_db() -> raypher_core::database::Database {
    // Use a temp path so tests don't conflict with the real database
    // Note: Database::init() uses a fixed path. For testing, we'd need
    // to either parameterize the path or use a test-specific approach.
    raypher_core::database::Database::init().expect("Failed to init test DB")
}

// ── Phase 1: Scanner Tests ──

#[test]
fn test_scanner_returns_processes() {
    let system = raypher_core::scanner::create_system();
    let processes = raypher_core::scanner::scan_all_processes(&system);
    assert!(!processes.is_empty(), "Scanner should find at least one process");
}

#[test]
fn test_scanner_fingerprint_deterministic() {
    let system = raypher_core::scanner::create_system();
    let processes = raypher_core::scanner::scan_all_processes(&system);
    if let Some(proc) = processes.first() {
        let fp1 = raypher_core::scanner::fingerprint_process(proc);
        let fp2 = raypher_core::scanner::fingerprint_process(proc);
        assert_eq!(fp1, fp2, "Fingerprint should be deterministic");
    }
}

// ── Phase 1: Identity Tests ──

#[test]
fn test_silicon_id_not_empty() {
    let id = raypher_core::identity::get_silicon_id();
    assert!(!id.is_empty(), "Silicon ID should not be empty");
    assert!(id.len() >= 16, "Silicon ID should be at least 16 chars");
}

#[test]
fn test_silicon_id_deterministic() {
    let id1 = raypher_core::identity::get_silicon_id();
    let id2 = raypher_core::identity::get_silicon_id();
    assert_eq!(id1, id2, "Silicon ID should be deterministic across calls");
}

// ── Phase 1: Safety Tests ──

#[test]
fn test_safety_blocks_system_processes() {
    assert!(!raypher_core::safety::is_safe_to_kill(0, "System"));
    assert!(!raypher_core::safety::is_safe_to_kill(4, "System"));
    assert!(!raypher_core::safety::is_safe_to_kill(50, "csrss.exe"));
    assert!(!raypher_core::safety::is_safe_to_kill(100, "explorer.exe"));
}

#[test]
fn test_safety_allows_normal_processes() {
    assert!(raypher_core::safety::is_safe_to_kill(9999, "suspicious_agent.exe"));
}

// ── Phase 3: DLP Tests ──

#[test]
fn test_dlp_detects_openai_key() {
    let result = raypher_core::dlp::scan(
        "Here is my key: sk-proj-ABC123DEF456GHI789JKL0123456789",
        &raypher_core::policy::DlpAction::Redact,
        &[],
        &[],
    );
    assert!(result.total_findings > 0, "DLP should detect OpenAI key pattern");
}

#[test]
fn test_dlp_detects_credit_card() {
    let result = raypher_core::dlp::scan(
        "My card is 4111111111111111",
        &raypher_core::policy::DlpAction::Redact,
        &[],
        &[],
    );
    assert!(result.total_findings > 0, "DLP should detect Visa test card");
}

#[test]
fn test_dlp_respects_exclusions() {
    let result = raypher_core::dlp::scan(
        "Test email: test@example.com",
        &raypher_core::policy::DlpAction::Redact,
        &[],
        &["test@example.com".to_string()],
    );
    assert_eq!(result.total_findings, 0, "DLP should skip excluded patterns");
}

// ── Phase 3: Policy Tests ──

#[test]
fn test_policy_yaml_roundtrip() {
    let policy = raypher_core::policy::PolicyConfig::default();
    let yaml = serde_yaml::to_string(&policy).expect("Serialize failed");
    let loaded: raypher_core::policy::PolicyConfig = serde_yaml::from_str(&yaml).expect("Deserialize failed");
    assert_eq!(policy.capabilities.len(), loaded.capabilities.len());
}

#[test]
fn test_model_routing_downgrade() {
    let policy = raypher_core::policy::PolicyConfig::default();
    let result = raypher_core::policy::route_model(&policy, "gpt-4-turbo", true);
    // When budget is exceeded, should downgrade
    assert_ne!(result, "gpt-4-turbo", "Should downgrade when budget exceeded");
}
```

> **IMPORTANT:** The module visibility matters. Check if the functions are `pub` and the modules are `pub mod` in `main.rs`. If `main.rs` uses `mod scanner;` (private), then integration tests cannot access `raypher_core::scanner`. In that case, either:
>
> 1. Change to `pub mod scanner;` in `main.rs` (or in a `lib.rs`)
> 2. Or create a `src/lib.rs` that re-exports the public API

You'll likely need to create `src/lib.rs`:

```rust
pub mod scanner;
pub mod heuristics;
pub mod identity;
pub mod terminator;
pub mod safety;
pub mod watchtower;
pub mod panic;
pub mod database;
pub mod dlp;
pub mod policy;
pub mod tls;
pub mod installer;
pub mod secrets;
pub mod config;
// Keep service, proxy, dashboard, etc. internal
```

And adjust `Cargo.toml` to include both a `[[bin]]` and `[lib]` target.

#### Verification

```bash
cargo test --test integration_tests 2>&1
# Or with nextest:
cargo nextest run --test integration_tests
```

---

### TASK 10: Add Domain Whitelist Enforcement in Proxy

**Priority:** P2 — Phase 3 build plan specifies domain whitelist blocking
**File:** `src/proxy.rs`
**Dependencies:** None (policy.rs already has `check_domain`)
**Estimated LOC:** +15

#### What To Do

In `handle_proxy()`, after the provider is detected and before forwarding, add domain policy check:

```rust
// ── DOMAIN WHITELIST CHECK ──
let provider_route = installer::get_provider_route(&provider_name);
let upstream_domain = provider_route
    .map(|r| r.base_url)
    .unwrap_or("https://api.openai.com");

// Extract just the hostname from the upstream URL
if let Ok(parsed_url) = url::Url::parse(upstream_domain) {
    if let Some(host) = parsed_url.host_str() {
        if !policy::check_domain(&policy_snapshot, host) {
            tracing::warn!(domain = host, "Domain blocked by policy whitelist");
            log_proxy_event(
                &state.db,
                "DOMAIN_BLOCKED",
                &addr,
                &format!("Blocked: destination {} not in whitelist", host),
                Severity::Critical,
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Add "api.openai.com" to domain_whitelist in policy.yaml, verify deepseek.com is blocked
```

---

### TASK 11: Enhance Time-Based Policy Enforcement in Proxy

**Priority:** P3 — Phase 3 build plan temporal policies
**File:** `src/proxy.rs`
**Dependencies:** Task 6 (enhanced `check_time_restriction`)
**Estimated LOC:** +10

#### What To Do

In `handle_proxy()`, add time restriction check early in the pipeline:

```rust
// ── TEMPORAL POLICY CHECK ──
if !policy::check_time_restriction(&policy_snapshot) {
    tracing::warn!("Request denied: outside allowed time window");
    log_proxy_event(
        &state.db,
        "TIME_RESTRICTED",
        &addr,
        "Denied: AI access blocked outside work hours",
        Severity::Warning,
    );
    return Err(StatusCode::FORBIDDEN);
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Test: Set work_hours_start to a future hour, send request through proxy — should get 403
```

---

### TASK 12: WiX MSI Installer — Add Silent Setup Custom Action

**Priority:** P3 — Phase 3 build plan specifies MSI runs `raypher setup --silent`
**File:** `wix/main.wxs` [MODIFY]
**Dependencies:** Task 7 (setup must include CA install)
**Estimated LOC:** +15 XML

#### What To Do

Add a Custom Action to the WiX installer that runs `raypher setup` silently after MSI installation:

```xml
<!-- Add inside the <Package> element -->
<CustomAction Id="RunSetup"
    Directory="INSTALLFOLDER"
    ExeCommand="[INSTALLFOLDER]raypher-core.exe setup"
    Execute="deferred"
    Impersonate="no"
    Return="ignore" />

<InstallExecuteSequence>
    <Custom Action="RunSetup" After="InstallFiles">NOT Installed</Custom>
</InstallExecuteSequence>
```

> **NOTE:** Check the existing `wix/main.wxs` for the current structure and element names. The binary might be installed as `raypher-core.exe` or `raypher.exe` — match whatever the `<File>` element specifies.

Also add a `--silent` flag to the `Setup` command in `main.rs` so the setup runs non-interactively:

```rust
/// Zero-touch setup — configure env vars and auto-allow runtimes
Setup {
    /// Run in silent mode (no interactive prompts, for MSI installer)
    #[arg(long)]
    silent: bool,
},
```

And modify `handle_setup()` to skip interactive prompts when `silent` is true.

#### Verification

```bash
cargo build --release 2>&1 | grep -E "^error"
# Build MSI: cargo wix (or the build.ps1 script)
# Manual: Install MSI on a clean Windows VM, verify env vars are set and service is running
```

---

### TASK 13: Add `RequestContext` Struct for Full Policy Rule Evaluation

**Priority:** P3 — Enables Phase 3 advanced rule matching (trust scores, model checks, etc.)
**File:** `src/policy.rs`
**Dependencies:** None
**Estimated LOC:** +60

#### What To Do

The Phase 3 build plan describes a `RequestContext` struct used for evaluating policy rules. Currently the policy has individual check functions (`check_budget`, `check_domain`, `check_time_restriction`), but no unified context object for composite rule evaluation.

Add:

```rust
/// The request context passed to policy evaluation.
/// Contains all information needed to make allow/deny decisions.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The agent's process hash (SHA-256 of exe path)
    pub agent_hash: String,
    /// The agent's trust score (0–1000, from behavioral analysis)
    pub trust_score: u32,
    /// The requested model name (e.g., "gpt-4-turbo")
    pub model: Option<String>,
    /// The destination domain
    pub destination: Option<String>,
    /// Today's accumulated spend for this agent
    pub daily_spend: f64,
    /// The action type (e.g., "chat", "completion", "embedding")
    pub action_type: Option<String>,
}

/// Result of a policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyVerdict {
    pub allowed: bool,
    pub reason: String,
    pub suggested_model: Option<String>,
}

/// Evaluate a full request context against all policy rules.
pub fn evaluate_request(policy: &PolicyConfig, ctx: &RequestContext) -> PolicyVerdict {
    // 1. Time check
    if !check_time_restriction(policy) {
        return PolicyVerdict {
            allowed: false,
            reason: "Outside allowed time window".to_string(),
            suggested_model: None,
        };
    }

    // 2. Domain check
    if let Some(ref domain) = ctx.destination {
        if !check_domain(policy, domain) {
            return PolicyVerdict {
                allowed: false,
                reason: format!("Domain '{}' not in whitelist", domain),
                suggested_model: None,
            };
        }
    }

    // 3. Budget check
    if let Some(ref budget) = Some(&policy.budget) {
        if ctx.daily_spend > budget.daily_limit_usd {
            return PolicyVerdict {
                allowed: false,
                reason: format!("Daily budget exceeded: ${:.2} > ${:.2}", ctx.daily_spend, budget.daily_limit_usd),
                suggested_model: None,
            };
        }
    }

    // 4. Model routing (allow but potentially downgrade)
    let suggested = ctx.model.as_ref().map(|m| {
        route_model(policy, m, ctx.daily_spend > policy.budget.daily_limit_usd * 0.8)
    });

    PolicyVerdict {
        allowed: true,
        reason: "All policy checks passed".to_string(),
        suggested_model: suggested,
    }
}
```

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
cargo test test_policy -- --nocapture
```

---

### TASK 14: Wire `start_policy_watcher` into Service and Proxy Startup

**Priority:** P3 — Hot-reload is implemented but must be started somewhere
**File:** `src/proxy.rs` (or `src/service.rs`)
**Dependencies:** None
**Estimated LOC:** +10

#### What To Do

Check if `start_policy_watcher()` is already called during proxy startup in `start_proxy()` or `run_service_inner()`. If not, add it.

In `start_proxy()` (around line 53–161 of `proxy.rs`), after the `PolicyHolder` is created, add:

```rust
// Start the policy hot-reload file watcher
let _watcher = policy::start_policy_watcher(
    policy_holder.clone(),
    state.db.clone().expect("DB required for policy watcher"),
);
// Note: _watcher must be kept alive for the duration of the proxy
```

> **CHECK FIRST:** The watcher might already be started. Search the codebase for `start_policy_watcher` to see if it's called anywhere.

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Start proxy, edit ~/.raypher/policy.yaml, check logs for "Policy hot-reloaded"
```

---

### TASK 15: Enhance Dashboard Spend Panel with Real Data

**Priority:** P3 — Dashboard spend endpoints exist but may return placeholder data
**File:** `src/dashboard.rs`
**Dependencies:** Task 1 (spend tracking in DB)
**Estimated LOC:** +20

#### What To Do

Check the `handle_spend_stats()` function (line ~454–490). Verify it actually queries the `spend_tracking` table. If it returns mock data, replace with real queries using `db.get_spend_by_provider()` and `db.get_daily_spend_total()`.

#### Verification

```bash
cargo build 2>&1 | grep -E "^error"
# Manual: Send several proxy requests, open dashboard at localhost:8888/dashboard, verify spend panel shows real data
```

---

## 📋 EXECUTION ORDER SUMMARY

| Order | Task | Priority | Dependencies |
|-------|------|----------|-------------|
| 1 | T1: Spend tracking in database.rs | P1 | None |
| 2 | T2: Bi-directional DLP in proxy.rs | P1 | None |
| 3 | T3: Spend tracking in proxy pipeline | P1 | T1 |
| 4 | T4: Budget check in proxy pre-forward | P1 | T1, T3 |
| 5 | T5: Heuristics Level 3 implementation | P2 | None |
| 6 | T6: Time restriction day-of-week | P2 | None |
| 7 | T7: Wire TLS CA into setup/uninstall | P2 | None |
| 8 | T8: `--service` flag in main.rs | P2 | None |
| 9 | T9: Integration test suite | P2 | T1 |
| 10 | T10: Domain whitelist in proxy | P2 | None |
| 11 | T11: Time-based policy in proxy | P3 | T6 |
| 12 | T12: WiX MSI silent setup | P3 | T7 |
| 13 | T13: RequestContext for policy eval | P3 | None |
| 14 | T14: Wire policy hot-reload watcher | P3 | None |
| 15 | T15: Dashboard spend panel real data | P3 | T1 |

---

## ✅ POST-IMPLEMENTATION VERIFICATION CHECKLIST

After all tasks are complete, run these verification steps in order:

### 1. Compile Check

```bash
cargo build 2>&1 | grep -E "^error"
# Expected: no errors
```

### 2. Unit Tests

```bash
cargo test 2>&1
# Expected: all tests pass (existing + new)
```

### 3. Integration Tests

```bash
cargo test --test integration_tests 2>&1
# Expected: all integration tests pass
```

### 4. Lint & Warnings

```bash
cargo clippy 2>&1 | head -50
# Expected: no critical warnings
```

### 5. Release Build

```bash
cargo build --release 2>&1
# Expected: successful release compilation
```

### 6. Functional Verification Sequence

```bash
# 1. Run setup
cargo run -- setup

# 2. Verify Silicon ID
cargo run -- identity

# 3. Seal a test key
cargo run -- seal openai --key "sk-test-placeholder"

# 4. Start proxy in background
cargo run -- proxy &

# 5. Send a test request through the proxy
curl -X POST http://127.0.0.1:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello with SSN 123-45-6789"}]}'

# 6. Check DLP redaction in logs
cargo run -- logs --limit 5

# 7. Check spend tracking
# sqlite3 ~/.raypher/data.db "SELECT * FROM spend_tracking;"

# 8. Open dashboard
cargo run -- dashboard
# Verify DLP panel, spend panel, policy panel show real data

# 9. Clean uninstall
cargo run -- uninstall
```

---

## 🧰 REFERENCE: KEY FILE PATHS

| Path | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point, all subcommand handlers |
| `src/proxy.rs` | Core proxy pipeline — most modifications go here |
| `src/database.rs` | SQLite audit ledger + all DB methods |
| `src/policy.rs` | YAML policy engine, budget, model routing |
| `src/dlp.rs` | DLP scanner (regex + entropy + custom) |
| `src/tls.rs` | Local CA generation + trust store management |
| `src/installer.rs` | Env var injection, provider routes, runtime detection |
| `src/heuristics.rs` | 3-level process analysis |
| `src/identity.rs` | TPM-backed Silicon ID |
| `src/scanner.rs` | Process scanner + AI detection |
| `src/terminator.rs` | Process tree termination |
| `src/safety.rs` | Kill-protection for system processes |
| `src/service.rs` | Windows SCM service registration |
| `src/secrets.rs` | Vault seal/unseal + allow list |
| `src/dashboard.rs` | API route handlers for the web UI |
| `src/dashboard_spa.html` | Embedded HTML for the dashboard SPA |
| `src/config.rs` | TOML configuration management |
| `src/watchtower.rs` | Continuous monitoring loop |
| `Cargo.toml` | Rust dependencies |
| `wix/main.wxs` | MSI installer definition |
| `~/.raypher/data.db` | Runtime SQLite database |
| `~/.raypher/policy.yaml` | Policy file (hot-reloaded) |
| `~/.raypher/config.toml` | User configuration |

---

**END OF IMPLEMENTATION PLAN**
