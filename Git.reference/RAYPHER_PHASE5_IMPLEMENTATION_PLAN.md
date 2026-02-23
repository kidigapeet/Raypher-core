# Phase 5: Real-World Hardening — Implementation Plan

Raypher Phase 4 is architecturally complete, but running a real agent (OpenClaw via `node.exe`) exposed critical UX and security gaps. This plan addresses every gap found during live testing plus proactive security improvements.

---

## User Review Required

> [!IMPORTANT]
> **Agent Identity Mapping:** OpenClaw registers as `node.exe` because the scanner only reads the OS binary name. We will add a command-line argument parser that maps `node.exe` running `openclaw` scripts → "OpenClaw.ai". This requires a curated list of known agent signatures. Should we allow users to manually label agents from the dashboard, or auto-detect only?

> [!WARNING]
> **Trust Score Starting Value:** Currently hardcoded at 850 in the front-end. We will make this backend-computed with a starting value of 850. Bad events (BUDGET_BLOCKED, DLP_BLOCKED, JAILBREAK_BLOCKED) will lower it. Clean operations slowly raise it back. Should the floor be 0 or should we use a 300-850 credit-score-style range?

> [!CAUTION]
> **Agent Runtime Limit:** Adding a "max runtime" to the budget section means Raypher will **kill agent API access** after the time limit expires. The agent itself won't be killed—only its ability to send API requests through Raypher. Is this the desired behavior, or should Raypher also terminate the agent process?

---

## Proposed Changes

### Component 1: Agent Identity & Per-Agent Tracking

This fixes the core problem: OpenClaw showing as `node.exe` with no per-agent attribution.

---

#### [MODIFY] [scanner.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/scanner.rs)

Add a `resolve_agent_name()` function that inspects command-line arguments to determine the real agent name:

```rust
/// Known agent signatures — maps command-line patterns to friendly names.
const AGENT_SIGNATURES: &[(&str, &str)] = &[
    ("openclaw", "OpenClaw.ai"),
    ("aider", "Aider"),
    ("cursor", "Cursor"),
    ("copilot", "GitHub Copilot"),
    ("continue", "Continue.dev"),
    ("cline", "Cline"),
    ("windsurf", "Windsurf"),
    ("devin", "Devin"),
    ("autogpt", "AutoGPT"),
    ("langchain", "LangChain Agent"),
    ("crewai", "CrewAI"),
    ("antigravity", "Antigravity"),
];

pub fn resolve_agent_name(process_name: &str, cmd_args: &[String]) -> String {
    let full_cmd = cmd_args.join(" ").to_lowercase();
    for (sig, name) in AGENT_SIGNATURES {
        if full_cmd.contains(sig) || process_name.to_lowercase().contains(sig) {
            return name.to_string();
        }
    }
    process_name.to_string()  // Fallback to binary name
}
```

Also add `friendly_name` field to `ProcessData` struct.

---

#### [NEW] [agent_registry.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/agent_registry.rs)

New module to track per-agent state: trust score, runtime, event counts.

- `struct AgentRecord { pid, agent_name, exe_hash, trust_score, first_seen, last_seen, total_requests, blocked_requests, runtime_start }`
- `fn register_agent(db, pid, name, hash) → AgentRecord`
- `fn update_trust_score(db, agent_hash, event_type) → i32`
- `fn get_agent_trust(db, agent_hash) → i32`
- `fn get_all_agents(db) → Vec<AgentRecord>`

---

#### [MODIFY] [database.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/database.rs)

Add new `agent_registry` table to `init_at()` schema:

```sql
CREATE TABLE IF NOT EXISTS agent_registry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_hash      TEXT NOT NULL UNIQUE,
    agent_name      TEXT NOT NULL,
    exe_path        TEXT,
    trust_score     INTEGER DEFAULT 850,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    total_requests  INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    runtime_start   TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_hash ON agent_registry(agent_hash);
```

Add `agent_name` field to `Event` struct:

```diff
pub struct Event {
    pub event_type: String,
    pub details_json: String,
    pub severity: Severity,
+   pub agent_name: Option<String>,
}
```

Add column `agent_name` to `events` table schema.

---

#### [MODIFY] [proxy.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/proxy.rs)

Update `log_proxy_event()` (line 969) to include PID and resolved agent name:

```diff
fn log_proxy_event(
    state: &ProxyState,
    event_type: &str,
    addr: &SocketAddr,
    path: &str,
    severity: Severity,
+   caller_pid: Option<u32>,
+   agent_name: Option<&str>,
) {
    let details = serde_json::json!({
        "client": addr.to_string(),
        "path": path,
+       "pid": caller_pid,
+       "agent": agent_name.unwrap_or("unknown"),
    });
```

Update `handle_proxy()` to resolve agent name from PID using `scanner::resolve_agent_name()` and pass it downstream. Update all `log_proxy_event()` call sites (roughly 8 calls) to pass the new parameters.

---

#### [MODIFY] [dashboard.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard.rs)

Update `handle_api_agents()` (line 283) to include `friendly_name` from the agent name resolver, and `trust_score` from the database.

---

### Component 2: Human-Readable Audit Ledger

The audit log currently shows raw JSON like `{"client":"127.0.0.1:53606","path":"/v1/chat/completions"}`. Users need plain English.

---

#### [NEW] [event_descriptions.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/event_descriptions.rs)

Translate event types to plain English:

```rust
pub fn describe_event(event_type: &str, details: &serde_json::Value) -> String {
    match event_type {
        "PROXY_FORWARD" => {
            let agent = details["agent"].as_str().unwrap_or("Unknown agent");
            let path = details["path"].as_str().unwrap_or("unknown");
            let provider = details["provider"].as_str().unwrap_or("AI provider");
            format!("{} sent a request to {} via {}", agent, path, provider)
        }
        "BUDGET_BLOCKED" => {
            let agent = details["agent"].as_str().unwrap_or("An agent");
            format!("{} was blocked — daily budget limit exceeded", agent)
        }
        "DLP_BLOCKED" => {
            format!("Sensitive data detected and blocked in outbound request")
        }
        "SSRF_HOST_BLOCKED" => {
            format!("SSRF attack blocked — agent tried to reach an internal network address")
        }
        "JAILBREAK_BLOCKED" => {
            format!("Prompt injection / jailbreak attempt detected and blocked")
        }
        "PROXY_UNAUTHORIZED" => {
            format!("Unauthorized request — missing Raypher security token")
        }
        "TIME_RESTRICTED" => {
            format!("Request blocked — AI access is outside allowed work hours")
        }
        "PANIC_DASHBOARD" => {
            format!("Emergency kill executed from the Dashboard")
        }
        _ => format!("Event: {}", event_type),
    }
}
```

---

#### [MODIFY] [dashboard.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard.rs)

Update `handle_api_events()` (line 98) to include:

- `description`: human-readable text from `describe_event()`
- `formatted_time`: parse ISO 8601 timestamp into `"Sat, 22 Feb 2026 — 15:17:43"`
- Keep existing `details_json` as the raw technical detail

Update `handle_api_merkle_status()` (line 611) to convert Unix timestamps to human-readable format.

---

#### [MODIFY] [dashboard_spa.html](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard_spa.html)

- Audit log rows: show `description` as the main text, `formatted_time` as full "Day, Date — Time" column, raw JSON expandable underneath
- Merkle entries table: add "Date & Time" column with human-readable format
- Agent detail view: show agent events filtered by agent name

---

### Component 3: Dynamic Trust Score

Replace the hardcoded 850 with a backend-computed score.

---

#### [NEW] [trust_score.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/trust_score.rs)

```rust
pub const INITIAL_TRUST: i32 = 850;
pub const MIN_TRUST: i32 = 0;
pub const MAX_TRUST: i32 = 850;

/// Score penalties for bad events
pub fn trust_penalty(event_type: &str) -> i32 {
    match event_type {
        "JAILBREAK_BLOCKED" => -100,    // Most severe
        "DLP_BLOCKED" => -50,           // Data leak attempt
        "SSRF_HOST_BLOCKED" => -75,     // Internal network attack
        "BUDGET_BLOCKED" => -25,        // Over-spending
        "PROXY_UNAUTHORIZED" => -30,    // Missing auth
        "PROXY_BLOCKED" => -40,         // Not in allowlist
        _ => 0,
    }
}

/// Score recovery for clean operations
pub fn trust_recovery(event_type: &str) -> i32 {
    match event_type {
        "PROXY_FORWARD" => 1,  // Slow recovery per clean request
        _ => 0,
    }
}
```

#### [MODIFY] [proxy.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/proxy.rs)

After each `log_proxy_event()` call, also call `agent_registry::update_trust_score()` with the event type to adjust the agent's trust score.

#### [MODIFY] [dashboard_spa.html](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard_spa.html)

Remove hardcoded `850` trust gauge and use the value from `/api/agents` response.

---

### Component 4: Custom DLP Words/Patterns UI

The DLP tab currently shows built-in patterns only. Users need a way to add custom words to redact.

---

#### [MODIFY] [dashboard.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard.rs)

Add three new API endpoints:

- `POST /api/dlp/patterns` — Add a custom DLP pattern (receives `name`, `pattern` regex, `severity`, optional `redact_to`)
- `GET /api/dlp/patterns` — List all custom patterns from policy
- `DELETE /api/dlp/patterns/:name` — Remove a custom pattern by name

These endpoints read/write to `phase4.custom_dlp_patterns` in the policy config and save via `policy::save_policy()`.

#### [MODIFY] [dashboard_spa.html](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard_spa.html)

Add to the DLP tab:

- "Custom Redaction Patterns" section with a table of existing patterns
- "Add Pattern" form: text input for the word/phrase, severity dropdown, and "Add" button
- Delete button per row
- Help text: "Add words, phrases, or regex patterns to automatically redact from all AI traffic"

---

### Component 5: Budget — Agent Runtime Controls

---

#### [MODIFY] [policy.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/policy.rs)

Add `max_runtime_minutes` to `BudgetConfig` (line 127):

```diff
pub struct BudgetConfig {
    pub daily_limit_usd: f64,
    pub hourly_limit_usd: f64,
    pub per_request_limit_usd: f64,
    pub action_on_exceed: BudgetAction,
+   #[serde(default = "default_runtime")]
+   pub max_runtime_minutes: u64,  // 0 = unlimited
}
```

Default: `0` (unlimited).

#### [MODIFY] [proxy.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/proxy.rs)

Add runtime check after budget check (around line 600):

- Look up agent's `runtime_start` from `agent_registry`
- If elapsed > `max_runtime_minutes` and limit > 0, block the request with `RUNTIME_EXCEEDED` event

#### [MODIFY] [dashboard_spa.html](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard_spa.html)

Add "Max Agent Runtime (minutes)" input field to the Budget tab, with save functionality via `/api/config/policy/update`.

---

### Component 6: Merkle Ledger UX

---

#### [MODIFY] [dashboard_spa.html](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard_spa.html)

- **Refresh Button**: Wire the existing "Refresh" button to call `loadMerkle()` on click. Currently it renders but has no `onclick` handler.
- **Date/Time Column**: Add a "Date & Time" column that converts `entry.timestamp` (Unix seconds) to a locale-formatted string: `new Date(entry.timestamp * 1000).toLocaleString()`
- **Event Description**: Show `describe_event()` output alongside the raw `event` type

#### [MODIFY] [dashboard.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/dashboard.rs)

In `handle_api_merkle_status()` (line 648), add `formatted_time` and `description` to each entry in `last_entries`:

```diff
let last_entries: Vec<serde_json::Value> = entries.iter().rev().take(10).map(|e| {
    serde_json::json!({
        "seq": e.seq,
        "event": e.event,
        "details": e.details,
        "timestamp": e.timestamp,
+       "formatted_time": format_unix_timestamp(e.timestamp),
+       "description": event_descriptions::describe_event(&e.event, &serde_json::from_str(&e.details).unwrap_or_default()),
        "hash_short": &e.own_hash[..8],
    })
}).collect();
```

---

### Component 7: Security Hardening for Real Agents

These are proactive security improvements identified during OpenClaw testing.

---

#### [MODIFY] [proxy.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/proxy.rs)

1. **Per-Agent Rate Limiting**: Add a `HashMap<String, (u64, Instant)>` to `ProxyState` tracking requests-per-minute per agent hash. Block if an agent exceeds 60 req/min.

2. **Session Binding**: After first successful request, bind the `X-Raypher-Token` to a specific PID. Reject if the PID changes (prevents token theft by another process).

#### [MODIFY] [scanner.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/scanner.rs)

1. **Child Process Spawning Alert**: When scanning, compare current process tree against previous scan. If a managed agent spawns new child processes not in the allowlist, log a `CHILD_SPAWN_ALERT` event.

#### [MODIFY] [heuristics.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/heuristics.rs)

1. **Enhanced Heuristic Patterns**: Add patterns for common agent framework file paths and environment variables beyond the current binary name matching.

---

### Component 8: Module Registration

---

#### [MODIFY] [lib.rs](file:///c:/Users/rayki/OneDrive/Desktop/Empire/Ideas/Raypher%20.exe/raypher-phase1-complete-master/src/lib.rs)

Register new modules:

```rust
pub mod agent_registry;
pub mod trust_score;
pub mod event_descriptions;
```

---

## Verification Plan

### Automated Tests

All commands run from the project root: `c:\Users\rayki\OneDrive\Desktop\Empire\Ideas\Raypher .exe\raypher-phase1-complete-master`

1. **Build check:**

   ```powershell
   cargo build --release 2>&1
   ```

   Must compile with zero errors.

2. **Existing test suite:**

   ```powershell
   cargo test 2>&1
   ```

   All existing tests (including `test_proxy_dlp_redaction`) must still pass.

3. **New unit tests** (added as part of implementation):
   - `trust_score::tests::test_penalty_and_recovery`
   - `event_descriptions::tests::test_describe_all_events`
   - `agent_registry::tests::test_register_and_score`

### Manual Verification

1. **Launch proxy:** `.\target\release\raypher-core.exe proxy`
2. **Open dashboard:** Navigate to `http://127.0.0.1:8888/dashboard`
3. **Verify Agent Identity:**
   - Start OpenClaw → agent should show as "OpenClaw.ai", not "node.exe"
   - Check agent detail card shows real trust score (not hardcoded 850)
4. **Verify Audit Log:**
   - Each entry should show: "Day, Date — Time" (e.g., "Sat, 22 Feb 2026 — 15:17:43")
   - Each entry should show a plain English description
   - Raw JSON should be visible when expanding the entry
5. **Verify DLP Custom Patterns:**
   - Go to DLP tab → Add a custom word (e.g., "ProjectCodename")
   - Send a request containing that word → verify it gets redacted
   - Delete the custom pattern → verify it's removed
6. **Verify Budget Runtime:**
   - Go to Budget tab → Set "Max Runtime" to 1 minute
   - Wait 1 minute → send a request → verify it gets blocked with `RUNTIME_EXCEEDED`
7. **Verify Merkle Refresh:**
   - Go to Merkle/Ledger tab → Click "Refresh" button
   - Verify entries reload with new data and show full date/time
8. **Verify Trust Score:**
   - Trigger a DLP block → verify agent trust score decreases
   - Send clean requests → verify trust slowly recovers
