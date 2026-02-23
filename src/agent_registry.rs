// ──────────────────────────────────────────────────────────────
//  Raypher — Agent Registry (Phase 5)
//  Tracks all discovered AI agents, their trust scores, and session
//  metadata. This is the "DMV" that knows every agent on the machine.
// ──────────────────────────────────────────────────────────────

use crate::database::Database;
use crate::trust_score;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// A record of a known AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Unique identifier: SHA-256 of the exe path, or PID-string if exe unknown.
    pub agent_hash: String,
    /// Friendly resolved name (e.g., "OpenClaw.ai" instead of "node.exe")
    pub agent_name: String,
    /// Full path to the executable on disk
    pub exe_path: Option<String>,
    /// Dynamic trust score (300–850)
    pub trust_score: i32,
    /// ISO 8601 timestamp of first detection
    pub first_seen: String,
    /// ISO 8601 timestamp of most recent activity
    pub last_seen: String,
    /// Total requests forwarded through the proxy
    pub total_requests: i64,
    /// Total requests blocked by any policy
    pub blocked_requests: i64,
    /// ISO 8601 timestamp of session start (reset on re-launch)
    pub runtime_start: Option<String>,
}

impl AgentRecord {
    /// How many minutes this agent has been running in the current session.
    pub fn runtime_minutes(&self) -> Option<i64> {
        let start_str = self.runtime_start.as_deref()?;
        let start = chrono::DateTime::parse_from_rfc3339(start_str).ok()?;
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(start.with_timezone(&chrono::Utc));
        Some(diff.num_minutes())
    }
}

/// Register a new agent or update its last_seen timestamp.
/// Returns the current trust score for the agent.
pub fn register_or_update(
    db: &Database,
    agent_hash: &str,
    agent_name: &str,
    exe_path: Option<&str>,
) -> i32 {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.get_conn();

    // Try INSERT — if it already exists, update last_seen + name only
    match conn.execute(
        "INSERT INTO agent_registry
            (agent_hash, agent_name, exe_path, trust_score, first_seen, last_seen,
             total_requests, blocked_requests, runtime_start)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0, 0, ?5)
         ON CONFLICT(agent_hash) DO UPDATE SET
            agent_name = ?2,
            last_seen  = ?5",
        params![
            agent_hash,
            agent_name,
            exe_path,
            trust_score::INITIAL_TRUST,
            now,
        ],
    ) {
        Ok(_) => {}
        Err(e) => warn!("agent_registry: register failed: {}", e),
    }

    // Return current trust score
    get_trust_score(db, agent_hash)
}

/// Apply an event to an agent's trust score and request counters.
pub fn record_event(db: &Database, agent_hash: &str, event_type: &str) {
    let current = get_trust_score(db, agent_hash);
    let new_score = trust_score::apply_event(current, event_type);
    let is_block = trust_score::trust_penalty(event_type) < 0;
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.get_conn();

    if is_block {
        let _ = conn.execute(
            "UPDATE agent_registry SET
                trust_score = ?1,
                last_seen = ?2,
                blocked_requests = blocked_requests + 1
             WHERE agent_hash = ?3",
            params![new_score, now, agent_hash],
        );
    } else {
        let _ = conn.execute(
            "UPDATE agent_registry SET
                trust_score = ?1,
                last_seen = ?2,
                total_requests = total_requests + 1
             WHERE agent_hash = ?3",
            params![new_score, now, agent_hash],
        );
    }
}

/// Get the current trust score for an agent. Returns INITIAL_TRUST if not found.
pub fn get_trust_score(db: &Database, agent_hash: &str) -> i32 {
    let conn = db.get_conn();
    conn.query_row(
        "SELECT trust_score FROM agent_registry WHERE agent_hash = ?1",
        params![agent_hash],
        |row| row.get::<_, i32>(0),
    )
    .unwrap_or(trust_score::INITIAL_TRUST)
}

/// Get all registered agents ordered by last_seen descending.
pub fn get_all_agents(db: &Database) -> Vec<AgentRecord> {
    let conn = db.get_conn();
    let sql = "SELECT agent_hash, agent_name, exe_path, trust_score, first_seen, last_seen,
                      total_requests, blocked_requests, runtime_start
               FROM agent_registry
               ORDER BY last_seen DESC";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    // Collect all rows into an owned Vec while stmt is still in scope.
    let mut out: Vec<AgentRecord> = Vec::new();
    if let Ok(iter) = stmt.query_map([], |row| {
        Ok(AgentRecord {
            agent_hash:       row.get(0)?,
            agent_name:       row.get(1)?,
            exe_path:         row.get(2)?,
            trust_score:      row.get(3)?,
            first_seen:       row.get(4)?,
            last_seen:        row.get(5)?,
            total_requests:   row.get(6)?,
            blocked_requests: row.get(7)?,
            runtime_start:    row.get(8)?,
        })
    }) {
        for r in iter.flatten() {
            out.push(r);
        }
    }
    out
}

/// Get one agent by hash.
pub fn get_agent(db: &Database, agent_hash: &str) -> Option<AgentRecord> {
    let conn = db.get_conn();
    conn.query_row(
        "SELECT agent_hash, agent_name, exe_path, trust_score, first_seen, last_seen,
                total_requests, blocked_requests, runtime_start
         FROM agent_registry WHERE agent_hash = ?1",
        params![agent_hash],
        |row| {
            Ok(AgentRecord {
                agent_hash:       row.get(0)?,
                agent_name:       row.get(1)?,
                exe_path:         row.get(2)?,
                trust_score:      row.get(3)?,
                first_seen:       row.get(4)?,
                last_seen:        row.get(5)?,
                total_requests:   row.get(6)?,
                blocked_requests: row.get(7)?,
                runtime_start:    row.get(8)?,
            })
        },
    )
    .ok()
}

/// Check if an agent has exceeded its allowed runtime in minutes.
/// Returns true if max_runtime > 0 AND runtime_minutes >= max_runtime.
pub fn is_runtime_exceeded(db: &Database, agent_hash: &str, max_runtime_minutes: u64) -> bool {
    if max_runtime_minutes == 0 {
        return false; // 0 = unlimited
    }
    if let Some(agent) = get_agent(db, agent_hash) {
        if let Some(minutes) = agent.runtime_minutes() {
            return minutes >= max_runtime_minutes as i64;
        }
    }
    false
}
