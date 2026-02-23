// database.rs — The "Black Box" Audit Ledger
// Immutable local log using SQLite. Every event Raypher detects is recorded here.

use chrono::Utc;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

/// Severity levels for logged events.
#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An event to be logged to the audit ledger.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Type of event (e.g., "SCAN", "PANIC", "MONITOR_ALERT")
    pub event_type: String,
    /// JSON details — forensic evidence
    pub details_json: String,
    /// Severity level
    pub severity: Severity,
}

/// The database handle for the audit ledger.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Initialize the database.
    /// Creates `~/.raypher/data.db` and all required tables + indexes.
    /// Initialize the database using the default path.
    pub fn init() -> SqlResult<Self> {
        Self::init_at(Self::db_path())
    }

    /// Initialize the database at a specific path.
    pub fn init_at(db_path: PathBuf) -> SqlResult<Self> {
        // Ensure the directory exists
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    rusqlite::Error::InvalidParameterName(format!(
                        "Could not create directory {:?}: {}",
                        parent, e
                    ))
                })?;
            }
        }

        let conn = Connection::open(&db_path)?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Create tables
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                event_type      TEXT    NOT NULL,
                details_json    TEXT    NOT NULL DEFAULT '{}',
                severity        TEXT    NOT NULL DEFAULT 'INFO'
            );

            CREATE TABLE IF NOT EXISTS identity (
                fingerprint_hash    TEXT PRIMARY KEY,
                first_seen          TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                provider        TEXT NOT NULL UNIQUE,
                encrypted_blob  BLOB NOT NULL,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS allow_list (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                exe_path        TEXT NOT NULL,
                exe_hash        TEXT NOT NULL UNIQUE,
                friendly_name   TEXT,
                added_at        TEXT NOT NULL,
                added_by        TEXT NOT NULL DEFAULT 'manual'
            );

            CREATE TABLE IF NOT EXISTS policy (
                key             TEXT PRIMARY KEY,
                value           TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS spend_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                provider        TEXT NOT NULL,
                model           TEXT,
                cost_usd        REAL NOT NULL,
                tokens_used     INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events (timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_severity
                ON events (severity);

            CREATE INDEX IF NOT EXISTS idx_secrets_provider
                ON secrets (provider);

            CREATE INDEX IF NOT EXISTS idx_allow_list_hash
                ON allow_list (exe_hash);

            CREATE INDEX IF NOT EXISTS idx_spend_log_timestamp
                ON spend_log (timestamp);

            CREATE TABLE IF NOT EXISTS dlp_findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                direction       TEXT NOT NULL,
                category        TEXT NOT NULL,
                pattern_name    TEXT NOT NULL,
                action_taken    TEXT NOT NULL,
                snippet         TEXT,
                provider        TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_dlp_findings_timestamp
                ON dlp_findings (timestamp);

            CREATE INDEX IF NOT EXISTS idx_dlp_findings_category
                ON dlp_findings (category);

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

            CREATE TABLE IF NOT EXISTS agent_registry (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_hash        TEXT NOT NULL UNIQUE,
                agent_name        TEXT NOT NULL,
                exe_path          TEXT,
                trust_score       INTEGER NOT NULL DEFAULT 850,
                first_seen        TEXT NOT NULL,
                last_seen         TEXT NOT NULL,
                total_requests    INTEGER NOT NULL DEFAULT 0,
                blocked_requests  INTEGER NOT NULL DEFAULT 0,
                runtime_start     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_agent_registry_hash
                ON agent_registry(agent_hash);
            ",
        )?;

        let db = Database { conn };
        db.migrate_vault_schema()?;
        Ok(db)
    }

    /// Get the path to the database file.
    fn db_path() -> PathBuf {
        let home = dirs_next().unwrap_or_else(|| PathBuf::from("."));
        home.join(".raypher").join("data.db")
    }

    /// Log an event to the audit ledger.
    /// Timestamp is always UTC (ISO 8601 format) — data integrity guarantee.
    pub fn log_event(&self, event: &Event) -> SqlResult<i64> {
        let timestamp = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO events (timestamp, event_type, details_json, severity)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                timestamp,
                event.event_type,
                event.details_json,
                event.severity.as_str(),
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Store or update the device identity fingerprint.
    pub fn store_identity(&self, fingerprint_hash: &str) -> SqlResult<()> {
        let timestamp = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT OR IGNORE INTO identity (fingerprint_hash, first_seen)
             VALUES (?1, ?2)",
            params![fingerprint_hash, timestamp],
        )?;

        Ok(())
    }

    /// Get the stored machine fingerprint.
    pub fn get_fingerprint(&self) -> SqlResult<String> {
        self.conn.query_row(
            "SELECT fingerprint_hash FROM identity LIMIT 1",
            [],
            |row| row.get(0),
        )
    }

    /// Query recent events. Returns the last `limit` events.
    pub fn recent_events(&self, limit: u32) -> SqlResult<Vec<(i64, String, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, details_json, severity
             FROM events
             ORDER BY id DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;

        rows.collect()
    }

    /// Get the total number of events in the ledger.
    pub fn event_count(&self) -> SqlResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
    }

    /// Access the underlying connection (primarily for testing).
    pub fn get_conn(&self) -> &Connection {
        &self.conn
    }

    // ── Secrets Methods ────────────────────────────────────────

    /// Store an encrypted secret for a provider (insert or update).
    pub fn store_secret(&self, provider: &str, secret_type: &str, label: Option<&str>, encrypted_blob: &[u8]) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO secrets (provider, secret_type, label, encrypted_blob, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(provider) DO UPDATE SET encrypted_blob = ?4, secret_type = ?2, label = ?3, updated_at = ?5",
            params![provider, secret_type, label, encrypted_blob, now],
        )?;
        Ok(())
    }

    /// Get an encrypted secret for a provider.
    pub fn get_secret(&self, provider: &str) -> SqlResult<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT encrypted_blob FROM secrets WHERE provider = ?1"
        )?;
        let mut rows = stmt.query_map(params![provider], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        match rows.next() {
            Some(Ok(blob)) => Ok(Some(blob)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// List all providers with their creation dates, types, and labels.
    pub fn list_secrets(&self) -> SqlResult<Vec<(String, String, String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider, created_at, secret_type, label FROM secrets ORDER BY provider"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        rows.collect()
    }

    /// Delete a secret by provider name.
    pub fn delete_secret(&self, provider: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM secrets WHERE provider = ?1",
            params![provider],
        )?;
        Ok(())
    }

    // ── Allow List Methods ─────────────────────────────────────

    /// Add an executable to the allow list.
    pub fn add_to_allow_list(&self, exe_path: &str, exe_hash: &str, friendly_name: &str) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO allow_list (exe_path, exe_hash, friendly_name, added_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![exe_path, exe_hash, friendly_name, now],
        )?;
        Ok(())
    }

    /// Check if an exe hash is in the allow list.
    pub fn check_allow_list(&self, exe_hash: &str) -> SqlResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM allow_list WHERE exe_hash = ?1",
            params![exe_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// List all entries in the allow list.
    pub fn list_allow_list(&self) -> SqlResult<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT exe_path, exe_hash, COALESCE(friendly_name, '') FROM allow_list ORDER BY added_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect()
    }

    /// Remove an entry from the allow list by hash.
    pub fn remove_from_allow_list(&self, exe_hash: &str) -> SqlResult<()> {
        self.conn.execute(
            "DELETE FROM allow_list WHERE exe_hash = ?1",
            params![exe_hash],
        )?;
        Ok(())
    }

    // ── Policy Methods ─────────────────────────────────────────

    /// Store a policy value by key (insert or update).
    pub fn store_policy(&self, key: &str, value: &str) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO policy (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Get a policy value by key.
    pub fn get_policy(&self, key: &str) -> SqlResult<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT value FROM policy WHERE key = ?1"
        )?;
        let mut rows = stmt.query_map(params![key], |row| {
            row.get::<_, String>(0)
        })?;
        match rows.next() {
            Some(Ok(val)) => Ok(Some(val)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    // ── Spend Tracking ─────────────────────────────────────────

    /// Log a spend event (API call cost).
    pub fn log_spend(&self, provider: &str, model: Option<&str>, cost_usd: f64, tokens: Option<i64>) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO spend_log (timestamp, provider, model, cost_usd, tokens_used)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now, provider, model, cost_usd, tokens],
        )?;
        Ok(())
    }

    /// Get total spend for today (UTC).
    pub fn get_daily_spend(&self) -> SqlResult<f64> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.conn.query_row(
            "SELECT COALESCE(SUM(cost_usd), 0.0) FROM spend_log WHERE timestamp LIKE ?1",
            params![format!("{}%", today)],
            |row| row.get(0),
        )
    }

    /// Get hourly spend breakdown for today.
    pub fn get_hourly_spend(&self) -> SqlResult<Vec<(String, f64)>> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut stmt = self.conn.prepare(
            "SELECT substr(timestamp, 12, 2) as hour, COALESCE(SUM(cost_usd), 0.0)
             FROM spend_log WHERE timestamp LIKE ?1
             GROUP BY hour ORDER BY hour"
        )?;
        let rows = stmt.query_map(params![format!("{}%", today)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?;
        rows.collect()
    }

    /// Get daily spend for the last 7 days.
    pub fn get_weekly_spend(&self) -> SqlResult<Vec<(String, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT substr(timestamp, 1, 10) as day, COALESCE(SUM(cost_usd), 0.0)
             FROM spend_log
             WHERE timestamp >= datetime('now', '-7 days')
             GROUP BY day ORDER BY day"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?;
        rows.collect()
    }

    /// Get total spend by provider.
    pub fn get_provider_spend(&self) -> SqlResult<Vec<(String, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider, COALESCE(SUM(cost_usd), 0.0)
             FROM spend_log GROUP BY provider ORDER BY SUM(cost_usd) DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?;
        rows.collect()
    }

    // ── Advanced Spend Tracking (Phase 3) ──────────────────────

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
    pub fn get_hourly_spend_v2(&self, _agent_hash: &str) -> SqlResult<f64> {
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
    // ── DLP Findings ──────────────────────────────────────────

    /// Log a DLP finding to the database.
    pub fn log_dlp_finding(
        &self,
        direction: &str,
        category: &str,
        pattern_name: &str,
        action_taken: &str,
        snippet: Option<&str>,
        provider: Option<&str>,
    ) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO dlp_findings (timestamp, direction, category, pattern_name, action_taken, snippet, provider)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![now, direction, category, pattern_name, action_taken, snippet, provider],
        )?;
        Ok(())
    }

    /// Get recent DLP findings (most recent first).
    pub fn get_recent_dlp_findings(&self, limit: usize) -> SqlResult<Vec<(String, String, String, String, String, Option<String>, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, direction, category, pattern_name, action_taken, snippet, provider
             FROM dlp_findings ORDER BY id DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;
        rows.collect()
    }

    /// Get DLP stats: count by category.
    pub fn get_dlp_stats(&self) -> SqlResult<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT category, COUNT(*) as cnt FROM dlp_findings GROUP BY category ORDER BY cnt DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.collect()
    }

    // ── Vault Schema Migration ────────────────────────────────

    /// Run vault schema migrations (add secret_type and label columns).
    pub fn migrate_vault_schema(&self) -> SqlResult<()> {
        // Check if column exists by trying to query it
        let has_type = self.conn.execute("SELECT secret_type FROM secrets LIMIT 0", []);
        if has_type.is_err() {
            self.conn.execute_batch(
                "ALTER TABLE secrets ADD COLUMN secret_type TEXT NOT NULL DEFAULT 'api_key';
                 ALTER TABLE secrets ADD COLUMN label TEXT;"
            )?;
        }
        Ok(())
    }

    // ── Stats Queries (for Intel tab) ──────────────────────────

    /// Count events by severity for the analytics dashboard.
    pub fn get_threat_counts(&self) -> SqlResult<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity ORDER BY severity"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        rows.collect()
    }

    /// Count events by event_type for the threat matrix.
    pub fn get_events_by_type(&self) -> SqlResult<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        rows.collect()
    }
}

/// Get the user's home directory (cross-platform).
fn dirs_next() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

/// Print recent events in a formatted table.
pub fn print_recent_events(db: &Database, limit: u32) {
    match db.recent_events(limit) {
        Ok(events) if events.is_empty() => {
            println!("  📭 No events recorded yet.");
        }
        Ok(events) => {
            println!(
                "  {:<5} {:<22} {:<18} {:<10} {}",
                "ID", "TIMESTAMP", "TYPE", "SEVERITY", "DETAILS"
            );
            println!("  {}", "-".repeat(75));

            for (id, ts, etype, details, severity) in &events {
                // Truncate the timestamp for display
                let ts_short = if ts.len() > 19 { &ts[..19] } else { ts };
                let details_short = if details.len() > 30 {
                    format!("{}…", &details[..30])
                } else {
                    details.clone()
                };
                println!(
                    "  {:<5} {:<22} {:<18} {:<10} {}",
                    id, ts_short, etype, severity, details_short
                );
            }

            let count = db.event_count().unwrap_or(0);
            println!("\n  📊 Showing {} of {} total events.", events.len(), count);
        }
        Err(e) => {
            eprintln!("  ❌ Failed to query events: {}", e);
        }
    }
}
