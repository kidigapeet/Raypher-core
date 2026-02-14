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
    pub fn init() -> SqlResult<Self> {
        let db_path = Self::db_path();

        // Ensure the directory exists
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                rusqlite::Error::InvalidParameterName(format!(
                    "Could not create directory {:?}: {}",
                    parent, e
                ))
            })?;
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

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events (timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_severity
                ON events (severity);

            CREATE INDEX IF NOT EXISTS idx_secrets_provider
                ON secrets (provider);

            CREATE INDEX IF NOT EXISTS idx_allow_list_hash
                ON allow_list (exe_hash);
            ",
        )?;

        Ok(Database { conn })
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

    // ── Secrets Methods ────────────────────────────────────────

    /// Store an encrypted secret for a provider (insert or update).
    pub fn store_secret(&self, provider: &str, encrypted_blob: &[u8]) -> SqlResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO secrets (provider, encrypted_blob, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(provider) DO UPDATE SET encrypted_blob = ?2, updated_at = ?3",
            params![provider, encrypted_blob, now],
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

    /// List all providers with their creation dates.
    pub fn list_secrets(&self) -> SqlResult<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider, created_at FROM secrets ORDER BY provider"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
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
