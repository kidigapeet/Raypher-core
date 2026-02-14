// ──────────────────────────────────────────────────────────────
//  Raypher — Watchdog Module
//  Internal health monitoring with heartbeat tracking.
//  If the main loop stalls, the watchdog flags unhealthy status
//  which can be queried via the /health endpoint or CLI.
// ──────────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Watchdog monitors the health of the Raypher service by tracking
/// heartbeats from the main scan loop. If the loop stalls (no heartbeat
/// within the configured timeout), the system is considered unhealthy.
#[derive(Clone)]
pub struct Watchdog {
    /// Heartbeat counter — incremented each successful scan cycle
    heartbeat_count: Arc<AtomicU64>,
    /// When the watchdog was created (for uptime tracking)
    started_at: Instant,
    /// Last heartbeat timestamp (epoch millis stored as AtomicU64)
    last_heartbeat_ms: Arc<AtomicU64>,
    /// Maximum allowed time between heartbeats before flagging unhealthy
    heartbeat_timeout: Duration,
}

impl Watchdog {
    /// Create a new Watchdog with the given heartbeat timeout.
    /// Default timeout: 30 seconds (if the scan loop stalls for 30s, we're unhealthy).
    pub fn new(heartbeat_timeout: Duration) -> Self {
        let now_ms = Instant::now().elapsed().as_millis() as u64;
        Watchdog {
            heartbeat_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
            last_heartbeat_ms: Arc::new(AtomicU64::new(now_ms)),
            heartbeat_timeout,
        }
    }

    /// Record a heartbeat — called by the Watchtower after each successful scan cycle.
    pub fn heartbeat(&self) {
        self.heartbeat_count.fetch_add(1, Ordering::Relaxed);
        let elapsed_ms = self.started_at.elapsed().as_millis() as u64;
        self.last_heartbeat_ms.store(elapsed_ms, Ordering::Relaxed);
    }

    /// Returns true if the system is healthy (received a heartbeat within the timeout).
    pub fn is_healthy(&self) -> bool {
        let last_ms = self.last_heartbeat_ms.load(Ordering::Relaxed);
        let now_ms = self.started_at.elapsed().as_millis() as u64;
        let elapsed = Duration::from_millis(now_ms.saturating_sub(last_ms));
        elapsed < self.heartbeat_timeout
    }

    /// Get the total number of heartbeats received since startup.
    pub fn heartbeat_count(&self) -> u64 {
        self.heartbeat_count.load(Ordering::Relaxed)
    }

    /// Get the uptime of the service since the watchdog was created.
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get a health status report suitable for logging or the CLI.
    pub fn status_report(&self) -> WatchdogStatus {
        let last_ms = self.last_heartbeat_ms.load(Ordering::Relaxed);
        let now_ms = self.started_at.elapsed().as_millis() as u64;
        let since_last = Duration::from_millis(now_ms.saturating_sub(last_ms));

        WatchdogStatus {
            healthy: self.is_healthy(),
            heartbeats: self.heartbeat_count(),
            uptime: self.uptime(),
            since_last_heartbeat: since_last,
            timeout: self.heartbeat_timeout,
        }
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Watchdog::new(Duration::from_secs(30))
    }
}

/// Snapshot of watchdog health status for reporting.
#[derive(Debug)]
pub struct WatchdogStatus {
    pub healthy: bool,
    pub heartbeats: u64,
    pub uptime: Duration,
    pub since_last_heartbeat: Duration,
    pub timeout: Duration,
}

impl std::fmt::Display for WatchdogStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let health_icon = if self.healthy { "✅" } else { "❌" };
        let uptime_secs = self.uptime.as_secs();
        let hours = uptime_secs / 3600;
        let minutes = (uptime_secs % 3600) / 60;
        let seconds = uptime_secs % 60;

        writeln!(f, "  Health:     {} {}", health_icon, if self.healthy { "Healthy" } else { "UNHEALTHY — heartbeat stalled" })?;
        writeln!(f, "  Heartbeats: {}", self.heartbeats)?;
        writeln!(f, "  Uptime:     {:02}h {:02}m {:02}s", hours, minutes, seconds)?;
        writeln!(f, "  Last Beat:  {:.1}s ago", self.since_last_heartbeat.as_secs_f64())?;
        write!(f, "  Timeout:    {}s", self.timeout.as_secs())
    }
}
