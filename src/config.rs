// ──────────────────────────────────────────────────────────────
//  Raypher — Configuration File System
//  Loads settings from ~/.raypher/config.toml with sensible defaults.
//  Enterprise-ready: every parameter is configurable without recompilation.
// ──────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

// ── Top-Level Config ───────────────────────────────────────────

/// Root configuration structure. Maps 1:1 to config.toml sections.
#[derive(Debug, Deserialize, Serialize)]
pub struct RaypherConfig {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub watchtower: WatchtowerConfig,
    #[serde(default)]
    pub updater: UpdaterConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

// ── Section: Service ───────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceConfig {
    /// Windows service name (must match MSI installer)
    #[serde(default = "default_service_name")]
    pub name: String,
    /// Human-readable display name in services.msc
    #[serde(default = "default_display_name")]
    pub display_name: String,
}

fn default_service_name() -> String { "RaypherService".into() }
fn default_display_name() -> String { "Raypher AI Safety Agent".into() }

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: default_service_name(),
            display_name: default_display_name(),
        }
    }
}

// ── Section: Proxy ─────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Address to bind the proxy (NEVER 0.0.0.0)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Port for the localhost proxy
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Default upstream API target
    #[serde(default = "default_upstream")]
    pub default_upstream: String,
    /// Max requests per PID per minute
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
    /// Connection pool idle timeout in seconds
    #[serde(default = "default_pool_idle")]
    pub pool_idle_timeout_secs: u64,
    /// Max idle connections per host
    #[serde(default = "default_pool_max")]
    pub pool_max_idle_per_host: usize,
}

fn default_listen_addr() -> String { "127.0.0.1".into() }
fn default_listen_port() -> u16 { 8888 }
fn default_upstream() -> String { "https://api.openai.com".into() }
fn default_rate_limit() -> u32 { 100 }
fn default_pool_idle() -> u64 { 90 }
fn default_pool_max() -> usize { 10 }

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            default_upstream: default_upstream(),
            rate_limit: default_rate_limit(),
            pool_idle_timeout_secs: default_pool_idle(),
            pool_max_idle_per_host: default_pool_max(),
        }
    }
}

// ── Section: Watchtower ────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct WatchtowerConfig {
    /// Scan interval in seconds
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u64,
    /// Minimum risk level to alert on
    #[serde(default = "default_alert_threshold")]
    pub alert_threshold: String,
    /// Verbose output
    #[serde(default)]
    pub verbose: bool,
}

fn default_scan_interval() -> u64 { 5 }
fn default_alert_threshold() -> String { "Medium".into() }

impl Default for WatchtowerConfig {
    fn default() -> Self {
        Self {
            scan_interval_secs: default_scan_interval(),
            alert_threshold: default_alert_threshold(),
            verbose: false,
        }
    }
}

// ── Section: Updater ───────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdaterConfig {
    /// Enable auto-update checks
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Check interval in hours
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,
    /// GitHub repo owner
    #[serde(default = "default_repo_owner")]
    pub repo_owner: String,
    /// GitHub repo name
    #[serde(default = "default_repo_name")]
    pub repo_name: String,
}

fn default_enabled() -> bool { true }
fn default_check_interval() -> u64 { 6 }
fn default_repo_owner() -> String { "kidigapeet".into() }
fn default_repo_name() -> String { "Raypher-core".into() }

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            check_interval_hours: default_check_interval(),
            repo_owner: default_repo_owner(),
            repo_name: default_repo_name(),
        }
    }
}

// ── Section: Logging ───────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log directory (relative to ~/.raypher/)
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    /// Days to keep log files before rotation deletes them
    #[serde(default = "default_retention")]
    pub retention_days: u32,
}

fn default_log_level() -> String { "info".into() }
fn default_log_dir() -> String { "logs".into() }
fn default_retention() -> u32 { 7 }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            log_dir: default_log_dir(),
            retention_days: default_retention(),
        }
    }
}

// ── Loader ─────────────────────────────────────────────────────

impl Default for RaypherConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            proxy: ProxyConfig::default(),
            watchtower: WatchtowerConfig::default(),
            updater: UpdaterConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl RaypherConfig {
    /// Load configuration from `~/.raypher/config.toml`.
    /// Falls back to compiled defaults if the file doesn't exist.
    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    match toml::from_str(&content) {
                        Ok(config) => {
                            info!("Configuration loaded from {}", path.display());
                            return config;
                        }
                        Err(e) => {
                            warn!("Failed to parse config file: {}. Using defaults.", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read config file: {}. Using defaults.", e);
                }
            }
        }
        Self::default()
    }

    /// Path to config file: ~/.raypher/config.toml
    pub fn config_path() -> PathBuf {
        let home = dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".raypher").join("config.toml")
    }

    /// Write the default config to disk (for `raypher init` or first-run).
    pub fn write_defaults() -> std::io::Result<PathBuf> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let default_content = include_str!("../config/raypher.toml");
        std::fs::write(&path, default_content)?;
        info!("Default configuration written to {}", path.display());
        Ok(path)
    }
}
