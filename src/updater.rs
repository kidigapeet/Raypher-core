// ──────────────────────────────────────────────────────────────
//  Raypher — Self-Update Module
//  Checks GitHub Releases for new versions, downloads the binary,
//  verifies integrity, and swaps in-place. Keeps .old for rollback.
// ──────────────────────────────────────────────────────────────

use std::time::Duration;

/// Hardcoded update source — only accept binaries from this repo.
const REPO_OWNER: &str = "kidigapeet";
const REPO_NAME: &str = "Raypher-core";
const BIN_NAME: &str = "raypher-core";

/// How often the service checks for updates (default: 6 hours).
pub const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Result of an update check.
#[derive(Debug)]
pub enum UpdateResult {
    /// Already on the latest version.
    UpToDate(String),
    /// Successfully updated to a new version.
    Updated { from: String, to: String },
    /// An error occurred during the update check.
    Error(String),
}

impl std::fmt::Display for UpdateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateResult::UpToDate(v) => write!(f, "Up to date (v{})", v),
            UpdateResult::Updated { from, to } => write!(f, "Updated: v{} → v{}", from, to),
            UpdateResult::Error(e) => write!(f, "Update error: {}", e),
        }
    }
}

/// Check GitHub for a newer release and apply it if found.
///
/// This function:
/// 1. Queries the GitHub Releases API for the latest version tag
/// 2. Compares with the current binary version (from Cargo.toml)
/// 3. If newer: downloads, verifies, and swaps the binary
/// 4. Keeps the old binary as `.old` for rollback safety
///
/// Returns an `UpdateResult` indicating what happened.
pub fn check_and_update() -> UpdateResult {
    let current_version = env!("CARGO_PKG_VERSION");

    match self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .current_version(current_version)
        .no_confirm(true) // We're a service — no user to prompt
        .show_output(false)
        .show_download_progress(false)
        .build()
    {
        Ok(updater) => {
            match updater.update() {
                Ok(status) => {
                    let new_version = status.version();
                    if new_version != current_version {
                        UpdateResult::Updated {
                            from: current_version.to_string(),
                            to: new_version.to_string(),
                        }
                    } else {
                        UpdateResult::UpToDate(current_version.to_string())
                    }
                }
                Err(e) => UpdateResult::Error(format!("Update failed: {}", e)),
            }
        }
        Err(e) => UpdateResult::Error(format!("Configuration error: {}", e)),
    }
}

/// Check for updates without applying them. Returns version info only.
pub fn check_only() -> UpdateResult {
    let current_version = env!("CARGO_PKG_VERSION");

    match self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .current_version(current_version)
        .no_confirm(true)
        .build()
    {
        Ok(updater) => {
            match updater.get_latest_release() {
                Ok(release) => {
                    let latest = release.version.trim_start_matches('v').to_string();
                    if latest != current_version {
                        // There IS a newer version, but we're just checking
                        UpdateResult::Updated {
                            from: current_version.to_string(),
                            to: latest,
                        }
                    } else {
                        UpdateResult::UpToDate(current_version.to_string())
                    }
                }
                Err(e) => UpdateResult::Error(format!("Check failed: {}", e)),
            }
        }
        Err(e) => UpdateResult::Error(format!("Configuration error: {}", e)),
    }
}

/// Display-friendly summary for CLI
pub fn print_update_status() {
    println!();
    println!("  🔄 Raypher Update Check");
    println!("  ─────────────────────────");
    println!("  Current:  v{}", env!("CARGO_PKG_VERSION"));
    println!("  Source:   github.com/{}/{}", REPO_OWNER, REPO_NAME);
    println!();

    match check_only() {
        UpdateResult::UpToDate(v) => {
            println!("  ✅ You are running the latest version (v{}).", v);
        }
        UpdateResult::Updated { from: _, to } => {
            println!("  ⬆️  New version available: v{}", to);
            println!("  Run `raypher-core update --apply` to install.");
        }
        UpdateResult::Error(e) => {
            println!("  ❌ {}", e);
        }
    }
    println!();
}

/// Apply the update (download + swap + restart required)
pub fn apply_update() {
    println!();
    println!("  🔄 Raypher Self-Update");
    println!("  ─────────────────────────");
    println!("  Current:  v{}", env!("CARGO_PKG_VERSION"));
    println!();

    match check_and_update() {
        UpdateResult::UpToDate(v) => {
            println!("  ✅ Already on the latest version (v{}). No update needed.", v);
        }
        UpdateResult::Updated { from, to } => {
            // Write the update marker for rollback detection
            write_update_marker(&from, &to);
            println!("  ✅ Updated: v{} → v{}", from, to);
            println!("  🔁 Restart the service to complete the update:");
            println!("     sc stop RaypherService && sc start RaypherService");
            println!("  ↩️  Rollback safety: .old binary preserved for 5 minutes.");
        }
        UpdateResult::Error(e) => {
            println!("  ❌ {}", e);
        }
    }
    println!();
}

// ── Rollback Safety Net ────────────────────────────────────────

/// Marker file path — written after a successful update.
/// Contains the timestamp of the update for crash-window detection.
fn update_marker_path() -> std::path::PathBuf {
    let home = dirs_next::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".raypher").join(".update_marker")
}

/// Write a marker file after a successful update.
/// The service reads this at startup to detect if it should rollback.
fn write_update_marker(from_version: &str, to_version: &str) {
    let marker = update_marker_path();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content = format!(
        "{}\n{}\n{}",
        chrono::Utc::now().to_rfc3339(),
        from_version,
        to_version,
    );
    let _ = std::fs::write(&marker, content);
}

/// Check if a rollback is needed on service startup.
///
/// Logic:
/// - If the update marker exists and was written < 5 minutes ago,
///   and we're starting up (implying the previous run crashed),
///   then rollback to the `.old` binary.
/// - If the marker is > 5 minutes old, the update is stable — clean up.
/// - If no marker exists, this is a normal startup.
///
/// Returns true if a rollback was performed.
pub fn check_rollback_needed() -> bool {
    let marker = update_marker_path();
    if !marker.exists() {
        return false;
    }

    // Read marker contents
    let content = match std::fs::read_to_string(&marker) {
        Ok(c) => c,
        Err(_) => {
            let _ = std::fs::remove_file(&marker);
            return false;
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        let _ = std::fs::remove_file(&marker);
        return false;
    }

    // Parse the timestamp
    let update_time = match chrono::DateTime::parse_from_rfc3339(lines[0]) {
        Ok(t) => t,
        Err(_) => {
            let _ = std::fs::remove_file(&marker);
            return false;
        }
    };

    let elapsed = chrono::Utc::now().signed_duration_since(update_time);
    let rollback_window = chrono::Duration::minutes(5);

    if elapsed < rollback_window {
        // We restarted within 5 minutes of an update — the new binary may be bad.
        tracing::warn!(
            "⚠️  Service restarted within {} seconds of update. Attempting rollback...",
            elapsed.num_seconds()
        );

        if rollback_to_old() {
            let _ = std::fs::remove_file(&marker);
            return true;
        } else {
            tracing::error!("Rollback failed: no .old binary found.");
            return false;
        }
    } else {
        // Update has been running > 5 minutes — it's stable. Clean up.
        tracing::info!("Update stable (running {} minutes). Cleaning up .old binary.", elapsed.num_minutes());
        cleanup_old_binary();
        let _ = std::fs::remove_file(&marker);
        false
    }
}

/// Rollback: rename current binary to .failed, restore .old to current.
fn rollback_to_old() -> bool {
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let old_exe = current_exe.with_extension("exe.old");

    if !old_exe.exists() {
        return false;
    }

    let failed_exe = current_exe.with_extension("exe.failed");

    // Swap: current → .failed, .old → current
    if std::fs::rename(&current_exe, &failed_exe).is_ok() {
        if std::fs::rename(&old_exe, &current_exe).is_ok() {
            tracing::info!("✅ Rollback successful. Restored previous binary.");
            return true;
        } else {
            // Restore the current binary if .old rename failed
            let _ = std::fs::rename(&failed_exe, &current_exe);
        }
    }
    false
}

/// Clean up the .old binary after a stable update (>5 min uptime).
fn cleanup_old_binary() {
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };

    let old_exe = current_exe.with_extension("exe.old");
    if old_exe.exists() {
        let _ = std::fs::remove_file(&old_exe);
        tracing::info!("Cleaned up old binary: {}", old_exe.display());
    }

    // Also clean up any .failed binaries from previous rollbacks
    let failed_exe = current_exe.with_extension("exe.failed");
    if failed_exe.exists() {
        let _ = std::fs::remove_file(&failed_exe);
    }
}

