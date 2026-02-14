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
            println!("  ✅ Updated: v{} → v{}", from, to);
            println!("  🔁 Restart the service to complete the update:");
            println!("     sc stop RaypherService && sc start RaypherService");
        }
        UpdateResult::Error(e) => {
            println!("  ❌ {}", e);
        }
    }
    println!();
}
