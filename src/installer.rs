// ──────────────────────────────────────────────────────────────
//  Raypher — Zero-Touch Installer (Phase 3: The Invisible Hand)
//  Automatically configures environment variables so that
//  AI SDKs route through the Raypher proxy without any
//  code changes.  Supports backup and clean uninstall.
// ──────────────────────────────────────────────────────────────

use tracing::{info, warn, error};

use crate::database::Database;

// ── Provider Definitions ───────────────────────────────────────

/// All environment variables that popular AI SDKs check for base URL overrides.
/// Setting these to 127.0.0.1:8888 makes every SDK call flow through our proxy.
pub const PROXY_ENV_VARS: &[(&str, &str)] = &[
    // OpenAI SDK
    ("OPENAI_BASE_URL",         "http://127.0.0.1:8888/v1"),
    ("OPENAI_API_BASE",         "http://127.0.0.1:8888/v1"),
    // Anthropic SDK
    ("ANTHROPIC_BASE_URL",      "http://127.0.0.1:8888/v1"),
    // Google Generative AI
    ("GOOGLE_API_BASE",         "http://127.0.0.1:8888/v1"),
    // HuggingFace Inference
    ("HF_INFERENCE_ENDPOINT",   "http://127.0.0.1:8888/v1"),
    // Generic / LangChain
    ("LLM_BASE_URL",            "http://127.0.0.1:8888/v1"),
];

/// Known safe runtimes that should be auto-added to the allow list.
pub const AUTO_ALLOW_RUNTIMES: &[&str] = &[
    "python.exe",
    "python3.exe",
    "python",
    "python3",
    "node.exe",
    "node",
    "bun.exe",
    "bun",
    "deno.exe",
    "deno",
    "java.exe",
    "java",
    "dotnet.exe",
    "dotnet",
    "ruby.exe",
    "ruby",
    "cargo.exe",
    "cargo",
];

/// A provider endpoint mapping — given a provider name, return the upstream URL.
#[derive(Debug, Clone)]
pub struct ProviderRoute {
    pub name: &'static str,
    pub base_url: &'static str,
    pub auth_header: &'static str,
    pub auth_prefix: &'static str,
}

/// All supported AI providers and their upstream endpoints.
pub const PROVIDERS: &[ProviderRoute] = &[
    ProviderRoute {
        name: "openai",
        base_url: "https://api.openai.com",
        auth_header: "Authorization",
        auth_prefix: "Bearer ",
    },
    ProviderRoute {
        name: "anthropic",
        base_url: "https://api.anthropic.com",
        auth_header: "x-api-key",
        auth_prefix: "",
    },
    ProviderRoute {
        name: "google",
        base_url: "https://generativelanguage.googleapis.com",
        auth_header: "x-goog-api-key",
        auth_prefix: "",
    },
    ProviderRoute {
        name: "huggingface",
        base_url: "https://api-inference.huggingface.co",
        auth_header: "Authorization",
        auth_prefix: "Bearer ",
    },
    ProviderRoute {
        name: "mock",
        base_url: "http://127.0.0.1:9000",
        auth_header: "Authorization",
        auth_prefix: "Bearer ",
    },
];

// ── Setup / Install ────────────────────────────────────────────

/// Result of the setup operation.
#[derive(Debug)]
pub struct SetupResult {
    pub env_vars_set: usize,
    pub env_vars_backed_up: usize,
    pub runtimes_allowed: usize,
    pub errors: Vec<String>,
}

/// Perform the full zero-touch setup.
/// 1. Back up any existing values for the env vars we're about to set
/// 2. Set the env vars (User-level on Windows, profile on Linux)
/// 3. Auto-allow common runtimes
pub fn run_setup(db: &Database) -> SetupResult {
    let mut result = SetupResult {
        env_vars_set: 0,
        env_vars_backed_up: 0,
        runtimes_allowed: 0,
        errors: Vec::new(),
    };

    info!("═══════════════════════════════════════════════════");
    info!("  Raypher Zero-Touch Setup — The Invisible Hand");
    info!("═══════════════════════════════════════════════════");

    // ── Step 1: Back up and set environment variables ──
    for (var_name, proxy_url) in PROXY_ENV_VARS {
        // Check if already set to our proxy
        if let Ok(current) = std::env::var(var_name) {
            if current == *proxy_url {
                info!("  ✓ {} already configured", var_name);
                result.env_vars_set += 1;
                continue;
            }
            // Back up the existing value
            if let Err(e) = backup_env_var(db, var_name, &current) {
                let msg = format!("Failed to backup {}: {}", var_name, e);
                warn!("{}", msg);
                result.errors.push(msg);
            } else {
                info!("  ⟳ Backed up {} = {}", var_name, current);
                result.env_vars_backed_up += 1;
            }
        }

        // Set the env var
        match set_persistent_env_var(var_name, proxy_url) {
            Ok(()) => {
                info!("  ✓ Set {} = {}", var_name, proxy_url);
                result.env_vars_set += 1;
            }
            Err(e) => {
                let msg = format!("Failed to set {}: {}", var_name, e);
                error!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // ── Step 2: Auto-allow common runtimes ──
    info!("");
    info!("  Scanning for common AI runtimes...");
    for runtime in AUTO_ALLOW_RUNTIMES {
        if let Some(full_path) = find_runtime_path(runtime) {
            // Compute exe hash and add to allow list
            match add_runtime_to_allowlist(db, &full_path) {
                Ok(()) => {
                    info!("  ✓ Auto-allowed: {}", full_path);
                    result.runtimes_allowed += 1;
                }
                Err(e) => {
                    warn!("  ✗ Failed to allow {}: {}", runtime, e);
                }
            }
        }
    }

    info!("");
    info!("═══════════════════════════════════════════════════");
    info!("  Setup Complete!");
    info!("  {} env vars configured, {} backups saved", result.env_vars_set, result.env_vars_backed_up);
    info!("  {} runtimes auto-allowed", result.runtimes_allowed);
    if !result.errors.is_empty() {
        warn!("  {} errors encountered", result.errors.len());
    }
    info!("═══════════════════════════════════════════════════");

    result
}

// ── Uninstall ──────────────────────────────────────────────────

/// Reverse everything the setup did:
/// 1. Restore backed-up env vars (or remove if no backup existed)
/// 2. Remove auto-allowed runtimes (optional — we leave them for safety)
pub fn run_uninstall(db: &Database) -> Result<(), Box<dyn std::error::Error>> {
    info!("═══════════════════════════════════════════════════");
    info!("  Raypher Uninstall — Restoring Original State");
    info!("═══════════════════════════════════════════════════");

    for (var_name, _proxy_url) in PROXY_ENV_VARS {
        // Try to restore backed-up value
        match restore_env_var(db, var_name) {
            Ok(Some(original)) => {
                match set_persistent_env_var(var_name, &original) {
                    Ok(()) => info!("  ✓ Restored {} = {}", var_name, original),
                    Err(e) => error!("  ✗ Failed to restore {}: {}", var_name, e),
                }
            }
            Ok(None) => {
                // No backup — remove the env var entirely
                match remove_persistent_env_var(var_name) {
                    Ok(()) => info!("  ✓ Removed {}", var_name),
                    Err(e) => error!("  ✗ Failed to remove {}: {}", var_name, e),
                }
            }
            Err(e) => {
                error!("  ✗ Failed to read backup for {}: {}", var_name, e);
            }
        }
    }

    info!("═══════════════════════════════════════════════════");
    info!("  Uninstall complete. System restored.");
    info!("═══════════════════════════════════════════════════");

    Ok(())
}

// ── Provider Detection ─────────────────────────────────────────

/// Detect which AI provider a request is targeting based on:
/// 1. X-Raypher-Provider header (explicit)
/// 2. Original Host header
/// 3. Request body "model" field pattern matching
pub fn detect_provider(
    provider_header: Option<&str>,
    original_host: Option<&str>,
    body: Option<&serde_json::Value>,
) -> &'static str {
    // Priority 1: Explicit header
    if let Some(header) = provider_header {
        let lower = header.to_lowercase();
        for p in PROVIDERS {
            if lower == p.name {
                return p.name;
            }
        }
    }

    // Priority 2: Original Host header (when traffic is redirected)
    if let Some(host) = original_host {
        let host_lower = host.to_lowercase();
        if host_lower.contains("openai") {
            return "openai";
        }
        if host_lower.contains("anthropic") {
            return "anthropic";
        }
        if host_lower.contains("googleapis") || host_lower.contains("google") {
            return "google";
        }
        if host_lower.contains("huggingface") || host_lower.contains("hf.co") {
            return "huggingface";
        }
    }

    // Priority 3: Infer from model name in body
    if let Some(body) = body {
        if let Some(model) = body.get("model").and_then(|m| m.as_str()) {
            let model_lower = model.to_lowercase();
            if model_lower.starts_with("gpt-") || model_lower.starts_with("o1") || model_lower.starts_with("dall-e") {
                return "openai";
            }
            if model_lower.starts_with("claude") {
                return "anthropic";
            }
            if model_lower.starts_with("gemini") || model_lower.starts_with("models/") {
                return "google";
            }
        }
    }

    // Default to OpenAI
    "openai"
}

/// Look up the provider route configuration by name.
pub fn get_provider_route(name: &str) -> Option<&'static ProviderRoute> {
    PROVIDERS.iter().find(|p| p.name == name)
}

// ── Platform-Specific Implementations ──────────────────────────

/// Set a persistent environment variable (survives reboots).
#[cfg(target_os = "windows")]
fn set_persistent_env_var(name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Use setx for User-level persistence
    let output = std::process::Command::new("setx")
        .args([name, value])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("setx failed: {}", stderr).into());
    }

    // Also set in current process so it takes effect immediately
    std::env::set_var(name, value);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_persistent_env_var(name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Write to ~/.bashrc and ~/.profile for persistence
    let home = dirs_next::home_dir().ok_or("Cannot determine home directory")?;

    for rc_file in &[".bashrc", ".profile", ".zshrc"] {
        let path = home.join(rc_file);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let export_line = format!("export {}=\"{}\"", name, value);
            let marker = format!("# RAYPHER: {}", name);

            if content.contains(&marker) {
                // Replace existing line
                let mut new_content = String::new();
                for line in content.lines() {
                    if line.contains(&marker) {
                        new_content.push_str(&format!("{} {}\n", export_line, marker));
                    } else {
                        new_content.push_str(line);
                        new_content.push('\n');
                    }
                }
                std::fs::write(&path, new_content)?;
            } else {
                // Append
                let mut f = std::fs::OpenOptions::new().append(true).open(&path)?;
                use std::io::Write;
                writeln!(f, "\n{} {}", export_line, marker)?;
            }
        }
    }

    // Also set in current process
    std::env::set_var(name, value);
    Ok(())
}

/// Remove a persistent environment variable.
#[cfg(target_os = "windows")]
fn remove_persistent_env_var(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // On Windows, setx with empty string or use reg delete
    let output = std::process::Command::new("reg")
        .args(["delete", "HKCU\\Environment", "/v", name, "/f"])
        .output()?;

    if !output.status.success() {
        // It's OK if it doesn't exist
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("unable to find") {
            warn!("reg delete warning: {}", stderr);
        }
    }

    std::env::remove_var(name);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn remove_persistent_env_var(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let home = dirs_next::home_dir().ok_or("Cannot determine home directory")?;
    let marker = format!("# RAYPHER: {}", name);

    for rc_file in &[".bashrc", ".profile", ".zshrc"] {
        let path = home.join(rc_file);
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            if content.contains(&marker) {
                let new_content: String = content
                    .lines()
                    .filter(|line| !line.contains(&marker))
                    .collect::<Vec<_>>()
                    .join("\n");
                std::fs::write(&path, new_content)?;
            }
        }
    }

    std::env::remove_var(name);
    Ok(())
}

/// Back up an environment variable's current value to the database.
fn backup_env_var(db: &Database, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = format!("env_backup:{}", name);
    db.store_policy(&key, value)
        .map_err(|e| e.into())
}

/// Restore a backed-up environment variable from the database.
fn restore_env_var(db: &Database, name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let key = format!("env_backup:{}", name);
    match db.get_policy(&key) {
        Ok(value) => Ok(value),
        Err(e) => Err(e.into()),
    }
}

/// Find the full path of a runtime executable using `which` / `where`.
fn find_runtime_path(name: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    let cmd = "where";
    #[cfg(not(target_os = "windows"))]
    let cmd = "which";

    let output = std::process::Command::new(cmd)
        .arg(name)
        .output()
        .ok()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()?
            .trim()
            .to_string();
        if !path.is_empty() {
            return Some(path);
        }
    }
    None
}

/// Add a runtime's exe to the allow list.
fn add_runtime_to_allowlist(db: &Database, exe_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    crate::secrets::allow_process(db, exe_path)
        .map_err(|e| e.into())
}
