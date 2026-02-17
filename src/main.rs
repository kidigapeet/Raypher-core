
mod database;
mod killer;
mod monitor;
mod scanner;
mod heuristics;
mod identity;
mod terminator;
mod safety;
mod panic;
mod proxy;
mod secrets;
mod service;
mod updater;
mod watchdog;
mod watchtower;
mod config;
mod policy;
mod dashboard;
mod installer;
mod dlp;
mod tls;

use clap::{Parser, Subcommand};
use database::{Database, Event, Severity};
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "raypher",
    version,
    about = "AI Safety Agent — Shadow AI Discovery & Kill Switch",
    long_about = "Raypher scans your system for unauthorized AI processes,\n\
                  monitors resource consumption, and provides an emergency\n\
                  kill switch to terminate rogue agents and their child processes."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan the system for AI-related processes
    Scan,

    /// Start continuous monitoring (passive mode)
    Monitor,

    /// Emergency kill — terminate a process and all its children
    Panic {
        /// Process ID (PID) to terminate. Must be a positive integer.
        #[arg(value_name = "PID")]
        pid: u32,
    },

    /// View the audit ledger (recent events)
    Logs {
        /// Number of recent events to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },

    /// Display the hardware-bound Silicon ID (TPM fingerprint)
    Identity,

    /// Show Raypher system status
    Status,

    /// Seal an API key into the TPM vault
    Seal {
        /// Provider name (e.g., "openai", "anthropic", "google")
        #[arg(short, long)]
        provider: String,
        /// API key (if omitted, you'll be prompted)
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Unseal and display a stored API key (admin only)
    Unseal {
        /// Provider name to retrieve
        #[arg(short, long)]
        provider: String,
    },

    /// List all sealed API key providers
    Secrets,

    /// Register a process in the proxy allow list
    Allow {
        /// Full path to the executable to authorize
        #[arg(short, long)]
        exe_path: String,
    },

    /// Start the localhost proxy (for testing, normally runs in service mode)
    Proxy,

    /// Check for updates or apply a self-update from GitHub
    Update {
        /// Actually download and apply the update (default: check only)
        #[arg(long)]
        apply: bool,
    },

    /// Zero-touch setup — configure env vars and auto-allow runtimes
    Setup,

    /// Reverse the setup — restore original env vars and remove CA
    Uninstall,
}

fn main() {
    // Initialize tracing subscriber with INFO level
    tracing_subscriber::fmt()
        .with_env_filter("raypher_core=info,raypher=info")
        .init();

    // ── Split Brain Detection ──────────────────────────────────
    // If launched with --service flag, enter Service Mode (no console).
    // This is how the SCM (Service Control Manager) starts us.
    if std::env::args().any(|a| a == "--service") {
        if let Err(e) = service::run_service() {
            eprintln!("Service error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── CLI Mode ──────────────────────────────────────────────
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan => handle_scan(),
        Commands::Monitor => handle_monitor(),
        Commands::Panic { pid } => handle_panic(pid),
        Commands::Logs { limit } => handle_logs(limit),
        Commands::Identity => handle_identity(),
        Commands::Status => handle_status(),
        Commands::Seal { provider, key } => handle_seal(&provider, key),
        Commands::Unseal { provider } => handle_unseal(&provider),
        Commands::Secrets => handle_secrets(),
        Commands::Allow { exe_path } => handle_allow(&exe_path),
        Commands::Proxy => handle_proxy(),
        Commands::Update { apply } => handle_update(apply),
        Commands::Setup => handle_setup(),
        Commands::Uninstall => handle_uninstall(),
    }
}

/// Handle the `scan` subcommand.
/// Runs the AI process scanner, displays results, and logs to the audit ledger.
fn handle_scan() {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — Shadow AI Discovery      ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();
    println!("  Scanning all processes...\n");

    let results = scanner::scan_for_ai();
    scanner::print_scan_results(&results);

    // Log the scan event to the audit ledger
    match Database::init() {
        Ok(db) => {
            let details = serde_json::json!({
                "processes_found": results.len(),
                "processes": results,
            });

            let event = Event {
                event_type: "SCAN".to_string(),
                details_json: details.to_string(),
                severity: if results.is_empty() {
                    Severity::Info
                } else {
                    Severity::Warning
                },
            };

            match db.log_event(&event) {
                Ok(id) => println!("  📝 Event logged to audit ledger (ID: {})", id),
                Err(e) => eprintln!("  ⚠️  Failed to log event: {}", e),
            }
        }
        Err(e) => eprintln!("  ⚠️  Database unavailable: {}", e),
    }

    println!();
}

/// Handle the `monitor` subcommand.
/// Runs the passive Guard Loop — scans every second, alerts on high memory.
fn handle_monitor() {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — Passive Monitor          ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    let config = monitor::MonitorConfig::default();
    monitor::run_monitor(&config);
}

/// Handle the `panic` subcommand.
/// Full flow: snapshot → log CRITICAL event → kill tree → confirm.
fn handle_panic(pid: u32) {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — PANIC PROTOCOL           ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    // Hard safety check — never kill system processes
    if pid < 100 {
        eprintln!("  ❌ ERROR: Cannot kill system-critical process (PID < 100).");
        eprintln!("  → PID {} is likely a core OS process. Aborting.", pid);
        process::exit(1);
    }

    println!("  🎯 Target PID: {}", pid);

    // Step 1: Capture forensic snapshot BEFORE killing
    println!("  📸 Capturing forensic snapshot...");
    let snapshot = killer::capture_snapshot(pid);

    match &snapshot {
        Some(snap) => {
            println!("  ├── Name:     {}", snap.name);
            println!("  ├── Memory:   {}", snap.memory_human);
            println!("  ├── Status:   {}", snap.status);
            println!("  ├── Command:  {}", if snap.cmd.is_empty() { "(hidden)" } else { &snap.cmd });
            println!("  └── Children: {}", snap.children_killed.len());
        }
        None => {
            eprintln!("  ❌ Process PID {} not found or inaccessible.", pid);
            process::exit(1);
        }
    }

    // Step 2: Log the CRITICAL event to the audit ledger
    if let Some(snap) = &snapshot {
        match Database::init() {
            Ok(db) => {
                let details = serde_json::to_string(snap).unwrap_or_default();
                let event = Event {
                    event_type: "PANIC".to_string(),
                    details_json: details,
                    severity: Severity::Critical,
                };
                match db.log_event(&event) {
                    Ok(id) => println!("\n  📝 Forensic evidence logged (Event ID: {})", id),
                    Err(e) => eprintln!("\n  ⚠️  Failed to log event: {}", e),
                }
            }
            Err(e) => eprintln!("\n  ⚠️  Database unavailable: {}", e),
        }
    }

    // Step 3: Execute the kill
    println!("\n  💀 Executing kill on process tree...");
    let result = killer::kill_process_tree(pid);

    if result.success {
        let children_count = result.snapshot.children_killed.len();
        println!("  ✅ Process PID {} terminated successfully.", pid);
        if children_count > 0 {
            println!("  ✅ {} child process(es) also terminated.", children_count);
        }
    } else {
        let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
        eprintln!("  ❌ Kill failed: {}", err_msg);
        process::exit(1);
    }

    println!();
}

/// Handle the `logs` subcommand.
/// Displays recent events from the audit ledger.
fn handle_logs(limit: u32) {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — Audit Ledger             ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    match Database::init() {
        Ok(db) => database::print_recent_events(&db, limit),
        Err(e) => eprintln!("  ❌ Database error: {}", e),
    }

    println!();
}

/// Handle the `identity` subcommand.
/// Reads the TPM-backed Silicon ID and stores it in the audit ledger.
fn handle_identity() {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — Silicon Identity          ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    println!("  🔐 Reading hardware-bound identity...");
    let silicon_id = identity::get_silicon_id();

    println!("  ────────────────────────────────────────────");
    println!("  🆔 Silicon ID: {}", silicon_id);
    println!("  ────────────────────────────────────────────");

    // Store in the audit ledger
    match Database::init() {
        Ok(db) => {
            match db.store_identity(&silicon_id) {
                Ok(()) => println!("  ✅ Identity stored in audit ledger."),
                Err(e) => eprintln!("  ⚠️  Failed to store identity: {}", e),
            }

            // Also log as an event for audit trail
            let details = serde_json::json!({
                "silicon_id": silicon_id,
                "source": if silicon_id.starts_with("FALLBACK_") { "fallback" }
                          else if silicon_id.starts_with("MOCK_") { "mock" }
                          else { "tpm" },
            });
            let event = Event {
                event_type: "IDENTITY".to_string(),
                details_json: details.to_string(),
                severity: Severity::Info,
            };
            match db.log_event(&event) {
                Ok(id) => println!("  📝 Identity event logged (ID: {})", id),
                Err(e) => eprintln!("  ⚠️  Failed to log event: {}", e),
            }
        }
        Err(e) => eprintln!("  ❌ Database error: {}", e),
    }

    println!();
}

/// Handle the `status` subcommand.
/// Displays a dashboard overview of the Raypher system.
fn handle_status() {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║   RAYPHER — System Status             ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();

    // Version
    println!("  Version:     v{}", env!("CARGO_PKG_VERSION"));

    // Silicon ID
    let silicon_id = identity::get_silicon_id();
    let short_id = if silicon_id.len() > 16 {
        format!("{}...", &silicon_id[..16])
    } else {
        silicon_id.clone()
    };
    println!("  Silicon ID:  {}", short_id);

    // Service status (Windows only)
    #[cfg(target_os = "windows")]
    {
        println!("  Platform:    Windows (Service-capable)");
    }
    #[cfg(not(target_os = "windows"))]
    {
        println!("  Platform:    Linux/macOS (systemd)");
    }

    // Database stats
    match Database::init() {
        Ok(db) => {
            match db.event_count() {
                Ok(count) => println!("  Events:      {} logged", count),
                Err(_) => println!("  Events:      (unavailable)"),
            }
            println!("  Database:    ✅ Connected");
        }
        Err(_) => {
            println!("  Database:    ❌ Unavailable");
        }
    }

    println!();
}

// ── Vault Handlers ─────────────────────────────────────────────

fn handle_seal(provider: &str, key_arg: Option<String>) {
    println!();
    println!("  🔐 Seal API Key — Provider: \"{}\"", provider);
    println!();

    // Use provided key, or prompt for it
    let key = if let Some(k) = key_arg {
        k
    } else {
        // Try rpassword first, fall back to visible stdin
        match rpassword::prompt_password("  Enter API Key: ") {
            Ok(k) if !k.trim().is_empty() => k,
            _ => {
                // Fallback: read from stdin with echo (works in all terminals)
                use std::io::{self, Write};
                print!("  Enter API Key (visible): ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap_or_else(|e| {
                    eprintln!("  ❌ Failed to read input: {}", e);
                    process::exit(1);
                });
                input
            }
        }
    };

    if key.trim().is_empty() {
        eprintln!("  ❌ API key cannot be empty.");
        process::exit(1);
    }

    let db = Database::init().unwrap_or_else(|e| {
        eprintln!("  ❌ Database error: {}", e);
        process::exit(1);
    });

    match secrets::seal_key(&db, provider, "api_key", None, key.trim()) {
        Ok(()) => {
            println!("  ✅ Key sealed for provider '{}'.", provider);
            println!("  🔒 Stored in TPM-bound vault. No plaintext on disk.");
        }
        Err(e) => {
            eprintln!("  ❌ Seal failed: {}", e);
            process::exit(1);
        }
    }
    println!();
}

fn handle_unseal(provider: &str) {
    println!();
    println!("  🔓 Unseal API Key — Provider: \"{}\"", provider);
    println!();

    let db = Database::init().unwrap_or_else(|e| {
        eprintln!("  ❌ Database error: {}", e);
        process::exit(1);
    });

    match secrets::unseal_key(&db, provider) {
        Ok(key) => {
            // Show first and last 4 chars, mask the middle
            let masked = if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len()-4..])
            } else {
                key.clone()
            };
            println!("  Key:  {}", masked);
            println!("  ⚠️  Full key displayed above. Clear your terminal.");
        }
        Err(e) => {
            eprintln!("  ❌ Unseal failed: {}", e);
            process::exit(1);
        }
    }
    println!();
}

fn handle_secrets() {
    println!();
    println!("  🗝️  Sealed Providers");
    println!("  ─────────────────────");

    let db = Database::init().unwrap_or_else(|e| {
        eprintln!("  ❌ Database error: {}", e);
        process::exit(1);
    });

    match secrets::list_providers(&db) {
        Ok(providers) if providers.is_empty() => {
            println!("  (none) — Use `raypher seal --provider <name>` to add one.");
        }
        Ok(providers) => {
            for (name, created, secret_type, label) in &providers {
                let lbl = label.as_deref().unwrap_or(name);
                println!("  • {:<15} | {:<10} | Sealed: {} ({})", lbl, secret_type, &created[..10], name);
            }
            println!();
            println!("  Total: {} provider(s)", providers.len());
        }
        Err(e) => {
            eprintln!("  ❌ Failed to list: {}", e);
        }
    }
    println!();
}

fn handle_allow(exe_path: &str) {
    println!();
    println!("  🛡️  Register Process in Allow List");
    println!();

    let db = Database::init().unwrap_or_else(|e| {
        eprintln!("  ❌ Database error: {}", e);
        process::exit(1);
    });

    match secrets::allow_process(&db, exe_path) {
        Ok(()) => {
            println!("  ✅ Process registered: {}", exe_path);
            println!("  📋 This exe can now access the proxy at 127.0.0.1:8888");
        }
        Err(e) => {
            eprintln!("  ❌ Failed to register: {}", e);
            process::exit(1);
        }
    }
    println!();
}

fn handle_proxy() {
    println!();
    println!("  🌐 Starting Raypher Proxy (CLI test mode)");
    println!("  Press Ctrl+C to stop.");
    println!();

    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("  ❌ Failed to create async runtime: {}", e);
        process::exit(1);
    });

    rt.block_on(async {
        if let Err(e) = proxy::start_proxy().await {
            eprintln!("  ❌ Proxy error: {}", e);
            process::exit(1);
        }
    });
}

fn handle_update(apply: bool) {
    if apply {
        updater::apply_update();
    } else {
        updater::print_update_status();
    }
}

// ── Phase 3 Handlers ───────────────────────────────────────────

fn handle_setup() {
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║   Raypher — Zero-Touch Setup             ║");
    println!("  ║   Phase 3: The Invisible Hand            ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    let db = match Database::init() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("  ❌ Database error: {}", e);
            std::process::exit(1);
        }
    };

    let result = installer::run_setup(&db);

    println!();
    if result.errors.is_empty() {
        println!("  ✅ Setup complete! All AI SDKs will now route through Raypher.");
        println!("  ℹ️  Restart your terminal for env var changes to take effect.");
    } else {
        println!("  ⚠️  Setup completed with {} error(s).", result.errors.len());
        for err in &result.errors {
            println!("     • {}", err);
        }
    }
    println!();
}

fn handle_uninstall() {
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║   Raypher — Uninstall                    ║");
    println!("  ║   Restoring Original Configuration       ║");
    println!("  ╚══════════════════════════════════════════╝");
    println!();

    let db = match Database::init() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("  ❌ Database error: {}", e);
            std::process::exit(1);
        }
    };

    // Restore env vars
    if let Err(e) = installer::run_uninstall(&db) {
        eprintln!("  ❌ Uninstall error: {}", e);
        std::process::exit(1);
    }

    // Remove CA from trust store
    let tls_mgr = tls::TlsManager::new(&db, "uninstall");
    if let Err(e) = tls_mgr.uninstall_ca() {
        eprintln!("  ⚠️  CA removal warning: {}", e);
    }

    println!();
    println!("  ✅ Uninstall complete. System restored to original state.");
    println!("  ℹ️  Restart your terminal for env var changes to take effect.");
    println!();
}
