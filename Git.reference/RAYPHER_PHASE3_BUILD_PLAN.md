# RAYPHER PHASE 3: THE INVISIBLE HAND

## Complete Step-by-Step Implementation Plan — Weeks 9–12

> **"Stop asking permission. Start seizing control."**
>
> Phase 1 built the ENGINE. Phase 2 built the GHOST.
> Phase 3 builds the INVISIBLE HAND — the layer that makes Raypher work
> without anyone changing a single line of their code.

**Date:** 2026-02-15
**Predecessor:** Phase 2 — The Ghost Protocol (Complete)
**Timeline:** 4 Weeks (Weeks 9–12)

---

## The Problem Phase 3 Solves

Right now, Raypher is **Voluntary Security**. The developer must:

1. Change their agent's base URL from `api.openai.com` → `localhost:8888`
2. Remove the real API key and use a placeholder
3. Add the `X-Raypher-Token` header
4. Run `raypher seal` and `raypher allow` manually

This is a dealbreaker. A lazy developer (or a rogue agent) can bypass Raypher entirely by calling `api.openai.com` directly. The entire security model collapses.

**Phase 3 transforms Raypher from "please use our proxy" into "we see everything."**

After Phase 3:

- **Zero code changes** — agents auto-redirect through Raypher via environment variables
- **Zero secrets in code** — DLP scanner catches API keys, SSNs, credit cards before they leave
- **Zero manual config** — installer handles everything automatically
- **Dynamic governance** — YAML policies hot-reload without restart
- **TLS foundation** — local CA certificate ready for transparent HTTPS interception

---

## The Architecture Shift

| Feature | **Phase 2 (Current)** | **Phase 3 (Target)** |
|---|---|---|
| **Agent Routing** | Developer changes `base_url` manually | **Auto-redirect via `*_BASE_URL` env vars** |
| **Secret Protection** | Keys sealed in TPM only | **DLP scans every payload for leaked secrets** |
| **Policy Engine** | Hardcoded allow/deny + basic zones | **YAML policy files with hot-reload** |
| **HTTPS Traffic** | HTTP only (plaintext to proxy) | **Local CA + TLS termination foundation** |
| **Installation** | Manual `seal` + `allow` commands | **One-click installer does everything** |
| **Model Control** | Forward as-is | **Policy-driven model routing/downgrade** |

---

## New Dependencies (Cargo.toml Additions)

```toml
[dependencies]
# Phase 3 additions
regex = "1.10"                    # DLP pattern matching
lazy_static = "1.4"              # Compile-once regex patterns
shannon-entropy = "0.2"          # Entropy-based secret detection
notify = "6.1"                   # Filesystem watcher for policy hot-reload
rcgen = "0.12"                   # Local CA certificate generation
rustls-pemfile = "2.0"           # PEM parsing for TLS
x509-parser = "0.16"             # Certificate validation
winreg = "0.52"                  # Windows Registry for env var injection
```

---

## Technology Stack Additions

| Component | Technology | Why |
|---|---|---|
| **DLP Engine** | `regex` crate (Rust) | 10x faster than Python regex, based on ripgrep automaton |
| **Entropy Scanner** | Shannon entropy calculation | Catches unknown token/password patterns that regex misses |
| **Policy Hot-Reload** | `notify` crate (fsnotify) | Watches `policy.yaml` for changes, applies without restart |
| **CA Generation** | `rcgen` crate | Pure-Rust X.509 certificate generation, no OpenSSL dependency |
| **TLS Termination** | `rustls` + `tokio-rustls` | Already in Cargo.toml, extend for local CA |
| **Registry Access** | `winreg` crate | Set system environment variables on Windows programmatically |

---

# Week 9: The "Zero-Touch" Install (Environment Variable Auto-Configuration)

**Codename:** The Invisible Router
**Objective:** Make Raypher work without ANY code changes from the developer. When a user installs Raypher, their AI agents automatically route through the proxy.

**Philosophy:** The best security is the security nobody has to think about. If a developer has to change their code to use Raypher, most won't bother. If Raypher changes the environment so all AI SDKs automatically route through it, every developer is protected by default.

---

## Day 1–2: The SDK Auto-Redirect (Environment Variable Injection)

### The Insight

Every major AI SDK already supports a `*_BASE_URL` environment variable:

| SDK | Environment Variable | Default Value |
|---|---|---|
| **OpenAI Python/Node** | `OPENAI_BASE_URL` | `https://api.openai.com/v1` |
| **Anthropic Python** | `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| **Azure OpenAI** | `AZURE_OPENAI_ENDPOINT` | Customer-specific |
| **Google Gemini** | `GOOGLE_API_BASE` | `https://generativelanguage.googleapis.com` |
| **HuggingFace** | `HF_INFERENCE_ENDPOINT` | `https://api-inference.huggingface.co` |
| **Ollama** | `OLLAMA_HOST` | `http://localhost:11434` |
| **LangChain** | Inherits from provider SDK | N/A |
| **CrewAI** | Inherits from provider SDK | N/A |
| **AutoGPT** | Inherits from provider SDK | N/A |

**The Magic:** If we set `OPENAI_BASE_URL=http://127.0.0.1:8888/v1`, the OpenAI SDK automatically sends all requests to Raypher instead of `api.openai.com`. The developer's code is completely unchanged. They don't even know Raypher is there.

### What You Build

**File:** `src/installer.rs` [NEW]

```rust
/// The environment variable auto-configuration module.
/// Sets system-level environment variables so AI SDKs auto-redirect through Raypher.

use std::collections::HashMap;

/// All known AI SDK base URL environment variables and their Raypher redirects.
pub fn get_redirect_vars() -> HashMap<&'static str, &'static str> {
    let mut vars = HashMap::new();

    // OpenAI ecosystem (covers LangChain, CrewAI, AutoGPT, etc.)
    vars.insert("OPENAI_BASE_URL",        "http://127.0.0.1:8888/v1");
    vars.insert("OPENAI_API_BASE",        "http://127.0.0.1:8888/v1");  // Legacy

    // Anthropic
    vars.insert("ANTHROPIC_BASE_URL",     "http://127.0.0.1:8888/v1");

    // Google
    vars.insert("GOOGLE_API_BASE",        "http://127.0.0.1:8888/v1");

    // HuggingFace
    vars.insert("HF_INFERENCE_ENDPOINT",  "http://127.0.0.1:8888/v1");

    // Generic fallbacks used by some frameworks
    vars.insert("LLM_BASE_URL",           "http://127.0.0.1:8888/v1");

    vars
}

/// Set environment variables at the SYSTEM level (persists across reboots).
/// Windows: writes to HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
/// Linux: writes to /etc/environment
pub fn install_env_redirects() -> Result<(), Box<dyn std::error::Error>> {
    let vars = get_redirect_vars();

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let env_key = hklm.open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_SET_VALUE | KEY_READ,
        )?;

        for (key, value) in &vars {
            // Only set if not already set by the user
            if env_key.get_value::<String, _>(key).is_err() {
                env_key.set_value(key, value)?;
                tracing::info!(var = key, value = value, "Set system environment variable");
            } else {
                tracing::warn!(var = key, "Skipped — already set by user");
            }
        }

        // Broadcast WM_SETTINGCHANGE so running processes pick up the new vars
        // without requiring a reboot
        broadcast_environment_change();
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .append(true)
            .open("/etc/environment")?;

        for (key, value) in &vars {
            if std::env::var(key).is_err() {
                writeln!(file, "{}={}", key, value)?;
                tracing::info!(var = key, value = value, "Added to /etc/environment");
            }
        }
    }

    Ok(())
}

/// Remove all Raypher environment variable redirects (clean uninstall).
pub fn uninstall_env_redirects() -> Result<(), Box<dyn std::error::Error>> {
    let vars = get_redirect_vars();

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let env_key = hklm.open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_SET_VALUE,
        )?;

        for (key, _) in &vars {
            let _ = env_key.delete_value(key);
            tracing::info!(var = key, "Removed system environment variable");
        }

        broadcast_environment_change();
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn broadcast_environment_change() {
    use windows::Win32::UI::WindowsAndMessaging::*;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM("Environment\0".as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            5000,
            std::ptr::null_mut(),
        );
    }
}
```

### The "Backup & Restore" Safety Net

**Critical:** We must NOT destroy existing environment variables. If a user already has `OPENAI_BASE_URL` set (e.g., pointing to their own proxy or Azure endpoint), we must:

1. **Back up** the original value to `RAYPHER_BACKUP_OPENAI_BASE_URL`
2. **Set** the Raypher redirect
3. On **uninstall**, restore from the backup

```rust
/// Back up existing env var before overwriting
fn backup_and_set(key: &str, new_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(existing) = std::env::var(key) {
        let backup_key = format!("RAYPHER_BACKUP_{}", key);
        // Store original value as backup
        set_system_env(&backup_key, &existing)?;
        tracing::info!(var = key, backup = %backup_key, "Backed up existing value");
    }
    set_system_env(key, new_value)?;
    Ok(())
}
```

### Senior Review Checklist — Day 1–2

- [ ] `install_env_redirects()` sets all 6+ SDK variables at system level
- [ ] Existing user values are backed up before overwriting
- [ ] `uninstall_env_redirects()` restores original values from backup
- [ ] `WM_SETTINGCHANGE` broadcast works (new terminals pick up vars immediately)
- [ ] Linux `/etc/environment` writes are idempotent (no duplicates on re-install)
- [ ] Test: Python `openai.chat.completions.create()` auto-routes to `:8888` after install

---

## Day 3: The Multi-Provider Proxy Router

### The Problem

Right now, `proxy.rs` only forwards to OpenAI (`api.openai.com`). But with env var injection, Anthropic, Google, and HuggingFace traffic will also arrive at `:8888`. We need to route each request to the correct upstream provider.

### What You Build

**File:** `src/proxy.rs` [MODIFY] — Add provider detection and routing.

```rust
/// Determine the upstream provider from the request context.
/// Priority: 1) X-Raypher-Provider header  2) Original Host header  3) Path prefix
fn resolve_provider(headers: &HeaderMap, path: &str) -> ProviderRoute {
    // Check explicit header first
    if let Some(provider) = headers.get("X-Raypher-Provider") {
        return match provider.to_str().unwrap_or("") {
            "anthropic" => ProviderRoute::Anthropic,
            "google"    => ProviderRoute::Google,
            "huggingface" => ProviderRoute::HuggingFace,
            _           => ProviderRoute::OpenAI,
        };
    }

    // Check the original Host header (SDKs may forward this)
    if let Some(host) = headers.get("host") {
        let host_str = host.to_str().unwrap_or("");
        if host_str.contains("anthropic") { return ProviderRoute::Anthropic; }
        if host_str.contains("googleapis") || host_str.contains("google") {
            return ProviderRoute::Google;
        }
    }

    // Check path patterns
    if path.starts_with("/v1/messages") { return ProviderRoute::Anthropic; }
    if path.starts_with("/v1beta/") { return ProviderRoute::Google; }

    // Default: OpenAI-compatible
    ProviderRoute::OpenAI
}

#[derive(Debug, Clone)]
enum ProviderRoute {
    OpenAI,
    Anthropic,
    Google,
    HuggingFace,
}

impl ProviderRoute {
    fn upstream_url(&self) -> &'static str {
        match self {
            Self::OpenAI      => "https://api.openai.com",
            Self::Anthropic   => "https://api.anthropic.com",
            Self::Google      => "https://generativelanguage.googleapis.com",
            Self::HuggingFace => "https://api-inference.huggingface.co",
        }
    }

    fn secret_key_name(&self) -> &'static str {
        match self {
            Self::OpenAI      => "openai",
            Self::Anthropic   => "anthropic",
            Self::Google      => "google",
            Self::HuggingFace => "huggingface",
        }
    }

    fn auth_header_name(&self) -> &'static str {
        match self {
            Self::OpenAI      => "Authorization",    // Bearer sk-...
            Self::Anthropic   => "x-api-key",        // Direct key
            Self::Google      => "x-goog-api-key",   // Direct key
            Self::HuggingFace => "Authorization",    // Bearer hf_...
        }
    }

    fn auth_header_value(&self, key: &str) -> String {
        match self {
            Self::OpenAI | Self::HuggingFace => format!("Bearer {}", key),
            Self::Anthropic | Self::Google   => key.to_string(),
        }
    }
}
```

### The Auto-Allow List

**The Problem:** Currently, users must run `raypher allow --exe-path "C:\Python312\python.exe"` manually. Phase 3 should auto-detect common runtimes.

**What You Build:**

```rust
/// Auto-detect and allow common AI runtimes on first scan.
/// Called during installer setup or on first proxy start.
pub fn auto_populate_allow_list(db: &Database) -> Result<(), Box<dyn std::error::Error>> {
    let common_runtimes = vec![
        // Python installations
        r"C:\Python3*\python.exe",
        r"C:\Users\*\AppData\Local\Programs\Python\*\python.exe",
        r"C:\Users\*\anaconda3\python.exe",
        r"C:\Users\*\miniconda3\python.exe",
        "/usr/bin/python3",
        "/usr/local/bin/python3",

        // Node.js
        r"C:\Program Files\nodejs\node.exe",
        "/usr/bin/node",
        "/usr/local/bin/node",

        // Common AI tools
        r"C:\Users\*\AppData\Local\Ollama\ollama.exe",
        "/usr/local/bin/ollama",
    ];

    for pattern in common_runtimes {
        for path in glob::glob(pattern).unwrap().filter_map(Result::ok) {
            if path.exists() {
                let hash = compute_sha256(&path)?;
                db.add_allowed_exe(&path.to_string_lossy(), &hash)?;
                tracing::info!(path = %path.display(), "Auto-allowed runtime");
            }
        }
    }

    Ok(())
}
```

### Day 3 Senior Review Checklist

- [ ] Provider routing correctly identifies OpenAI, Anthropic, Google, HuggingFace
- [ ] Each provider uses the correct auth header format
- [ ] Secrets are fetched per-provider from the vault
- [ ] Auto-allow list populates for common Python/Node paths
- [ ] Fallback: unknown providers default to OpenAI-compatible format
- [ ] Test: Anthropic SDK auto-routes and receives correct `x-api-key` header

---

## Day 4–5: The One-Click Installer Enhancement

### What You Build

**File:** `src/main.rs` [MODIFY] — Add `raypher setup` command that does everything:

```
raypher setup
```

This single command:

1. **Scans** for all Python/Node installations → auto-populates the allow list
2. **Prompts** for API keys → `raypher seal` for each provider
3. **Sets** environment variables → `install_env_redirects()`
4. **Installs** the Windows Service → `sc create RaypherService`
5. **Starts** the proxy → service starts automatically
6. **Verifies** the setup → sends a test request through the proxy

```rust
/// The "one-click" setup command.
/// After this runs, the user's agents auto-route through Raypher.
pub async fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛡️  Raypher Setup — Zero-Touch Configuration\n");

    // Step 1: Auto-detect runtimes
    println!("🔍 Step 1/6: Scanning for AI runtimes...");
    let runtimes = auto_populate_allow_list(&db)?;
    println!("   Found {} runtimes. Added to allow list.", runtimes);

    // Step 2: Seal API keys
    println!("\n🔑 Step 2/6: Seal your API keys (press Enter to skip any)");
    for provider in &["openai", "anthropic", "google"] {
        print!("   {} API key: ", provider);
        let key = rpassword::read_password()?;
        if !key.is_empty() {
            secrets::seal_key(&db, provider, &key)?;
            println!("   ✅ {} key sealed in TPM", provider);
        } else {
            println!("   ⏭️  Skipped");
        }
    }

    // Step 3: Set environment variables
    println!("\n🌐 Step 3/6: Setting environment variables...");
    installer::install_env_redirects()?;
    println!("   ✅ All AI SDKs now auto-redirect to Raypher");

    // Step 4: Install service
    println!("\n👻 Step 4/6: Installing Windows Service...");
    install_service()?;
    println!("   ✅ RaypherService installed (starts on boot)");

    // Step 5: Start proxy
    println!("\n🚀 Step 5/6: Starting proxy...");
    start_service()?;
    println!("   ✅ Proxy running on 127.0.0.1:8888");

    // Step 6: Verify
    println!("\n✅ Step 6/6: Verification...");
    let test = reqwest::get("http://127.0.0.1:8888/health").await?;
    if test.status().is_success() {
        println!("   ✅ Proxy responding. Setup complete!\n");
        println!("   Your agents will now auto-route through Raypher.");
        println!("   No code changes needed. Run your agents normally.\n");
    } else {
        println!("   ⚠️  Proxy not responding. Check logs: raypher query events");
    }

    Ok(())
}
```

### The MSI Installer Integration

**File:** `wix/main.wxs` [MODIFY] — Add Custom Action to run `raypher setup --silent` after MSI install.

The MSI installer should:

1. Copy binary to `C:\Program Files\Raypher\raypher.exe`
2. Run `raypher setup --silent` (auto-detect runtimes, set env vars, install service)
3. Launch the dashboard shortcut on desktop
4. **No terminal window** — everything runs silently

### Week 9 Completion Checklist

- [ ] `installer.rs` module created with `install_env_redirects()` and `uninstall_env_redirects()`
- [ ] System-level env vars set: `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, etc.
- [ ] Existing env vars backed up before overwriting, restored on uninstall
- [ ] `WM_SETTINGCHANGE` broadcast works (no reboot needed)
- [ ] Multi-provider routing in `proxy.rs` (OpenAI, Anthropic, Google, HuggingFace)
- [ ] Each provider uses correct auth header format and upstream URL
- [ ] Auto-allow list populates for common Python/Node/Ollama paths
- [ ] `raypher setup` one-click command works end-to-end
- [ ] MSI installer runs setup silently after install
- [ ] Test: Fresh Windows install → MSI → Python `openai.chat.completions.create()` works without ANY code changes
- [ ] Test: `raypher uninstall` cleanly removes all env vars and restores originals

### Week 9 Founder Checkpoint

> **"Can someone install the MSI, run their existing Python agent, and have it work through Raypher without changing a single line of code?"**
>
> If yes — Week 9 is complete. You have achieved **Zero-Touch Installation**.

---

# Week 10: The "Content Filter" (DLP Scanner)

**Codename:** The Censor
**Objective:** Scan every byte of outbound data passing through the proxy. Detect and redact/block API keys, credit cards, SSNs, emails, and other secrets before they leave the device.

**Philosophy:** "Sanitize at the Source." We do not trust the Agent to know what is sensitive. An authorized agent with a valid TPM key can still accidentally send `sk-proj-REAL_KEY` in a prompt. We catch it before it leaves.

**Why This Week:** This is the **P1 Quick Win** from the gap analysis. The proxy already intercepts all traffic — we just need to add a scanning step before forwarding. Estimated: 1–2 days for regex, 2–3 days for the full engine.

---

## Day 1–2: The Regex Engine (High-Speed Pattern Matching)

### What You Build

**File:** `src/dlp.rs` [NEW]

```rust
//! Data Loss Prevention (DLP) Scanner
//!
//! Scans request and response bodies for sensitive data patterns.
//! Supports four detection layers:
//!   1. Regex — Credit cards, SSNs, API keys, emails
//!   2. Entropy — High-entropy strings (likely tokens/passwords)
//!   3. Custom — User-defined blocklist from policy.yaml
//!   4. NER — Named Entity Recognition (future, Enterprise tier)

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

/// A DLP finding with its category, matched text, and position.
#[derive(Debug, Clone)]
pub struct DlpFinding {
    pub category: DlpCategory,
    pub matched_text: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f64,        // 0.0–1.0
    pub redacted_form: String,  // e.g., "[REDACTED-CC]"
}

#[derive(Debug, Clone, PartialEq)]
pub enum DlpCategory {
    CreditCard,
    SocialSecurity,
    ApiKeyOpenAI,
    ApiKeyAnthropic,
    ApiKeyAWS,
    ApiKeyGitHub,
    ApiKeyGeneric,
    EmailAddress,
    PhoneNumber,
    CryptoWallet,
    PrivateIP,
    HighEntropy,
    CustomPattern(String),
}

lazy_static! {
    static ref PATTERNS: Vec<(DlpCategory, Regex, &'static str)> = vec![
        // Credit Cards (Visa, MasterCard, Amex, Discover)
        (DlpCategory::CreditCard,
         Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap(),
         "[REDACTED-CREDIT-CARD]"),

        // Social Security Numbers
        (DlpCategory::SocialSecurity,
         Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
         "[REDACTED-SSN]"),

        // OpenAI API Keys (all formats)
        (DlpCategory::ApiKeyOpenAI,
         Regex::new(r"\bsk-(?:proj-)?[a-zA-Z0-9]{20,}\b").unwrap(),
         "[REDACTED-OPENAI-KEY]"),

        // Anthropic API Keys
        (DlpCategory::ApiKeyAnthropic,
         Regex::new(r"\bsk-ant-[a-zA-Z0-9\-]{20,}\b").unwrap(),
         "[REDACTED-ANTHROPIC-KEY]"),

        // AWS Access Keys
        (DlpCategory::ApiKeyAWS,
         Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
         "[REDACTED-AWS-KEY]"),

        // GitHub Personal Access Tokens
        (DlpCategory::ApiKeyGitHub,
         Regex::new(r"\bghp_[a-zA-Z0-9]{36}\b").unwrap(),
         "[REDACTED-GITHUB-TOKEN]"),

        // Email Addresses
        (DlpCategory::EmailAddress,
         Regex::new(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b").unwrap(),
         "[REDACTED-EMAIL]"),

        // Phone Numbers (US format)
        (DlpCategory::PhoneNumber,
         Regex::new(r"\b(?:\+1[\s\-]?)?\(?[0-9]{3}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}\b").unwrap(),
         "[REDACTED-PHONE]"),

        // Ethereum Wallets
        (DlpCategory::CryptoWallet,
         Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap(),
         "[REDACTED-CRYPTO-WALLET]"),

        // Private/Internal IP Addresses
        (DlpCategory::PrivateIP,
         Regex::new(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b").unwrap(),
         "[REDACTED-INTERNAL-IP]"),
    ];
}

/// Scan a text body for all DLP violations.
/// Returns a list of findings ordered by position.
pub fn scan(text: &str) -> Vec<DlpFinding> {
    let mut findings = Vec::new();

    // Layer 1: Regex patterns
    for (category, pattern, redacted) in PATTERNS.iter() {
        for m in pattern.find_iter(text) {
            // Validate credit cards with Luhn check
            if *category == DlpCategory::CreditCard {
                let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                if !luhn_check(&digits) { continue; }
            }

            findings.push(DlpFinding {
                category: category.clone(),
                matched_text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: 0.95,
                redacted_form: redacted.to_string(),
            });
        }
    }

    // Layer 2: Entropy-based detection for unknown secrets
    for word in text.split_whitespace() {
        if word.len() > 16 && is_high_entropy(word) {
            // Skip if already caught by regex
            let already = findings.iter().any(|f|
                f.start <= text.find(word).unwrap_or(usize::MAX)
                && f.end >= text.find(word).unwrap_or(0) + word.len()
            );
            if !already {
                if let Some(pos) = text.find(word) {
                    findings.push(DlpFinding {
                        category: DlpCategory::HighEntropy,
                        matched_text: word.to_string(),
                        start: pos,
                        end: pos + word.len(),
                        confidence: 0.70,
                        redacted_form: "[REDACTED-HIGH-ENTROPY]".to_string(),
                    });
                }
            }
        }
    }

    findings.sort_by_key(|f| f.start);
    findings
}

/// Redact all findings in the original text, returning the sanitized version.
pub fn redact(text: &str, findings: &[DlpFinding]) -> String {
    let mut result = text.to_string();
    // Process from end to start to preserve positions
    for finding in findings.iter().rev() {
        result.replace_range(finding.start..finding.end, &finding.redacted_form);
    }
    result
}

/// Shannon entropy calculation. Scores > 4.5 on strings > 16 chars suggest secrets.
fn shannon_entropy(data: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in data.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = data.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_high_entropy(s: &str) -> bool {
    let alphanumeric: String = s.chars().filter(|c| c.is_alphanumeric()).collect();
    alphanumeric.len() > 16 && shannon_entropy(&alphanumeric) > 4.5
}

/// Luhn algorithm for credit card validation.
fn luhn_check(digits: &str) -> bool {
    let sum: u32 = digits.chars().rev().enumerate().map(|(i, c)| {
        let mut d = c.to_digit(10).unwrap_or(0);
        if i % 2 == 1 {
            d *= 2;
            if d > 9 { d -= 9; }
        }
        d
    }).sum();
    sum % 10 == 0
}
```

### Senior Review Checklist — Day 1–2

- [ ] All 11 regex patterns compile and match correctly
- [ ] Luhn check filters false-positive credit card matches
- [ ] Shannon entropy correctly flags high-entropy strings > 4.5 bits/char
- [ ] `scan()` returns findings in position order
- [ ] `redact()` produces correct output with non-overlapping replacements
- [ ] Performance: scanning a 10KB payload completes in < 1ms
- [ ] No false positives on common text (e.g., "There are 123-45-6789 steps" should NOT match SSN in prose context — tune as needed)

---

## Day 3: Proxy Integration (The Scanning Pipeline)

### What You Modify

**File:** `src/proxy.rs` [MODIFY] — Insert DLP scanning between policy check and forwarding.

The proxy flow becomes:

```
Agent Request
    │
    ▼
┌──────────────────┐
│ 1. PID Resolution│
│ 2. Allow-List    │
│ 3. Policy Check  │
│ 4. ★ DLP SCAN ★  │ ◄── NEW: scan body before forwarding
│ 5. Key Injection │
│ 6. Forward       │
│ 7. ★ DLP SCAN ★  │ ◄── NEW: scan response before returning
│ 8. Spend Tracking│
│ 9. Return        │
└──────────────────┘
```

```rust
// In handle_proxy(), after policy check, before forwarding:

// ── Step 4: DLP Scan — check request body for sensitive data ──
let dlp_action = policy_config.dlp_action.as_deref().unwrap_or("redact");
let findings = dlp::scan(&body_text);

if !findings.is_empty() {
    let categories: Vec<String> = findings.iter()
        .map(|f| format!("{:?}", f.category))
        .collect();

    tracing::warn!(
        findings = findings.len(),
        categories = ?categories,
        "DLP: Sensitive data detected in request"
    );

    // Log to audit ledger
    log_proxy_event(&state.db, "DLP_DETECTION", &addr,
        &format!("Found {} sensitive items: {}", findings.len(), categories.join(", ")),
        Severity::Warning);

    match dlp_action {
        "block" => {
            log_proxy_event(&state.db, "REQUEST_BLOCKED", &addr,
                "DLP policy: request blocked due to sensitive data",
                Severity::Critical);
            return Err(StatusCode::FORBIDDEN);
        }
        "redact" => {
            // Replace sensitive data in-flight
            body_text = dlp::redact(&body_text, &findings);
            tracing::info!("DLP: Redacted {} findings, forwarding sanitized request", findings.len());
        }
        "alert" => {
            // Forward as-is but log critical alert
            log_proxy_event(&state.db, "DLP_ALERT", &addr,
                &format!("Sensitive data forwarded (alert-only mode): {}", categories.join(", ")),
                Severity::Critical);
        }
        _ => { /* default: redact */ body_text = dlp::redact(&body_text, &findings); }
    }
}
```

### Bi-Directional Scanning

Also scan the **response** from the API provider. Why? Because an LLM might echo back sensitive data that was in its training set, or repeat information from the prompt.

```rust
// After receiving response from upstream, before returning to agent:

let resp_findings = dlp::scan(&resp_body_text);
if !resp_findings.is_empty() {
    tracing::warn!(findings = resp_findings.len(), "DLP: Sensitive data in response");
    resp_body_text = dlp::redact(&resp_body_text, &resp_findings);
    log_proxy_event(&state.db, "DLP_RESPONSE_REDACTION", &addr,
        &format!("Redacted {} findings from API response", resp_findings.len()),
        Severity::Warning);
}
```

---

## Day 4–5: Custom Patterns and Dashboard Integration

### Custom Patterns from Policy

**File:** `src/dlp.rs` [MODIFY] — Add support for user-defined patterns from `policy.yaml`:

```yaml
# In ~/.raypher/policy.yaml
dlp:
  action: "redact"   # redact | block | alert
  custom_patterns:
    - name: "Internal Project Codename"
      pattern: "(?i)\\b(project[_\\s]?phoenix|operation[_\\s]?sunrise)\\b"
      redact_to: "[REDACTED-INTERNAL]"
    - name: "Employee IDs"
      pattern: "\\bEMP-[0-9]{6}\\b"
      redact_to: "[REDACTED-EMPLOYEE-ID]"
  exclusions:
    - "test@example.com"     # Whitelisted test data
    - "4111111111111111"     # Test credit card
```

### Dashboard DLP Panel

**File:** `src/dashboard_spa.html` [MODIFY] — Add a DLP section to the dashboard:

- **DLP Overview Card:** Total scans today, findings blocked, findings redacted
- **Pattern Hit Table:** Which patterns are triggering most (helps tune false positives)
- **Recent DLP Events:** Live feed of redactions/blocks with timestamp and category
- **DLP Settings:** Toggle between Redact/Block/Alert modes from the dashboard

### Dashboard API Endpoints

**File:** `src/dashboard.rs` [MODIFY] — Add:

- `GET /api/dlp/stats` → Return DLP scan statistics
- `GET /api/dlp/events` → Return recent DLP findings
- `POST /api/dlp/config` → Update DLP action mode (redact/block/alert)

### Week 10 Completion Checklist

- [ ] `dlp.rs` module created with 11+ regex patterns
- [ ] Credit card Luhn validation eliminates false positives
- [ ] Shannon entropy catches unknown tokens/passwords
- [ ] `scan()` function processes 10KB payload in < 1ms
- [ ] `redact()` function produces correct sanitized output
- [ ] Proxy integrates DLP scan before forwarding (request body)
- [ ] Proxy integrates DLP scan on response (bi-directional)
- [ ] Policy controls DLP action: redact / block / alert
- [ ] Custom patterns loadable from `policy.yaml`
- [ ] Exclusion list for whitelisted test data
- [ ] All DLP events logged to audit ledger with category and severity
- [ ] Dashboard DLP panel shows stats, events, and settings
- [ ] Test: Send `sk-proj-ABC123...` in a prompt → redacted before reaching OpenAI
- [ ] Test: Send `123-45-6789` in a prompt → detected as SSN, redacted
- [ ] Test: DLP "block" mode returns HTTP 403 with clear message

### Week 10 Founder Checkpoint

> **"Can I send a prompt containing my real OpenAI API key, and have Raypher automatically scrub it out before it reaches the LLM?"**
>
> If yes — Week 10 is complete. You have built the **Content Filter**.

---

# Week 11: The "Constitution" (Enhanced Dynamic Policy Engine)

**Codename:** The Rulebook
**Objective:** Upgrade the existing `policy.rs` from hardcoded zones into a full dynamic policy engine that reads YAML files, hot-reloads on change, and supports the Four Pillars of Control: Operational, Financial, Network, and Temporal.

**Philosophy:** "Governance as Code." The CISO writes rules in YAML. Raypher compiles them into real-time enforcement. No developer involvement required. No restarts. No downtime.

**Why This Week:** This is the **P2 priority** from the gap analysis. The current policy engine (Phase 2) supports basic zone-based allow/deny, but enterprises need budget limits, time-fencing, model restrictions, and trust-score-based dynamic rules.

---

## Day 1–2: The YAML Policy Schema and Parser

### The Policy File Format

**File:** `~/.raypher/policy.yaml` — The single source of truth for all governance rules.

```yaml
# Raypher Policy File v1.0
# Hot-reloaded: changes apply within 2 seconds, no restart needed.
version: "1.0"
default_action: "deny"   # Fail-closed: if no rule matches → DENY

rules:
  # ── Operational Policies (What can you touch?) ──
  - name: "Block Dangerous File Operations"
    match:
      action_type: "file_delete"
      path_pattern: "/etc/*|/System/*|C:\\Windows\\*"
    action: DENY
    severity: critical
    message: "Blocked: Agent attempted to delete protected system file"

  - name: "Allow Read-Only Access for New Agents"
    match:
      trust_score: { lt: 500 }
      action_type: "file_write"
    action: DENY
    message: "Low-trust agent restricted to read-only access"

  # ── Financial Policies (What can you spend?) ──
  - name: "Budget Limit - Daily"
    match:
      daily_spend: { gt: 50.00 }
    action: DENY
    message: "Daily budget exceeded ($50 limit)"

  - name: "Block Expensive Models for Low Trust"
    match:
      trust_score: { lt: 700 }
      model: { in: ["gpt-4-turbo", "gpt-4-32k", "claude-3-opus"] }
    action: DENY
    message: "Low-trust agents restricted to standard models"
    suggest_model: "gpt-3.5-turbo"  # Auto-downgrade suggestion

  # ── Network Policies (Who can you talk to?) ──
  - name: "Domain Whitelist"
    match:
      action_type: "network"
      destination: { not_in: [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com"
      ]}
    action: DENY
    message: "Destination not in approved domain whitelist"

  - name: "Block Known Risky Domains"
    match:
      destination: { in: ["*.deepseek.com", "*.suspicious-ai.ru"] }
    action: DENY
    severity: critical
    message: "Blocked: Connection to banned AI provider"

  # ── Temporal Policies (When can you work?) ──
  - name: "After-Hours Block"
    match:
      time: { after: "18:00", before: "06:00" }
      day: { in: ["Saturday", "Sunday"] }
    action: DENY
    message: "AI agents blocked outside business hours"

  - name: "Maintenance Window - Read Only"
    match:
      time: { after: "02:00", before: "04:00" }
    action: DENY
    conditions:
      action_type: { in: ["file_write", "file_delete", "network"] }
    message: "Maintenance window: read-only mode active"

# ── DLP Configuration ──
dlp:
  action: "redact"
  custom_patterns:
    - name: "Internal Project Names"
      pattern: "(?i)\\b(project[_\\s]?phoenix|codename[_\\s]?alpha)\\b"
      redact_to: "[REDACTED-INTERNAL]"

# ── Model Routing ──
model_routing:
  enabled: true
  rules:
    - match_model: "gpt-4-turbo"
      downgrade_to: "gpt-3.5-turbo"
      condition:
        trust_score: { lt: 700 }
    - match_model: "claude-3-opus"
      downgrade_to: "claude-3-haiku"
      condition:
        daily_spend: { gt: 25.00 }
```

### What You Build

**File:** `src/policy.rs` [MAJOR MODIFY] — Replace the hardcoded policy engine with a YAML-driven one.

```rust
/// Dynamic Policy Engine — reads rules from YAML, evaluates in real-time.
///
/// Architecture:
///   1. PolicyConfig loaded from YAML on startup
///   2. notify crate watches the file for changes
///   3. On change → re-parse YAML, swap Arc<PolicyConfig> atomically
///   4. Every proxy request evaluates against current rules (top-to-bottom, first match wins)

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub version: String,
    pub default_action: String,  // "allow" or "deny"
    pub rules: Vec<PolicyRule>,
    pub dlp: Option<DlpConfig>,
    pub model_routing: Option<ModelRoutingConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub match_conditions: MatchConditions,
    pub action: PolicyAction,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub suggest_model: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Prompt,   // Human approval required
    Redact,   // Allow but redact sensitive content
}

/// Evaluate a request against all policy rules.
/// Returns the first matching rule's action, or default_action if none match.
pub fn evaluate(
    config: &PolicyConfig,
    context: &RequestContext,
) -> PolicyVerdict {
    for rule in &config.rules {
        if rule.matches(context) {
            return PolicyVerdict {
                action: rule.action.clone(),
                rule_name: rule.name.clone(),
                message: rule.message.clone().unwrap_or_default(),
                suggested_model: rule.suggest_model.clone(),
            };
        }
    }

    // No rule matched → use default (fail-closed = DENY)
    PolicyVerdict {
        action: match config.default_action.as_str() {
            "allow" => PolicyAction::Allow,
            _ => PolicyAction::Deny,
        },
        rule_name: "default".to_string(),
        message: "No matching policy rule".to_string(),
        suggested_model: None,
    }
}
```

### The Hot-Reload Watcher

```rust
/// Watch policy.yaml for changes and hot-reload without restart.
pub async fn start_policy_watcher(
    policy: Arc<RwLock<PolicyConfig>>,
    policy_path: PathBuf,
) {
    use notify::{Watcher, RecursiveMode, Event};

    let (tx, mut rx) = tokio::sync::mpsc::channel(10);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                let _ = tx.blocking_send(());
            }
        }
    }).expect("Failed to create file watcher");

    watcher.watch(&policy_path, RecursiveMode::NonRecursive)
        .expect("Failed to watch policy file");

    while rx.recv().await.is_some() {
        // Debounce: wait 500ms for file to finish writing
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        match std::fs::read_to_string(&policy_path) {
            Ok(content) => match serde_yaml::from_str::<PolicyConfig>(&content) {
                Ok(new_config) => {
                    let mut policy_guard = policy.write().await;
                    *policy_guard = new_config;
                    tracing::info!("Policy hot-reloaded from {:?}", policy_path);
                }
                Err(e) => {
                    tracing::error!("Policy YAML parse error (keeping old policy): {}", e);
                }
            },
            Err(e) => tracing::error!("Failed to read policy file: {}", e),
        }
    }
}
```

---

## Day 3: Budget Tracking and Model Routing

### Budget Enforcement

**File:** `src/database.rs` [MODIFY] — Add spend tracking tables and queries.

```sql
-- New table: per-agent, per-day spend tracking
CREATE TABLE IF NOT EXISTS spend_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_hash TEXT NOT NULL,
    date TEXT NOT NULL,           -- YYYY-MM-DD
    total_tokens INTEGER DEFAULT 0,
    total_cost_usd REAL DEFAULT 0.0,
    request_count INTEGER DEFAULT 0,
    UNIQUE(agent_hash, date)
);
```

```rust
/// Record API spend for an agent, calculate cost from token usage.
pub fn record_spend(
    &self,
    agent_hash: &str,
    tokens: u32,
    model: &str,
) -> Result<f64, Box<dyn std::error::Error>> {
    let cost = estimate_cost(model, tokens);
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    self.conn.execute(
        "INSERT INTO spend_tracking (agent_hash, date, total_tokens, total_cost_usd, request_count)
         VALUES (?1, ?2, ?3, ?4, 1)
         ON CONFLICT(agent_hash, date) DO UPDATE SET
           total_tokens = total_tokens + ?3,
           total_cost_usd = total_cost_usd + ?4,
           request_count = request_count + 1",
        params![agent_hash, today, tokens, cost],
    )?;

    // Return today's total for budget check
    let daily_total: f64 = self.conn.query_row(
        "SELECT total_cost_usd FROM spend_tracking WHERE agent_hash = ?1 AND date = ?2",
        params![agent_hash, today],
        |row| row.get(0),
    )?;

    Ok(daily_total)
}

/// Cost estimation per model per 1K tokens
fn estimate_cost(model: &str, tokens: u32) -> f64 {
    let cost_per_1k = match model {
        m if m.contains("gpt-4-turbo") => 0.01,
        m if m.contains("gpt-4") => 0.03,
        m if m.contains("gpt-3.5") => 0.0005,
        m if m.contains("claude-3-opus") => 0.015,
        m if m.contains("claude-3-sonnet") => 0.003,
        m if m.contains("claude-3-haiku") => 0.00025,
        _ => 0.001,  // Default estimate
    };
    (tokens as f64 / 1000.0) * cost_per_1k
}
```

### Model Routing / Downgrade

When a policy rule says `suggest_model: "gpt-3.5-turbo"`, the proxy should rewrite the `model` field in the request JSON before forwarding:

```rust
/// Rewrite the model field in the request JSON if policy requires downgrade.
fn apply_model_downgrade(body: &mut serde_json::Value, target_model: &str) {
    if let Some(obj) = body.as_object_mut() {
        if let Some(model) = obj.get_mut("model") {
            let original = model.as_str().unwrap_or("unknown");
            tracing::info!(
                original = original,
                downgraded = target_model,
                "Policy: Model downgraded for cost control"
            );
            *model = serde_json::Value::String(target_model.to_string());
        }
    }
}
```

---

## Day 4–5: Dashboard Policy Editor and Testing

### Dashboard Integration

**File:** `src/dashboard_spa.html` [MODIFY] — Add a Policy Management section:

- **Active Rules List:** Shows all loaded policy rules with their status (active/disabled)
- **Budget Overview:** Per-agent daily spend with progress bars toward limit
- **Model Usage Chart:** Pie chart showing which models are being used most
- **Policy Editor:** Read-only YAML viewer showing current loaded policy (editing via file only for safety)
- **Recent Policy Events:** Timeline of allow/deny/downgrade decisions

### Dashboard API Endpoints

**File:** `src/dashboard.rs` [MODIFY] — Add:

- `GET /api/policy/rules` → Return current policy rules
- `GET /api/policy/events` → Return recent policy decisions  
- `GET /api/spend/daily` → Return per-agent daily spend data
- `GET /api/spend/summary` → Return aggregate spend statistics

### Week 11 Completion Checklist

- [ ] Policy YAML schema defined (version, rules, dlp, model_routing)
- [ ] YAML parser with serde_yaml reads the policy file
- [ ] Hot-reload watcher: policy.yaml changes apply in < 2 seconds without restart
- [ ] Bad YAML → keep old policy, log error (never crash on bad config)
- [ ] Four Pillars implemented: Operational, Financial, Network, Temporal
- [ ] Rule evaluation: top-to-bottom, first match wins
- [ ] Default action: fail-closed (DENY if no rule matches)
- [ ] Budget tracking: per-agent, per-day in database
- [ ] Cost estimation: per-model token pricing
- [ ] Model routing: auto-downgrade expensive models for low-trust agents
- [ ] Time-fencing: after-hours and weekend blocks
- [ ] Domain whitelist: block connections to unapproved destinations
- [ ] Dashboard Policy panel: rules, budget, model usage, events
- [ ] Test: Change policy.yaml → verify proxy behavior changes within 2 seconds
- [ ] Test: Agent exceeds $50 daily budget → DENY with clear message
- [ ] Test: Low-trust agent requests gpt-4 → downgraded to gpt-3.5-turbo

### Week 11 Founder Checkpoint

> **"Can a CISO write a YAML file that says 'block all AI after 6pm' and have it take effect immediately without restarting anything?"**
>
> If yes — Week 11 is complete. You have built the **Dynamic Policy Engine**.

---

# Week 12: The "Foundation" (Local CA + TLS Termination)

**Codename:** The Certificate Authority
**Objective:** Generate a machine-local Root CA certificate, install it into the OS Trust Store, and enable the proxy to accept HTTPS connections. This is the FOUNDATION for transparent HTTPS interception (Phase 4 will add the kernel redirect via WFP/eBPF).

**Philosophy:** "Trust from Within." Every enterprise proxy needs TLS termination. By generating a local CA on each machine (private key never leaves the device), we create a cryptographic trust anchor tied to that specific hardware.

**Why This Week:** This is the prerequisite for Phase 4's kernel-level transparent proxy (WFP redirect). Without a local CA, intercepted HTTPS traffic would cause certificate errors. With it, the proxy can seamlessly terminate and inspect TLS traffic.

---

## Day 1–2: Local CA Certificate Generation

### What You Build

**File:** `src/tls.rs` [NEW]

```rust
//! TLS Certificate Authority and Certificate Management
//!
//! Generates a machine-local Root CA that:
//! 1. Is unique per machine (tied to TPM fingerprint in the Subject)
//! 2. Private key is stored encrypted in data.db (sealed to TPM if available)
//! 3. Is installed in the OS Trust Store so browsers and SDKs trust it
//! 4. Can issue per-domain certificates on-the-fly for TLS interception

use rcgen::{
    Certificate, CertificateParams, DistinguishedName,
    DnType, KeyPair, SignatureAlgorithm,
    BasicConstraints, IsCa,
};
use chrono::{Utc, Duration};

/// Generate a new Raypher Root CA certificate.
/// The CA is unique per machine — the TPM fingerprint is embedded in the Subject.
pub fn generate_root_ca(
    machine_fingerprint: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    // Distinguished Name — identifies this specific machine's CA
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Raypher Local Security CA");
    dn.push(DnType::OrganizationName, "Raypher AI Security");
    dn.push(DnType::OrganizationalUnitName,
        &format!("Machine: {}", &machine_fingerprint[..16]));
    params.distinguished_name = dn;

    // CA constraints
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // Validity: 10 years (machine-local, no rotation needed)
    params.not_before = Utc::now().into();
    params.not_after = (Utc::now() + Duration::days(3650)).into();

    // Generate the CA certificate
    let key_pair = KeyPair::generate(&SignatureAlgorithm::ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Generate a per-domain certificate signed by the Root CA.
/// Used for on-the-fly TLS interception (e.g., api.openai.com).
pub fn generate_domain_cert(
    domain: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    params.not_before = Utc::now().into();
    params.not_after = (Utc::now() + Duration::days(30)).into();

    let domain_key = KeyPair::generate(&SignatureAlgorithm::ECDSA_P256_SHA256)?;
    let domain_cert = params.signed_by(&domain_key, &ca_cert, &ca_key)?;

    Ok((domain_cert.pem(), domain_key.serialize_pem()))
}

/// Install the Root CA into the OS Trust Store.
pub fn install_ca_to_trust_store(cert_pem: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        // Use certutil to install into the Local Machine Root store
        let temp_path = std::env::temp_dir().join("raypher_ca.crt");
        std::fs::write(&temp_path, cert_pem)?;

        let output = std::process::Command::new("certutil")
            .args(["-addstore", "Root", &temp_path.to_string_lossy()])
            .output()?;

        std::fs::remove_file(&temp_path)?;

        if output.status.success() {
            tracing::info!("Root CA installed in Windows Trust Store");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("Failed to install CA: {}", stderr);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Copy to /usr/local/share/ca-certificates and update
        let ca_path = "/usr/local/share/ca-certificates/raypher-local-ca.crt";
        std::fs::write(ca_path, cert_pem)?;

        std::process::Command::new("update-ca-certificates")
            .output()?;

        tracing::info!("Root CA installed in Linux Trust Store");
    }

    Ok(())
}

/// Remove the Raypher CA from the OS Trust Store (clean uninstall).
pub fn remove_ca_from_trust_store() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("certutil")
            .args(["-delstore", "Root", "Raypher Local Security CA"])
            .output()?;
        tracing::info!("Root CA removed from Windows Trust Store");
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file("/usr/local/share/ca-certificates/raypher-local-ca.crt");
        std::process::Command::new("update-ca-certificates").output()?;
    }

    Ok(())
}
```

---

## Day 3–4: HTTPS Proxy Listener

### What You Modify

**File:** `src/proxy.rs` [MODIFY] — Add a second listener on `:8889` for HTTPS connections.

The proxy now has TWO listeners:

| Port | Protocol | Use Case |
|---|---|---|
| `127.0.0.1:8888` | HTTP | SDK clients using `OPENAI_BASE_URL` (current behavior) |
| `127.0.0.1:8889` | HTTPS | Future: intercepted traffic from WFP/eBPF redirect |

```rust
/// Start both HTTP and HTTPS proxy listeners.
pub async fn start_proxy() -> Result<(), Box<dyn std::error::Error>> {
    // HTTP listener (existing)
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:8888").await?;

    // HTTPS listener (new — uses local CA)
    let tls_config = load_tls_config(&state).await?;
    let https_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let https_listener = tokio::net::TcpListener::bind("127.0.0.1:8889").await?;

    tracing::info!("Proxy HTTP  on 127.0.0.1:8888");
    tracing::info!("Proxy HTTPS on 127.0.0.1:8889");

    // Run both listeners concurrently
    tokio::select! {
        _ = serve_http(http_listener, app.clone()) => {},
        _ = serve_https(https_listener, https_acceptor, app.clone()) => {},
    }

    Ok(())
}
```

---

## Day 5: Integration Testing and Security Verification

### Security Checklist

Before Phase 3 is tagged as complete, verify these security properties:

1. **Private key never leaves the machine:** CA private key is encrypted in `data.db`, never transmitted
2. **CA is machine-unique:** Subject contains TPM fingerprint, cannot be copied to another device
3. **Uninstall is clean:** `raypher uninstall` removes CA from Trust Store, removes env vars, restores backups
4. **No permanent system damage:** If Raypher is uninstalled, the system returns to its original state
5. **DLP cannot be bypassed:** All outbound traffic through the proxy is scanned, no bypass path
6. **Policy is fail-closed:** If policy.yaml is missing or corrupt, default action is DENY

### The Full Phase 3 Proxy Pipeline (After Week 12)

```
Agent starts → SDK reads $OPENAI_BASE_URL → connects to 127.0.0.1:8888

┌──────────────────────────────────────────────────────────────┐
│                    RAYPHER PROXY PIPELINE                     │
│                                                              │
│  1. PID Resolution      → Who is calling?                    │
│  2. Allow-List Check    → Are they authorized?               │
│  3. Provider Detection  → OpenAI? Anthropic? Google?         │
│  4. Policy Evaluation   → Check YAML rules (budget, time,    │
│     │                     model, domain, trust score)         │
│     ├── DENY → 403 + audit log                              │
│     ├── DOWNGRADE → rewrite model field                      │
│     └── ALLOW → continue                                     │
│  5. DLP Scan (Request)  → Regex + Entropy + Custom patterns  │
│     ├── BLOCK → 403                                          │
│     ├── REDACT → sanitize payload                            │
│     └── CLEAN → continue                                     │
│  6. Key Injection       → Unseal TPM key for provider        │
│  7. Forward             → HTTPS to upstream provider         │
│  8. DLP Scan (Response) → Scan LLM response for leaks       │
│  9. Spend Tracking      → Record tokens + cost               │
│ 10. Audit Log           → Record everything to data.db       │
│ 11. Return              → Response back to agent             │
└──────────────────────────────────────────────────────────────┘
```

### Week 12 Completion Checklist

- [ ] `tls.rs` module created with CA generation, domain cert creation, trust store management
- [ ] Root CA generated with machine-unique Subject (TPM fingerprint)
- [ ] CA private key encrypted at rest in `data.db`
- [ ] CA installed in Windows Trust Store via `certutil`
- [ ] CA installed in Linux Trust Store via `update-ca-certificates`
- [ ] HTTPS listener on `:8889` accepts TLS connections using local CA
- [ ] Per-domain certificates generated on-the-fly for intercepted domains
- [ ] `raypher uninstall` cleanly removes CA from Trust Store
- [ ] Domain cert cache to avoid re-generation on every request
- [ ] Test: HTTPS connection to `:8889` succeeds with valid TLS handshake
- [ ] Test: `curl https://127.0.0.1:8889/health` returns healthy (no cert warnings)
- [ ] Test: Uninstall removes CA — no leftover certificates in Trust Store

### Week 12 Founder Checkpoint

> **"Can the proxy accept an HTTPS connection, decrypt the traffic, inspect it through DLP, and re-encrypt it to the upstream provider — all using a locally generated CA that the OS trusts?"**
>
> If yes — Week 12 is complete. You have built the **TLS Foundation**.

---

# Phase 3 Complete — "The Invisible Hand" Summary

## What Changed (Before → After)

| Capability | Phase 2 (Before) | Phase 3 (After) |
|---|---|---|
| **Developer Effort** | Change base_url, add headers, seal keys manually | **ZERO** — install MSI, done |
| **Providers** | OpenAI only | **OpenAI + Anthropic + Google + HuggingFace** |
| **Data Protection** | None — payload not inspected | **11 regex patterns + entropy + custom** |
| **Governance** | Binary allow/deny | **YAML policies: budget, time, model, domain** |
| **Model Control** | Forward as-is | **Auto-downgrade for cost control** |
| **HTTPS** | HTTP only | **Local CA + TLS termination ready** |
| **Installation** | 5+ manual commands | **One-click MSI / `raypher setup`** |

## New Files Created

| File | Lines (est.) | Purpose |
|---|---|---|
| `src/installer.rs` | ~200 | Environment variable injection + backup/restore |
| `src/dlp.rs` | ~250 | DLP scanner (regex + entropy + custom patterns) |
| `src/tls.rs` | ~200 | Local CA generation + Trust Store management |

## Files Modified

| File | Changes |
|---|---|
| `src/proxy.rs` | Multi-provider routing, DLP pipeline, HTTPS listener |
| `src/policy.rs` | YAML-driven dynamic engine with hot-reload |
| `src/database.rs` | Spend tracking tables + budget queries |
| `src/main.rs` | `raypher setup` one-click command |
| `src/dashboard_spa.html` | DLP panel, policy panel, budget charts |
| `src/dashboard.rs` | New API endpoints for DLP and policy data |
| `wix/main.wxs` | Silent setup Custom Action in MSI |
| `Cargo.toml` | 7 new dependencies |

## Real-World Attack Scenarios — How Phase 3 Defends

### Scenario 1: "The Accidental Key Leak"

> Developer pastes their real OpenAI key into an agent prompt by accident.

**Without Phase 3:** Key sent to OpenAI, logged in their system, potentially exposed in training.
**With Phase 3:** DLP scanner detects `sk-proj-...` pattern → REDACTED before it leaves the laptop.

### Scenario 2: "The Budget Blowout"

> Intern's agent gets stuck in a loop, burning $500/hour on GPT-4-Turbo.

**Without Phase 3:** Bill arrives at end of month. $5,000 wasted.
**With Phase 3:** Budget policy triggers at $50/day → DENY → agent gets 403. Cost capped automatically.

### Scenario 3: "The Shadow Model"

> Marketing team switches from approved GPT-4 to banned DeepSeek without telling IT.

**Without Phase 3:** DeepSeek receives proprietary data. Compliance violation.
**With Phase 3:** Domain whitelist blocks `*.deepseek.com` → DENY → audit log captures the attempt.

### Scenario 4: "The Weekend Rogue"

> Agent runs unsupervised on Saturday, makes destructive changes.

**Without Phase 3:** No one notices until Monday.
**With Phase 3:** Temporal policy blocks all AI after 6pm and on weekends → DENY.

---

## What Phase 3 Does NOT Include (Deferred to Phase 4+)

| Feature | Why Deferred | Target Phase |
|---|---|---|
| **WFP/eBPF Kernel Redirect** | Complex kernel driver development, needs Phase 3's TLS foundation first | Phase 4 |
| **Dynamic Trust Score** | Needs behavioral data from DLP and policy engine running in production | Phase 4+ |
| **gRPC Cloud Connectivity** | Needs fleet deployment, cloud backend infrastructure | Phase 5+ |
| **mDNS Shadow Discovery** | Network scanning features, less critical than core security | Phase 6+ |
| **NER/Presidio Deep PII** | Heavyweight ML dependency, regex covers 90% of use cases | Phase 7+ |

---

## Phase 3 Completion Gate

> **Phase 3 is complete when ALL of these are true:**
>
> 1. ✅ A fresh MSI install auto-configures everything — ZERO code changes needed
> 2. ✅ Multi-provider routing works for OpenAI, Anthropic, Google, HuggingFace
> 3. ✅ DLP scanner catches API keys, credit cards, SSNs, emails in transit
> 4. ✅ YAML policy engine with hot-reload governs budget, time, model, domain
> 5. ✅ Local CA generated and installed — HTTPS proxy listener works
> 6. ✅ Dashboard shows DLP events, policy decisions, and budget tracking
> 7. ✅ Clean uninstall restores everything to original state
>
> **When all 7 boxes are checked, tag `v0.3.0` and push.**

---

*Document: RAYPHER_PHASE3_BUILD_PLAN.md*
*Created: 2026-02-15*
*Status: PLANNING — Not yet started*
*Predecessor: Phase 2 — The Ghost Protocol (Complete)*
*Successor: Phase 4 — The Kernel Guard (WFP + eBPF Transparent Proxy)*
