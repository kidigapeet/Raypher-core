// ──────────────────────────────────────────────────────────────
//  Raypher — Policy Engine (The Guardrails)
//  YAML-driven policy with hot-reload, model routing,
//  budget enforcement, and DLP action configuration.
// ──────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::database::Database;

// ── Data Structures ────────────────────────────────────────────

/// A single capability card for the Mission Control Kanban board.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub description: String,
    pub zone: Zone,
}

/// Which Kanban column a capability lives in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    Allowed,
    AskMe,
    Blocked,
}

impl Zone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Zone::Allowed => "allowed",
            Zone::AskMe => "ask_me",
            Zone::Blocked => "blocked",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "allowed" => Zone::Allowed,
            "ask_me" => Zone::AskMe,
            "blocked" => Zone::Blocked,
            _ => Zone::Blocked,
        }
    }
}

/// DLP action configuration per-category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    Redact,
    Block,
    Alert,
    Allow,
}

impl Default for DlpAction {
    fn default() -> Self { DlpAction::Redact }
}

/// DLP policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPolicy {
    pub default_action: DlpAction,
    pub api_keys: DlpAction,
    pub financial: DlpAction,
    pub pii: DlpAction,
    pub crypto_material: DlpAction,
    pub entropy_detection: bool,
    pub entropy_threshold: f64,
    pub exclusions: Vec<String>,
}

impl Default for DlpPolicy {
    fn default() -> Self {
        Self {
            default_action: DlpAction::Redact,
            api_keys: DlpAction::Redact,
            financial: DlpAction::Block,
            pii: DlpAction::Redact,
            crypto_material: DlpAction::Block,
            entropy_detection: true,
            entropy_threshold: 4.5,
            exclusions: vec![],
        }
    }
}

impl DlpPolicy {
    /// Get the DLP action for a given category.
    pub fn action_for_category(&self, category: &str) -> &DlpAction {
        match category {
            "api_keys" => &self.api_keys,
            "financial" => &self.financial,
            "pii" => &self.pii,
            "crypto_material" => &self.crypto_material,
            _ => &self.default_action,
        }
    }
}

/// Model routing rule — auto-downgrade expensive models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRoute {
    pub from_model: String,
    pub to_model: String,
    pub condition: RouteCondition,
}

/// When to apply a model routing rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RouteCondition {
    Always,
    BudgetExceeded,
    AfterHours,
}

/// Budget tracking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub daily_limit_usd: f64,
    pub hourly_limit_usd: f64,
    pub per_request_limit_usd: f64,
    pub action_on_exceed: BudgetAction,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            daily_limit_usd: 50.0,
            hourly_limit_usd: 10.0,
            per_request_limit_usd: 5.0,
            action_on_exceed: BudgetAction::Downgrade,
        }
    }
}

/// What to do when budget is exceeded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BudgetAction {
    Block,
    Downgrade,
    Alert,
}

/// The full policy configuration shown in the Mission Control tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub daily_budget_limit: f64,
    pub work_hours_only: bool,
    pub work_hours_start: String,
    pub work_hours_end: String,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub file_read_paths: Vec<String>,
    pub file_write_paths: Vec<String>,
    pub capabilities: Vec<Capability>,
    // Phase 3 additions
    #[serde(default)]
    pub dlp: DlpPolicy,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub model_routes: Vec<ModelRoute>,
}

// ── Defaults ───────────────────────────────────────────────────

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            daily_budget_limit: 50.0,
            work_hours_only: false,
            work_hours_start: "09:00".to_string(),
            work_hours_end: "17:00".to_string(),
            allowed_domains: vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
                "github.com".to_string(),
            ],
            blocked_domains: vec![
                "pastebin.com".to_string(),
                "paste.ee".to_string(),
            ],
            file_read_paths: vec![],
            file_write_paths: vec![],
            capabilities: default_capabilities(),
            dlp: DlpPolicy::default(),
            budget: BudgetConfig::default(),
            model_routes: default_model_routes(),
        }
    }
}

/// The default set of capability cards for the Kanban board.
fn default_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            id: "internet_whitelist".to_string(),
            name: "Internet Access (Whitelisted)".to_string(),
            description: "Allow network access to whitelisted domains only".to_string(),
            zone: Zone::Allowed,
        },
        Capability {
            id: "internet_any".to_string(),
            name: "Internet Access (Any)".to_string(),
            description: "Allow network access to any domain".to_string(),
            zone: Zone::Blocked,
        },
        Capability {
            id: "file_read".to_string(),
            name: "File System (Read)".to_string(),
            description: "Allow reading files from whitelisted paths".to_string(),
            zone: Zone::Allowed,
        },
        Capability {
            id: "file_write".to_string(),
            name: "File System (Write)".to_string(),
            description: "Allow writing files to whitelisted paths".to_string(),
            zone: Zone::AskMe,
        },
        Capability {
            id: "file_delete".to_string(),
            name: "File System (Delete)".to_string(),
            description: "Allow deleting files".to_string(),
            zone: Zone::Blocked,
        },
        Capability {
            id: "high_spend".to_string(),
            name: "High Spend (>$10)".to_string(),
            description: "Allow single requests costing more than $10".to_string(),
            zone: Zone::AskMe,
        },
        Capability {
            id: "shell_exec".to_string(),
            name: "Execute Shell Commands".to_string(),
            description: "Allow spawning shell processes (bash, powershell)".to_string(),
            zone: Zone::Blocked,
        },
        Capability {
            id: "model_expensive".to_string(),
            name: "Expensive Models (GPT-4, Opus)".to_string(),
            description: "Allow using expensive AI models".to_string(),
            zone: Zone::AskMe,
        },
        Capability {
            id: "after_hours".to_string(),
            name: "After-Hours Operation".to_string(),
            description: "Allow agent activity outside work hours".to_string(),
            zone: Zone::Allowed,
        },
    ]
}

/// Default model routing rules — downgrade expensive models when budget exceeded.
fn default_model_routes() -> Vec<ModelRoute> {
    vec![
        ModelRoute {
            from_model: "gpt-4".to_string(),
            to_model: "gpt-3.5-turbo".to_string(),
            condition: RouteCondition::BudgetExceeded,
        },
        ModelRoute {
            from_model: "gpt-4-turbo".to_string(),
            to_model: "gpt-3.5-turbo".to_string(),
            condition: RouteCondition::BudgetExceeded,
        },
        ModelRoute {
            from_model: "claude-3-opus".to_string(),
            to_model: "claude-3-haiku".to_string(),
            condition: RouteCondition::BudgetExceeded,
        },
    ]
}

// ── YAML File Support ──────────────────────────────────────────

/// Get the policy YAML file path (~/.raypher/policy.yaml).
pub fn policy_yaml_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".raypher").join("policy.yaml")
}

/// Load policy from YAML file. Returns None if file doesn't exist or is invalid.
pub fn load_policy_from_yaml() -> Option<PolicyConfig> {
    let path = policy_yaml_path();
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => match serde_yaml::from_str::<PolicyConfig>(&contents) {
            Ok(policy) => {
                info!("Loaded policy from YAML: {}", path.display());
                Some(policy)
            }
            Err(e) => {
                warn!("Failed to parse policy YAML ({}): {}. Using defaults.", path.display(), e);
                None
            }
        },
        Err(e) => {
            warn!("Failed to read policy YAML ({}): {}", path.display(), e);
            None
        }
    }
}

/// Save policy to YAML file.
pub fn save_policy_to_yaml(policy: &PolicyConfig) -> Result<(), String> {
    let path = policy_yaml_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    let yaml = serde_yaml::to_string(policy)
        .map_err(|e| format!("Failed to serialize policy to YAML: {}", e))?;
    std::fs::write(&path, yaml)
        .map_err(|e| format!("Failed to write policy YAML: {}", e))?;
    info!("Policy saved to YAML: {}", path.display());
    Ok(())
}

// ── Load / Save (Database + YAML) ──────────────────────────────

/// Load the policy. Priority: YAML file > database > defaults.
pub fn load_policy(db: &Database) -> PolicyConfig {
    // YAML file takes priority (operator override)
    if let Some(yaml_policy) = load_policy_from_yaml() {
        return yaml_policy;
    }
    // Fall back to database
    match db.get_policy("policy_config") {
        Ok(Some(json_str)) => {
            serde_json::from_str(&json_str).unwrap_or_default()
        }
        _ => PolicyConfig::default(),
    }
}

/// Save the policy to both the database and YAML file.
pub fn save_policy(db: &Database, policy: &PolicyConfig) -> Result<(), String> {
    let json = serde_json::to_string(policy)
        .map_err(|e| format!("Failed to serialize policy: {}", e))?;
    db.store_policy("policy_config", &json)
        .map_err(|e| format!("Failed to store policy: {}", e))?;
    // Also write to YAML for operator editing
    if let Err(e) = save_policy_to_yaml(policy) {
        warn!("Could not write policy YAML: {}", e);
    }
    info!("Policy configuration saved.");
    Ok(())
}

// ── Hot-Reload ─────────────────────────────────────────────────

/// A hot-reloadable policy container.
/// The proxy holds an Arc<PolicyHolder> and checks for updates.
pub struct PolicyHolder {
    pub config: RwLock<PolicyConfig>,
}

impl PolicyHolder {
    pub fn new(initial: PolicyConfig) -> Self {
        Self {
            config: RwLock::new(initial),
        }
    }

    /// Get a snapshot of the current policy.
    pub fn get(&self) -> PolicyConfig {
        self.config.read().unwrap().clone()
    }

    /// Reload policy from YAML file if it exists, otherwise from database.
    pub fn reload(&self, db: &Database) {
        let new_policy = load_policy(db);
        *self.config.write().unwrap() = new_policy;
        info!("Policy hot-reloaded.");
    }
}

/// Start a background file watcher that reloads the policy on file changes.
/// Returns the watcher handle (must be kept alive).
pub fn start_policy_watcher(
    holder: Arc<PolicyHolder>,
    db: Arc<std::sync::Mutex<Database>>,
) -> Option<notify::RecommendedWatcher> {
    use notify::{Watcher, RecursiveMode, Event, EventKind};

    let yaml_path = policy_yaml_path();
    if let Some(parent) = yaml_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!("Cannot create policy dir for watcher: {}", e);
                return None;
            }
        }
    }

    let holder_clone = holder.clone();
    let db_clone = db.clone();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    info!("Policy YAML changed, hot-reloading...");
                    let db = db_clone.lock().unwrap();
                    holder_clone.reload(&db);
                }
            }
            Err(e) => warn!("Policy file watcher error: {}", e),
        }
    }).ok()?;

    let watch_path = yaml_path.parent().unwrap_or(&yaml_path);
    if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
        warn!("Failed to watch policy directory: {}", e);
        return None;
    }

    info!("Policy file watcher started on: {}", watch_path.display());
    Some(watcher)
}

// ── Runtime Checks ─────────────────────────────────────────────

/// Check if the current time is within work hours.
pub fn check_time_restriction(policy: &PolicyConfig) -> bool {
    if !policy.work_hours_only {
        return true; // no restriction
    }

    let now = chrono::Local::now();
    let current_time = now.format("%H:%M").to_string();

    current_time >= policy.work_hours_start && current_time <= policy.work_hours_end
}

/// Check if a domain is allowed by the policy.
pub fn check_domain(policy: &PolicyConfig, domain: &str) -> bool {
    // If explicitly blocked, deny
    if policy.blocked_domains.iter().any(|d| domain.contains(d)) {
        return false;
    }

    // Check if the "internet_any" capability is Allowed
    let any_internet = policy.capabilities.iter()
        .find(|c| c.id == "internet_any");
    if let Some(cap) = any_internet {
        if cap.zone == Zone::Allowed {
            return true;
        }
    }

    // Otherwise, must be in the whitelist
    policy.allowed_domains.iter().any(|d| domain.contains(d))
}

/// Check if a capability is in the Allowed zone.
pub fn is_capability_allowed(policy: &PolicyConfig, capability_id: &str) -> bool {
    policy.capabilities.iter()
        .find(|c| c.id == capability_id)
        .map(|c| c.zone == Zone::Allowed)
        .unwrap_or(false)
}

// ── Budget Enforcement ─────────────────────────────────────────

/// Check if the daily budget has been exceeded.
pub fn check_budget(policy: &PolicyConfig, db: &Database) -> BudgetStatus {
    let daily = db.get_daily_spend().unwrap_or(0.0);
    let hourly_breakdown = db.get_hourly_spend().unwrap_or_default();
    // Sum spending for the current hour
    let current_hour = chrono::Utc::now().format("%H").to_string();
    let hourly: f64 = hourly_breakdown.iter()
        .filter(|(h, _)| h == &current_hour)
        .map(|(_, v)| v)
        .sum();

    if daily >= policy.budget.daily_limit_usd {
        return BudgetStatus::DailyExceeded { spent: daily, limit: policy.budget.daily_limit_usd };
    }
    if hourly >= policy.budget.hourly_limit_usd {
        return BudgetStatus::HourlyExceeded { spent: hourly, limit: policy.budget.hourly_limit_usd };
    }

    BudgetStatus::Ok { daily_spent: daily, daily_limit: policy.budget.daily_limit_usd }
}

/// Budget check result.
#[derive(Debug)]
pub enum BudgetStatus {
    Ok { daily_spent: f64, daily_limit: f64 },
    DailyExceeded { spent: f64, limit: f64 },
    HourlyExceeded { spent: f64, limit: f64 },
}

impl BudgetStatus {
    pub fn is_exceeded(&self) -> bool {
        !matches!(self, BudgetStatus::Ok { .. })
    }
}

// ── Model Routing ──────────────────────────────────────────────

/// Apply model routing rules. Returns a potentially downgraded model name.
pub fn route_model(policy: &PolicyConfig, requested_model: &str, budget_exceeded: bool) -> String {
    for rule in &policy.model_routes {
        if requested_model.starts_with(&rule.from_model) {
            let should_apply = match &rule.condition {
                RouteCondition::Always => true,
                RouteCondition::BudgetExceeded => budget_exceeded,
                RouteCondition::AfterHours => !check_time_restriction(policy),
            };
            if should_apply {
                info!(
                    "Model auto-downgrade: {} → {} (condition: {:?})",
                    requested_model, rule.to_model, rule.condition
                );
                return rule.to_model.clone();
            }
        }
    }
    requested_model.to_string()
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = PolicyConfig::default();
        assert_eq!(policy.daily_budget_limit, 50.0);
        assert!(!policy.work_hours_only);
        assert_eq!(policy.dlp.default_action, DlpAction::Redact);
        assert_eq!(policy.budget.daily_limit_usd, 50.0);
        assert_eq!(policy.model_routes.len(), 3);
    }

    #[test]
    fn test_dlp_action_for_category() {
        let dlp = DlpPolicy::default();
        assert_eq!(*dlp.action_for_category("api_keys"), DlpAction::Redact);
        assert_eq!(*dlp.action_for_category("financial"), DlpAction::Block);
        assert_eq!(*dlp.action_for_category("unknown"), DlpAction::Redact);
    }

    #[test]
    fn test_model_routing_budget_exceeded() {
        let policy = PolicyConfig::default();
        let result = route_model(&policy, "gpt-4", true);
        assert_eq!(result, "gpt-3.5-turbo");
    }

    #[test]
    fn test_model_routing_budget_ok() {
        let policy = PolicyConfig::default();
        let result = route_model(&policy, "gpt-4", false);
        assert_eq!(result, "gpt-4");
    }

    #[test]
    fn test_yaml_roundtrip() {
        let policy = PolicyConfig::default();
        let yaml = serde_yaml::to_string(&policy).unwrap();
        let parsed: PolicyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.daily_budget_limit, policy.daily_budget_limit);
        assert_eq!(parsed.dlp.entropy_threshold, policy.dlp.entropy_threshold);
    }

    #[test]
    fn test_domain_check() {
        let policy = PolicyConfig::default();
        assert!(check_domain(&policy, "api.openai.com"));
        assert!(!check_domain(&policy, "pastebin.com"));
        assert!(!check_domain(&policy, "evil.com"));
    }
}
