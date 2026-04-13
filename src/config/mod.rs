use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration for estoppl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub agent: AgentConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub ledger: LedgerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Human-readable agent identifier (e.g. "treasury-bot-v2").
    pub id: String,
    /// Semantic version of the agent.
    #[serde(default = "default_version")]
    pub version: String,
    /// Human user who authorized this agent's operation.
    #[serde(default)]
    pub authorized_by: Option<String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// Tools that are always allowed (bypass policy check).
    #[serde(default)]
    pub allow_tools: Vec<String>,
    /// Tools that are always blocked.
    #[serde(default)]
    pub block_tools: Vec<String>,
    /// Tools that require human approval (logged as HUMAN_REQUIRED).
    #[serde(default)]
    pub human_review_tools: Vec<String>,
    /// Block tool calls where an amount field exceeds this USD value.
    #[serde(default)]
    pub max_amount_usd: Option<f64>,
    /// JSON path to the amount field in tool arguments (e.g. "amount").
    #[serde(default = "default_amount_field")]
    pub amount_field: String,
    /// Rate limit: max calls per tool per minute. 0 = unlimited.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    /// Rate limit overrides for specific tools (e.g. { "stripe.create_payment" = 5 }).
    #[serde(default)]
    pub rate_limit_tools: std::collections::HashMap<String, u32>,
    /// Fields to redact from tool arguments before syncing to cloud.
    /// These fields are replaced with "[REDACTED]" in input_data.
    /// If empty, all fields are logged as-is.
    #[serde(default)]
    pub redact_fields: Vec<String>,
    /// Only require human review when amount exceeds this threshold.
    /// Below this amount, human_review_tools are auto-allowed.
    /// DEPRECATED: use custom_rules instead. Kept for backward compatibility.
    #[serde(default)]
    pub human_review_above_usd: Option<f64>,
    /// Per-agent rule overrides. Keyed by agent_id.
    #[serde(default)]
    pub agent_rules: std::collections::HashMap<String, AgentRulesConfig>,
    /// Custom conditional rules. Evaluated in order after built-in rules.
    /// These allow arbitrary field checks on tool arguments.
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
    /// Behavior when human review is required but cloud is not configured.
    /// "closed" (default) = block the call. "open" = forward with warning (dev only).
    #[serde(default)]
    pub fail_mode: FailMode,
}

/// Fail mode when human review cannot be performed (no cloud connection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Block the call (secure default). Recommended for production.
    #[default]
    Closed,
    /// Forward the call with a warning. For development/testing only.
    Open,
}

/// A custom conditional rule that checks a field in tool arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Tool name pattern to match (supports wildcards like "wire_*"). Use "*" for all tools.
    #[serde(default = "default_wildcard")]
    pub tool: String,
    /// Condition to evaluate against tool arguments.
    pub condition: RuleCondition,
    /// Action to take when condition matches.
    pub action: RuleAction,
}

fn default_wildcard() -> String {
    "*".to_string()
}

/// Condition that checks a field in tool call arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// JSON path to the field in arguments (supports dot notation: "payment.amount").
    pub field: String,
    /// Comparison operator.
    pub operator: RuleOperator,
    /// Value to compare against. Interpreted as number or string based on operator.
    pub value: serde_json::Value,
}

/// Comparison operators for custom rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleOperator {
    #[serde(alias = ">")]
    Gt,
    #[serde(alias = "<")]
    Lt,
    #[serde(alias = ">=")]
    Gte,
    #[serde(alias = "<=")]
    Lte,
    #[serde(alias = "==")]
    Eq,
    #[serde(alias = "!=")]
    Neq,
    Contains,
    NotContains,
}

/// Action to take when a custom rule condition matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    HumanReview,
    Allow,
}

/// Per-agent rule overrides. Fields that are set override the org-wide defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentRulesConfig {
    #[serde(default)]
    pub allow_tools: Option<Vec<String>>,
    #[serde(default)]
    pub block_tools: Option<Vec<String>>,
    #[serde(default)]
    pub human_review_tools: Option<Vec<String>>,
    #[serde(default)]
    pub max_amount_usd: Option<f64>,
    #[serde(default)]
    pub human_review_above_usd: Option<f64>,
    #[serde(default)]
    pub custom_rules: Option<Vec<CustomRule>>,
}

fn default_amount_field() -> String {
    "amount".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    /// Path to the local SQLite database.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Cloud endpoint for syncing events. Defaults to https://api.estoppl.ai/v1/events
    /// when cloud_api_key is set. Override for local dev (e.g. http://localhost:8080/v1/events).
    #[serde(default)]
    pub cloud_endpoint: Option<String>,
    /// API key for cloud sync. When set, the proxy automatically syncs events to the cloud.
    #[serde(default)]
    pub cloud_api_key: Option<String>,
    /// Organization ID. Required for policy sync (remote kill switch) and human review.
    #[serde(default)]
    pub org_id: Option<String>,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            cloud_endpoint: None,
            cloud_api_key: None,
            org_id: None,
        }
    }
}

const DEFAULT_CLOUD_ENDPOINT: &str = "https://api.estoppl.ai/v1/events";

impl LedgerConfig {
    /// Returns the cloud endpoint, defaulting to https://api.estoppl.ai/v1/events
    /// when cloud_api_key is set but cloud_endpoint is not.
    pub fn effective_cloud_endpoint(&self) -> Option<&str> {
        match &self.cloud_endpoint {
            Some(ep) if !ep.is_empty() => Some(ep.as_str()),
            _ if self.cloud_api_key.is_some() => Some(DEFAULT_CLOUD_ENDPOINT),
            _ => None,
        }
    }
}

fn default_db_path() -> PathBuf {
    PathBuf::from(".estoppl/events.db")
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let mut config: Self = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        // Resolve relative db_path against the config file's directory.
        if config.ledger.db_path.is_relative()
            && let Some(config_dir) = path
                .canonicalize()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            config.ledger.db_path = config_dir.join(&config.ledger.db_path);
        }

        Ok(config)
    }

    /// Generate a default config file.
    pub fn generate_default(agent_id: &str) -> Self {
        Self {
            agent: AgentConfig {
                id: agent_id.to_string(),
                version: "0.1.0".to_string(),
                authorized_by: None,
            },
            rules: RulesConfig {
                allow_tools: vec![],
                block_tools: vec![],
                human_review_tools: vec!["wire_transfer".into(), "execute_trade".into()],
                max_amount_usd: Some(50_000.0),
                amount_field: "amount".to_string(),
                rate_limit_per_minute: None,
                rate_limit_tools: std::collections::HashMap::new(),
                redact_fields: vec![],
                human_review_above_usd: None,
                agent_rules: std::collections::HashMap::new(),
                custom_rules: vec![],
                fail_mode: FailMode::Closed,
            },
            ledger: LedgerConfig::default(),
        }
    }
}
