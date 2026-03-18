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
}

fn default_amount_field() -> String {
    "amount".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    /// Path to the local SQLite database.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Cloud ledger endpoint (future use).
    #[serde(default)]
    pub cloud_endpoint: Option<String>,
    /// API key for cloud ledger (future use).
    #[serde(default)]
    pub cloud_api_key: Option<String>,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            cloud_endpoint: None,
            cloud_api_key: None,
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
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))
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
            },
            ledger: LedgerConfig::default(),
        }
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("Failed to serialize config")
    }
}
