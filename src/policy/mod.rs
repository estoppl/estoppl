use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::RulesConfig;
use crate::mcp::ToolCallParams;

/// Result of a policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Block { rule: String },
    HumanRequired { rule: String },
}

impl PolicyDecision {
    pub fn as_str(&self) -> &str {
        match self {
            PolicyDecision::Allow => "ALLOW",
            PolicyDecision::Block { .. } => "BLOCK",
            PolicyDecision::HumanRequired { .. } => "HUMAN_REQUIRED",
        }
    }

    pub fn rule_name(&self) -> &str {
        match self {
            PolicyDecision::Allow => "",
            PolicyDecision::Block { rule } => rule,
            PolicyDecision::HumanRequired { rule } => rule,
        }
    }
}

/// Tracks call timestamps per tool for rate limiting.
struct RateTracker {
    /// tool_name -> list of call timestamps within the current window
    calls: HashMap<String, Vec<Instant>>,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }

    /// Record a call and return the count within the last 60 seconds.
    fn record_and_count(&mut self, tool_name: &str) -> u32 {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        let timestamps = self.calls.entry(tool_name.to_string()).or_default();
        // Prune old entries outside the window.
        timestamps.retain(|t| now.duration_since(*t) < window);
        timestamps.push(now);
        timestamps.len() as u32
    }
}

/// Rules-based policy engine with rate limiting.
pub struct PolicyEngine {
    rules: RulesConfig,
    rate_tracker: Mutex<RateTracker>,
}

impl PolicyEngine {
    pub fn new(rules: RulesConfig) -> Self {
        Self {
            rules,
            rate_tracker: Mutex::new(RateTracker::new()),
        }
    }

    /// Evaluate a tool call against the configured rules.
    pub fn evaluate(&self, tool_call: &ToolCallParams) -> PolicyDecision {
        // Check explicit block list first.
        if self
            .rules
            .block_tools
            .iter()
            .any(|t| tool_matches(&tool_call.name, t))
        {
            return PolicyDecision::Block {
                rule: format!("block_tools:{}", tool_call.name),
            };
        }

        // Check human review list.
        if self
            .rules
            .human_review_tools
            .iter()
            .any(|t| tool_matches(&tool_call.name, t))
        {
            return PolicyDecision::HumanRequired {
                rule: format!("human_review_tools:{}", tool_call.name),
            };
        }

        // Check amount threshold.
        if let Some(max_amount) = self.rules.max_amount_usd {
            if let Some(amount) = extract_amount(&tool_call.arguments, &self.rules.amount_field) {
                if amount > max_amount {
                    return PolicyDecision::Block {
                        rule: format!("max_amount_usd:{}>{}", amount, max_amount),
                    };
                }
            }
        }

        // Check rate limits.
        if let Some(decision) = self.check_rate_limit(&tool_call.name) {
            return decision;
        }

        PolicyDecision::Allow
    }

    fn check_rate_limit(&self, tool_name: &str) -> Option<PolicyDecision> {
        // Determine the applicable limit: tool-specific override > global default.
        let limit = self
            .rules
            .rate_limit_tools
            .get(tool_name)
            .copied()
            .or(self.rules.rate_limit_per_minute);

        let limit = match limit {
            Some(l) if l > 0 => l,
            _ => return None,
        };

        let mut tracker = self.rate_tracker.lock().unwrap();
        let count = tracker.record_and_count(tool_name);

        if count > limit {
            Some(PolicyDecision::Block {
                rule: format!("rate_limit:{}>{}/min", count, limit),
            })
        } else {
            None
        }
    }
}

/// Match tool name with support for wildcards (e.g. "stripe.*" matches "stripe.create_payment").
fn tool_matches(tool_name: &str, pattern: &str) -> bool {
    if pattern.ends_with(".*") {
        let prefix = &pattern[..pattern.len() - 2];
        tool_name.starts_with(prefix)
    } else {
        tool_name == pattern
    }
}

/// Extract a numeric amount from tool call arguments by field name.
/// Supports nested paths with dot notation (e.g. "payment.amount").
fn extract_amount(args: &serde_json::Value, field: &str) -> Option<f64> {
    let mut current = args;
    for part in field.split('.') {
        current = current.get(part)?;
    }
    current.as_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rules() -> RulesConfig {
        RulesConfig {
            allow_tools: vec![],
            block_tools: vec!["dangerous_tool".into(), "stripe.*".into()],
            human_review_tools: vec!["wire_transfer".into()],
            max_amount_usd: Some(50_000.0),
            amount_field: "amount".to_string(),
            rate_limit_per_minute: None,
            rate_limit_tools: HashMap::new(),
        }
    }

    #[test]
    fn test_block_exact_match() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "dangerous_tool".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(
            engine.evaluate(&call),
            PolicyDecision::Block {
                rule: "block_tools:dangerous_tool".into(),
            }
        );
    }

    #[test]
    fn test_block_wildcard() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "stripe.create_payment".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            engine.evaluate(&call),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_human_review() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "wire_transfer".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            engine.evaluate(&call),
            PolicyDecision::HumanRequired { .. }
        ));
    }

    #[test]
    fn test_amount_threshold_block() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "send_payment".into(),
            arguments: serde_json::json!({"amount": 75000.0}),
        };
        assert!(matches!(
            engine.evaluate(&call),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_amount_under_threshold() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "send_payment".into(),
            arguments: serde_json::json!({"amount": 100.0}),
        };
        assert_eq!(engine.evaluate(&call), PolicyDecision::Allow);
    }

    #[test]
    fn test_allow_by_default() {
        let engine = PolicyEngine::new(make_rules());
        let call = ToolCallParams {
            name: "read_portfolio".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(engine.evaluate(&call), PolicyDecision::Allow);
    }

    #[test]
    fn test_rate_limit_global() {
        let mut rules = make_rules();
        rules.rate_limit_per_minute = Some(3);
        let engine = PolicyEngine::new(rules);

        let call = ToolCallParams {
            name: "read_portfolio".into(),
            arguments: serde_json::json!({}),
        };

        // First 3 calls should be allowed.
        assert_eq!(engine.evaluate(&call), PolicyDecision::Allow);
        assert_eq!(engine.evaluate(&call), PolicyDecision::Allow);
        assert_eq!(engine.evaluate(&call), PolicyDecision::Allow);

        // 4th call should be blocked.
        assert!(matches!(
            engine.evaluate(&call),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_rate_limit_per_tool() {
        let mut rules = make_rules();
        rules.rate_limit_tools.insert("fast_tool".into(), 2);
        let engine = PolicyEngine::new(rules);

        let fast = ToolCallParams {
            name: "fast_tool".into(),
            arguments: serde_json::json!({}),
        };
        let other = ToolCallParams {
            name: "other_tool".into(),
            arguments: serde_json::json!({}),
        };

        assert_eq!(engine.evaluate(&fast), PolicyDecision::Allow);
        assert_eq!(engine.evaluate(&fast), PolicyDecision::Allow);
        assert!(matches!(
            engine.evaluate(&fast),
            PolicyDecision::Block { .. }
        ));

        // other_tool should still be allowed (no limit on it).
        assert_eq!(engine.evaluate(&other), PolicyDecision::Allow);
    }
}
