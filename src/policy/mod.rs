use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::config::{CustomRule, RuleAction, RuleCondition, RuleOperator, RulesConfig};
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
///
/// Rules are wrapped in `Arc<RwLock<>>` so the cloud policy syncer can
/// hot-reload them without restarting the proxy.
pub struct PolicyEngine {
    rules: Arc<RwLock<RulesConfig>>,
    rate_tracker: Mutex<RateTracker>,
}

impl PolicyEngine {
    pub fn new(rules: RulesConfig) -> Self {
        Self {
            rules: Arc::new(RwLock::new(rules)),
            rate_tracker: Mutex::new(RateTracker::new()),
        }
    }

    /// Replace the current rules with new ones from the cloud.
    pub fn update_rules(&self, new_rules: RulesConfig) {
        let mut rules = self.rules.write().unwrap();
        *rules = new_rules;
    }

    /// Evaluate a tool call against the configured rules.
    ///
    /// Evaluation order:
    /// 1. Block list — always blocked, even if also in allow list
    /// 2. Allow list — if non-empty, only listed tools are allowed (everything else is blocked)
    /// 3. Human review list (with optional amount threshold)
    /// 4. Amount threshold (block)
    /// 5. Rate limits
    /// 6. Default: allow
    ///
    /// Per-agent rules override org-wide defaults when the agent_id matches.
    pub fn evaluate(&self, tool_call: &ToolCallParams) -> PolicyDecision {
        self.evaluate_for_agent(tool_call, None)
    }

    /// Evaluate with agent-specific rule overrides.
    pub fn evaluate_for_agent(
        &self,
        tool_call: &ToolCallParams,
        agent_id: Option<&str>,
    ) -> PolicyDecision {
        let rules = self.rules.read().unwrap();

        // Resolve effective rules: agent-specific overrides > org-wide defaults
        let block_tools: &[String] = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.block_tools.as_deref())
            .unwrap_or(&rules.block_tools);

        let allow_tools: &[String] = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.allow_tools.as_deref())
            .unwrap_or(&rules.allow_tools);

        let human_review_tools: &[String] = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.human_review_tools.as_deref())
            .unwrap_or(&rules.human_review_tools);

        let max_amount = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.max_amount_usd)
            .or(rules.max_amount_usd);

        let human_review_above = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.human_review_above_usd)
            .or(rules.human_review_above_usd);

        // Check explicit block list first (highest priority).
        if block_tools.iter().any(|t| tool_matches(&tool_call.name, t)) {
            return PolicyDecision::Block {
                rule: format!("block_tools:{}", tool_call.name),
            };
        }

        // Check allow list — if non-empty, only listed tools pass through.
        if !allow_tools.is_empty() && !allow_tools.iter().any(|t| tool_matches(&tool_call.name, t))
        {
            return PolicyDecision::Block {
                rule: format!("allow_tools:not_listed:{}", tool_call.name),
            };
        }

        // Check human review list.
        if human_review_tools
            .iter()
            .any(|t| tool_matches(&tool_call.name, t))
        {
            // If human_review_above_usd is set, only require review above that amount.
            if let Some(threshold) = human_review_above {
                if let Some(amount) = extract_amount(&tool_call.arguments, &rules.amount_field) {
                    if amount > threshold {
                        return PolicyDecision::HumanRequired {
                            rule: format!("human_review_above_usd:{}>{}", amount, threshold),
                        };
                    }
                    // Below threshold — skip human review, continue to other checks
                } else {
                    // No amount field — require review (safe default)
                    return PolicyDecision::HumanRequired {
                        rule: format!("human_review_tools:{}", tool_call.name),
                    };
                }
            } else {
                return PolicyDecision::HumanRequired {
                    rule: format!("human_review_tools:{}", tool_call.name),
                };
            }
        }

        // Check amount threshold (block).
        if let Some(max) = max_amount
            && let Some(amount) = extract_amount(&tool_call.arguments, &rules.amount_field)
            && amount > max
        {
            return PolicyDecision::Block {
                rule: format!("max_amount_usd:{}>{}", amount, max),
            };
        }

        // Check custom conditional rules.
        let custom_rules: &[CustomRule] = agent_id
            .and_then(|id| rules.agent_rules.get(id))
            .and_then(|ar| ar.custom_rules.as_deref())
            .unwrap_or(&rules.custom_rules);

        for rule in custom_rules {
            if tool_matches(&tool_call.name, &rule.tool)
                && evaluate_condition(&rule.condition, &tool_call.arguments)
            {
                match &rule.action {
                    RuleAction::Block => {
                        return PolicyDecision::Block {
                            rule: format!("custom:{}", rule.name),
                        };
                    }
                    RuleAction::HumanReview => {
                        return PolicyDecision::HumanRequired {
                            rule: format!("custom:{}", rule.name),
                        };
                    }
                    RuleAction::Allow => {
                        // Explicit allow — skip remaining rules.
                        return PolicyDecision::Allow;
                    }
                }
            }
        }

        // Drop the read lock before acquiring the mutex for rate limiting.
        drop(rules);

        // Check rate limits.
        if let Some(decision) = self.check_rate_limit(&tool_call.name) {
            return decision;
        }

        PolicyDecision::Allow
    }

    fn check_rate_limit(&self, tool_name: &str) -> Option<PolicyDecision> {
        let rules = self.rules.read().unwrap();
        // Determine the applicable limit: tool-specific override > global default.
        let limit = rules
            .rate_limit_tools
            .get(tool_name)
            .copied()
            .or(rules.rate_limit_per_minute);
        drop(rules);

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

/// Evaluate a custom rule condition against tool call arguments.
fn evaluate_condition(condition: &RuleCondition, args: &serde_json::Value) -> bool {
    // Extract the field value using dot notation.
    let field_value = {
        let mut current = args;
        for part in condition.field.split('.') {
            match current.get(part) {
                Some(v) => current = v,
                None => return false, // Field not found — condition doesn't match
            }
        }
        current.clone()
    };

    match &condition.operator {
        // Numeric comparisons
        RuleOperator::Gt => compare_numbers(&field_value, &condition.value, |a, b| a > b),
        RuleOperator::Lt => compare_numbers(&field_value, &condition.value, |a, b| a < b),
        RuleOperator::Gte => compare_numbers(&field_value, &condition.value, |a, b| a >= b),
        RuleOperator::Lte => compare_numbers(&field_value, &condition.value, |a, b| a <= b),

        // Equality (works for strings, numbers, booleans)
        RuleOperator::Eq => field_value == condition.value,
        RuleOperator::Neq => field_value != condition.value,

        // String containment
        RuleOperator::Contains => {
            let haystack = field_value.as_str().unwrap_or("");
            let needle = condition.value.as_str().unwrap_or("");
            haystack.contains(needle)
        }
        RuleOperator::NotContains => {
            let haystack = field_value.as_str().unwrap_or("");
            let needle = condition.value.as_str().unwrap_or("");
            !haystack.contains(needle)
        }
    }
}

/// Compare two JSON values as f64 using the given comparison function.
fn compare_numbers(
    a: &serde_json::Value,
    b: &serde_json::Value,
    cmp: fn(f64, f64) -> bool,
) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Match tool name with support for wildcards (e.g. "stripe.*" matches "stripe.create_payment").
fn tool_matches(tool_name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(prefix) = pattern.strip_suffix(".*") {
        tool_name.starts_with(prefix)
    } else if let Some(prefix) = pattern.strip_suffix("_*") {
        tool_name.starts_with(&format!("{}_", prefix))
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
            redact_fields: vec![],
            human_review_above_usd: None,
            agent_rules: HashMap::new(),
            custom_rules: vec![],
            fail_mode: crate::config::FailMode::Closed,
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
    fn test_allow_list_permits_listed_tools() {
        let mut rules = make_rules();
        rules.allow_tools = vec!["read_portfolio".into(), "get_balance".into()];
        rules.block_tools = vec![]; // clear block list for this test
        let engine = PolicyEngine::new(rules);

        let allowed = ToolCallParams {
            name: "read_portfolio".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(engine.evaluate(&allowed), PolicyDecision::Allow);

        let also_allowed = ToolCallParams {
            name: "get_balance".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(engine.evaluate(&also_allowed), PolicyDecision::Allow);
    }

    #[test]
    fn test_allow_list_blocks_unlisted_tools() {
        let mut rules = make_rules();
        rules.allow_tools = vec!["read_portfolio".into()];
        rules.block_tools = vec![];
        let engine = PolicyEngine::new(rules);

        let blocked = ToolCallParams {
            name: "send_payment".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            engine.evaluate(&blocked),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_allow_list_with_wildcards() {
        let mut rules = make_rules();
        rules.allow_tools = vec!["read.*".into()];
        rules.block_tools = vec![];
        let engine = PolicyEngine::new(rules);

        let allowed = ToolCallParams {
            name: "read.portfolio".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(engine.evaluate(&allowed), PolicyDecision::Allow);

        let blocked = ToolCallParams {
            name: "write.portfolio".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            engine.evaluate(&blocked),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_block_list_overrides_allow_list() {
        let mut rules = make_rules();
        rules.allow_tools = vec!["stripe.*".into()];
        rules.block_tools = vec!["stripe.delete_account".into()];
        let engine = PolicyEngine::new(rules);

        let allowed = ToolCallParams {
            name: "stripe.create_payment".into(),
            arguments: serde_json::json!({}),
        };
        assert_eq!(engine.evaluate(&allowed), PolicyDecision::Allow);

        let blocked = ToolCallParams {
            name: "stripe.delete_account".into(),
            arguments: serde_json::json!({}),
        };
        assert!(matches!(
            engine.evaluate(&blocked),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn test_empty_allow_list_allows_everything() {
        let rules = make_rules(); // allow_tools is empty by default
        let engine = PolicyEngine::new(rules);

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
