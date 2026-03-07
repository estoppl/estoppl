use crate::ledger::LocalLedger;
use anyhow::Result;

/// Generate an HTML compliance report from the local ledger.
pub fn generate_html_report(ledger: &LocalLedger) -> Result<String> {
    let stats = ledger.summary_stats()?;
    let (total_chain, broken_links) = ledger.verify_chain()?;
    let chain_status = if broken_links.is_empty() {
        "INTACT".to_string()
    } else {
        format!("BROKEN ({} issues)", broken_links.len())
    };
    let chain_class = if broken_links.is_empty() {
        "intact"
    } else {
        "broken"
    };

    let events = ledger.query_events(Some(100), None)?;

    let mut event_rows = String::new();
    for e in &events {
        let decision_class = match e.policy_decision.as_str() {
            "ALLOW" => "allow",
            "BLOCK" => "block",
            "HUMAN_REQUIRED" => "human",
            _ => "",
        };
        event_rows.push_str(&format!(
            r#"<tr>
                <td class="mono">{}</td>
                <td>{}</td>
                <td>{}</td>
                <td><span class="badge {}">{}</span></td>
                <td>{}</td>
                <td>{}ms</td>
            </tr>"#,
            &e.event_id[..8],
            html_escape(&e.tool_name),
            &e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            decision_class,
            e.policy_decision,
            html_escape(&e.policy_rule),
            e.latency_ms,
        ));
    }

    let broken_html = if broken_links.is_empty() {
        String::new()
    } else {
        let items: String = broken_links
            .iter()
            .map(|b| format!("<li>{}</li>", html_escape(b)))
            .collect();
        format!(
            r#"<div class="warning"><h3>Chain Integrity Issues</h3><ul>{}</ul></div>"#,
            items
        )
    };

    let report_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    Ok(format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Estoppl Agent Action Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8f9fa; color: #1a1a2e; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .header {{ background: #1a1a2e; color: white; padding: 2rem; border-radius: 8px 8px 0 0; }}
  .header h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .header .subtitle {{ color: #a0a0b0; font-size: 0.9rem; }}
  .disclaimer {{ background: #fff3cd; border: 1px solid #ffc107; padding: 1rem; font-size: 0.85rem; color: #664d03; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; padding: 1.5rem; background: white; }}
  .stat {{ text-align: center; }}
  .stat .value {{ font-size: 2rem; font-weight: 700; color: #1a1a2e; }}
  .stat .label {{ font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }}
  .chain-status {{ padding: 1rem 1.5rem; background: white; border-top: 1px solid #eee; }}
  .chain-status .intact {{ color: #198754; font-weight: 600; }}
  .chain-status .broken {{ color: #dc3545; font-weight: 600; }}
  .warning {{ background: #f8d7da; border: 1px solid #f5c2c7; padding: 1rem; margin: 1rem 1.5rem; border-radius: 4px; color: #842029; }}
  table {{ width: 100%; border-collapse: collapse; background: white; }}
  th {{ background: #f1f3f5; text-align: left; padding: 0.75rem 1rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #666; }}
  td {{ padding: 0.6rem 1rem; border-top: 1px solid #eee; font-size: 0.85rem; }}
  .mono {{ font-family: 'SF Mono', Monaco, monospace; font-size: 0.8rem; }}
  .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }}
  .badge.allow {{ background: #d1e7dd; color: #0f5132; }}
  .badge.block {{ background: #f8d7da; color: #842029; }}
  .badge.human {{ background: #fff3cd; color: #664d03; }}
  .section {{ margin-top: 1.5rem; }}
  .section h2 {{ padding: 1rem 1.5rem; background: white; border-bottom: 1px solid #eee; font-size: 1rem; }}
  .footer {{ padding: 1.5rem; background: white; border-radius: 0 0 8px 8px; border-top: 1px solid #eee; font-size: 0.8rem; color: #999; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Estoppl Agent Action Report</h1>
    <div class="subtitle">Generated {report_time}</div>
  </div>

  <div class="disclaimer">
    FOR VISIBILITY ONLY — NOT LEGALLY DEFENSIBLE. This report is generated from a local SQLite
    database and has not been written to immutable WORM storage or independently verified. It is
    intended for internal review and development use. For legally defensible audit records suitable
    for SEC, FINRA, or EU AI Act submissions, use the Estoppl cloud ledger.
  </div>

  <div class="stats">
    <div class="stat"><div class="value">{total}</div><div class="label">Total Events</div></div>
    <div class="stat"><div class="value">{allowed}</div><div class="label">Allowed</div></div>
    <div class="stat"><div class="value">{blocked}</div><div class="label">Blocked</div></div>
    <div class="stat"><div class="value">{human}</div><div class="label">Human Review</div></div>
    <div class="stat"><div class="value">{tools}</div><div class="label">Unique Tools</div></div>
    <div class="stat"><div class="value">{agents}</div><div class="label">Unique Agents</div></div>
  </div>

  <div class="chain-status">
    Hash Chain: <span class="{chain_class}">{chain_status}</span> — {chain_total} events verified
  </div>

  {broken_html}

  <div class="section">
    <h2>Event Log (latest {event_count})</h2>
    <table>
      <thead>
        <tr>
          <th>Event ID</th>
          <th>Tool</th>
          <th>Timestamp</th>
          <th>Decision</th>
          <th>Rule</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody>
        {event_rows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Estoppl v{version} — estoppl.ai — Agent action compliance for financial services
  </div>
</div>
</body>
</html>"##,
        report_time = report_time,
        total = stats.total_events,
        allowed = stats.allowed,
        blocked = stats.blocked,
        human = stats.human_required,
        tools = stats.unique_tools,
        agents = stats.unique_agents,
        chain_class = chain_class,
        chain_status = chain_status,
        chain_total = total_chain,
        broken_html = broken_html,
        event_count = events.len(),
        event_rows = event_rows,
        version = env!("CARGO_PKG_VERSION"),
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
