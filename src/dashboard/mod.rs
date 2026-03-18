use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use crate::ledger::LocalLedger;

const INDEX_HTML: &str = include_str!("static/index.html");

struct DashboardState {
    db_path: PathBuf,
}

/// Open a fresh connection per request (sees WAL commits from concurrent proxy).
fn open_ledger(state: &DashboardState) -> Result<LocalLedger, (StatusCode, String)> {
    LocalLedger::open(&state.db_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Serialize)]
struct StatsResponse {
    summary: crate::ledger::ReportStats,
    latency: crate::ledger::LatencyStats,
}

async fn api_stats(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let ledger = match open_ledger(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };

    let summary = match ledger.summary_stats() {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let latency = match ledger.latency_percentiles() {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Json(StatsResponse { summary, latency }).into_response()
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<u32>,
    tool: Option<String>,
    decision: Option<String>,
    since: Option<String>,
}

async fn api_events(
    State(state): State<Arc<DashboardState>>,
    Query(params): Query<EventsQuery>,
) -> impl IntoResponse {
    let ledger = match open_ledger(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };

    let events = match ledger.query_events_filtered(
        Some(params.limit.unwrap_or(100)),
        None,
        params.tool.as_deref(),
        params.decision.as_deref(),
        params.since.as_deref(),
    ) {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Json(events).into_response()
}

async fn api_tools(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let ledger = match open_ledger(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };

    match ledger.tool_stats() {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct VerifyResponse {
    total: usize,
    intact: bool,
    issues: Vec<String>,
}

async fn api_verify(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let ledger = match open_ledger(&state) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };

    match ledger.verify_chain() {
        Ok((total, issues)) => Json(VerifyResponse {
            total,
            intact: issues.is_empty(),
            issues,
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn run_dashboard(port: u16, db_path: PathBuf) -> Result<()> {
    let state = Arc::new(DashboardState { db_path });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/stats", get(api_stats))
        .route("/api/events", get(api_events))
        .route("/api/tools", get(api_tools))
        .route("/api/verify", get(api_verify))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("Dashboard running at http://{}", addr);
    println!("Press Ctrl+C to stop.");

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_html_is_embedded() {
        assert!(!INDEX_HTML.is_empty());
        assert!(INDEX_HTML.contains("Estoppl Dashboard"));
        assert!(INDEX_HTML.contains("/api/stats"));
        assert!(INDEX_HTML.contains("/api/events"));
    }
}
