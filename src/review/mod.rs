use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::Duration;

/// Outcome of a human review decision.
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewOutcome {
    Approved,
    Denied,
    Expired,
}

/// Client for communicating with the cloud review API.
pub struct ReviewClient {
    http_client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Deserialize)]
struct ReviewStatusResponse {
    status: String,
}

impl ReviewClient {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            base_url,
            api_key,
        }
    }

    /// Submit a review request to the cloud.
    pub async fn submit_review(
        &self,
        event_id: &str,
        tool_name: &str,
        agent_id: &str,
        input_hash: &str,
        proxy_key_id: &str,
        timeout_sec: u64,
    ) -> Result<()> {
        let url = format!("{}/v1/review", self.base_url);

        let payload = serde_json::json!({
            "event_id": event_id,
            "tool_name": tool_name,
            "agent_id": agent_id,
            "input_hash": input_hash,
            "proxy_key_id": proxy_key_id,
            "timeout_sec": timeout_sec,
        });

        let mut req = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload);

        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let resp = req.send().await.context("Failed to submit review")?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Submit review failed: {}", body);
        }

        Ok(())
    }

    /// Poll the cloud for the current review status.
    pub async fn poll_status(&self, event_id: &str) -> Result<String> {
        let url = format!("{}/v1/review/{}", self.base_url, event_id);

        let mut req = self.http_client.get(&url);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let resp = req.send().await.context("Failed to poll review status")?;
        if !resp.status().is_success() {
            anyhow::bail!("Poll review failed: {}", resp.status());
        }

        let body: ReviewStatusResponse =
            resp.json().await.context("Failed to parse review status")?;
        Ok(body.status)
    }

    /// Block until the review is decided or times out.
    pub async fn wait_for_decision(
        &self,
        event_id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<ReviewOutcome> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Check if we've exceeded the deadline
            if tokio::time::Instant::now() >= deadline {
                // One final poll before giving up
                if let Ok(status) = self.poll_status(event_id).await {
                    match status.as_str() {
                        "approved" => return Ok(ReviewOutcome::Approved),
                        "denied" => return Ok(ReviewOutcome::Denied),
                        _ => {}
                    }
                }
                return Ok(ReviewOutcome::Expired);
            }

            match self.poll_status(event_id).await {
                Ok(status) => match status.as_str() {
                    "approved" => return Ok(ReviewOutcome::Approved),
                    "denied" => return Ok(ReviewOutcome::Denied),
                    "expired" => return Ok(ReviewOutcome::Expired),
                    _ => {} // "pending" or unknown — keep polling
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to poll review status, retrying...");
                }
            }

            // Sleep until next poll or deadline, whichever comes first
            let remaining = deadline - tokio::time::Instant::now();
            let wait = poll_interval.min(remaining);
            tokio::time::sleep(wait).await;
        }
    }
}
