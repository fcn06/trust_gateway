use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use trust_core::executor::{Executor, VerifiedGrant};
use trust_core::errors::TrustError;
use crate::token_store::TokenStore;

pub struct ConnectorExecutor {
    pub nats: async_nats::Client,
    pub token_store: TokenStore,
    pub http_client: reqwest::Client,
}

impl ConnectorExecutor {
    pub async fn new(nats: async_nats::Client) -> Result<Self> {
        let js = async_nats::jetstream::new(nats.clone());
        let token_store = TokenStore::new(js).await?;
        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            nats,
            token_store,
            http_client,
        })
    }
}

#[async_trait]
impl Executor for ConnectorExecutor {
    fn name(&self) -> &str {
        "connector"
    }

    fn handles(&self, tool_id: &str) -> bool {
        matches!(
            tool_id,
            "google_calendar_list_events"
                | "google_calendar_create_event"
                | "stripe_list_payments"
                | "shopify_list_orders"
        )
    }

    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        match grant.allowed_action() {
            "google_calendar_list_events" => {
                self.execute_google_calendar_list(grant.tenant_id(), args).await
            }
            "google_calendar_create_event" => {
                self.execute_google_calendar_create(grant.tenant_id(), args).await
            }
            "stripe_list_payments" => {
                Ok(json!({ "error": "Stripe integration not yet connected" }))
            }
            "shopify_list_orders" => {
                Ok(json!({ "error": "Shopify integration not yet connected" }))
            }
            _ => Err(TrustError::Internal(format!(
                "Unsupported connector tool: {}",
                grant.allowed_action()
            ))),
        }
    }
}

impl ConnectorExecutor {
    async fn execute_google_calendar_list(
        &self,
        tenant_id: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let token = self.token_store.get_token(tenant_id, "google").await
            .map_err(|e| TrustError::Internal(e.to_string()))?
            .ok_or_else(|| TrustError::Internal("Google Calendar not connected".to_string()))?;

        if !TokenStore::is_token_valid(&token) {
            return Err(TrustError::Internal("Google OAuth token expired".to_string()));
        }

        let max_results = args["max_results"].as_u64().unwrap_or(10);
        let time_min = args["time_min"].as_str().unwrap_or(&chrono::Utc::now().to_rfc3339()).to_string();

        let resp = self.http_client
            .get("https://www.googleapis.com/calendar/v3/calendars/primary/events")
            .bearer_auth(&token.access_token)
            .query(&[
                ("maxResults", max_results.to_string()),
                ("timeMin", time_min),
                ("singleEvents", "true".to_string()),
                ("orderBy", "startTime".to_string()),
            ])
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Google API error: {}", e)))?;

        let data: serde_json::Value = resp.json().await
            .map_err(|e| TrustError::Internal(format!("Failed to parse response: {}", e)))?;

        Ok(data)
    }

    async fn execute_google_calendar_create(
        &self,
        tenant_id: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let token = self.token_store.get_token(tenant_id, "google").await
            .map_err(|e| TrustError::Internal(e.to_string()))?
            .ok_or_else(|| TrustError::Internal("Google Calendar not connected".to_string()))?;

        if !TokenStore::is_token_valid(&token) {
            return Err(TrustError::Internal("Google OAuth token expired".to_string()));
        }

        let start_dt = args["start_time"].as_str()
            .or_else(|| args["start_datetime"].as_str())
            .or_else(|| args["start"].as_str())
            .or_else(|| args["start"]["dateTime"].as_str())
            .ok_or_else(|| TrustError::Internal("Missing start_time/start_datetime/start".to_string()))?;

        let end_dt = args["end_time"].as_str()
            .or_else(|| args["end_datetime"].as_str())
            .or_else(|| args["end"].as_str())
            .or_else(|| args["end"]["dateTime"].as_str())
            .ok_or_else(|| TrustError::Internal("Missing end_time/end_datetime/end".to_string()))?;

        let event_body = json!({
            "summary": args["summary"].as_str().unwrap_or("Untitled Event"),
            "description": args["description"].as_str().unwrap_or(""),
            "start": { "dateTime": start_dt },
            "end": { "dateTime": end_dt },
        });

        let resp = self.http_client
            .post("https://www.googleapis.com/calendar/v3/calendars/primary/events")
            .bearer_auth(&token.access_token)
            .json(&event_body)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Google API error: {}", e)))?;

        let data: serde_json::Value = resp.json().await
            .map_err(|e| TrustError::Internal(format!("Failed to parse response: {}", e)))?;

        Ok(data)
    }
}
