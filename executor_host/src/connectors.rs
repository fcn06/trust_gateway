use crate::nats_token_broker::NatsTokenBroker;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use trust_core::errors::TrustError;
use trust_core::executor::{Executor, VerifiedGrant};
use trust_core::oauth_token::TokenBroker;

pub struct ConnectorExecutor {
    pub nats: async_nats::Client,
    pub token_broker: NatsTokenBroker,
    pub http_client: reqwest::Client,
}

impl ConnectorExecutor {
    pub async fn new(nats: async_nats::Client) -> Result<Self> {
        let js = async_nats::jetstream::new(nats.clone());
        let kv = match js
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: "oauth_tokens".to_string(),
                description: "Tenant OAuth tokens".to_string(),
                history: 3,
                ..Default::default()
            })
            .await
        {
            Ok(store) => store,
            Err(e) => {
                tracing::warn!(
                    "⚠️ oauth_tokens KV bucket creation failed, trying to bind to existing: {}",
                    e
                );
                js.get_key_value("oauth_tokens").await?
            }
        };

        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let token_broker = NatsTokenBroker::new(kv, nats.clone(), http_client.clone());

        Ok(Self {
            nats,
            token_broker,
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
        trust_core::tool_registry::builtin_descriptors()
            .iter()
            .any(|d| {
                d.mcp_name == tool_id
                    && d.executor_profile == trust_core::tool_registry::ExecutorProfile::Connector
            })
    }

    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        match grant.allowed_action() {
            "google_calendar_list_events" => {
                self.execute_google_calendar_list(grant.tenant_id(), args)
                    .await
            }
            "google_calendar_create_event" => {
                self.execute_google_calendar_create(grant.tenant_id(), args)
                    .await
            }
            "stripe_list_payments" => {
                Ok(json!({ "error": "Stripe integration not yet connected" }))
            }
            "shopify_list_orders" => {
                Ok(json!({ "error": "Shopify integration not yet connected" }))
            }
            "box_shop_checkout" => self.execute_box_shop_checkout(&grant, args).await,
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
        let token = self
            .token_broker
            .get_valid_token(tenant_id, "google")
            .await
            .map_err(|e| TrustError::Internal(e.to_string()))?;

        let max_results = args["max_results"].as_u64().unwrap_or(10);
        let time_min = args["time_min"]
            .as_str()
            .unwrap_or(&chrono::Utc::now().to_rfc3339())
            .to_string();

        let resp = self
            .http_client
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
            .map_err(|e| TrustError::Internal(format!("Google API error: {e}")))?;

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to parse response: {e}")))?;

        Ok(data)
    }

    async fn execute_google_calendar_create(
        &self,
        tenant_id: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let token = self
            .token_broker
            .get_valid_token(tenant_id, "google")
            .await
            .map_err(|e| TrustError::Internal(e.to_string()))?;

        let start_dt = args["start_time"]
            .as_str()
            .or_else(|| args["start_datetime"].as_str())
            .or_else(|| args["start"].as_str())
            .or_else(|| args["start"]["dateTime"].as_str())
            .ok_or_else(|| {
                TrustError::Internal("Missing start_time/start_datetime/start".to_string())
            })?;

        let end_dt = args["end_time"]
            .as_str()
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

        let resp = self
            .http_client
            .post("https://www.googleapis.com/calendar/v3/calendars/primary/events")
            .bearer_auth(&token.access_token)
            .json(&event_body)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Google API error: {e}")))?;

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to parse response: {e}")))?;

        Ok(data)
    }

    async fn execute_box_shop_checkout(
        &self,
        grant: &VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let shop_url = std::env::var("BOX_DEMO_SHOP_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3003".to_string());
        let checkout_url = format!("{}/api/checkout", shop_url.trim_end_matches('/'));

        let mut payload = args.clone();
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("grant_id".to_string(), json!(grant.grant_id()));
            obj.insert("owner_did".to_string(), json!(grant.owner_did()));
            obj.insert("tenant_id".to_string(), json!(grant.tenant_id()));
            obj.insert("input_hash".to_string(), json!(grant.input_hash()));
            if !obj.contains_key("recipient_did") || obj["recipient_did"].is_null() {
                obj.insert("recipient_did".to_string(), json!(grant.owner_did()));
            }
        }

        let resp = self
            .http_client
            .post(&checkout_url)
            .header("X-Execution-Grant-Id", grant.grant_id())
            .header("X-Tenant-Id", grant.tenant_id())
            .header("X-Owner-Did", grant.owner_did())
            .json(&payload)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Box Demo Shop API error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(TrustError::Internal(format!(
                "Box Demo Shop checkout failed with status {status}: {err_text}"
            )));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to parse checkout response: {e}")))?;

        Ok(data)
    }
}
