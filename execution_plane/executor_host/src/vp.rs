use anyhow::Result;
use async_trait::async_trait;
use trust_core::executor::{Executor, VerifiedGrant};
use trust_core::errors::TrustError;

#[derive(Clone)]
pub struct VpExecutor {
    http_client: reqwest::Client,
}

impl VpExecutor {
    pub fn new() -> Result<Self, TrustError> {
        Ok(Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| TrustError::Internal(format!("Failed to build http client: {}", e)))?,
        })
    }
}

#[async_trait]
impl Executor for VpExecutor {
    fn name(&self) -> &str {
        "vp"
    }

    fn handles(&self, tool_id: &str) -> bool {
        matches!(tool_id, "vp_search")
    }

    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        match grant.allowed_action() {
            "vp_search" => self.execute_search(args).await,
            _ => Err(TrustError::Internal(format!("Unsupported VP tool: {}", grant.allowed_action()))),
        }
    }
}

impl VpExecutor {
    async fn execute_search(&self, args: serde_json::Value) -> Result<serde_json::Value, TrustError> {
        let query = args.get("search_query")
            .or_else(|| args.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        tracing::info!("🔍 [VP Search] Query: '{}'", query);

        if query.is_empty() {
            return Ok(serde_json::json!({ "error": "Search query is empty" }));
        }

        let url = format!("https://api.duckduckgo.com/?q={}&format=json", urlencoding::encode(query));
        
        let response = self.http_client.get(&url)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Search request failed: {}", e)))?;

        let body: serde_json::Value = response.json()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to parse search response: {}", e)))?;

        // Extract multiple fields for a richer result
        let abstract_text = body.get("AbstractText").and_then(|v| v.as_str()).unwrap_or("");
        let abstract_source = body.get("AbstractSource").and_then(|v| v.as_str()).unwrap_or("");
        let heading = body.get("Heading").and_then(|v| v.as_str()).unwrap_or("");
        
        let mut result_text = String::new();

        if !heading.is_empty() {
            result_text.push_str(&format!("## {}\n\n", heading));
        }

        if !abstract_text.is_empty() {
            result_text.push_str(&format!("Summary (from {}): {}\n\n", abstract_source, abstract_text));
        }

        if let Some(related) = body.get("RelatedTopics").and_then(|v| v.as_array()) {
            if !related.is_empty() {
                result_text.push_str("### Related Information:\n");
                for (i, topic) in related.iter().enumerate() {
                    if let Some(text) = topic.get("Text").and_then(|v| v.as_str()) {
                        result_text.push_str(&format!("{}. {}\n", i + 1, text));
                    }
                    if i >= 5 { break; } // Limit to top 6 related topics
                }
            }
        }

        if result_text.trim().is_empty() {
            result_text = format!("No specific information found for '{}' on DuckDuckGo.", query);
        }

        tracing::info!("✅ [VP Search] Returning {} chars", result_text.len());
        Ok(serde_json::Value::String(result_text))
    }
}
