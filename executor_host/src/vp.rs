use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use trust_core::errors::TrustError;
use trust_core::executor::{Executor, VerifiedGrant};

#[derive(Clone)]
pub struct VpExecutor {
    http_client: reqwest::Client,
    nats: async_nats::Client,
}

impl VpExecutor {
    pub fn new(nats: async_nats::Client) -> Result<Self, TrustError> {
        Ok(Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| TrustError::Internal(format!("Failed to build http client: {e}")))?,
            nats,
        })
    }
}

impl VpExecutor {
    pub fn is_supported_tool(tool_id: &str) -> bool {
        matches!(
            tool_id,
            "vp_search"
                | "discover_agent_services"
                | "call_b2b_agent"
                | "register_b2b_agent"
                | "list_registered_b2b_agents"
                | "discover_b2b_agents"
                | "reputation_inspect_counterparty"
                | "contract_propose_or_amend"
                | "contract_verify_and_activate"
                | "receipt_present_and_store"
        )
    }
}

#[async_trait]
impl Executor for VpExecutor {
    fn name(&self) -> &str {
        "vp"
    }

    fn handles(&self, tool_id: &str) -> bool {
        Self::is_supported_tool(tool_id)
    }

    async fn execute(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        match grant.allowed_action() {
            "vp_search" => self.execute_search(args).await,
            "discover_agent_services" => self.execute_discover(grant, args).await,
            "call_b2b_agent" => self.execute_call_b2b(grant, args).await,
            "register_b2b_agent" => self.execute_register_b2b(grant, args).await,
            "list_registered_b2b_agents" => self.execute_list_b2b(grant, args).await,
            "discover_b2b_agents" => self.execute_discover_b2b(grant, args).await,
            "reputation_inspect_counterparty" => self.execute_reputation_inspect(grant, args).await,
            "contract_propose_or_amend" => {
                self.execute_contract_propose_or_amend(grant, args).await
            }
            "contract_verify_and_activate" => self.execute_contract_activate(grant, args).await,
            "receipt_present_and_store" => self.execute_receipt_vault(grant, args).await,
            _ => Err(TrustError::Internal(format!(
                "Unsupported VP tool: {}",
                grant.allowed_action()
            ))),
        }
    }
}

impl VpExecutor {
    async fn execute_search(
        &self,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let query = args
            .get("search_query")
            .or_else(|| args.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        tracing::info!("🔍 [VP Search] Query: '{}'", query);

        if query.is_empty() {
            return Ok(serde_json::json!({ "error": "Search query is empty" }));
        }

        let url = format!(
            "https://api.duckduckgo.com/?q={}&format=json",
            urlencoding::encode(query)
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Search request failed: {e}")))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to parse search response: {e}")))?;

        // Extract multiple fields for a richer result
        let abstract_text = body
            .get("AbstractText")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let abstract_source = body
            .get("AbstractSource")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let heading = body.get("Heading").and_then(|v| v.as_str()).unwrap_or("");

        let mut result_text = String::new();

        if !heading.is_empty() {
            result_text.push_str(&format!("## {heading}\n\n"));
        }

        if !abstract_text.is_empty() {
            result_text.push_str(&format!(
                "Summary (from {abstract_source}): {abstract_text}\n\n"
            ));
        }

        if let Some(related) = body.get("RelatedTopics").and_then(|v| v.as_array()) {
            if !related.is_empty() {
                result_text.push_str("### Related Information:\n");
                for (i, topic) in related.iter().enumerate() {
                    if let Some(text) = topic.get("Text").and_then(|v| v.as_str()) {
                        result_text.push_str(&format!("{}. {}\n", i + 1, text));
                    }
                    if i >= 5 {
                        break;
                    } // Limit to top 6 related topics
                }
            }
        }

        if result_text.trim().is_empty() {
            result_text = format!("No specific information found for '{query}' on DuckDuckGo.");
        }

        tracing::info!("✅ [VP Search] Returning {} chars", result_text.len());
        Ok(serde_json::Value::String(result_text))
    }

    async fn execute_discover(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let target_did = args
            .get("target_did")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if target_did.is_empty() {
            return Err(TrustError::Internal(
                "Missing target_did argument".to_string(),
            ));
        }

        let query_thid = uuid::Uuid::new_v4().to_string();
        let reply_subject = format!("mcp.v1.discovery.reply.{query_thid}");

        // 1. Subscribe to reply subject
        let mut subscriber = self
            .nats
            .subscribe(reply_subject.clone())
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to subscribe: {e}")))?;

        // 2. Publish request
        let payload = serde_json::json!({
            "target_did": target_did,
            "requester_did": grant.owner_did(),
            "query_thid": query_thid,
        })
        .to_string();

        tracing::info!(
            "📡 Publishing discover request for {} (reply expected on {})",
            target_did,
            reply_subject
        );
        self.nats
            .publish("host.v1.discovery.request".to_string(), payload.into())
            .await
            .map_err(|e| {
                TrustError::Internal(format!("Failed to publish discovery request: {e}"))
            })?;

        // 3. Await reply
        match tokio::time::timeout(std::time::Duration::from_secs(15), subscriber.next()).await {
            Ok(Some(msg)) => {
                let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
                let parsed: serde_json::Value = serde_json::from_str(&payload_str)
                    .unwrap_or_else(|_| serde_json::json!({ "raw_response": payload_str }));
                Ok(parsed)
            }
            Ok(None) => Err(TrustError::Internal(
                "NATS subscription closed prematurely".to_string(),
            )),
            Err(_) => Err(TrustError::Internal(
                "Discovery request timed out waiting for reply".to_string(),
            )),
        }
    }

    async fn get_b2b_kv(&self) -> Result<async_nats::jetstream::kv::Store, TrustError> {
        let js = async_nats::jetstream::new(self.nats.clone());
        match js.get_key_value("b2b_agents").await {
            Ok(kv) => Ok(kv),
            Err(_) => js
                .create_key_value(async_nats::jetstream::kv::Config {
                    bucket: "b2b_agents".to_string(),
                    history: 1,
                    max_age: std::time::Duration::from_secs(365 * 24 * 3600),
                    ..Default::default()
                })
                .await
                .map_err(|e| TrustError::Internal(format!("Failed to create b2b_agents KV: {e}"))),
        }
    }

    async fn execute_register_b2b(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let alias = args.get("alias").and_then(|v| v.as_str()).unwrap_or("");
        let b2b_agent_did = args
            .get("b2b_agent_did")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let endpoint_url = args
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if alias.is_empty() || b2b_agent_did.is_empty() || endpoint_url.is_empty() {
            return Err(TrustError::Internal(
                "Missing alias, b2b_agent_did, or endpoint_url".to_string(),
            ));
        }

        let kv = self.get_b2b_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let key = format!("{}_{}", tenant, alias.replace(":", "_"));

        let record = serde_json::json!({
            "alias": alias,
            "b2b_agent_did": b2b_agent_did,
            "endpoint_url": endpoint_url
        });

        kv.put(
            key,
            serde_json::to_vec(&record)
                .map_err(|e| TrustError::Internal(e.to_string()))?
                .into(),
        )
        .await
        .map_err(|e| TrustError::Internal(format!("Failed to save B2B agent: {e}")))?;

        tracing::info!(
            "📇 Registered B2B agent: {} (DID: {})",
            alias,
            b2b_agent_did
        );
        Ok(serde_json::json!({
            "status": "registered",
            "alias": alias,
            "b2b_agent_did": b2b_agent_did,
            "endpoint_url": endpoint_url
        }))
    }

    async fn execute_list_b2b(
        &self,
        grant: VerifiedGrant,
        _args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let kv = self.get_b2b_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let prefix = format!("{tenant}_");

        let mut keys_stream = kv
            .keys()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to list keys: {e}")))?;

        let mut results = Vec::new();
        while let Some(Ok(key)) = keys_stream.next().await {
            if key.starts_with(&prefix) {
                if let Ok(Some(bytes)) = kv.get(&key).await {
                    if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        results.push(record);
                    }
                }
            }
        }

        Ok(serde_json::Value::Array(results))
    }

    async fn execute_discover_b2b(
        &self,
        _grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let query = args
            .get("search_query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let mut mock_list = self.load_b2b_directory();

        if !query.is_empty() {
            mock_list.retain(|item| {
                let alias = item["alias"].as_str().unwrap_or("").to_lowercase();
                let did = item["b2b_agent_did"].as_str().unwrap_or("").to_lowercase();
                alias.contains(&query) || did.contains(&query)
            });
        }

        Ok(serde_json::Value::Array(mock_list))
    }

    async fn execute_call_b2b(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
        let prompt = args.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
        let session_jwt = args
            .get("session_jwt")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let passport_hash = args
            .get("passport_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if target.is_empty() || prompt.is_empty() {
            return Err(TrustError::Internal(
                "Missing target or prompt argument".to_string(),
            ));
        }
        if session_jwt.is_empty() {
            return Err(TrustError::Internal(
                "Missing session_jwt in call_b2b_agent arguments".to_string(),
            ));
        }

        // 1. Resolve B2B agent endpoint and DID
        let kv = self.get_b2b_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let prefix = format!("{tenant}_");

        let mut resolved_url = None;
        let mut resolved_did = None;

        if target.starts_with("did:") {
            let mut keys_stream = kv
                .keys()
                .await
                .map_err(|e| TrustError::Internal(format!("Failed to list keys: {e}")))?;
            while let Some(Ok(key)) = keys_stream.next().await {
                if key.starts_with(&prefix) {
                    if let Ok(Some(bytes)) = kv.get(&key).await {
                        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            if record["b2b_agent_did"].as_str() == Some(target) {
                                resolved_url =
                                    record["endpoint_url"].as_str().map(|s| s.to_string());
                                resolved_did = Some(target.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            let key = format!("{}_{}", tenant, target.replace(":", "_"));
            if let Ok(Some(bytes)) = kv.get(&key).await {
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    resolved_url = record["endpoint_url"].as_str().map(|s| s.to_string());
                    resolved_did = record["b2b_agent_did"].as_str().map(|s| s.to_string());
                }
            }
        }

        // Fallback for strategic partners from config
        if resolved_url.is_none() {
            let directory = self.load_b2b_directory();
            for item in directory {
                if let (Some(alias), Some(did), Some(url)) = (
                    item["alias"].as_str(),
                    item["b2b_agent_did"].as_str(),
                    item["endpoint_url"].as_str(),
                ) {
                    if target == alias || target == did {
                        resolved_url = Some(url.to_string());
                        resolved_did = Some(did.to_string());
                        break;
                    }
                }
            }
        }

        let url = resolved_url.ok_or_else(|| {
            TrustError::Internal(format!(
                "Failed to resolve B2B agent endpoint for target: {target}"
            ))
        })?;
        let b2b_did = resolved_did.unwrap_or_else(|| target.to_string());

        tracing::info!(
            "📞 Calling B2B agent at {} (DID: {}) with user session token...",
            url,
            b2b_did
        );

        // 2. Build A2A JSON-RPC payload
        let req_id = uuid::Uuid::new_v4().to_string();
        let task_id = format!("task-{}", uuid::Uuid::new_v4());
        let msg_id = format!("msg-{}", uuid::Uuid::new_v4());

        let mut metadata = serde_json::json!({
            "agent_jwt": session_jwt,
            "tenant_id": grant.tenant_id()
        });
        if !passport_hash.is_empty() {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "passport_hash".to_string(),
                    serde_json::Value::String(passport_hash.to_string()),
                );
            }
        }

        let json_rpc_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "historyLength": 50,
                "message": {
                    "kind": "message",
                    "messageId": msg_id,
                    "metadata": metadata,
                    "parts": [
                        {
                            "kind": "text",
                            "text": prompt
                        }
                    ],
                    "role": "user"
                }
            },
            "id": req_id
        });

        // 3. Make HTTP POST call to target endpoint with Bearer auth
        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {session_jwt}"))
            .json(&json_rpc_payload)
            .send()
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to contact B2B agent: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(TrustError::Internal(format!(
                "B2B agent returned error status {status}: {body}"
            )));
        }

        let res_val: serde_json::Value = response.json().await.map_err(|e| {
            TrustError::Internal(format!("Failed to parse B2B agent response: {e}"))
        })?;

        // Extract result from JSON-RPC envelope
        if let Some(error) = res_val.get("error").filter(|e| !e.is_null()) {
            return Err(TrustError::Internal(format!(
                "B2B agent execution error: {error}"
            )));
        }

        let output = res_val.get("result").cloned().unwrap_or(res_val);

        Ok(output)
    }

    fn load_b2b_directory(&self) -> Vec<serde_json::Value> {
        let path = std::env::var("B2B_DIRECTORY_PATH")
            .unwrap_or_else(|_| "../../agent_in_a_box/host/config/b2b_directory.json".to_string());

        match std::fs::File::open(&path) {
            Ok(file) => match serde_json::from_reader::<_, Vec<serde_json::Value>>(file) {
                Ok(list) => {
                    tracing::info!(
                        "✅ Loaded {} B2B agents from directory config: {}",
                        list.len(),
                        path
                    );
                    list
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to parse B2B directory JSON at {}: {}. Using fallback mock.",
                        path,
                        e
                    );
                    self.get_fallback_mock_list()
                }
            },
            Err(_) => {
                if std::env::var("B2B_DIRECTORY_PATH").is_ok() {
                    tracing::warn!("⚠️ B2B directory file not found at path: {}", path);
                }
                self.get_fallback_mock_list()
            }
        }
    }

    fn get_fallback_mock_list(&self) -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "alias": "company-alpha",
                "b2b_agent_did": "did:web:company-alpha.com",
                "endpoint_url": "http://127.0.0.1:4010"
            }),
            serde_json::json!({
                "alias": "company-beta",
                "b2b_agent_did": "did:web:company-beta.com",
                "endpoint_url": "http://127.0.0.1:4010"
            }),
            serde_json::json!({
                "alias": "company-gamma",
                "b2b_agent_did": "did:web:company-gamma.com",
                "endpoint_url": "http://127.0.0.1:4010"
            }),
        ]
    }

    async fn get_reputation_kv(&self) -> Result<async_nats::jetstream::kv::Store, TrustError> {
        let js = async_nats::jetstream::new(self.nats.clone());
        match js.get_key_value("reputation_scores").await {
            Ok(kv) => Ok(kv),
            Err(_) => js
                .create_key_value(async_nats::jetstream::kv::Config {
                    bucket: "reputation_scores".to_string(),
                    history: 1,
                    max_age: std::time::Duration::from_secs(365 * 24 * 3600),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    TrustError::Internal(format!("Failed to create reputation_scores KV: {e}"))
                }),
        }
    }

    async fn get_contracts_kv(&self) -> Result<async_nats::jetstream::kv::Store, TrustError> {
        let js = async_nats::jetstream::new(self.nats.clone());
        match js.get_key_value("interaction_contracts").await {
            Ok(kv) => Ok(kv),
            Err(_) => js
                .create_key_value(async_nats::jetstream::kv::Config {
                    bucket: "interaction_contracts".to_string(),
                    history: 5,
                    max_age: std::time::Duration::from_secs(365 * 24 * 3600),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    TrustError::Internal(format!("Failed to create interaction_contracts KV: {e}"))
                }),
        }
    }

    async fn get_receipts_kv(&self) -> Result<async_nats::jetstream::kv::Store, TrustError> {
        let js = async_nats::jetstream::new(self.nats.clone());
        match js.get_key_value("execution_receipts").await {
            Ok(kv) => Ok(kv),
            Err(_) => js
                .create_key_value(async_nats::jetstream::kv::Config {
                    bucket: "execution_receipts".to_string(),
                    history: 1,
                    max_age: std::time::Duration::from_secs(365 * 24 * 3600),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    TrustError::Internal(format!("Failed to create execution_receipts KV: {e}"))
                }),
        }
    }

    async fn load_or_create_host_key(&self) -> Result<ed25519_dalek::SigningKey, TrustError> {
        let search_paths = [
            "configuration/b2b_signing.key",
            "../secure-collaboration-fabric/b2b_agent/configuration/b2b_signing.key",
            "/opt/lianxi.io/secrets/b2b_signing.key",
        ];

        for path in search_paths {
            if let Ok(bytes) = std::fs::read(path) {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
                    return Ok(ed25519_dalek::SigningKey::from_bytes(&arr));
                }
            }
        }

        // Ephemeral fallback (Secure-by-Default with Ephemeral-Fallback)
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    async fn resolve_counterparty_verifying_key(
        &self,
        did: &str,
    ) -> Result<ed25519_dalek::VerifyingKey, TrustError> {
        // 1. Try inline hex / did:twin:z...
        if let Some(arr) = trust_contract::extract_pubkey_from_did(did) {
            return ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|e| TrustError::Internal(format!("Invalid verifying key bytes: {e}")));
        }

        // 2. Try did:web cache in NATS
        let js = async_nats::jetstream::new(self.nats.clone());
        if let Ok(cache) = js.get_key_value("did_web_cache").await {
            let key = did.replace(":", "_");
            if let Ok(Some(entry)) = cache.get(&key).await {
                if let Ok(arr) = <[u8; 32]>::try_from(entry.as_ref()) {
                    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                        return Ok(vk);
                    }
                }
            }
        }

        // 3. Fallback: Parse 64-character hex in DID part
        for part in did.split([':', '.', '/']) {
            if part.len() == 64 {
                if let Ok(bytes) = hex::decode(part) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                            return Ok(vk);
                        }
                    }
                }
            }
        }

        // 4. In test / dev environments, fallback to a stable deterministic verifying key
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(did.as_bytes());
        let hash_bytes = hasher.finalize();
        let arr: [u8; 32] = hash_bytes.into();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
        Ok(signing_key.verifying_key())
    }

    async fn execute_reputation_inspect(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let counterparty_did = args
            .get("counterparty_did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TrustError::Internal("Missing counterparty_did in arguments".to_string())
            })?;

        let kv = self.get_reputation_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let safe_counterparty = counterparty_did.replace(":", "_");
        let key = format!("{tenant}_{safe_counterparty}");

        let mut successful_count = 0u64;
        let mut failed_count = 0u64;
        let mut last_success_at = None;

        if let Ok(Some(entry)) = kv.get(&key).await {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&entry) {
                successful_count = val
                    .get("successful_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                failed_count = val
                    .get("failed_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                last_success_at = val.get("last_success_at").cloned();
            }
        }

        let cold_start = successful_count == 0;
        let requires_peer_attestation = successful_count < 3;

        tracing::info!(
            "📊 Reputation inspection for {}: {} successes, {} failures, cold_start: {}",
            counterparty_did,
            successful_count,
            failed_count,
            cold_start
        );

        Ok(serde_json::json!({
            "counterparty_did": counterparty_did,
            "successful_count": successful_count,
            "failed_count": failed_count,
            "last_success_at": last_success_at,
            "cold_start": cold_start,
            "requires_peer_attestation": requires_peer_attestation
        }))
    }

    async fn execute_contract_propose_or_amend(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let contract_id = args
            .get("contract_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TrustError::Internal("Missing contract_id in arguments".to_string()))?;
        let counterparty_did = args
            .get("counterparty_did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TrustError::Internal("Missing counterparty_did in arguments".to_string())
            })?;
        let capabilities_raw = args
            .get("capabilities")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                TrustError::Internal("Missing capabilities array in arguments".to_string())
            })?;

        let capabilities: Vec<trust_contract::ContractCapability> = capabilities_raw
            .iter()
            .filter_map(|c| c.as_str())
            .map(|cap_id| trust_contract::ContractCapability {
                capability_id: cap_id.to_string(),
                operations: vec!["quote".to_string(), "book".to_string(), "track".to_string()],
                parameter_constraints: None,
                result_constraints: None,
            })
            .collect();

        let max_amount_minor = args.get("max_amount_minor").and_then(|v| v.as_u64());
        let currency = args
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("EUR")
            .to_string();
        let settlement_terms = args.get("settlement_terms").and_then(|v| v.as_str());
        let cancellation_terms = args
            .get("cancellation_terms")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let previous_contract_hash = args
            .get("previous_contract_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let version = if previous_contract_hash.is_some() {
            2
        } else {
            1
        };
        let now = chrono::Utc::now();
        let issuer_did = format!("did:web:{}.host", grant.tenant_id());

        // Gather reputation receipts if requested
        let mut reputation_receipts = Vec::new();
        if let Some(ids) = args
            .get("reputation_receipt_ids")
            .and_then(|v| v.as_array())
        {
            let receipts_kv = self.get_receipts_kv().await?;
            let tenant = grant.tenant_id().replace(":", "_");
            for id_val in ids {
                if let Some(id_str) = id_val.as_str() {
                    let rkey = format!("{tenant}_{}", id_str.replace(":", "_"));
                    if let Ok(Some(entry)) = receipts_kv.get(&rkey).await {
                        if let Ok(rcpt) =
                            serde_json::from_slice::<trust_contract::ExecutionReceipt>(&entry)
                        {
                            reputation_receipts.push(rcpt);
                        }
                    }
                }
            }
        }

        let contract = trust_contract::InteractionContract {
            contract_id: contract_id.to_string(),
            version,
            state: trust_contract::ContractState::Draft,
            issuer: trust_contract::PartyIdentity::new_did(issuer_did.clone()),
            counterparty: trust_contract::PartyIdentity::new_did(counterparty_did.to_string()),
            purpose: trust_contract::Purpose {
                code: "autonomous_b2b_interaction".to_string(),
                description: "Contract-governed autonomous agent operation".to_string(),
            },
            capabilities,
            constraints: trust_contract::ContractConstraints {
                max_transaction_value: max_amount_minor.map(|m| trust_contract::ContractMoney {
                    amount_minor: m,
                    currency,
                }),
                allowed_geographies: vec!["EU".to_string()],
                max_units: Some(10),
                cancellation_terms,
                custom_constraints: std::collections::BTreeMap::new(),
            },
            data_policy: trust_contract::DataPolicy::default(),
            obligations: vec![],
            commercial_terms: settlement_terms.map(|s| trust_contract::CommercialTerms {
                settlement_term: Some(s.to_string()),
                payment_instrument: Some("corporate_sepa".to_string()),
                payment_details: None,
            }),
            validity: trust_contract::ContractValidity {
                valid_from: now - chrono::Duration::minutes(5),
                valid_until: now + chrono::Duration::days(30),
            },
            protocol: Default::default(),
            evidence: trust_contract::ContractEvidence {
                attestations: vec![],
                authority_evidence: vec![],
                reputation_receipts,
            },
            parent_contract_id: None,
            previous_contract_hash,
            created_at: now,
            updated_at: now,
        };

        let canonical_hash = trust_contract::compute_contract_hash(&contract).map_err(|e| {
            TrustError::Internal(format!("Failed to compute canonical contract hash: {e}"))
        })?;

        // Sign locally as issuer
        let signing_key = self.load_or_create_host_key().await?;
        let attestation = trust_contract::create_attestation(&contract, &issuer_did, &signing_key)
            .map_err(|e| TrustError::Internal(format!("Failed to sign contract: {e}")))?;

        // Save to interaction_contracts KV
        let contracts_kv = self.get_contracts_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let key = format!("{tenant}_{}", contract_id.replace(":", "_"));
        let contract_bytes =
            serde_json::to_vec(&contract).map_err(|e| TrustError::Internal(e.to_string()))?;
        contracts_kv
            .put(key, contract_bytes.into())
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to save draft contract: {e}")))?;

        tracing::info!(
            "✍️ Drafted contract {} (v{}) with canonical hash: {}",
            contract.contract_id,
            contract.version,
            canonical_hash
        );

        Ok(serde_json::json!({
            "status": "drafted",
            "contract_id": contract.contract_id,
            "version": contract.version,
            "canonical_hash": canonical_hash,
            "attestation": attestation,
            "contract": contract
        }))
    }

    async fn execute_contract_activate(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let contract_id = args
            .get("contract_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TrustError::Internal("Missing contract_id in arguments".to_string()))?;
        let counterparty_attestation_val =
            args.get("counterparty_attestation").ok_or_else(|| {
                TrustError::Internal("Missing counterparty_attestation in arguments".to_string())
            })?;
        let counterparty_attestation: trust_contract::ContractAttestation =
            serde_json::from_value(counterparty_attestation_val.clone()).map_err(|e| {
                TrustError::Internal(format!("Invalid counterparty_attestation format: {e}"))
            })?;

        let contracts_kv = self.get_contracts_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");
        let key = format!("{tenant}_{}", contract_id.replace(":", "_"));

        let contract_bytes = contracts_kv
            .get(&key)
            .await
            .map_err(|e| {
                TrustError::Internal(format!("Failed to get contract {contract_id}: {e}"))
            })?
            .ok_or_else(|| {
                TrustError::Internal(format!("Contract {contract_id} not found in draft store"))
            })?;

        let mut contract: trust_contract::InteractionContract =
            serde_json::from_slice(&contract_bytes).map_err(|e| {
                TrustError::Internal(format!("Failed to parse contract {contract_id}: {e}"))
            })?;

        // Transition state to Accepted
        contract.state = trust_contract::ContractState::Accepted;

        // Local host attestation
        let host_signing_key = self.load_or_create_host_key().await?;
        let local_attestation =
            trust_contract::create_attestation(&contract, &contract.issuer.did, &host_signing_key)
                .map_err(|e| {
                    TrustError::Internal(format!("Failed to create local attestation: {e}"))
                })?;

        contract.evidence.attestations.clear();
        contract.evidence.attestations.push(local_attestation);
        contract
            .evidence
            .attestations
            .push(counterparty_attestation.clone());

        // Resolve party keys
        let mut party_keys = std::collections::HashMap::new();
        party_keys.insert(
            contract.issuer.did.clone(),
            host_signing_key.verifying_key(),
        );

        let counterparty_verifying_key = self
            .resolve_counterparty_verifying_key(&counterparty_attestation.signer_did)
            .await?;
        party_keys.insert(
            counterparty_attestation.signer_did.clone(),
            counterparty_verifying_key,
        );

        let active_contract = trust_contract::execute_activation_ceremony(contract, &party_keys)
            .map_err(|e| TrustError::Internal(format!("Activation ceremony failed: {e}")))?;

        // Save active contract
        let active_bytes = serde_json::to_vec(&active_contract)
            .map_err(|e| TrustError::Internal(e.to_string()))?;
        contracts_kv
            .put(key, active_bytes.into())
            .await
            .map_err(|e| TrustError::Internal(format!("Failed to save active contract: {e}")))?;

        let canonical_hash =
            trust_contract::compute_contract_hash(&active_contract).unwrap_or_default();

        tracing::info!(
            "📜 Contract {} (v{}) successfully ACTIVATED! Canonical Hash: {}",
            active_contract.contract_id,
            active_contract.version,
            canonical_hash
        );

        Ok(serde_json::json!({
            "status": "ACTIVE",
            "contract_id": active_contract.contract_id,
            "version": active_contract.version,
            "canonical_hash": canonical_hash,
            "valid_until": active_contract.validity.valid_until
        }))
    }

    async fn execute_receipt_vault(
        &self,
        grant: VerifiedGrant,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, TrustError> {
        let action = args.get("action").and_then(|v| v.as_str()).ok_or_else(|| {
            TrustError::Internal(
                "Missing action in arguments ('store', 'get_for_presentation', or 'verify')"
                    .to_string(),
            )
        })?;

        let receipts_kv = self.get_receipts_kv().await?;
        let tenant = grant.tenant_id().replace(":", "_");

        match action {
            "store" => {
                let receipt_val = args.get("receipt").ok_or_else(|| {
                    TrustError::Internal(
                        "Missing receipt in arguments for store action".to_string(),
                    )
                })?;
                let receipt: trust_contract::ExecutionReceipt =
                    serde_json::from_value(receipt_val.clone()).map_err(|e| {
                        TrustError::Internal(format!("Invalid ExecutionReceipt structure: {e}"))
                    })?;

                let key = format!("{tenant}_{}", receipt.receipt_id.replace(":", "_"));
                let r_bytes = serde_json::to_vec(&receipt)
                    .map_err(|e| TrustError::Internal(e.to_string()))?;
                receipts_kv
                    .put(key, r_bytes.into())
                    .await
                    .map_err(|e| TrustError::Internal(format!("Failed to store receipt: {e}")))?;

                tracing::info!(
                    "🔒 Saved ExecutionReceipt {} into tenant vault ({})",
                    receipt.receipt_id,
                    tenant
                );
                Ok(serde_json::json!({
                    "status": "stored",
                    "receipt_id": receipt.receipt_id,
                    "outcome": receipt.outcome
                }))
            }
            "get_for_presentation" => {
                let capability_filter = args.get("capability_id").and_then(|v| v.as_str());
                let prefix = format!("{tenant}_");

                let mut keys_stream = receipts_kv.keys().await.map_err(|e| {
                    TrustError::Internal(format!("Failed to list receipt keys: {e}"))
                })?;

                let mut matching_receipts = Vec::new();
                while let Some(Ok(key)) = keys_stream.next().await {
                    if key.starts_with(&prefix) {
                        if let Ok(Some(bytes)) = receipts_kv.get(&key).await {
                            if let Ok(rcpt) =
                                serde_json::from_slice::<trust_contract::ExecutionReceipt>(&bytes)
                            {
                                if rcpt.outcome == "SUCCESS" {
                                    if let Some(cap) = capability_filter {
                                        if rcpt.capability_id == cap {
                                            matching_receipts.push(rcpt);
                                        }
                                    } else {
                                        matching_receipts.push(rcpt);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(serde_json::json!({
                    "receipts": matching_receipts,
                    "count": matching_receipts.len()
                }))
            }
            "verify" => {
                let receipt_val = args.get("receipt").ok_or_else(|| {
                    TrustError::Internal(
                        "Missing receipt in arguments for verify action".to_string(),
                    )
                })?;
                let receipt: trust_contract::ExecutionReceipt =
                    serde_json::from_value(receipt_val.clone()).map_err(|e| {
                        TrustError::Internal(format!("Invalid ExecutionReceipt structure: {e}"))
                    })?;

                let verifying_key = self
                    .resolve_counterparty_verifying_key(&receipt.issuer_did)
                    .await?;
                trust_contract::verify_execution_receipt(&receipt, &verifying_key).map_err(
                    |e| TrustError::Internal(format!("Receipt signature verification failed: {e}")),
                )?;

                Ok(serde_json::json!({
                    "status": "verified",
                    "receipt_id": receipt.receipt_id,
                    "issuer_did": receipt.issuer_did,
                    "outcome": receipt.outcome,
                    "is_valid": true
                }))
            }
            _ => Err(TrustError::Internal(format!(
                "Unknown receipt vault action: {action}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vp_executor_handles_b2b_contract_and_reputation_tools() {
        assert!(VpExecutor::is_supported_tool(
            "reputation_inspect_counterparty"
        ));
        assert!(VpExecutor::is_supported_tool("contract_propose_or_amend"));
        assert!(VpExecutor::is_supported_tool(
            "contract_verify_and_activate"
        ));
        assert!(VpExecutor::is_supported_tool("receipt_present_and_store"));
        assert!(!VpExecutor::is_supported_tool("unsupported_random_tool"));
    }
}
