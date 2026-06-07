use anyhow::Result;
use async_nats::jetstream;
use async_nats::Message;
use futures::StreamExt;
use std::sync::Arc;
use trust_core::executor::{Executor, VerifiedGrant};
use trust_core::grant_validator::GrantValidator;
use trust_core::envelope::{TrustEnvelope, GrantedAction, ExecutionResult};
use chrono::Utc;

pub struct Runtime {
    pub nats: async_nats::Client,
    pub js: jetstream::Context,
    pub grant_validator: Arc<GrantValidator>,
    pub execution_results_kv: jetstream::kv::Store,
}

impl Runtime {
    pub async fn new(nats: async_nats::Client, grant_validator: Arc<GrantValidator>) -> Result<Self> {
        let js = jetstream::new(nats.clone());
        
        // Ensure execution_results KV bucket exists with a 7-day TTL
        // RULE 020: Use _ as separator for Jetstream keys (bucket name is fine with _)
        let execution_results_kv = match js.create_key_value(jetstream::kv::Config {
            bucket: "execution_results".to_string(),
            description: "Idempotent tool execution results".to_string(),
            history: 1,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days TTL (1.3)
            ..Default::default()
        }).await {
            Ok(store) => store,
            Err(e) => {
                tracing::warn!("⚠️ execution_results KV bucket creation failed, trying to bind to existing: {}", e);
                js.get_key_value("execution_results").await?
            }
        };

        Ok(Self {
            nats,
            js,
            grant_validator,
            execution_results_kv,
        })
    }

    pub async fn run(&self, executor: Arc<dyn Executor>, profile: &str) -> Result<()> {
        tracing::info!("🏃 Runtime starting for profile: {}", profile);
        
        // Ensure the EXEC_STREAM stream (capturing "exec.v1.>" subjects) is resolved or created
        let stream = match self.js.get_or_create_stream(async_nats::jetstream::stream::Config {
            name: "EXEC_STREAM".to_string(),
            subjects: vec!["exec.v1.>".to_string()],
            max_age: std::time::Duration::from_secs(24 * 3600), // 24 hours TTL
            ..Default::default()
        }).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("⚠️ EXEC_STREAM stream creation failed, trying to bind to existing: {}", e);
                self.js.get_stream("EXEC_STREAM").await?
            }
        };

        // Bind a durable JetStream pull consumer matching the executor's profile name (e.g. executor_{profile})
        // and filter by exec.v1.*.{profile}.invoke
        let consumer_name = format!("executor_{}", profile);
        let subject_filter = format!("exec.v1.*.{}.invoke", profile);

        let consumer = match stream.get_or_create_consumer(
            &consumer_name,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(consumer_name.clone()),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                filter_subject: subject_filter,
                ..Default::default()
            }
        ).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("⚠️ Consumer {} creation failed, trying to bind to existing: {}", consumer_name, e);
                stream.get_consumer(&consumer_name).await
                    .map_err(|err| anyhow::anyhow!("Failed to open existing consumer: {}", err))?
            }
        };

        tracing::info!("✅ Durable pull consumer bound: {}", consumer_name);

        loop {
            match consumer.messages().await {
                Ok(mut messages) => {
                    while let Some(msg_result) = messages.next().await {
                        match msg_result {
                            Ok(msg) => {
                                let runtime = self.clone_self();
                                let executor = executor.clone();
                                let profile = profile.to_string();
                                tokio::spawn(async move {
                                    if let Err(e) = runtime.handle_invocation_jetstream(msg, executor.as_ref(), &profile).await {
                                        tracing::error!("❌ Invocation failed: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("❌ Error reading message: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("❌ Pull consumer error: {} — retrying in 2s", e);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn handle_invocation_jetstream(
        &self,
        msg: async_nats::jetstream::Message,
        executor: &dyn Executor,
        profile: &str,
    ) -> Result<()> {
        let envelope: TrustEnvelope<GrantedAction> = serde_json::from_slice(&msg.payload)?;
        let action_id = &envelope.action_id;
        
        tracing::info!("📥 [{}] Handling JetStream invocation for tool: {}", action_id, envelope.payload.tool_id);

        // 1. Check idempotency cache
        if let Ok(Some(cached_entry)) = self.execution_results_kv.get(action_id).await {
            tracing::info!("♻️ [{}] Returning cached result (idempotency hit)", action_id);
            self.nats.publish(envelope.payload.reply_subject.clone(), cached_entry.into()).await?;
            let _ = msg.ack().await;
            return Ok(());
        }

        // 2. Verify grant
        let grant = match self.grant_validator.validate_bound(
            &envelope.payload.grant_jwt,
            &envelope.payload.tool_id,
            &envelope.payload.canonical_args,
        ).await {
            Ok(g) => g,
            Err(e) => {
                let err_res = self.create_error_envelope(&envelope, format!("Grant validation failed: {}", e), profile);
                self.nats.publish(envelope.payload.reply_subject.clone(), serde_json::to_vec(&err_res)?.into()).await?;
                let _ = msg.ack().await;
                return Ok(());
            }
        };

        // 3. Execute
        let start_time = std::time::Instant::now();
        let result = match executor.execute(VerifiedGrant::new(grant), envelope.payload.canonical_args.clone()).await {
            Ok(output) => {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                TrustEnvelope {
                    schema_version: 1,
                    tenant_id: envelope.tenant_id.clone(),
                    action_id: action_id.clone(),
                    trace_id: envelope.trace_id.clone(),
                    issued_at: Utc::now(),
                    auth_context: envelope.auth_context.clone(),
                    policy_fingerprint: envelope.policy_fingerprint.clone(),
                    idempotency_key: envelope.idempotency_key.clone(),
                    payload: ExecutionResult {
                        success: true,
                        output: Some(output),
                        error: None,
                        duration_ms,
                        executor_profile: profile.to_string(),
                    },
                }
            }
            Err(e) => {
                self.create_error_envelope(&envelope, format!("Execution failed: {}", e), profile)
            }
        };

        // 4. Persist and Publish
        let payload = serde_json::to_vec(&result)?;
        self.execution_results_kv.put(action_id, payload.clone().into()).await?;
        self.nats.publish(envelope.payload.reply_subject.clone(), payload.into()).await?;
        
        // 5. Acknowledge message
        let _ = msg.ack().await;

        tracing::info!("✅ [{}] JetStream Execution completed and result published", action_id);
        Ok(())
    }

    fn create_error_envelope(&self, req: &TrustEnvelope<GrantedAction>, error: String, profile: &str) -> TrustEnvelope<ExecutionResult> {
        TrustEnvelope {
            schema_version: 1,
            tenant_id: req.tenant_id.clone(),
            action_id: req.action_id.clone(),
            trace_id: req.trace_id.clone(),
            issued_at: Utc::now(),
            auth_context: req.auth_context.clone(),
            policy_fingerprint: req.policy_fingerprint.clone(),
            idempotency_key: req.idempotency_key.clone(),
            payload: ExecutionResult {
                success: false,
                output: None,
                error: Some(error),
                duration_ms: 0,
                executor_profile: profile.to_string(),
            },
        }
    }

    fn clone_self(&self) -> Self {
        Self {
            nats: self.nats.clone(),
            js: self.js.clone(),
            grant_validator: self.grant_validator.clone(),
            execution_results_kv: self.execution_results_kv.clone(),
        }
    }
}
