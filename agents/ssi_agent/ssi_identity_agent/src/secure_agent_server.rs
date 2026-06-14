//! Secure Agent Server module.
//!
//! Provides the main server infrastructure for running A2A agents with
//! configurable authentication and optional discovery service integration.

use a2a_rs::adapter::{
    BearerTokenAuthenticator, DefaultRequestProcessor, HttpPushNotificationSender, HttpServer,
    InMemoryTaskStorage, NoopPushNotificationSender, SimpleAgentInfo,
};

use agent_core::business_logic::agent::Agent;
use agent_core::business_logic::services::DiscoveryService;
use agent_core::server::agent_handler::AgentHandler;
use agent_models::registry::registry_models::{AgentDefinition, AgentSkillDefinition};
use anyhow::Result;
use configuration::AgentConfig;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth_config::AuthConfig;
use crate::discovery::register_with_discovery_service;

/// A secure A2A agent server with configurable authentication and discovery.
pub struct SecureAgentServer<T: Agent> {
    config: AgentConfig,
    agent: T,
    auth: AuthConfig,
    discovery_service: Option<Arc<dyn DiscoveryService>>,
    nats_subject: Option<String>,
}

impl<T: Agent> SecureAgentServer<T> {
    /// Create a new SecureAgentServer instance.
    pub async fn new(
        agent_config: AgentConfig,
        agent: T,
        auth: AuthConfig,
        discovery_service: Option<Arc<dyn DiscoveryService>>,
        nats_subject: Option<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config: agent_config,
            agent,
            auth,
            discovery_service,
            nats_subject,
        })
    }

    /// Create in-memory storage without push notification.
    fn create_in_memory_storage(&self) -> InMemoryTaskStorage {
        tracing::info!("Using in-memory storage");
        let push_sender = NoopPushNotificationSender;
        InMemoryTaskStorage::with_push_sender(push_sender)
    }

    /// Create in-memory storage with push notification support.
    #[allow(dead_code)]
    fn create_in_memory_storage_with_push_notification(&self) -> InMemoryTaskStorage {
        tracing::info!("Using in-memory storage with push notification support");
        let push_sender = HttpPushNotificationSender::new()
            .with_timeout(30)
            .with_max_retries(3);
        InMemoryTaskStorage::with_push_sender(push_sender)
    }

    /// Start the HTTP server for the agent.
    pub async fn start_http(&self) -> Result<(), Box<dyn std::error::Error>> {
        let storage = self.create_in_memory_storage();
        let message_handler =
            AgentHandler::<T>::with_storage(self.agent.clone(), storage.clone());

        let agent_http_endpoint = format!("{}", self.config.agent_http_endpoint());
        let _agent_ws_endpoint = format!("{}", self.config.agent_ws_endpoint());

        let simple_agent_info =
            SimpleAgentInfo::new(self.config.agent_name(), agent_http_endpoint.clone());

        let processor =
            DefaultRequestProcessor::with_handler(message_handler, simple_agent_info);

        let agent_info = SimpleAgentInfo::new(self.config.agent_name(), agent_http_endpoint.clone())
            .with_description(self.config.agent_description())
            .with_documentation_url(
                self.config
                    .agent_doc_url()
                    .expect("NO DOC URL PROVIDED IN CONFIG"),
            )
            .with_streaming()
            .add_comprehensive_skill(
                self.config.agent_skill_id(),
                self.config.agent_skill_name(),
                Some(self.config.agent_skill_description()),
                Some(self.config.agent_tags()),
                Some(self.config.agent_examples()),
                Some(vec!["text".to_string(), "data".to_string()]),
                Some(vec!["text".to_string(), "data".to_string()]),
            );

        let agent_definition = AgentDefinition {
            id: Uuid::new_v4().to_string(),
            name: self.config.agent_name(),
            description: self.config.agent_description(),
            agent_endpoint: agent_http_endpoint.clone(),
            skills: vec![AgentSkillDefinition {
                name: self.config.agent_skill_name(),
                description: self.config.agent_skill_description(),
                parameters: serde_json::Value::Null,
                output: serde_json::Value::Null,
            }],
        };

        if let Some(true) = self.config.agent_discoverable() {
            register_with_discovery_service(&self.discovery_service, &agent_definition).await?;
        }

        // bind address is on format 0.0.0.0:0000
        let bind_address = agent_http_endpoint.clone().replace("http://", "");

        println!(
            "🌐 Starting HTTP a2a agent server {} on {}",
            self.config.agent_name(),
            self.config.agent_http_endpoint()
        );
        println!(
            "📋 Agent card: {}/agent-card",
            self.config.agent_http_endpoint(),
        );
        println!("🛠️  Skills: {}/skills", self.config.agent_http_endpoint());
        println!("💾 Storage: In-memory (non-persistent)");

        // Phase 5: Spawn NATS-first dispatch listener
        let nats_dispatch_enabled = std::env::var("NATS_DISPATCH_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true); // Default to NATS dispatch
            
        if nats_dispatch_enabled {
            let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
            let mut nats_options = if let Some(seed) = identity_context::load_secret("NATS_NKEY_SEED") {
                async_nats::ConnectOptions::with_nkey(seed.expose_secret().to_string())
            } else {
                async_nats::ConnectOptions::new()
            };
            nats_options = nats_options.request_timeout(Some(std::time::Duration::from_secs(30)));
            
            let local_http_endpoint = self.config.agent_http_endpoint().to_string();
            let nats_subject = self.nats_subject.clone();
            let agent_name = self.config.agent_name().to_lowercase();
            
            tokio::spawn(async move {
                // We use a separate local reqwest client
                let http_client = reqwest::Client::new();
                
                match async_nats::connect_with_options(&nats_url, nats_options).await {
                    Ok(nc) => {
                        println!("✅ {} connected to NATS at {}", agent_name, nats_url);
                        // Subscribe to tasks.send. Note: the tenant namespace wildcard allows this
                        // agent to receive tasks for any tenant it's authorized for.
                        let subject_str = nats_subject.as_deref().unwrap_or("a2a.v1.*.tasks.send");
                        let subject = subject_str.to_string();
                        match nc.subscribe(subject.clone()).await {
                            Ok(mut sub) => {
                                println!("📬 {} NATS listener subscribed to {}", agent_name, subject);
                                use futures_util::StreamExt;
                                while let Some(msg) = sub.next().await {
                                    if let Some(reply) = msg.reply.clone() {
                                        tracing::info!("📨 NATS listener received message on subject: {} (reply_to: {})", msg.subject, reply);
                                        let client = http_client.clone();
                                        let endpoint = local_http_endpoint.clone();
                                        let nc_clone = nc.clone();
                                        let payload = msg.payload.to_vec();
                                        
                                        tokio::spawn(async move {
                                            // Extract token from metadata (the host puts it there)
                                            let token = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
                                                json.get("params")
                                                    .and_then(|p| p.get("message"))
                                                    .and_then(|m| m.get("metadata"))
                                                    .and_then(|meta| meta.get("agent_jwt"))
                                                    .and_then(|jwt| jwt.as_str())
                                                    .unwrap_or("")
                                                    .to_string()
                                            } else {
                                                "".to_string()
                                            };

                                            let mut req = client.post(&endpoint)
                                                .header("Content-Type", "application/json")
                                                .body(payload);
                                                
                                            if !token.is_empty() {
                                                req = req.header("Authorization", format!("Bearer {}", token));
                                            }

                                            match req.send().await {
                                                Ok(res) => {
                                                    let status = res.status();
                                                    tracing::info!("🔄 Local proxy response status: {}", status);
                                                    match res.bytes().await {
                                                        Ok(bytes) => {
                                                            let _ = nc_clone.publish(reply, bytes.into()).await;
                                                        }
                                                        Err(e) => {
                                                            let err = serde_json::json!({"error": format!("Read error: {}", e)});
                                                            let _ = nc_clone.publish(reply, err.to_string().into()).await;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!("❌ Local HTTP proxy error: {}", e);
                                                    let err = serde_json::json!({"error": format!("Local HTTP proxy error: {}", e)});
                                                    let _ = nc_clone.publish(reply, err.to_string().into()).await;
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("❌ ssi_agent failed to subscribe to NATS: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ ssi_agent failed to connect to NATS: {} (falling back to HTTP only)", e);
                    }
                }
            });
        }

        match &self.auth {
            AuthConfig::None => {
                println!("🔓 Authentication: None (public access)");
                let server = HttpServer::new(processor, agent_info, bind_address);
                server
                    .start()
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
            AuthConfig::BearerToken { tokens, format } => {
                println!(
                    "🔐 Authentication: Bearer token ({} token(s){})",
                    tokens.len(),
                    format
                        .as_ref()
                        .map(|f| format!(", format: {}", f))
                        .unwrap_or_default()
                );

                let authenticator = BearerTokenAuthenticator::new(tokens.clone());
                let server =
                    HttpServer::with_auth(processor, agent_info, bind_address, authenticator);
                server
                    .start()
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
            AuthConfig::ApiKey {
                keys,
                location,
                name,
            } => {
                println!(
                    "🔐 Authentication: API key ({} {}, {} key(s))",
                    location,
                    name,
                    keys.len()
                );
                println!("⚠️  API key authentication not yet supported, using no authentication");

                let server = HttpServer::new(processor, agent_info, bind_address);
                server
                    .start()
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
            AuthConfig::OAuth2Jwt { secret, audience, issuer } => {
                println!("🔐 Authentication: OAuth2 JWT Bearer Token validation");
                let authenticator = OAuth2JwtAuthenticator::new(secret, audience.clone(), issuer.clone());
                let server = HttpServer::with_auth(processor, agent_info, bind_address, authenticator);
                server
                    .start()
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
        }
    }
}

/// Dynamic OAuth2 JWT authenticator wrapper for AXUM HTTP server
#[derive(Clone)]
pub struct OAuth2JwtAuthenticator {
    verifier: Arc<identity_context::jwt::HmacAuthVerifier>,
    scheme: a2a_rs::domain::core::agent::SecurityScheme,
}

impl OAuth2JwtAuthenticator {
    pub fn new(secret: &str, audience: String, issuer: String) -> Self {
        Self {
            verifier: Arc::new(identity_context::jwt::HmacAuthVerifier::with_audience_and_issuer(
                secret,
                audience,
                issuer,
            )),
            scheme: a2a_rs::domain::core::agent::SecurityScheme::Http {
                scheme: "bearer".to_string(),
                bearer_format: Some("JWT".to_string()),
                description: Some("OAuth2 JWT Bearer Token".to_string()),
            },
        }
    }
}

#[async_trait::async_trait]
impl a2a_rs::port::authenticator::Authenticator for OAuth2JwtAuthenticator {
    async fn authenticate(
        &self,
        context: &a2a_rs::port::authenticator::AuthContext,
    ) -> Result<a2a_rs::port::authenticator::AuthPrincipal, a2a_rs::domain::A2AError> {
        self.validate_context(context)?;

        use identity_context::jwt::AuthVerifier;
        match self.verifier.verify(&context.credential) {
            Ok(verified) => {
                Ok(a2a_rs::port::authenticator::AuthPrincipal::new(
                    verified.tenant_id.clone(),
                    "bearer".to_string(),
                ))
            }
            Err(e) => Err(a2a_rs::domain::A2AError::Internal(format!(
                "OAuth2 JWT verification failed: {}",
                e
            ))),
        }
    }

    fn security_scheme(&self) -> &a2a_rs::domain::core::agent::SecurityScheme {
        &self.scheme
    }

    fn validate_context(
        &self,
        context: &a2a_rs::port::authenticator::AuthContext,
    ) -> Result<(), a2a_rs::domain::A2AError> {
        if context.scheme_type != "bearer" {
            return Err(a2a_rs::domain::A2AError::Internal(format!(
                "Invalid authentication scheme: expected 'bearer', got '{}'",
                context.scheme_type
            )));
        }
        Ok(())
    }
}