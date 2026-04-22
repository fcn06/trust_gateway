//! Shared state structures for the host orchestrator.
//!
//! Contains the main state types passed between handlers and the Wasm runtime.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use jwt_simple::prelude::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use wasmtime_wasi::{WasiCtx, ResourceTable};
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration, Webauthn};

use crate::commands::{VaultCommand, AclCommand, MlsSessionCommand, ContactStoreCommand};
use crate::dto::IncomingMessage;


/// Application configuration loaded from config.json or environment.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostConfig {
    pub api_listen_url: String,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    #[serde(default)]
    pub webauthn_rp_extra_origins: Vec<String>,
    pub service_gateway_base_url: String,
    #[serde(default)]
    pub gateway_did: String,
    #[serde(default)]
    pub global_relay_domain: String,
    #[serde(default = "default_mcp_nats_url")]
    pub mcp_server_nats_url: String,
    #[serde(default = "default_nats_url")]
    pub nats_global_domain_url: String,
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: String,
    #[serde(default = "default_ssi_agent_endpoint")]
    pub ssi_agent_endpoint: String,
    #[serde(default = "default_agent_jwt_ttl")]
    pub agent_jwt_ttl_seconds: u32,
    /// Multi-tenant: the tenant this host instance belongs to.
    #[serde(default)]
    pub tenant_id: String,
    /// Connection Model (V6): operate in keyless mode (no user master seeds on host)
    #[serde(default)]
    pub keyless_mode: bool,
    /// Connection Model (V6): this tenant's own Service DID
    #[serde(default)]
    pub service_did: Option<String>,
    /// Hybrid Architecture: Global Gateway URL for inter-user HTTP transport
    #[serde(default)]
    pub gateway_url: Option<String>,
    #[serde(default)]
    pub rp_domain: String,
    #[serde(default)]
    pub oid4vp_client_id: String,
    #[serde(default)]
    pub oid4vp_rsa_pem: String,

    /// Connector MCP server URL
    #[serde(default = "default_connector_mcp_url")]
    pub connector_mcp_url: String,
    /// Skill Executor URL
    #[serde(default = "default_skill_executor_url")]
    pub skill_executor_url: String,
    /// Restaurant Service URL
    #[serde(default = "default_restaurant_service_url")]
    pub restaurant_service_url: String,
    /// Restaurant Tenant ID (if operating in restaurant mode)
    #[serde(default)]
    pub restaurant_tenant_id: Option<String>,
    /// Shop Token
    #[serde(default)]
    pub shop_token: Option<String>,
}

fn default_connector_mcp_url() -> String {
    "http://127.0.0.1:3050".to_string()
}
fn default_allowed_origins() -> String {
    "http://localhost:8080,http://localhost:8083".to_string()
}
fn default_skill_executor_url() -> String {
    "http://127.0.0.1:3070".to_string()
}
fn default_restaurant_service_url() -> String {
    "http://127.0.0.1:3080".to_string()
}
fn default_ssi_agent_endpoint() -> String {
    std::env::var("SSI_AGENT_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8082".to_string())
}

fn default_agent_jwt_ttl() -> u32 {
    300 // 5 minutes
}

fn default_nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

fn default_mcp_nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

/// Shared state accessible across all async tasks and handlers.
pub struct WebauthnSharedState {
    /// (PasskeyRegistration, username, user_id, invite_code)
    pub registration_sessions: RwLock<HashMap<String, (PasskeyRegistration, String, String, Option<String>)>>,
    pub authentication_sessions: RwLock<HashMap<String, (PasskeyAuthentication, String, String)>>,
    pub user_credentials: RwLock<HashMap<String, Vec<Passkey>>>,
    pub vault_cmd_tx: tokio::sync::mpsc::Sender<VaultCommand>,
    pub messaging_cmd_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    pub acl_cmd_tx: tokio::sync::mpsc::Sender<AclCommand>,

    pub mls_cmd_tx: tokio::sync::mpsc::Sender<MlsSessionCommand>,
    pub contact_cmd_tx: tokio::sync::mpsc::Sender<ContactStoreCommand>,
    pub nats: Option<async_nats::Client>,
    pub kv_stores: Option<HashMap<String, async_nats::jetstream::kv::Store>>,
    pub jwt_key: jwt_simple::prelude::HS256Key,
    pub active_subscriptions: RwLock<HashSet<String>>,
    pub target_id_map: RwLock<HashMap<String, String>>, // Maps target_id -> DID
    pub portal_id_map: RwLock<HashMap<String, String>>, // Maps portal_hash (AID) -> user_id
    pub webauthn: Webauthn,
    pub house_salt: Vec<u8>,
    pub config: HostConfig,
    /// Hybrid Architecture: Global Gateway URL (derived from config)
    pub gateway_url: Option<String>,
    pub connections_kv: async_nats::jetstream::kv::Store,
    pub oid4vp_client_id: String,
    pub oid4vp_rsa_pem: String,
    /// Active conversation contexts, keyed by requester_did.
    /// Populated by messaging_loop before agent dispatch, consumed by escalation listener.
    pub active_conversations: RwLock<HashMap<String, ConversationContext>>,
    pub http_client: reqwest::Client,
}

/// Conversation context stored during agent dispatch for deterministic
/// escalation notification routing.
#[derive(Debug, Clone)]
pub struct ConversationContext {
    pub thid: String,
    pub sender_did: String,
    pub inst_did: String,
    pub user_id: String,
}

impl WebauthnSharedState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: HostConfig,
        vault_cmd_tx: tokio::sync::mpsc::Sender<VaultCommand>,
        messaging_cmd_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
        acl_cmd_tx: tokio::sync::mpsc::Sender<AclCommand>,

        mls_cmd_tx: tokio::sync::mpsc::Sender<MlsSessionCommand>,
        contact_cmd_tx: tokio::sync::mpsc::Sender<ContactStoreCommand>,
        nats: Option<async_nats::Client>,
        kv_stores: Option<HashMap<String, async_nats::jetstream::kv::Store>>,
        jwt_key: jwt_simple::prelude::HS256Key,
        webauthn: Webauthn,
        house_salt: Vec<u8>,
        connections_kv: async_nats::jetstream::kv::Store,
        http_client: reqwest::Client,
    ) -> Self {
        let gateway_url = config.gateway_url.clone();
        WebauthnSharedState {
            registration_sessions: RwLock::new(HashMap::new()),
            authentication_sessions: RwLock::new(HashMap::new()),
            user_credentials: RwLock::new(HashMap::new()),
            vault_cmd_tx,
            messaging_cmd_tx,
            acl_cmd_tx,

            mls_cmd_tx,
            contact_cmd_tx,
            nats,
            kv_stores,
            jwt_key,
            active_subscriptions: RwLock::new(HashSet::new()),
            target_id_map: RwLock::new(HashMap::new()),
            portal_id_map: RwLock::new(HashMap::new()),
            webauthn,
            house_salt,
            config,
            gateway_url,
            connections_kv,
            oid4vp_client_id: std::env::var("OID4VP_CLIENT_ID")
                .unwrap_or_else(|_| "did:web:example.com".to_string()),
            oid4vp_rsa_pem: std::env::var("OID4VP_RSA_PEM")
                .unwrap_or_default()
                // If loaded via `.env` as a single literal line for multiline PEMs, fix escapes:
                .replace("\\n", "\n"),
            active_conversations: RwLock::new(HashMap::new()),
            http_client,
        }
    }
}

/// State for the Wasmtime store, passed to each component.
pub struct HostState {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
    pub vault: Option<wasmtime::component::Instance>,

    pub messaging: Option<wasmtime::component::Instance>,
    pub acl: Option<wasmtime::component::Instance>,
    pub mls_session: Option<wasmtime::component::Instance>,
    pub contact_store: Option<wasmtime::component::Instance>,
    pub vault_store: Option<async_nats::jetstream::kv::Store>,
    pub acl_store: Option<async_nats::jetstream::kv::Store>,
    pub shared: Arc<WebauthnSharedState>,
}

impl wasmtime_wasi::WasiView for HostState {
    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx { &mut self.wasi }
    fn table(&mut self) -> &mut wasmtime_wasi::ResourceTable { &mut self.table }
}

/// Server keys for JWT signing and blind key derivation.
#[derive(Serialize, Deserialize)]
pub struct ServerKeys {
    pub jwt_key_bytes: Vec<u8>,
    pub house_salt: Vec<u8>,
}

/// CLI arguments parsed by clap.
#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Log level (info, debug, warn, error, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
