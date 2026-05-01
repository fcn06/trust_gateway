#[cfg(test)]
pub mod mocks {
    use std::sync::Arc;
    use std::collections::{HashMap, HashSet};
    use tokio::sync::RwLock;
    use tokio::sync::mpsc;
    use url::Url;
    use webauthn_rs::prelude::*;

    use crate::shared_state::{WebauthnSharedState, HostConfig};
    use crate::dto::IncomingMessage;
    use crate::commands::{VaultCommand, AclCommand, MlsSessionCommand, ContactStoreCommand};

    /// Build a minimal WebauthnSharedState for unit tests (no NATS, no real WebAuthn).
    pub fn mock_shared_state() -> Arc<WebauthnSharedState> {
        let config = HostConfig {
            api_listen_url: "127.0.0.1:8080".to_string(),
            webauthn_rp_id: "localhost".to_string(),
            webauthn_rp_origin: "http://localhost:8080".to_string(),
            webauthn_rp_extra_origins: vec![],
            service_gateway_base_url: "http://localhost:8080".to_string(),
            gateway_did: "did:web:localhost".to_string(),
            global_relay_domain: "localhost".to_string(),
            mcp_server_nats_url: "nats://localhost:4222".to_string(),
            nats_global_domain_url: "nats://localhost:4222".to_string(),
            allowed_origins: "*".to_string(),
            ssi_agent_endpoint: "http://localhost:8082".to_string(),
            agent_jwt_ttl_seconds: 300,
            tenant_id: "".to_string(),
            keyless_mode: false,
            service_did: None,
            gateway_url: Some("http://localhost:8080".to_string()),
            rp_domain: "localhost".to_string(),
            oid4vp_client_id: "did:web:test".to_string(),
            oid4vp_rsa_pem: "".to_string(),
            connector_mcp_url: "http://localhost:3050".to_string(),
            skill_executor_url: "http://localhost:3070".to_string(),
            restaurant_service_url: "http://localhost:3080".to_string(),
            restaurant_tenant_id: None,
            shop_token: None,
            allowed_agent_tenants: "".to_string(),
        };

        let rp_origin = Url::parse(&config.webauthn_rp_origin).unwrap();
        let webauthn = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin).unwrap().build().unwrap();

        let (vault_cmd_tx, _) = mpsc::channel::<VaultCommand>(1);
        let (messaging_cmd_tx, _) = mpsc::channel::<IncomingMessage>(1);
        let (acl_cmd_tx, _) = mpsc::channel::<AclCommand>(1);
        let (mls_cmd_tx, _) = mpsc::channel::<MlsSessionCommand>(1);
        let (contact_cmd_tx, _) = mpsc::channel::<ContactStoreCommand>(1);

        let jwt_key = jwt_simple::prelude::HS256Key::generate();
        let http_client = reqwest::Client::new();

        Arc::new(WebauthnSharedState {
            registration_sessions: RwLock::new(HashMap::new()),
            authentication_sessions: RwLock::new(HashMap::new()),
            user_credentials: RwLock::new(HashMap::new()),
            vault_cmd_tx,
            messaging_cmd_tx,
            acl_cmd_tx,
            mls_cmd_tx,
            contact_cmd_tx,
            nats: None,
            kv_stores: None,
            jwt_key,
            active_subscriptions: RwLock::new(HashSet::new()),
            target_id_map: RwLock::new(HashMap::new()),
            portal_id_map: RwLock::new(HashMap::new()),
            webauthn,
            house_salt: vec![0u8; 32],
            config: config.clone(),
            gateway_url: config.gateway_url,
            connections_kv: None,
            oid4vp_client_id: "did:web:test".to_string(),
            oid4vp_rsa_pem: "".to_string(),
            active_conversations: RwLock::new(HashMap::new()),
            http_client,
        })
    }
}
