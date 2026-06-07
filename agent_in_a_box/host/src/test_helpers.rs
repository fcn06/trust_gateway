#[cfg(test)]
pub mod mocks {
    use std::sync::Arc;
    use url::Url;
    use webauthn_rs::prelude::*;
    use tokio::sync::mpsc;

    use crate::shared_state::{WebauthnSharedState, HostConfig};
    use crate::commands::{VaultCommand, AclCommand};

    pub struct MockApprovalNotifier;
    #[async_trait::async_trait]
    impl trust_core::ports::ApprovalNotifier for MockApprovalNotifier {
        async fn notify_approval_requested(
            &self,
            _request: &trust_core::ports_dto::ApprovalNotification,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

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
            shop_token: None,
            allowed_agent_tenants: "".to_string(),
        };

        let rp_origin = Url::parse(&config.webauthn_rp_origin).unwrap();
        let webauthn = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin).unwrap().build().unwrap();

        let (vault_cmd_tx, _) = mpsc::channel::<VaultCommand>(1);
        let (acl_cmd_tx, _) = mpsc::channel::<AclCommand>(1);

        let jwt_key_bytes = vec![0u8; 32];
        let http_client = reqwest::Client::new();
        let approval_notifier = Arc::new(MockApprovalNotifier);

        Arc::new(WebauthnSharedState::new(
            config,
            vault_cmd_tx,
            acl_cmd_tx,
            approval_notifier,
            None,
            None,
            jwt_key_bytes,
            webauthn,
            vec![0u8; 32],
            None,
            http_client,
            None,
            None,
            None,
        ))
    }
}
