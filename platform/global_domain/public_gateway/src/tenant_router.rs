//! Tenant-aware NATS router for the public gateway.
//!
//! Looks up `tenant_id` from the routing token, resolves tenant NATS credentials,
//! and publishes messages into the correct tenant namespace.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

/// Routing token V2 — signed by gateway key, includes tenant context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTokenV2 {
    pub tenant_id: String,
    pub node_id: String,
    pub target_id: String,
    /// Channel of origin: didcomm, whatsapp, sms, email
    pub channel: String,
    /// Expiry timestamp (Unix epoch seconds)
    pub expiry: u64,
}

/// Per-tenant NATS routing configuration.
#[derive(Debug, Clone)]
pub struct TenantRoute {
    pub tenant_id: String,
    pub nats_subject_prefix: String,
    pub status: TenantGatewayStatus,
}

/// Gateway-level tenant status.
#[derive(Debug, Clone, PartialEq)]
pub enum TenantGatewayStatus {
    Active,
    Suspended,
    Unknown,
}

/// In-memory tenant route cache.
/// In production, this would be backed by NATS KV or a registry lookup.
#[derive(Clone)]
pub struct TenantNatsRouter {
    routes: Arc<Mutex<HashMap<String, TenantRoute>>>,
}

impl TenantNatsRouter {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a tenant's routing info.
    pub fn register_tenant(&self, tenant_id: &str, subject_prefix: &str) {
        let mut map = self.routes.lock().unwrap();
        map.insert(
            tenant_id.to_string(),
            TenantRoute {
                tenant_id: tenant_id.to_string(),
                nats_subject_prefix: subject_prefix.to_string(),
                status: TenantGatewayStatus::Active,
            },
        );
        tracing::info!("🔗 Registered tenant route: {} → {}", tenant_id, subject_prefix);
    }

    /// Resolve the NATS subject for a tenant + target.
    /// Wallet-channel messages get routed to a special wallet subject.
    pub fn resolve_subject(
        &self,
        tenant_id: &str,
        node_id: &str,
        target_id: &str,
    ) -> Result<String, String> {
        let map = self.routes.lock().unwrap();
        match map.get(tenant_id) {
            Some(route) => {
                if route.status == TenantGatewayStatus::Suspended {
                    return Err(format!("Tenant {} is suspended", tenant_id));
                }
                Ok(format!(
                    "{}.{}.didcomm.{}",
                    route.nats_subject_prefix, node_id, target_id
                ))
            }
            None => {
                // Fallback: use default subject format with tenant prefix
                Ok(format!("v1.{}.{}.didcomm.{}", tenant_id, node_id, target_id))
            }
        }
    }

    /// Resolve subject for wallet-channel messages.
    /// Wallet messages bypass the standard tenant subject and go to a wallet-specific subject.
    pub fn resolve_wallet_subject(
        &self,
        tenant_id: &str,
        node_id: &str,
        pairwise_did_pointer: &str,
    ) -> Result<String, String> {
        let map = self.routes.lock().unwrap();
        if let Some(route) = map.get(tenant_id) {
            if route.status == TenantGatewayStatus::Suspended {
                return Err(format!("Tenant {} is suspended", tenant_id));
            }
        }
        // Wallet messages use a dedicated subject namespace
        Ok(format!("v1.{}.{}.wallet.{}", tenant_id, node_id, pairwise_did_pointer))
    }

    /// Suspend a tenant (deny all routing).
    pub fn suspend_tenant(&self, tenant_id: &str) {
        let mut map = self.routes.lock().unwrap();
        if let Some(route) = map.get_mut(tenant_id) {
            route.status = TenantGatewayStatus::Suspended;
            tracing::warn!("⛔ Suspended tenant: {}", tenant_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_registered_tenant() {
        let router = TenantNatsRouter::new();
        router.register_tenant("t1", "v1.t1");
        let subject = router.resolve_subject("t1", "node1", "target1").unwrap();
        assert_eq!(subject, "v1.t1.node1.didcomm.target1");
    }

    #[test]
    fn test_resolve_unknown_tenant_uses_default() {
        let router = TenantNatsRouter::new();
        let subject = router.resolve_subject("t2", "node1", "target1").unwrap();
        assert_eq!(subject, "v1.t2.node1.didcomm.target1");
    }

    #[test]
    fn test_suspended_tenant_denied() {
        let router = TenantNatsRouter::new();
        router.register_tenant("t3", "v1.t3");
        router.suspend_tenant("t3");
        let result = router.resolve_subject("t3", "node1", "target1");
        assert!(result.is_err());
    }
}
