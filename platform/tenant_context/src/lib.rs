//! Shared tenant context types for the multi-tenant Agent-in-a-Box platform.
//!
//! This crate defines the core data structures that represent tenant identity
//! and configuration across all components: Host, Gateway, ssi_agent, and vp_mcp_server.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The tier of a tenant, determining feature access and LLM routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantTier {
    /// Entry-level: small local/cheap LLM, no tool access.
    Basic,
    /// Mid-tier LLM, tool access allowed.
    Pro,
    /// High-reliability LLM, mandatory escalation, full audit.
    Compliance,
    /// Custom pool, edge routing, dedicated infra.
    Telco,
    /// Deterministic + logging mode, full trace capture.
    Insurance,
}

impl Default for TenantTier {
    fn default() -> Self {
        Self::Basic
    }
}

impl std::fmt::Display for TenantTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Pro => write!(f, "pro"),
            Self::Compliance => write!(f, "compliance"),
            Self::Telco => write!(f, "telco"),
            Self::Insurance => write!(f, "insurance"),
        }
    }
}

/// The lifecycle status of a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Tenant is active and fully operational.
    Active,
    /// Tenant is suspended (e.g., overdue billing). No new operations allowed.
    Suspended,
    /// Tenant is soft-deleted. Data retained for grace period.
    Deleted,
}

impl Default for TenantStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Key management mode for the tenant's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMode {
    /// Platform manages all keys (SMB default).
    PlatformManaged,
    /// Customer manages keys via external KMS (AWS/GCP/Azure).
    CustomerManaged,
    /// Mutations require user-held mobile key + platform key.
    Hybrid,
    /// Connection Model (V6): users hold their own keys in a Sovereign Web Wallet.
    /// The tenant only holds a Service DID and UCAN delegations.
    Sovereign,
}

impl Default for KeyMode {
    fn default() -> Self {
        Self::PlatformManaged
    }
}

/// The full tenant record, stored in the Tenant Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: Uuid,
    pub display_name: String,
    #[serde(default)]
    pub tier: TenantTier,
    #[serde(default)]
    pub status: TenantStatus,
    pub created_at: i64,
    pub nats_account_id: String,
    pub vault_namespace: String,
    pub llm_policy_id: String,
    #[serde(default)]
    pub key_mode: KeyMode,
    /// Connection Model (V6): the tenant's own Service DID.
    #[serde(default)]
    pub service_did: Option<String>,
}

/// Connection Model (V6): a customer wallet connection to this tenant.
///
/// Created when a user's Sovereign Web Wallet connects to a B2B tenant
/// by performing DID-Auth and issuing a UCAN delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerConnection {
    /// The user's pairwise DID for this specific B2B connection.
    pub customer_pairwise_did: String,
    /// The currently active UCAN token (serialized JSON).
    pub active_ucan: String,
    /// DIDComm thread ID for this connection's messages.
    pub thread_id: String,
    /// When the connection was established (Unix epoch seconds).
    pub connected_at: i64,
}

/// Lightweight tenant context passed through request pipelines.
///
/// Extracted from JWTs and injected into request handlers.
/// Used by Host, Gateway, vp_mcp_server, and ssi_agent to scope operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub tier: TenantTier,
    pub status: TenantStatus,
}

impl TenantContext {
    /// Create a new tenant context from a tenant record.
    pub fn from_tenant(tenant: &Tenant) -> Self {
        Self {
            tenant_id: tenant.tenant_id.to_string(),
            tier: tenant.tier.clone(),
            status: tenant.status.clone(),
        }
    }

    /// Check if the tenant is active and can perform operations.
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }

    /// Check if the tenant has compliance-grade audit requirements.
    pub fn requires_full_audit(&self) -> bool {
        matches!(self.tier, TenantTier::Compliance | TenantTier::Insurance)
    }

    /// Returns the tenant-scoped NATS subject prefix.
    pub fn nats_prefix(&self) -> String {
        format!("tenant_{}", self.tenant_id)
    }

    /// Returns a tenant-scoped KV bucket name.
    pub fn kv_bucket(&self, bucket_name: &str) -> String {
        format!("tenant_{}_{}", self.tenant_id, bucket_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_context_nats_prefix() {
        let ctx = TenantContext {
            tenant_id: "abc-123".to_string(),
            tier: TenantTier::Pro,
            status: TenantStatus::Active,
        };
        assert_eq!(ctx.nats_prefix(), "tenant_abc-123");
        assert_eq!(ctx.kv_bucket("sovereign_kv"), "tenant_abc-123_sovereign_kv");
    }

    #[test]
    fn test_requires_full_audit() {
        let compliance = TenantContext {
            tenant_id: "t1".to_string(),
            tier: TenantTier::Compliance,
            status: TenantStatus::Active,
        };
        assert!(compliance.requires_full_audit());

        let basic = TenantContext {
            tenant_id: "t2".to_string(),
            tier: TenantTier::Basic,
            status: TenantStatus::Active,
        };
        assert!(!basic.requires_full_audit());
    }

    #[test]
    fn test_is_active() {
        let active = TenantContext {
            tenant_id: "t1".to_string(),
            tier: TenantTier::Basic,
            status: TenantStatus::Active,
        };
        assert!(active.is_active());

        let suspended = TenantContext {
            tenant_id: "t2".to_string(),
            tier: TenantTier::Basic,
            status: TenantStatus::Suspended,
        };
        assert!(!suspended.is_active());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let ctx = TenantContext {
            tenant_id: "test-id".to_string(),
            tier: TenantTier::Insurance,
            status: TenantStatus::Active,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: TenantContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tenant_id, "test-id");
        assert_eq!(deserialized.tier, TenantTier::Insurance);
    }
}
