// ─────────────────────────────────────────────────────────────
// Actor and source context types
//
// Maps the current JWT semantics (iss, sub, tenant_id, jti)
// into stable structs decoupled from JWT encoding details.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Who is performing the action and under what authority.
///
/// Derived from the session JWT issued by `ssi_vault`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActorContext {
    /// DID of the entity that owns the tenant / agent box (from JWT `iss`).
    pub owner_did: String,
    /// DID of the entity that initiated the action (from JWT `sub`).
    /// May be the same as `owner_did` for first-party requests.
    pub requester_did: String,
    /// Optional end-user DID when the action is on behalf of a customer.
    pub user_did: Option<String>,
    /// Session correlation token (from JWT `jti`).
    pub session_jti: String,
    /// Current authentication level of the actor.
    pub auth_level: AuthLevel,
}

/// Authentication strength of the current session.
///
/// Used by the policy engine to decide whether step-up is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthLevel {
    /// Basic session token — the default after Host login.
    Session,
    /// Re-authenticated (e.g. WebAuthn challenge completed).
    Elevated,
    /// Verified presentation was provided (OID4VP).
    Verified,
}

impl std::fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Elevated => write!(f, "elevated"),
            Self::Verified => write!(f, "verified"),
        }
    }
}

/// Where the action request originated.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceContext {
    /// Source type identifier: "ssi_agent", "whatsapp", "webhook",
    /// "portal", "picoclaw", etc.
    pub source_type: String,
    /// Optional human-readable name for the source instance.
    pub name: Option<String>,
    /// Optional instance/channel identifier.
    pub instance_id: Option<String>,
}

impl SourceContext {
    /// Convenience constructor for the ssi_agent source.
    pub fn ssi_agent() -> Self {
        Self {
            source_type: "ssi_agent".to_string(),
            name: Some("SSI Identity Agent".to_string()),
            instance_id: None,
        }
    }

    /// Convenience constructor for a webhook source.
    pub fn webhook(instance_id: impl Into<String>) -> Self {
        Self {
            source_type: "webhook".to_string(),
            name: None,
            instance_id: Some(instance_id.into()),
        }
    }

    /// Convenience constructor for a WhatsApp bridge source.
    pub fn whatsapp(instance_id: impl Into<String>) -> Self {
        Self {
            source_type: "whatsapp".to_string(),
            name: Some("WhatsApp Bridge".to_string()),
            instance_id: Some(instance_id.into()),
        }
    }

    /// Convenience constructor for the PicoClaw bypass source.
    pub fn picoclaw(instance_id: impl Into<String>) -> Self {
        Self {
            source_type: "picoclaw".to_string(),
            name: Some("PicoClaw Go Agent".to_string()),
            instance_id: Some(instance_id.into()),
        }
    }

    /// Convenience constructor for an external AI agent swarm source (spec §18).
    pub fn external_swarm(source_id: impl Into<String>, instance_id: Option<String>) -> Self {
        let sid = source_id.into();
        Self {
            source_type: "external_swarm".to_string(),
            name: Some(format!("External Swarm: {}", sid)),
            instance_id,
        }
    }
}
