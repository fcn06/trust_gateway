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
    /// The method used to authenticate this actor.
    /// Propagated from `IdentityContext.auth_method` during normalization.
    /// Used by the policy matcher for `auth_methods` rule filtering.
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// Scopes granted by the token (used for OAuth2 scope matching).
    #[serde(default)]
    pub oauth_scopes: Vec<String>,
}

/// Authentication strength of the current session.
///
/// Expanded to a 5-tier numeric hierarchy (1-5) to enable strict
/// `>= min_auth_level` policy evaluations.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthLevel {
    /// Level 1: Static API Key (Long-lived, lowest assurance).
    Level1ApiKey = 1,
    /// Level 2: Bearer Token (e.g., OAuth2 with scopes).
    Level2Bearer = 2,
    /// Level 3: Session Token (e.g., HMAC JWT, standard login).
    Level3Session = 3,
    /// Level 4: Verified Presentation (DID VP / EdDSA signed).
    Level4Verified = 4,
    /// Level 5: Hardware-backed (WebAuthn).
    Level5WebAuthn = 5,
}

impl Default for AuthLevel {
    fn default() -> Self {
        Self::Level3Session
    }
}

impl std::fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Level1ApiKey => write!(f, "level1_api_key"),
            Self::Level2Bearer => write!(f, "level2_bearer"),
            Self::Level3Session => write!(f, "level3_session"),
            Self::Level4Verified => write!(f, "level4_verified"),
            Self::Level5WebAuthn => write!(f, "level5_webauthn"),
        }
    }
}

/// The method used to authenticate a request.
/// Included in audit events and policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Static API key.
    ApiKey,
    /// OAuth2 or similar Bearer token.
    OAuth2,
    /// Standard HMAC JWT (e.g. Host session).
    HmacJwt,
    /// Verified Presentation or EdDSA JWT.
    VpEdDsa,
    /// WebAuthn hardware-backed token.
    WebAuthn,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::HmacJwt
    }
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "api_key"),
            Self::OAuth2 => write!(f, "oauth2"),
            Self::HmacJwt => write!(f, "hmac_jwt"),
            Self::VpEdDsa => write!(f, "vp_eddsa"),
            Self::WebAuthn => write!(f, "webauthn"),
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
