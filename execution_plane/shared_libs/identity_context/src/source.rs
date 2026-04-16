// ─────────────────────────────────────────────────────────────
// Source registry model (spec §18)
//
// Defines the data model for registering external swarm sources.
// Actual CRUD/KV storage is done by the gateway module
// (trust_gateway/src/source_registry.rs).
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use crate::models::TransportKind;

/// A registered external source (swarm) with its auth and policy config.
///
/// Spec §18.1 — loaded from config file or KV store at gateway startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRegistration {
    /// Unique identifier for this source (e.g., "swarm-alpha").
    pub source_id: String,

    /// Classification of the source.
    pub source_type: SourceType,

    /// Human-readable display name.
    pub display_name: String,

    /// Which transports this source is allowed to use.
    pub transport_modes: Vec<TransportKind>,

    /// How this source authenticates to the gateway.
    pub auth_mode: AuthMode,

    /// Policy profile to apply (maps to policy rules).
    pub policy_profile: String,

    /// Default tenant scope (if source always operates in one tenant).
    pub default_tenant_scope: Option<String>,

    /// Whether this source is currently enabled.
    pub enabled: bool,
}

/// Source type classification for policy matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// An external AI agent swarm.
    ExternalSwarm,
    /// An HTTP integration client.
    HttpClient,
    /// A partner system with elevated trust.
    TrustedPartner,
}

impl SourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExternalSwarm => "external_swarm",
            Self::HttpClient => "http_client",
            Self::TrustedPartner => "trusted_partner",
        }
    }
}

/// How an external source authenticates to the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// API key in `Authorization: Bearer` or `X-Source-Key` header.
    ApiKey {
        /// SHA-256 hash of the API key for secure storage.
        key_hash: String,
    },
    /// Mutual TLS with client certificate.
    MutualTls {
        /// Expected CN or SAN pattern.
        cert_pattern: String,
    },
    /// OAuth2 client credentials flow.
    OAuth2 {
        /// Token introspection endpoint.
        introspect_url: String,
        /// Expected client_id.
        expected_client_id: String,
    },
}

impl AuthMode {
    /// Validate an incoming credential against this auth mode.
    ///
    /// Returns true if the credential matches.
    pub fn validate(&self, credential: &str) -> bool {
        match self {
            AuthMode::ApiKey { key_hash } => {
                use sha2::{Digest, Sha256};
                let hash = hex::encode(Sha256::digest(credential.as_bytes()));
                let expected = key_hash
                    .strip_prefix("sha256:")
                    .unwrap_or(key_hash);
                hash == expected
            }
            AuthMode::MutualTls { .. } => {
                // mTLS validation is done at the transport layer, not here
                tracing::warn!("mTLS validation must be done at transport layer");
                false
            }
            AuthMode::OAuth2 { .. } => {
                // OAuth2 introspection would be async — not done here
                tracing::warn!("OAuth2 validation requires async introspection");
                false
            }
        }
    }
}
