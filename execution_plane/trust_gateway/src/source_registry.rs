// ─────────────────────────────────────────────────────────────
// Source Registry — external swarm authentication (spec §18)
//
// Manages registered external sources and validates their
// credentials before allowing access to the governance pipeline.
//
// P3/C2 fix: `load_sources_from_env()` now actually parses the
// TOML config file at SOURCE_REGISTRY_PATH. The module is no
// longer dead code — sources are loaded at startup and the
// registry is available for API key validation.
// ─────────────────────────────────────────────────────────────

use identity_context::source::{SourceRegistration, SourceType, AuthMode};
use identity_context::models::TransportKind;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory source registry loaded from config.
///
/// Sources are registered at gateway startup and matched against
/// incoming API keys on every external request.
pub struct SourceRegistry {
    /// source_id → registration
    sources: RwLock<HashMap<String, SourceRegistration>>,
    /// API key hash → source_id (index for fast lookup)
    key_index: RwLock<HashMap<String, String>>,
}

impl SourceRegistry {
    /// Create an empty source registry.
    pub fn new() -> Self {
        Self {
            sources: RwLock::new(HashMap::new()),
            key_index: RwLock::new(HashMap::new()),
        }
    }

    /// Register a source.
    pub fn register(&self, source: SourceRegistration) {
        // Build key index for API key auth
        if let AuthMode::ApiKey { ref key_hash } = source.auth_mode {
            let clean_hash = key_hash
                .strip_prefix("sha256:")
                .unwrap_or(key_hash)
                .to_string();
            self.key_index
                .write()
                .unwrap()
                .insert(clean_hash, source.source_id.clone());
        }

        tracing::info!(
            "📡 Registered source: {} ({:?})",
            source.source_id,
            source.source_type
        );
        self.sources
            .write()
            .unwrap()
            .insert(source.source_id.clone(), source);
    }

    /// Authenticate an API key and return the matching source registration.
    ///
    /// Returns None if the key doesn't match any registered source.
    pub fn authenticate_api_key(&self, api_key: &str) -> Option<SourceRegistration> {
        use sha2::{Digest, Sha256};
        let key_hash = hex::encode(Sha256::digest(api_key.as_bytes()));

        let source_id = self.key_index.read().unwrap().get(&key_hash).cloned()?;
        let sources = self.sources.read().unwrap();
        let source = sources.get(&source_id)?;

        if !source.enabled {
            tracing::warn!("🚫 Source '{}' is disabled", source_id);
            return None;
        }

        Some(source.clone())
    }

    /// Look up a source by ID.
    pub fn get(&self, source_id: &str) -> Option<SourceRegistration> {
        self.sources.read().unwrap().get(source_id).cloned()
    }

    /// List all registered sources.
    pub fn list_all(&self) -> Vec<SourceRegistration> {
        self.sources.read().unwrap().values().cloned().collect()
    }

    /// Returns the number of registered sources.
    pub fn count(&self) -> usize {
        self.sources.read().unwrap().len()
    }
}

/// TOML config model for source registrations.
///
/// Expected format:
/// ```toml
/// [[sources]]
/// source_id = "swarm-alpha"
/// source_type = "external_swarm"
/// display_name = "Alpha Swarm"
/// auth_mode = "api_key"
/// api_key_hash = "sha256:abc123..."
/// policy_profile = "external_default"
/// enabled = true
///
/// [[sources]]
/// source_id = "partner-beta"
/// source_type = "trusted_partner"
/// display_name = "Beta Partner"
/// auth_mode = "api_key"
/// api_key_hash = "sha256:def456..."
/// policy_profile = "trusted_partner"
/// enabled = true
/// ```
#[derive(serde::Deserialize)]
struct SourceConfig {
    #[serde(default)]
    sources: Vec<SourceEntry>,
}

#[derive(serde::Deserialize)]
struct SourceEntry {
    source_id: String,
    #[serde(default = "default_source_type")]
    source_type: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    auth_mode: String,
    #[serde(default)]
    api_key_hash: String,
    #[serde(default)]
    cert_pattern: String,
    #[serde(default)]
    introspect_url: String,
    #[serde(default)]
    expected_client_id: String,
    #[serde(default = "default_policy_profile")]
    policy_profile: String,
    #[serde(default)]
    default_tenant_scope: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    transport_modes: Vec<String>,
}

fn default_source_type() -> String { "external_swarm".to_string() }
fn default_policy_profile() -> String { "external_default".to_string() }
fn default_enabled() -> bool { true }

impl SourceEntry {
    /// Convert TOML entry to domain model.
    fn into_registration(self) -> SourceRegistration {
        let source_type = match self.source_type.as_str() {
            "http_client" => SourceType::HttpClient,
            "trusted_partner" => SourceType::TrustedPartner,
            _ => SourceType::ExternalSwarm,
        };

        let auth_mode = match self.auth_mode.as_str() {
            "mutual_tls" | "mtls" => AuthMode::MutualTls {
                cert_pattern: self.cert_pattern,
            },
            "oauth2" => AuthMode::OAuth2 {
                introspect_url: self.introspect_url,
                expected_client_id: self.expected_client_id,
            },
            _ => AuthMode::ApiKey {
                key_hash: self.api_key_hash,
            },
        };

        let transport_modes = if self.transport_modes.is_empty() {
            vec![TransportKind::Http]
        } else {
            self.transport_modes.iter().map(|t| match t.as_str() {
                "nats" => TransportKind::Nats,
                "mcp_sse" => TransportKind::McpSse,
                _ => TransportKind::Http,
            }).collect()
        };

        SourceRegistration {
            source_id: self.source_id,
            source_type,
            display_name: self.display_name,
            transport_modes,
            auth_mode,
            policy_profile: self.policy_profile,
            default_tenant_scope: self.default_tenant_scope,
            enabled: self.enabled,
        }
    }
}

/// Load source registrations from TOML config.
///
/// P3/C2 fix: Actually parses the TOML file at `SOURCE_REGISTRY_PATH`
/// instead of always returning an empty Vec. Each `[[sources]]` entry
/// is converted to a `SourceRegistration` and returned.
///
/// Falls back to an empty list if the env var is not set or the file
/// cannot be read/parsed.
pub fn load_sources_from_env() -> Vec<SourceRegistration> {
    let path = match std::env::var("SOURCE_REGISTRY_PATH") {
        Ok(p) => p,
        Err(_) => {
            tracing::debug!("SOURCE_REGISTRY_PATH not set — no external sources registered");
            return Vec::new();
        }
    };

    tracing::info!("📋 Loading source registry from: {}", path);

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("⚠️ Cannot read source registry file '{}': {}", path, e);
            return Vec::new();
        }
    };

    let config: SourceConfig = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("❌ Failed to parse source registry TOML '{}': {}", path, e);
            return Vec::new();
        }
    };

    let count = config.sources.len();
    let registrations: Vec<SourceRegistration> = config.sources
        .into_iter()
        .map(|entry| entry.into_registration())
        .collect();

    tracing::info!("✅ Loaded {} source registrations from {}", count, path);
    registrations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_config() {
        let toml_str = r#"
[[sources]]
source_id = "swarm-alpha"
source_type = "external_swarm"
display_name = "Alpha Swarm"
auth_mode = "api_key"
api_key_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
policy_profile = "external_default"
enabled = true

[[sources]]
source_id = "partner-beta"
source_type = "trusted_partner"
display_name = "Beta Partner"
auth_mode = "api_key"
api_key_hash = "sha256:abc123"
policy_profile = "trusted_partner"
enabled = false
"#;
        let config: SourceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.sources.len(), 2);

        let regs: Vec<SourceRegistration> = config.sources
            .into_iter()
            .map(|e| e.into_registration())
            .collect();

        assert_eq!(regs[0].source_id, "swarm-alpha");
        assert_eq!(regs[0].source_type, SourceType::ExternalSwarm);
        assert!(regs[0].enabled);

        assert_eq!(regs[1].source_id, "partner-beta");
        assert_eq!(regs[1].source_type, SourceType::TrustedPartner);
        assert!(!regs[1].enabled);
    }

    #[test]
    fn test_registry_api_key_auth() {
        let registry = SourceRegistry::new();

        // Register a source with a known API key hash
        // SHA-256 of "test-api-key-123" = the hash below
        use sha2::{Digest, Sha256};
        let api_key = "test-api-key-123";
        let key_hash = format!("sha256:{}", hex::encode(Sha256::digest(api_key.as_bytes())));

        registry.register(SourceRegistration {
            source_id: "test-swarm".to_string(),
            source_type: SourceType::ExternalSwarm,
            display_name: "Test Swarm".to_string(),
            transport_modes: vec![TransportKind::Http],
            auth_mode: AuthMode::ApiKey { key_hash },
            policy_profile: "test".to_string(),
            default_tenant_scope: None,
            enabled: true,
        });

        // Valid key should authenticate
        let result = registry.authenticate_api_key(api_key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().source_id, "test-swarm");

        // Invalid key should fail
        assert!(registry.authenticate_api_key("wrong-key").is_none());
    }

    #[test]
    fn test_registry_disabled_source() {
        let registry = SourceRegistry::new();

        use sha2::{Digest, Sha256};
        let api_key = "disabled-key";
        let key_hash = format!("sha256:{}", hex::encode(Sha256::digest(api_key.as_bytes())));

        registry.register(SourceRegistration {
            source_id: "disabled-swarm".to_string(),
            source_type: SourceType::ExternalSwarm,
            display_name: "Disabled".to_string(),
            transport_modes: vec![TransportKind::Http],
            auth_mode: AuthMode::ApiKey { key_hash },
            policy_profile: "test".to_string(),
            default_tenant_scope: None,
            enabled: false, // Disabled!
        });

        // Should fail even with correct key because source is disabled
        assert!(registry.authenticate_api_key(api_key).is_none());
    }
}
