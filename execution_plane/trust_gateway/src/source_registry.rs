// ─────────────────────────────────────────────────────────────
// Source Registry — external swarm authentication (spec §18)
//
// Manages registered external sources and validates their
// credentials before allowing access to the governance pipeline.
// ─────────────────────────────────────────────────────────────

use identity_context::source::{SourceRegistration, AuthMode};
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
}

/// Load source registrations from TOML config.
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
/// ```
pub fn load_sources_from_env() -> Vec<SourceRegistration> {
    // In v1, sources are configured via environment variables.
    // Full TOML config loading is deferred to Phase 3+.
    let sources = Vec::new();

    // Check for SOURCE_REGISTRY_PATH env var
    if let Ok(path) = std::env::var("SOURCE_REGISTRY_PATH") {
        tracing::info!("📋 Loading source registry from: {}", path);
        // TODO: Parse TOML file at `path`
        // For now, return empty — sources will be added via API or config in later phases
    }

    sources
}
