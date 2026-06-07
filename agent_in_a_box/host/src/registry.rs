//! Component Registry for dynamic Wasm component loading.
//!
//! Provides config-driven component management for the host orchestrator.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use wasmtime::component::Component;
use wasmtime::Engine;

/// Configuration for a single Wasm component.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ComponentConfig {
    /// Unique name for this component (e.g., "ssi_vault")
    pub name: String,
    /// Path to the .wasm file (relative to host working directory)
    pub path: String,
    /// Whether this component should be loaded
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Root configuration structure for components.toml
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ComponentsConfig {
    #[serde(rename = "component")]
    pub components: Vec<ComponentConfig>,
}

/// Central registry for managing Wasm components.
///
/// Provides dynamic loading from a TOML configuration file,
/// with support for enable/disable and path overrides.
pub struct ComponentRegistry {
    engine: Engine,
    components: HashMap<String, Component>,
    configs: Vec<ComponentConfig>,
}

impl ComponentRegistry {
    /// Create a new empty registry with the given Wasmtime engine.
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            components: HashMap::new(),
            configs: Vec::new(),
        }
    }

    /// Load component configurations from a TOML file.
    ///
    /// This parses the config but does NOT load the Wasm files yet.
    /// Call `load_enabled()` to actually load the components.
    pub fn load_config(&mut self, config_path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {:?}", config_path))?;
        
        let config: ComponentsConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse components.toml")?;
        
        self.configs = config.components;
        tracing::info!("📋 Loaded {} component configurations", self.configs.len());
        
        Ok(())
    }

    /// Load all enabled components from their configured paths.
    pub fn load_enabled(&mut self) -> Result<()> {
        let configs: Vec<_> = self.configs.iter().filter(|c| c.enabled).cloned().collect();
        
        for config in configs {
            if let Err(e) = self.load_component(&config.name, Path::new(&config.path)) {
                tracing::warn!("⚠️ Skipping component '{}': {}", config.name, e);
            }
        }
        
        Ok(())
    }

    /// Load a single component by name and path with active WASM module attestation.
    pub fn load_component(&mut self, name: &str, path: &Path) -> Result<()> {
        tracing::info!("📦 Loading component '{}' from {:?}", name, path);
        
        // 1. Read raw WASM file bytes
        let wasm_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read raw WASM bytes for '{}' from {:?}", name, path))?;
            
        // 2. Compute actual SHA-256 hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        let actual_hash = hex::encode(hasher.finalize());
        tracing::info!("🛡️ [WASM Attestation] Component '{}' SHA-256: {}", name, actual_hash);
        
        // 3. Enforce integrity checks via manifest.json
        let manifest_path = Path::new("config/manifest.json");
        let mut verified = false;
        if manifest_path.exists() {
            if let Ok(manifest_content) = std::fs::read_to_string(manifest_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest_content) {
                    if let Some(expected_hash) = json.get(name).and_then(|v| v.as_str()) {
                        if actual_hash != expected_hash {
                            anyhow::bail!(
                                "🛑 [WASM Attestation FAILURE] Integrity verification failed for component '{}'! Expected: {}, Got: {}",
                                name, expected_hash, actual_hash
                            );
                        }
                        tracing::info!("✅ [WASM Attestation] Verified component '{}' matches manifest signature", name);
                        verified = true;
                    }
                }
            }
        }
        
        // Dynamic self-healing/registration for development/first boot if no manifest entry exists
        if !verified {
            tracing::warn!("⚠️ [WASM Attestation] Component '{}' has no manifest entry. Registering current signature.", name);
            let mut manifest_map = if manifest_path.exists() {
                std::fs::read_to_string(manifest_path)
                    .ok()
                    .and_then(|c| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&c).ok())
                    .unwrap_or_default()
            } else {
                serde_json::Map::new()
            };
            manifest_map.insert(name.to_string(), serde_json::Value::String(actual_hash.clone()));
            if let Ok(new_content) = serde_json::to_string_pretty(&manifest_map) {
                let _ = std::fs::write(manifest_path, new_content);
            }
        }
        
        let component = Component::from_binary(&self.engine, &wasm_bytes)
            .with_context(|| format!("Failed to parse component '{}' from loaded binary", name))?;
        
        self.components.insert(name.to_string(), component);
        tracing::info!("✅ Loaded component: {}", name);
        
        Ok(())
    }

    /// Get a loaded component by name.
    pub fn get(&self, name: &str) -> Option<&Component> {
        self.components.get(name)
    }

    /// Get a loaded component, panicking with a clear message if not found.
    pub fn require(&self, name: &str) -> &Component {
        self.get(name)
            .unwrap_or_else(|| panic!("Required component '{}' not loaded", name))
    }

    /// List all loaded component names.
    pub fn list_loaded(&self) -> Vec<&str> {
        self.components.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a component is loaded.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.components.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing() {
        let toml = r#"
[[component]]
name = "test_comp"
path = "test.wasm"
enabled = true
"#;
        let config: ComponentsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.components.len(), 1);
        assert_eq!(config.components[0].name, "test_comp");
    }
}
