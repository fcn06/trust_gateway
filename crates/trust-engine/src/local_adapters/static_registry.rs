use crate::traits::{EngineError, SkillRegistry};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_sdk::manifest::{RemoteSkillPublication, SkillManifest};

pub struct StaticSkillRegistry {
    skills: Arc<RwLock<HashMap<String, SkillManifest>>>,
    tools_dir: PathBuf,
    require_signatures: bool,
    root_verifying_key: Option<VerifyingKey>,
}

impl StaticSkillRegistry {
    pub fn new(tools_dir: impl AsRef<Path>, require_signatures: bool) -> Self {
        Self {
            skills: Arc::new(RwLock::new(HashMap::new())),
            tools_dir: tools_dir.as_ref().to_path_buf(),
            require_signatures,
            root_verifying_key: None,
        }
    }

    pub fn with_root_key(mut self, key: VerifyingKey) -> Self {
        self.root_verifying_key = Some(key);
        self
    }

    pub async fn register_skill_direct(&self, skill: SkillManifest) {
        let mut map = self.skills.write().await;
        map.insert(skill.name.clone(), skill.clone());
        map.insert(skill.id.clone(), skill);
    }

    pub async fn load_all(&self) -> Result<usize, EngineError> {
        let mut map = HashMap::new();
        if self.tools_dir.exists() && self.tools_dir.is_dir() {
            let entries = std::fs::read_dir(&self.tools_dir)
                .map_err(|e| EngineError::StorageError(format!("Failed to read tools dir: {e}")))?;

            for entry in entries.flatten() {
                let dir_path = entry.path();
                if dir_path.is_dir() {
                    let manifest_file = dir_path.join("manifest.json");
                    if manifest_file.exists() {
                        let content = std::fs::read_to_string(&manifest_file).map_err(|e| {
                            EngineError::StorageError(format!(
                                "Failed to read manifest {}: {e}",
                                manifest_file.display()
                            ))
                        })?;

                        // Signature verification if required
                        if self.require_signatures {
                            let sig_file = dir_path.join("manifest.json.sig");
                            if !sig_file.exists() {
                                return Err(EngineError::SkillValidation(format!(
                                    "Enterprise signing required: missing manifest.json.sig in {}",
                                    dir_path.display()
                                )));
                            }
                            let sig_hex = std::fs::read_to_string(&sig_file).map_err(|e| {
                                EngineError::SkillValidation(format!(
                                    "Failed to read sig file: {e}"
                                ))
                            })?;
                            let key = self.root_verifying_key.as_ref().ok_or_else(|| {
                                EngineError::SkillValidation(
                                    "No root verifying key configured".to_string(),
                                )
                            })?;
                            verify_detached_sig(&content, sig_hex.trim(), key)?;
                        }

                        let manifest: SkillManifest =
                            serde_json::from_str(&content).map_err(|e| {
                                EngineError::SkillValidation(format!("JSON parse error: {e}"))
                            })?;

                        manifest.validate().map_err(|e| {
                            EngineError::SkillValidation(format!("Manifest validation error: {e}"))
                        })?;

                        // Index by both full ID and short name
                        map.insert(manifest.id.clone(), manifest.clone());
                        map.insert(manifest.name.clone(), manifest);
                    }
                }
            }
        }

        let count = map.len();
        let mut lock = self.skills.write().await;
        *lock = map;
        Ok(count)
    }
}

fn verify_detached_sig(
    content: &str,
    sig_hex: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), EngineError> {
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| EngineError::SkillValidation(format!("Invalid sig hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(EngineError::SkillValidation(
            "Signature must be 64 bytes".to_string(),
        ));
    }
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| EngineError::SkillValidation(e.to_string()))?;

    verifying_key
        .verify(content.as_bytes(), &signature)
        .map_err(|_| EngineError::SkillValidation("Detached signature check failed".to_string()))
}

#[async_trait]
impl SkillRegistry for StaticSkillRegistry {
    async fn list_skills(
        &self,
        _tenant_id: &str,
        _bundle: Option<&str>,
    ) -> Result<Vec<SkillManifest>, EngineError> {
        let lock = self.skills.read().await;
        let mut unique: HashMap<String, SkillManifest> = HashMap::new();
        for skill in lock.values() {
            unique.insert(skill.id.clone(), skill.clone());
        }
        Ok(unique.into_values().collect())
    }

    async fn get_skill(
        &self,
        _tenant_id: &str,
        skill_id: &str,
    ) -> Result<Option<SkillManifest>, EngineError> {
        let lock = self.skills.read().await;
        Ok(lock.get(skill_id).cloned())
    }

    async fn read_skill_docs(&self, skill_id: &str) -> Result<Option<String>, EngineError> {
        let lock = self.skills.read().await;
        if let Some(skill) = lock.get(skill_id) {
            let doc_path = self.tools_dir.join(&skill.name).join("README.md");
            if doc_path.exists() {
                return Ok(std::fs::read_to_string(doc_path).ok());
            }
        }
        Ok(None)
    }

    async fn register_remote_skill(
        &self,
        _p: RemoteSkillPublication,
    ) -> Result<SkillManifest, EngineError> {
        Err(EngineError::Internal(
            "Remote skill registration requires Pro edition".to_string(),
        ))
    }

    async fn revoke_skill(&self, _provider_did: &str, _skill_id: &str) -> Result<(), EngineError> {
        Err(EngineError::Internal(
            "Remote skill revocation requires Pro edition".to_string(),
        ))
    }
}
