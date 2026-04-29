//! Create Identity command implementation.
//!
//! Handles DID identity creation with deterministic derivation from master seed,
//! with fallback to random generation for locked vaults.

use crate::commands::VaultCommand;
use crate::{
    MasterSeed, EPHEMERAL_SEEDS,
    get_master_seed, count_user_dids, derive_did_key, 
    blind_set, blind_get, blind_key,
};
use ed25519_dalek::SigningKey;
use crate::sovereign::gateway::persistence;

/// Command to create a new DID identity for a user.
pub struct CreateIdentityCommand {
    pub user_id: String,
    pub is_peer: bool,
}

impl VaultCommand for CreateIdentityCommand {
    type Output = String;

    fn execute(&self) -> Result<Self::Output, String> {
        // Derive or generate signing key
        let signing_key = self.derive_or_generate_key()?;
        
        let verifying_key = signing_key.verifying_key();
        let prefix = if self.is_peer { "did:peer:z" } else { "did:twin:z" };
        let did = format!("{}{}", prefix, hex::encode(verifying_key.to_bytes().as_slice()));
        
        // Store the seed
        self.store_seed(&did, &signing_key)?;
        
        // Update user's DID list (peer DIDs now perfectly match twin DIDs in UI)
        self.update_did_list(&did)?;
        // Set active DID if not set
        self.set_active_if_needed(&did)?;
        
        tracing::info!("✅ Created identity - DID: {} | User: {} (is_peer: {})", did, self.user_id, self.is_peer);
        Ok(did)
    }
}

impl CreateIdentityCommand {
    /// Derive key from master seed or generate random fallback.
    fn derive_or_generate_key(&self) -> Result<SigningKey, String> {
        if let Ok(seed_guard) = get_master_seed(&self.user_id) {
            // Unlocked: Deterministic derivation
            let did_count = count_user_dids(&self.user_id);
            Ok(derive_did_key(&seed_guard.0, did_count))
        } else {
            // Locked: Generate random (discouraged but kept for safety)
            tracing::warn!("⚠️ Vault LOCKED: Generating non-recoverable random DID for {}", self.user_id);
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| "Failed to get entropy")?;
            Ok(SigningKey::from_bytes(&seed))
        }
    }
    
    /// Store signing key seed (blind encrypted or ephemeral).
    fn store_seed(&self, did: &str, signing_key: &SigningKey) -> Result<(), String> {
        if get_master_seed(&self.user_id).is_ok() {
            blind_set(&format!("seed:{}", did), &signing_key.to_bytes().to_vec(), &self.user_id)?;
        } else {
            tracing::warn!("⚠️ Vault LOCKED: Storing ephemeral seed for {} in memory only.", did);
            let mut map = EPHEMERAL_SEEDS.lock().unwrap();
            map.insert(did.to_string(), signing_key.to_bytes().to_vec());
        }
        Ok(())
    }
    
    /// Update user's DID list and reverse mapping.
    fn update_did_list(&self, did: &str) -> Result<(), String> {
        let mut dids: Vec<String> = match blind_get(&format!("user_dids:{}", self.user_id), &self.user_id) {
            Ok(Some(val)) => serde_json::from_slice(&val).unwrap_or_default(),
            _ => Vec::new(),
        };
        
        if !dids.contains(&did.to_string()) {
            dids.push(did.to_string());
            blind_set(&format!("user_dids:{}", self.user_id), &serde_json::to_vec(&dids).unwrap(), &self.user_id)?;
            let _ = persistence::set(&blind_key(&format!("did_user:{}", did)), self.user_id.as_bytes());
        }
        
        Ok(())
    }
    
    /// Set active DID if none is currently set.
    fn set_active_if_needed(&self, did: &str) -> Result<(), String> {
        if let Ok(None) = blind_get(&format!("active_did:{}", self.user_id), &self.user_id) {
            let _ = blind_set(&format!("active_did:{}", self.user_id), did.as_bytes(), &self.user_id);
        }
        Ok(())
    }
}
