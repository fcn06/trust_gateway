//! Unlock Vault command implementation.
//!
//! Handles vault unlocking with encrypted master seed decryption,
//! legacy V1 support, and HMAC secret self-healing.

use crate::commands::VaultCommand;
use crate::{
    MasterSeed, UNLOCKED_USERS, 
    blind_key, derive_kek,
    SALT_LEN, NONCE_LEN, INFO_HMAC_SECRET,
};
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::Aead, KeyInit};
use crate::sovereign::gateway::persistence;

/// Command to unlock a user's vault using their derivation path (password/PRF).
pub struct UnlockVaultCommand {
    pub user_id: String,
    pub derivation_path: String,
}

impl VaultCommand for UnlockVaultCommand {
    type Output = bool;

    fn execute(&self) -> Result<Self::Output, String> {
        let key = format!("master_seed:{}", self.user_id);
        
        // 1. Fetch encrypted blob (Hashed Key)
        let blob = persistence::get(&blind_key(&key)).ok_or("No Master Seed found")?;
        
        // Support Legacy V1 (Unencrypted) Master Seed
        if blob.len() == 32 {
            tracing::info!("📦 Found legacy V1 vault for user: {}", self.user_id);
            let master_seed = MasterSeed(blob);
            UNLOCKED_USERS.lock().unwrap().insert(self.user_id.clone(), master_seed.clone());
            
            // Self-heal: write hmac_secret
            self.write_hmac_secret(&master_seed)?;
            return Ok(true);
        }

        // Validate blob size
        if blob.len() < 1 + SALT_LEN + NONCE_LEN {
            return Err("Invalid blob size".to_string());
        }
        
        // 2. Parse Blob
        let version = blob[0];
        if version != 0x02 {
            return Err(format!("Unsupported vault version: {}", version));
        }

        let salt = &blob[1..1+SALT_LEN];
        let nonce_bytes = &blob[1+SALT_LEN..1+SALT_LEN+NONCE_LEN];
        let ciphertext = &blob[1+SALT_LEN+NONCE_LEN..];

        // 3. Derive KEK
        let kek = derive_kek(&self.derivation_path, salt)?;

        // 4. Decrypt
        let cipher = XChaCha20Poly1305::new(&kek);
        let nonce = XNonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed: Invalid credentials")?;

        if plaintext.len() != 32 {
            return Err("Invalid decrypted seed length".to_string());
        }

        // Add to in-memory unlocks
        let master_seed = MasterSeed(plaintext);
        UNLOCKED_USERS.lock().unwrap().insert(self.user_id.clone(), master_seed.clone());
        
        // Self-heal: write hmac_secret
        self.write_hmac_secret(&master_seed)?;
        
        tracing::info!("🔓 Vault successfully unlocked for user: {}", self.user_id);
        Ok(true)
    }
}

impl UnlockVaultCommand {
    /// Write HMAC secret for global login support (self-healing).
    fn write_hmac_secret(&self, master_seed: &MasterSeed) -> Result<(), String> {
        let hk = Hkdf::<Sha256>::new(None, &master_seed.0);
        let mut routing_secret = [0u8; 32];
        
        if hk.expand(INFO_HMAC_SECRET, &mut routing_secret).is_ok() {
            let h_key = blind_key(&format!("hmac_secret:{}", self.user_id));
            persistence::set(&h_key, &routing_secret.to_vec());
            tracing::info!("🔒 Verified/Updated hmac_secret for user: {}", self.user_id);
        }
        
        Ok(())
    }
}
