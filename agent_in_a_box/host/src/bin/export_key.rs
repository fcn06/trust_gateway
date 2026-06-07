use anyhow::{Result, Context};
use clap::Parser;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key, aead::Aead};
use hkdf::Hkdf;
use argon2::Argon2;
use std::collections::HashMap;
use async_nats::jetstream;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The DID to export the key for (e.g., did:twin:z...)
    #[arg(short, long)]
    did: String,

    /// Optional password (if not using passkeys or if derivation differs)
    #[arg(short, long)]
    password: Option<String>,
}

#[derive(serde::Deserialize)]
struct HostConfig {
    nats_global_domain_url: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ServerKeys {
    house_salt: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // 1. Load Config & Keys
    let config_content = std::fs::read_to_string("config.json")
        .or_else(|_| std::fs::read_to_string("config/config.json"))
        .context("Could not find config.json")?;
    let config: HostConfig = serde_json::from_str(&config_content)?;

    let keys_content = std::fs::read_to_string("config/server.keys")
        .context("Could not find config/server.keys")?;
    let keys: ServerKeys = serde_json::from_str(&keys_content)?;
    let house_salt = &keys.house_salt;

    // 2. Connect to NATS
    println!("🔌 Connecting to NATS at {}...", config.nats_global_domain_url);
    let nc = async_nats::connect(&config.nats_global_domain_url).await?;
    let js = jetstream::new(nc);
    let vault_store = js.get_key_value("vault").await.context("Vault KV not found")?;

    // 3. Find User ID for the DID
    let did_clean = if args.did.starts_with("did:twin:z") {
        args.did.clone()
    } else {
        format!("did:twin:z{}", args.did)
    };

    let did_user_key = blind_key(&format!("did_user:{}", did_clean), house_salt);
    let user_id_bytes = vault_store.get(hex::encode(hex::encode(did_user_key))).await?
        .context("DID owner not found in Vault")?;
    let user_id = String::from_utf8(user_id_bytes.to_vec())?;
    println!("👤 Found User ID: {}", user_id);

    // 4. Get Master Seed Blob
    let master_seed_key = blind_key(&format!("master_seed:{}", user_id), house_salt);
    let master_blob = vault_store.get(hex::encode(hex::encode(master_seed_key))).await?
        .context("Master seed not found for user")?;

    // 5. Decrypt Master Seed
    // For passkey users, password = HMAC(user_id, house_salt)
    let password = match args.password {
        Some(p) => p,
        None => {
            let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(house_salt).map_err(|e| anyhow::anyhow!(e))?;
            mac.update(user_id.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
    };

    let master_seed = decrypt_master_seed(&master_blob, &password)?;
    println!("🔑 Master Seed decrypted successfully.");

    // 6. Decrypt DID Seed
    let did_seed_key = format!("seed:{}", did_clean);
    let seed_bytes = blind_get(&vault_store, &did_seed_key, house_salt, &master_seed).await?
        .context("DID seed not found in Vault")?;

    println!("\n✅ DID: {}", did_clean);
    println!("✅ Private Key (Hex): {}", hex::encode(seed_bytes));
    println!("\nCopy this key to your Shop's private.key file.");

    Ok(())
}

fn blind_key(key: &str, salt: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(salt).expect("HMAC error");
    mac.update(key.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

async fn blind_get(
    store: &jetstream::kv::Store,
    key: &str,
    house_salt: &[u8],
    master_seed: &[u8]
) -> Result<Option<Vec<u8>>> {
    let b_key = blind_key(key, house_salt);
    let blob = match store.get(hex::encode(hex::encode(b_key))).await? {
        Some(b) => b,
        None => return Ok(None),
    };

    if blob.len() < 24 {
        anyhow::bail!("Invalid blind blob size");
    }

    // Derive enc_key from master_seed
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(b"sovereign:blind-vault:encryption", &mut enc_key_bytes)
        .map_err(|_| anyhow::anyhow!("HKDF failed"))?;
    let enc_key = Key::from_slice(&enc_key_bytes);

    // Decrypt
    let nonce = XNonce::from_slice(&blob[0..24]);
    let ciphertext = &blob[24..];
    let cipher = XChaCha20Poly1305::new(enc_key);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    Ok(Some(plaintext))
}

fn decrypt_master_seed(blob: &[u8], password: &str) -> Result<Vec<u8>> {
    if blob.len() < 1 + 16 + 24 {
        anyhow::bail!("Blob too short");
    }

    let version = blob[0];
    let salt = &blob[1..17];
    let nonce_bytes = &blob[17..41];
    let ciphertext = &blob[41..];

    if version != 0x02 {
        anyhow::bail!("Unsupported blob version: 0x{:02x}", version);
    }

    // Derive KEK
    let mut kek_bytes = [0u8; 32];
    let params = argon2::Params::default();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut kek_bytes
    ).map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;
    let kek = Key::from_slice(&kek_bytes);

    let cipher = XChaCha20Poly1305::new(kek);
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Master seed decryption failed"))?;

    Ok(plaintext)
}
