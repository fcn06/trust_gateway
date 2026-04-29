use crate::{blind_get, blind_key};
use crate::sovereign::gateway::persistence;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier};
use serde_json::json;
use base64::Engine;

pub struct IssueSessionJwtCommand {
    pub subject: String,
    pub scope: Vec<String>,
    pub user_did: String,
    pub ttl_seconds: u32,
    pub tenant_id: String,
}

impl IssueSessionJwtCommand {
    pub fn execute(&self) -> Result<String, String> {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiration = issued_at + self.ttl_seconds as u64;

        let b_key = blind_key(&format!("did_user:{}", self.user_did));
        let user_id_bytes = persistence::get(&b_key).map_err(|e| format!("Persistence error: {:?}", e))?.ok_or("DID owner not found")?;
        let user_id = String::from_utf8(user_id_bytes).map_err(|_| "Invalid user_id")?;

        let seed_bytes = blind_get(&format!("seed:{}", self.user_did), &user_id)?
            .ok_or("Seed not found")?;
        let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| "Invalid seed length")?;

        let signing_key = SigningKey::from_bytes(&seed);
        
        let header = json!({
            "alg": "EdDSA",
            "typ": "JWT"
        });

        let payload = json!({
            "iss": self.user_did,
            "sub": self.subject,
            "scope": self.scope,
            "tenant_id": self.tenant_id,
            "iat": issued_at,
            "exp": expiration,
            "jti": uuid::Uuid::new_v4().to_string()
        });

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        let message = format!("{}.{}", header_b64, payload_b64);

        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, sig_b64))
    }
}

pub struct VerifySessionJwtCommand {
    pub jwt: String,
}

impl VerifySessionJwtCommand {
    pub fn execute(&self) -> Result<String, String> {
        let parts: Vec<&str> = self.jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".to_string());
        }

        let payload_json = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
                .map_err(|_| "Payload B64 decode failed")?
        ).map_err(|_| "Payload UTF8 decode failed")?;

        let payload: serde_json::Value = serde_json::from_str(&payload_json)
            .map_err(|_| "Payload JSON parse failed")?;

        let iss = payload.get("iss").and_then(|v| v.as_str()).ok_or("Missing iss")?;
        
        if !iss.starts_with("did:twin:z") || iss.len() < 11 {
            return Err("Invalid issuer DID format".to_string());
        }
        
        let hex_part = &iss[10..];
        let pub_key_bytes = hex::decode(hex_part).map_err(|_| "Hex decode failed")?;
        let pub_key_arr: [u8; 32] = pub_key_bytes.try_into().map_err(|_| "Invalid key length")?;
        
        let pub_key = VerifyingKey::from_bytes(&pub_key_arr).map_err(|_| "Invalid VerifyingKey")?;

        let message = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])
            .map_err(|_| "Signature B64 decode failed")?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "Invalid signature length")?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        pub_key.verify(message.as_bytes(), &signature).map_err(|_| "Signature verification failed")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
            if now > exp {
                return Err("JWT expired".to_string());
            }
        }

        Ok(payload_json)
    }
}
