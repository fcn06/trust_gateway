use std::collections::HashMap;
use std::sync::Mutex;
use ed25519_dalek::SigningKey;
use jwt_simple::prelude::*;

wit_bindgen::generate!({
    world: "identity-server",
    path: "../wit",
});

use sovereign::gateway::vault;
use exports::sovereign::gateway::identity::{Guest, AuthSession};

struct IdentityServer;

static SESSIONS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

impl Guest for IdentityServer {
    fn authenticate(id: String) -> AuthSession {
        let _did = vault::get_active_did(&id);
        
        // Generate pseudo-NKey seed using ed25519-dalek
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        
        // In a real implementation we would format this as an NKey
        let nkey_seed = hex::encode(signing_key.to_bytes());
        
        AuthSession {
            user_id: id,
            nkey_seed,
        }
    }

    fn start_registration(username: String) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let options = serde_json::json!({
            "challenge": "mock-challenge",
            "user": {
                "id": uuid::Uuid::new_v4().to_string(),
                "name": username,
                "displayName": username
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
        });
        
        let mut sessions = SESSIONS.lock().unwrap();
        if sessions.is_none() {
            *sessions = Some(HashMap::new());
        }
        sessions.as_mut().unwrap().insert(session_id.clone(), username);
        
        serde_json::to_string(&serde_json::json!({
            "session_id": session_id,
            "options": options
        })).unwrap()
    }

    fn finish_registration(session_id: String, _response: String) -> bool {
        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(s) = sessions.as_mut() {
            if let Some(username) = s.remove(&session_id) {
                vault::create_identity(&username);
                return true;
            }
        }
        false
    }

    fn start_login(username: String) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let options = serde_json::json!({
            "challenge": "mock-login-challenge",
            "allowCredentials": []
        });
        
        let mut sessions = SESSIONS.lock().unwrap();
        if sessions.is_none() {
            *sessions = Some(HashMap::new());
        }
        sessions.as_mut().unwrap().insert(session_id.clone(), username);
        
        serde_json::to_string(&serde_json::json!({
            "session_id": session_id,
            "options": options
        })).unwrap()
    }

    fn finish_login(session_id: String, _response: String) -> String {
        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(s) = sessions.as_mut() {
            if let Some(username) = s.remove(&session_id) {
                // Use jwt-simple for pure-rust JWT
                let key = Ed25519KeyPair::generate();
                let claims = Claims::with_custom_claims(serde_json::json!({ "sub": username }), Duration::from_hours(1));
                return key.sign(claims).unwrap_or_else(|_| "error".to_string());
            }
        }
        "error".to_string()
    }

    fn process_global_login(assertion: Vec<u8>) -> Result<bool, String> {
        // Blueprint: This handles login requests arriving via NATS from the Global Web Service
        // The assertion is a WebAuthn assertion that was created on the Global Portal
        // and routed through NATS to this Local Gateway
        
        // TODO: Implement full WebAuthn verification flow
        // For now, this is a placeholder that logs and returns success if assertion is non-empty
        
        if assertion.is_empty() {
            return Err("Empty assertion".to_string());
        }
        
        tracing::info!("🌐 Processing global login assertion ({} bytes)", assertion.len());
        
        // In production:
        // 1. Decode the assertion
        // 2. Look up the credential from our local store
        // 3. Verify the assertion signature
        // 4. If valid, unlock the vault
        // 5. Return success
        
        Ok(true) // Placeholder
    }
}

export!(IdentityServer);
