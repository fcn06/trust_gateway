use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UcanError {
    #[error("Invalid UCAN format: {0}")]
    InvalidFormat(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid capability attenuation: {0}")]
    InvalidAttenuation(String),
    #[error("Token expired")]
    Expired,
    #[error("Token not yet active")]
    NotYetActive,
    #[error("Delegation chain broken: aud '{0}' does not match next iss '{1}'")]
    DelegationChainBroken(String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UcanCapability {
    pub with: String,
    pub can: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_minor_units: Option<u64>,
}

impl UcanCapability {
    pub fn new(
        with: impl Into<String>,
        can: impl Into<String>,
        max_cost_minor_units: Option<u64>,
    ) -> Self {
        Self {
            with: with.into(),
            can: can.into(),
            max_cost_minor_units,
        }
    }

    /// Pure attenuation math: does `self` strictly attenuate or equal `parent`?
    pub fn is_attenuation_of(&self, parent: &UcanCapability) -> bool {
        // 1. Resource check (`with`)
        let with_ok = if parent.with == "*" || parent.with == "tool:*" {
            true
        } else if parent.with.ends_with('*') {
            let prefix = &parent.with[..parent.with.len() - 1];
            self.with.starts_with(prefix)
        } else {
            self.with == parent.with
        };

        if !with_ok {
            return false;
        }

        // 2. Action check (`can`)
        let can_ok = if parent.can == "*" || parent.can == "tool/*" {
            true
        } else if parent.can.ends_with('*') {
            let prefix = &parent.can[..parent.can.len() - 1];
            self.can.starts_with(prefix)
        } else {
            self.can == parent.can
        };

        if !can_ok {
            return false;
        }

        // 3. Cost constraint check: child cannot remove or exceed a parent cost cap
        match (self.max_cost_minor_units, parent.max_cost_minor_units) {
            (Some(child_cost), Some(parent_cost)) => child_cost <= parent_cost,
            (None, Some(_)) => false, // Cannot widen cap to unlimited
            (_, None) => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UcanHeader {
    pub alg: String,
    pub typ: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ucv: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UcanPayload {
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    pub att: Vec<UcanCapability>,
    #[serde(default)]
    pub prf: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fct: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct UcanToken {
    pub raw: String,
    pub header: UcanHeader,
    pub payload: UcanPayload,
    pub signed_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UcanToken {
    pub fn parse(token_str: &str) -> Result<Self, UcanError> {
        let trimmed = token_str.trim();
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 3 {
            return Err(UcanError::InvalidFormat(format!(
                "Expected 3 parts in UCAN JWT, found {}",
                parts.len()
            )));
        }

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header_bytes = b64
            .decode(parts[0])
            .map_err(|e| UcanError::InvalidFormat(format!("Header base64 error: {e}")))?;
        let header: UcanHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| UcanError::InvalidFormat(format!("Header JSON error: {e}")))?;

        if header.alg != "EdDSA" {
            return Err(UcanError::InvalidFormat(format!(
                "Unsupported alg '{}', expected EdDSA",
                header.alg
            )));
        }

        let payload_bytes = b64
            .decode(parts[1])
            .map_err(|e| UcanError::InvalidFormat(format!("Payload base64 error: {e}")))?;
        let payload: UcanPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| UcanError::InvalidFormat(format!("Payload JSON error: {e}")))?;

        let sig_bytes = b64
            .decode(parts[2])
            .map_err(|e| UcanError::InvalidFormat(format!("Signature base64 error: {e}")))?;

        if sig_bytes.len() != 64 {
            return Err(UcanError::SignatureError(
                "Signature must be 64 bytes".to_string(),
            ));
        }

        let signed_data = format!("{}.{}", parts[0], parts[1]).into_bytes();

        Ok(Self {
            raw: trimmed.to_string(),
            header,
            payload,
            signed_data,
            signature: sig_bytes,
        })
    }

    pub fn verify_signature(&self, public_key_bytes: &[u8; 32]) -> Result<(), UcanError> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| UcanError::SignatureError(e.to_string()))?;

        let sig = Signature::from_slice(&self.signature)
            .map_err(|e| UcanError::SignatureError(e.to_string()))?;

        verifying_key
            .verify(&self.signed_data, &sig)
            .map_err(|_| UcanError::VerificationFailed)
    }

    pub fn check_timestamps(&self, now: u64) -> Result<(), UcanError> {
        if now >= self.payload.exp {
            return Err(UcanError::Expired);
        }
        if let Some(nbf) = self.payload.nbf {
            if now < nbf {
                return Err(UcanError::NotYetActive);
            }
        }
        Ok(())
    }
}

/// Helper to mint an Ed25519-signed UCAN token
pub fn mint_ucan(
    issuer_did: &str,
    signing_seed: &[u8; 32],
    audience_did: &str,
    exp: u64,
    att: Vec<UcanCapability>,
    prf: Vec<String>,
) -> Result<String, UcanError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = UcanHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
        ucv: Some("0.8.1".to_string()),
    };

    let payload = UcanPayload {
        iss: issuer_did.to_string(),
        aud: audience_did.to_string(),
        exp,
        nbf: None,
        att,
        prf,
        fct: None,
    };

    let header_json =
        serde_json::to_vec(&header).map_err(|e| UcanError::InvalidFormat(e.to_string()))?;
    let payload_json =
        serde_json::to_vec(&payload).map_err(|e| UcanError::InvalidFormat(e.to_string()))?;

    let h_b64 = b64.encode(header_json);
    let p_b64 = b64.encode(payload_json);

    let signing_input = format!("{h_b64}.{p_b64}");
    let signing_key = SigningKey::from_bytes(signing_seed);
    let sig = signing_key.sign(signing_input.as_bytes());
    let s_b64 = b64.encode(sig.to_bytes());

    Ok(format!("{signing_input}.{s_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ucan_capability_attenuation() {
        let parent = UcanCapability::new("tool:*", "tool/*", Some(1000));

        // Sub-tool with tighter cost cap is valid
        let child_valid =
            UcanCapability::new("tool:io.lianxi.skill.search@v1", "tool/execute", Some(500));
        assert!(child_valid.is_attenuation_of(&parent));

        // Equal capability is valid
        assert!(parent.is_attenuation_of(&parent));

        // Higher cost cap violates attenuation
        let child_expensive =
            UcanCapability::new("tool:io.lianxi.skill.search@v1", "tool/execute", Some(2000));
        assert!(!child_expensive.is_attenuation_of(&parent));

        // Uncapped child violates parent's capped budget
        let child_uncapped =
            UcanCapability::new("tool:io.lianxi.skill.search@v1", "tool/execute", None);
        assert!(!child_uncapped.is_attenuation_of(&parent));

        // Different root resource violates attenuation
        let specific_parent =
            UcanCapability::new("tool:io.lianxi.skill.search@v1", "tool/execute", Some(100));
        let unallowed_child =
            UcanCapability::new("tool:io.lianxi.skill.delete@v1", "tool/execute", Some(50));
        assert!(!unallowed_child.is_attenuation_of(&specific_parent));
    }

    #[test]
    fn test_ucan_mint_and_verify() {
        let seed = [55u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let iss = "did:twin:z123";
        let aud = "did:twin:z456";

        let cap = vec![UcanCapability::new("tool:*", "tool/*", Some(500))];
        let token_str = mint_ucan(iss, &seed, aud, 2000000000, cap.clone(), vec![]).unwrap();

        let parsed = UcanToken::parse(&token_str).unwrap();
        assert_eq!(parsed.payload.iss, iss);
        assert_eq!(parsed.payload.aud, aud);
        assert!(parsed.verify_signature(&pubkey).is_ok());

        // Verification fails with wrong key
        let wrong_key = [99u8; 32];
        assert!(parsed.verify_signature(&wrong_key).is_err());
    }
}
