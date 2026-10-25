use crate::canonical::canonical_hash;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
}

/// Sealed cryptographic receipt emitted after successful execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub grant_jti: String,
    pub contract_id: String,
    pub contract_hash: String,
    pub capability_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub issuer_did: String,
    pub counterparty_did: String,
    pub outcome: String,
    pub executed_at: DateTime<Utc>,
    pub signature: String,
}

/// Signable representation of an ExecutionReceipt for deterministic hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignableReceiptPayload {
    pub receipt_id: String,
    pub grant_jti: String,
    pub contract_id: String,
    pub contract_hash: String,
    pub capability_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub issuer_did: String,
    pub counterparty_did: String,
    pub outcome: String,
    pub executed_at: DateTime<Utc>,
}

impl From<&ExecutionReceipt> for SignableReceiptPayload {
    fn from(r: &ExecutionReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id.clone(),
            grant_jti: r.grant_jti.clone(),
            contract_id: r.contract_id.clone(),
            contract_hash: r.contract_hash.clone(),
            capability_id: r.capability_id.clone(),
            input_hash: r.input_hash.clone(),
            output_hash: r.output_hash.clone(),
            issuer_did: r.issuer_did.clone(),
            counterparty_did: r.counterparty_did.clone(),
            outcome: r.outcome.clone(),
            executed_at: r.executed_at,
        }
    }
}

pub fn compute_receipt_hash(payload: &SignableReceiptPayload) -> Result<String, ReceiptError> {
    let json_val =
        serde_json::to_value(payload).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
    Ok(canonical_hash(&json_val))
}

pub fn sign_execution_receipt(
    payload: SignableReceiptPayload,
    signing_key: &SigningKey,
) -> Result<ExecutionReceipt, ReceiptError> {
    let receipt_hash = compute_receipt_hash(&payload)?;
    let signature = signing_key.sign(receipt_hash.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    Ok(ExecutionReceipt {
        receipt_id: payload.receipt_id,
        grant_jti: payload.grant_jti,
        contract_id: payload.contract_id,
        contract_hash: payload.contract_hash,
        capability_id: payload.capability_id,
        input_hash: payload.input_hash,
        output_hash: payload.output_hash,
        issuer_did: payload.issuer_did,
        counterparty_did: payload.counterparty_did,
        outcome: payload.outcome,
        executed_at: payload.executed_at,
        signature: sig_hex,
    })
}

pub fn verify_execution_receipt(
    receipt: &ExecutionReceipt,
    verifying_key: &VerifyingKey,
) -> Result<(), ReceiptError> {
    let payload = SignableReceiptPayload::from(receipt);
    let computed_hash = compute_receipt_hash(&payload)?;

    let sig_bytes = hex::decode(&receipt.signature)
        .map_err(|e| ReceiptError::InvalidSignature(format!("Signature hex decode failed: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(ReceiptError::InvalidSignature(
            "Signature must be exactly 64 bytes".to_string(),
        ));
    }

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| ReceiptError::InvalidSignature(format!("Malformed Ed25519 signature: {e}")))?;

    verifying_key
        .verify(computed_hash.as_bytes(), &signature)
        .map_err(|_| {
            ReceiptError::InvalidSignature(format!(
                "Signature verification failed for issuer '{}'",
                receipt.issuer_did
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_sign_and_verify_roundtrip() {
        let key_bytes: [u8; 32] = [77u8; 32];
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        let payload = SignableReceiptPayload {
            receipt_id: "rcpt_100".to_string(),
            grant_jti: "grant_200".to_string(),
            contract_id: "ctr_300".to_string(),
            contract_hash: "hash_400".to_string(),
            capability_id: "io.lianxi.skill.weather@v1".to_string(),
            input_hash: "in_hash".to_string(),
            output_hash: "out_hash".to_string(),
            issuer_did: "did:web:lianxi.io".to_string(),
            counterparty_did: "did:web:partner.com".to_string(),
            outcome: "success".to_string(),
            executed_at: Utc::now(),
        };

        let receipt = sign_execution_receipt(payload, &signing_key).expect("signing should work");
        assert!(verify_execution_receipt(&receipt, &verifying_key).is_ok());

        // Tamper test: alter output_hash
        let mut tampered = receipt.clone();
        tampered.output_hash = "altered_output_hash".to_string();
        assert!(verify_execution_receipt(&tampered, &verifying_key).is_err());

        // Tamper test: alter outcome
        let mut tampered_outcome = receipt.clone();
        tampered_outcome.outcome = "failed".to_string();
        assert!(verify_execution_receipt(&tampered_outcome, &verifying_key).is_err());

        // Wrong key
        let wrong_key_bytes: [u8; 32] = [88u8; 32];
        let wrong_key = SigningKey::from_bytes(&wrong_key_bytes).verifying_key();
        assert!(verify_execution_receipt(&receipt, &wrong_key).is_err());
    }
}
