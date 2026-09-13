use crate::error::ContractError;
use crate::model::{ExecutionReceipt, SignableReceiptPayload};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use trust_canonical::canonical_hash;

/// Compute deterministic SHA-256 canonical hash of an execution receipt payload.
pub fn compute_receipt_hash(payload: &SignableReceiptPayload) -> Result<String, ContractError> {
    let json_val = serde_json::to_value(payload)
        .map_err(|e| ContractError::SerializationError(e.to_string()))?;
    Ok(canonical_hash(&json_val))
}

/// Sign an execution receipt using the Gateway's Ed25519 signing key.
pub fn sign_execution_receipt(
    payload: SignableReceiptPayload,
    signing_key: &SigningKey,
) -> Result<ExecutionReceipt, ContractError> {
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

/// Verify an ExecutionReceipt against an Ed25519 VerifyingKey.
pub fn verify_execution_receipt(
    receipt: &ExecutionReceipt,
    verifying_key: &VerifyingKey,
) -> Result<(), ContractError> {
    let payload = SignableReceiptPayload::from(receipt);
    let computed_hash = compute_receipt_hash(&payload)?;

    let sig_bytes = hex::decode(&receipt.signature).map_err(|e| {
        ContractError::InvalidAttestation(format!("Receipt signature hex decode failed: {e}"))
    })?;

    if sig_bytes.len() != 64 {
        return Err(ContractError::InvalidAttestation(
            "Receipt signature must be 64 bytes".to_string(),
        ));
    }

    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        ContractError::InvalidAttestation(format!("Malformed receipt Ed25519 signature: {e}"))
    })?;

    verifying_key
        .verify(computed_hash.as_bytes(), &signature)
        .map_err(|_| {
            ContractError::InvalidAttestation(format!(
                "Receipt signature verification failed for issuer '{}'",
                receipt.issuer_did
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_receipt_signing_and_verification_roundtrip() {
        let keypair_bytes: [u8; 32] = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&keypair_bytes);
        let verifying_key = signing_key.verifying_key();

        let payload = SignableReceiptPayload {
            receipt_id: "rcpt_001".to_string(),
            grant_jti: "grant_123".to_string(),
            contract_id: "ctr_abc".to_string(),
            contract_hash: "sha256:contract123".to_string(),
            capability_id: "io.company.orders@v1".to_string(),
            input_hash: "sha256:input456".to_string(),
            output_hash: "sha256:output789".to_string(),
            issuer_did: "did:web:buyer.example.corp".to_string(),
            counterparty_did: "did:web:supplier.example.corp".to_string(),
            outcome: "SUCCESS".to_string(),
            executed_at: Utc::now(),
        };

        let receipt =
            sign_execution_receipt(payload, &signing_key).expect("signing should succeed");

        assert!(verify_execution_receipt(&receipt, &verifying_key).is_ok());

        // Tamper test: modify output_hash
        let mut tampered = receipt.clone();
        tampered.output_hash = "sha256:tampered_output".to_string();
        assert!(verify_execution_receipt(&tampered, &verifying_key).is_err());

        // Tamper test: modify outcome
        let mut tampered_outcome = receipt.clone();
        tampered_outcome.outcome = "FAILED".to_string();
        assert!(verify_execution_receipt(&tampered_outcome, &verifying_key).is_err());

        // Tamper test: wrong verifying key
        let wrong_key_bytes: [u8; 32] = [99u8; 32];
        let wrong_signing_key = SigningKey::from_bytes(&wrong_key_bytes);
        let wrong_verifying_key = wrong_signing_key.verifying_key();
        assert!(verify_execution_receipt(&receipt, &wrong_verifying_key).is_err());
    }
}
