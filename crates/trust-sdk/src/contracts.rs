use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("Contract signature verification failed")]
    InvalidSignature,
    #[error("Contract expired at {0}, current time {1}")]
    ContractExpired(i64, i64),
    #[error("Tool mismatch: contract is for '{expected}', but called for '{actual}'")]
    ToolMismatch { expected: String, actual: String },
    #[error("Input violation against contract constraint: {0}")]
    ConstraintViolation(String),
    #[error("Contract serialization error: {0}")]
    SerializationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_cents: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_operations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedContract {
    pub contract_id: String,
    pub version: String,
    pub skill_id: String,
    pub author_did: String,
    pub schema_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_constraints: Option<InputConstraints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_ir_hash: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub signature: String,
}

impl SignedContract {
    pub fn compute_canonical_hash(&self) -> Result<String, ContractError> {
        // Clone with empty signature for signing/verifying canonical contract body
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        let canonical_bytes = serde_json::to_vec(&unsigned)
            .map_err(|e| ContractError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), ContractError> {
        let hash = self.compute_canonical_hash()?;
        let sig = signing_key.sign(hash.as_bytes());
        self.signature = hex::encode(sig.to_bytes());
        Ok(())
    }

    pub fn verify(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ContractError> {
        let hash = self.compute_canonical_hash()?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| ContractError::InvalidSignature)?;

        if sig_bytes.len() != 64 {
            return Err(ContractError::InvalidSignature);
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&arr);

        verifying_key
            .verify(hash.as_bytes(), &signature)
            .map_err(|_| ContractError::InvalidSignature)
    }

    pub fn validate_input(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
        now: i64,
    ) -> Result<(), ContractError> {
        // 1. Expiry check
        if self.expires_at > 0 && now > self.expires_at {
            return Err(ContractError::ContractExpired(self.expires_at, now));
        }

        // 2. Tool name match
        if self.skill_id != tool_name && !self.skill_id.ends_with(&format!(".{tool_name}@v1")) {
            return Err(ContractError::ToolMismatch {
                expected: self.skill_id.clone(),
                actual: tool_name.to_string(),
            });
        }

        // 3. Input constraints
        if let Some(ref constraints) = self.input_constraints {
            if let serde_json::Value::Object(map) = arguments {
                // Check required fields
                if let Some(ref reqs) = constraints.required_fields {
                    for req in reqs {
                        if !map.contains_key(req) {
                            return Err(ContractError::ConstraintViolation(format!(
                                "Mandatory field '{req}' missing from arguments"
                            )));
                        }
                    }
                }

                // Check forbidden fields
                if let Some(ref forbs) = constraints.forbidden_fields {
                    for forb in forbs {
                        if map.contains_key(forb) {
                            return Err(ContractError::ConstraintViolation(format!(
                                "Forbidden field '{forb}' present in arguments"
                            )));
                        }
                    }
                }

                // Check max amount cents
                if let Some(max_cents) = constraints.max_amount_cents {
                    for key in ["amount_cents", "amount", "cost", "price"] {
                        if let Some(val) = map.get(key) {
                            let cents = match val {
                                serde_json::Value::Number(n) => {
                                    if key == "amount_cents" {
                                        n.as_u64().unwrap_or(0)
                                    } else {
                                        (n.as_f64().unwrap_or(0.0) * 100.0) as u64
                                    }
                                }
                                serde_json::Value::String(s) => {
                                    (s.parse::<f64>().unwrap_or(0.0) * 100.0) as u64
                                }
                                _ => 0,
                            };
                            if cents > max_cents {
                                return Err(ContractError::ConstraintViolation(format!(
                                    "Financial amount {cents} cents exceeds contract limit of {max_cents} cents"
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_contract_lifecycle_and_verification() {
        let seed = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut contract = SignedContract {
            contract_id: "contract_vendor_ops_v1".to_string(),
            version: "1.0.0".to_string(),
            skill_id: "claw_weather".to_string(),
            author_did: "did:web:enterprise.com".to_string(),
            schema_hash: "abcd1234ef5678".to_string(),
            input_constraints: Some(InputConstraints {
                max_amount_cents: Some(10000), // $100.00 max
                required_fields: Some(vec!["location".to_string()]),
                forbidden_fields: Some(vec!["secret_key".to_string()]),
                allowed_operations: None,
            }),
            mapping_ir_hash: None,
            created_at: 1730000000,
            expires_at: 1739999999,
            signature: String::new(),
        };

        // Sign contract
        contract.sign(&signing_key).unwrap();
        assert!(!contract.signature.is_empty());

        // Verify valid signature
        assert!(contract.verify(&verifying_key).is_ok());

        // Tamper test
        let mut tampered = contract.clone();
        tampered.version = "1.0.1".to_string();
        assert_eq!(tampered.verify(&verifying_key), Err(ContractError::InvalidSignature));

        // Valid input passes
        let valid_args = serde_json::json!({ "location": "Berlin" });
        assert!(contract.validate_input("claw_weather", &valid_args, 1730000010).is_ok());

        // Missing required field fails
        let missing_args = serde_json::json!({ "query": "Berlin" });
        assert!(contract.validate_input("claw_weather", &missing_args, 1730000010).is_err());

        // Forbidden field fails
        let forbidden_args = serde_json::json!({ "location": "Berlin", "secret_key": "123" });
        assert!(contract.validate_input("claw_weather", &forbidden_args, 1730000010).is_err());
    }
}

