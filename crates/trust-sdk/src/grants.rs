use crate::canonical::canonical_hash;
use crate::model::{EconomicClaim, ExecutionBudget};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("JWT verification failed: {0}")]
    SignatureVerification(String),

    #[error("Algorithm not permitted (strictly Ed25519 required): {0}")]
    DisallowedAlgorithm(String),

    #[error("Token expired at {0}, current time {1}")]
    TokenExpired(i64, i64),

    #[error("Audience mismatch: expected '{expected}', got '{actual}'")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Tool name mismatch: grant authorizes '{authorized}', but requested '{requested}'")]
    ToolMismatch {
        authorized: String,
        requested: String,
    },

    #[error("Input hash mismatch: grant has '{claimed}', calculated '{calculated}'")]
    InputHashMismatch { claimed: String, calculated: String },

    #[error("Missing mandatory grant claim: {0}")]
    MissingMandatoryClaim(String),
}

/// How an execution grant was obtained
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantClearance {
    #[default]
    AutoApproved,
    HumanApproved,
    ElevatedApproval,
    ProofVerified,
}

impl std::fmt::Display for GrantClearance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AutoApproved => write!(f, "auto_approved"),
            Self::HumanApproved => write!(f, "human_approved"),
            Self::ElevatedApproval => write!(f, "elevated_approval"),
            Self::ProofVerified => write!(f, "proof_verified"),
        }
    }
}

/// Short-lived Ed25519 execution grant token payload
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Default)]
pub struct ExecutionGrant {
    #[serde(default, alias = "grant_id")]
    pub jti: String,
    #[serde(default)]
    pub action_id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    #[serde(default, alias = "allowed_action")]
    pub tool_name: String,
    #[serde(default)]
    pub input_hash: String,
    #[serde(default, alias = "issuer")]
    pub iss: String,
    #[serde(default, alias = "expires_at")]
    pub exp: i64,
    #[serde(default, alias = "policy_hash")]
    pub policy_fingerprint: String,
    #[serde(default)]
    pub clearance: GrantClearance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_claim: Option<EconomicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ExecutionBudget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_attestation: Option<String>,
}

fn default_workspace_id() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantCustomClaims {
    #[serde(default)]
    action_id: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    workspace_id: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    input_hash: String,
    #[serde(default)]
    policy_fingerprint: String,
    #[serde(default)]
    clearance: GrantClearance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    economic_claim: Option<EconomicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget: Option<ExecutionBudget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contract_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lineage_attestation: Option<String>,
}

/// Helper to sign an ExecutionGrant into a JWT with Ed25519
pub fn sign_grant_jwt(
    grant: &ExecutionGrant,
    aud: &str,
    key_pair: &Ed25519KeyPair,
) -> Result<String, GrantError> {
    let now = chrono::Utc::now().timestamp();
    let ttl_secs = (grant.exp - now).max(1);

    let custom = GrantCustomClaims {
        action_id: grant.action_id.clone(),
        tenant_id: grant.tenant_id.clone(),
        workspace_id: grant.workspace_id.clone(),
        tool_name: grant.tool_name.clone(),
        input_hash: grant.input_hash.clone(),
        policy_fingerprint: grant.policy_fingerprint.clone(),
        clearance: grant.clearance,
        economic_claim: grant.economic_claim.clone(),
        budget: grant.budget.clone(),
        contract_id: grant.contract_id.clone(),
        contract_hash: grant.contract_hash.clone(),
        lineage_attestation: grant.lineage_attestation.clone(),
    };

    let claims = Claims::with_custom_claims(custom, Duration::from_secs(ttl_secs as u64))
        .with_issuer(&grant.iss)
        .with_jwt_id(&grant.jti)
        .with_audience(aud);

    key_pair
        .sign(claims)
        .map_err(|e| GrantError::SignatureVerification(e.to_string()))
}

/// Pure validation of an ExecutionGrant JWT
pub fn validate_bound(
    grant_jwt: &str,
    expected_tool: &str,
    canonical_args: &serde_json::Value,
    expected_aud: &str,
    public_key: &Ed25519PublicKey,
) -> Result<ExecutionGrant, GrantError> {
    // 1. Verify header strictly forbids alg=none and HMAC
    let metadata = Token::decode_metadata(grant_jwt)
        .map_err(|e| GrantError::DisallowedAlgorithm(format!("Invalid JWT metadata: {e}")))?;

    let alg = metadata.algorithm();
    if alg != "EdDSA" && alg != "Ed25519" {
        return Err(GrantError::DisallowedAlgorithm(format!(
            "Only Ed25519/EdDSA is accepted, found '{alg}'"
        )));
    }

    // 2. Full signature, exp, and audience verification via public key
    let mut options = VerificationOptions::default();
    let mut aud_set = std::collections::HashSet::new();
    aud_set.insert(expected_aud.to_string());
    options.allowed_audiences = Some(aud_set);

    let token_claims = public_key
        .verify_token::<GrantCustomClaims>(grant_jwt, Some(options))
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("expired") {
                GrantError::TokenExpired(0, 0)
            } else if err_str.contains("audience") {
                GrantError::AudienceMismatch {
                    expected: expected_aud.to_string(),
                    actual: "mismatched".to_string(),
                }
            } else {
                GrantError::SignatureVerification(err_str)
            }
        })?;

    let jti = token_claims.jwt_id.unwrap_or_default();
    let iss = token_claims.issuer.unwrap_or_default();
    let exp = token_claims
        .expires_at
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let custom = token_claims.custom;

    let grant = ExecutionGrant {
        jti,
        action_id: custom.action_id,
        tenant_id: custom.tenant_id,
        workspace_id: custom.workspace_id,
        tool_name: custom.tool_name,
        input_hash: custom.input_hash,
        iss,
        exp,
        policy_fingerprint: custom.policy_fingerprint,
        clearance: custom.clearance,
        economic_claim: custom.economic_claim,
        budget: custom.budget,
        contract_id: custom.contract_id,
        contract_hash: custom.contract_hash,
        lineage_attestation: custom.lineage_attestation,
    };

    // 3. Expiration double check
    let now = chrono::Utc::now().timestamp();
    if grant.exp < now {
        return Err(GrantError::TokenExpired(grant.exp, now));
    }

    // 4. Mandatory claims check
    if grant.jti.is_empty() {
        return Err(GrantError::MissingMandatoryClaim("jti".to_string()));
    }
    if grant.iss.is_empty() {
        return Err(GrantError::MissingMandatoryClaim("iss".to_string()));
    }
    if grant.tenant_id.is_empty() {
        return Err(GrantError::MissingMandatoryClaim("tenant_id".to_string()));
    }
    if grant.policy_fingerprint.is_empty() {
        return Err(GrantError::MissingMandatoryClaim(
            "policy_fingerprint".to_string(),
        ));
    }
    if grant.input_hash.is_empty() {
        return Err(GrantError::MissingMandatoryClaim("input_hash".to_string()));
    }

    // 5. Tool name match
    if grant.tool_name != expected_tool {
        return Err(GrantError::ToolMismatch {
            authorized: grant.tool_name,
            requested: expected_tool.to_string(),
        });
    }

    // 6. Canonical input hash match
    let computed_hash = canonical_hash(canonical_args);
    if grant.input_hash != computed_hash {
        return Err(GrantError::InputHashMismatch {
            claimed: grant.input_hash,
            calculated: computed_hash,
        });
    }

    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn create_test_grant(tool_name: &str, input_hash: &str, exp: i64) -> ExecutionGrant {
        ExecutionGrant {
            jti: "grant_12345".to_string(),
            action_id: "act_999".to_string(),
            tenant_id: "tenant_default".to_string(),
            workspace_id: "default".to_string(),
            tool_name: tool_name.to_string(),
            input_hash: input_hash.to_string(),
            iss: "trust_gateway".to_string(),
            exp,
            policy_fingerprint: "pol_fingerprint_abc".to_string(),
            clearance: GrantClearance::AutoApproved,
            economic_claim: None,
            budget: None,
            contract_id: None,
            contract_hash: None,
            lineage_attestation: None,
        }
    }

    #[test]
    fn test_validate_bound_success() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let args = serde_json::json!({"location": "London"});
        let hash = canonical_hash(&args);
        let now = chrono::Utc::now().timestamp();
        let grant = create_test_grant("claw_weather", &hash, now + 30);

        let jwt = sign_grant_jwt(&grant, "executor-host", &key_pair).unwrap();

        let verified = validate_bound(&jwt, "claw_weather", &args, "executor-host", &pub_key)
            .expect("validation should succeed");
        assert_eq!(verified.tool_name, "claw_weather");
        assert_eq!(verified.input_hash, hash);
    }

    #[test]
    fn test_validate_bound_rejects_wrong_tool() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let args = serde_json::json!({"location": "London"});
        let hash = canonical_hash(&args);
        let now = chrono::Utc::now().timestamp();
        let grant = create_test_grant("claw_weather", &hash, now + 30);
        let jwt = sign_grant_jwt(&grant, "executor-host", &key_pair).unwrap();

        let res = validate_bound(&jwt, "claw_delete", &args, "executor-host", &pub_key);
        assert!(matches!(res, Err(GrantError::ToolMismatch { .. })));
    }

    #[test]
    fn test_validate_bound_rejects_altered_args() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let original_args = serde_json::json!({"location": "London"});
        let hash = canonical_hash(&original_args);
        let now = chrono::Utc::now().timestamp();
        let grant = create_test_grant("claw_weather", &hash, now + 30);
        let jwt = sign_grant_jwt(&grant, "executor-host", &key_pair).unwrap();

        let tampered_args = serde_json::json!({"location": "Paris"});
        let res = validate_bound(
            &jwt,
            "claw_weather",
            &tampered_args,
            "executor-host",
            &pub_key,
        );
        assert!(matches!(res, Err(GrantError::InputHashMismatch { .. })));
    }

    #[test]
    fn test_validate_bound_rejects_wrong_audience() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let args = serde_json::json!({"location": "London"});
        let hash = canonical_hash(&args);
        let now = chrono::Utc::now().timestamp();
        let grant = create_test_grant("claw_weather", &hash, now + 30);
        let jwt = sign_grant_jwt(&grant, "did:web:provider-a.com", &key_pair).unwrap();

        let res = validate_bound(
            &jwt,
            "claw_weather",
            &args,
            "did:web:provider-b.com",
            &pub_key,
        );
        assert!(matches!(
            res,
            Err(GrantError::AudienceMismatch { .. } | GrantError::SignatureVerification(_))
        ));
    }

    #[test]
    fn test_validate_bound_rejects_expired() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let args = serde_json::json!({"location": "London"});
        let hash = canonical_hash(&args);
        let grant = create_test_grant("claw_weather", &hash, 1000);
        let custom = GrantCustomClaims {
            action_id: grant.action_id.clone(),
            tenant_id: grant.tenant_id.clone(),
            workspace_id: grant.workspace_id.clone(),
            tool_name: grant.tool_name.clone(),
            input_hash: grant.input_hash.clone(),
            policy_fingerprint: grant.policy_fingerprint.clone(),
            clearance: grant.clearance,
            economic_claim: None,
            budget: None,
            contract_id: None,
            contract_hash: None,
            lineage_attestation: None,
        };
        let mut claims = Claims::with_custom_claims(custom, Duration::from_secs(0))
            .with_issuer("trust_gateway")
            .with_jwt_id("grant_12345")
            .with_audience("executor-host");
        claims.expires_at = Some(Duration::from_secs(1000));
        let jwt = key_pair.sign(claims).unwrap();

        let res = validate_bound(&jwt, "claw_weather", &args, "executor-host", &pub_key);
        assert!(matches!(res, Err(GrantError::TokenExpired(_, _))));
    }

    #[test]
    fn test_validate_bound_rejects_alg_none() {
        let key_pair = Ed25519KeyPair::generate();
        let pub_key = key_pair.public_key();

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"act_1","aud":["executor-host"],"iss":"trust_gateway"}"#);
        let fake_jwt = format!("{header}.{payload}.");

        let args = serde_json::json!({});
        let res = validate_bound(&fake_jwt, "claw_weather", &args, "executor-host", &pub_key);
        assert!(matches!(res, Err(GrantError::DisallowedAlgorithm(_))));
    }
}
