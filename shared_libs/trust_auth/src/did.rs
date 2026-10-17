// ─────────────────────────────────────────────────────────────
// VP Verifier — W3C Verifiable Presentation verification pipeline
//
// Phase 1: DID/JWK SSI Identity Layer
//
// Implements the 6-step verification flow from the implementation plan:
//   Step 2: VP detection (payload peek for "vp" field)
//   Step 3: Agent authentication (zero-network DID resolution)
//   Step 4: Issuer verification (did:web network resolution)
//   Step 5: Identity normalization (mapping to JwtClaims)
//   Step 6: Tenant namespace derivation (SHA256 of issuer DID)
//
// Agent DID (Holder): did:jwk, did:key, did:twin — zero network calls
// Issuer DID (Organization): did:web — HTTP fetch of did.json
// ─────────────────────────────────────────────────────────────

use crate::AuthMethod;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use identity_context::models::{IdentityContext, SourceContext};
use sha2::{Digest, Sha256};

/// Representation of an agent's public key (supports Ed25519 and P-256 / ES256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPublicKey {
    Ed25519([u8; 32]),
    P256(p256::ecdsa::VerifyingKey),
}

/// Representation of an issuer organization's public key (supports Ed25519 and P-256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerPublicKey {
    Ed25519([u8; 32]),
    P256(p256::ecdsa::VerifyingKey),
}

/// Result of a successfully verified Verifiable Presentation.
#[derive(Debug, Clone)]
pub struct VerifiedPresentation {
    /// The agent's self-certifying DID (holder).
    pub agent_did: String,
    /// The organization's domain-routable DID (issuer of the inner VC).
    pub issuer_did: String,
    /// Deterministic tenant namespace derived from SHA256(issuer_did).
    pub tenant_id: String,
    /// Credential subject claims (raw JSON from the inner VC).
    pub credential_subject: serde_json::Value,
}

/// Errors that can occur during VP verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpError {
    /// Token is not a VP (no "vp" field in payload).
    NotAVp,
    /// Malformed JWT structure.
    MalformedToken(String),
    /// Agent DID method is not in the whitelist.
    ForbiddenDidMethod(String),
    /// Could not resolve the agent's public key from the DID.
    AgentKeyResolution(String),
    /// VP outer signature verification failed.
    VpSignatureInvalid,
    /// No verifiable credential found inside the VP.
    NoCredential,
    /// Issuer DID is not did:web.
    IssuerNotDidWeb(String),
    /// Could not fetch or parse the issuer's did.json.
    IssuerResolution(String),
    /// Inner credential signature verification failed.
    CredentialSignatureInvalid,
    /// Binding check failed: credentialSubject.id != agent_did.
    BindingMismatch { expected: String, got: String },
    /// Token or credential has expired.
    TokenExpired(String),
    /// Token or credential is not yet valid (nbf).
    TokenNotYetValid(String),
    /// Presentation audience does not match expected gateway audience.
    AudienceMismatch { expected: String, got: String },
    /// Presentation replay detected via nonce/jti/signature cache.
    ReplayDetected(String),
    /// Issuer is not in the trusted issuer allowlist.
    UntrustedIssuer(String),
    /// Algorithm mismatch or unsupported cryptographic algorithm.
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for VpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAVp => write!(f, "Token is not a Verifiable Presentation"),
            Self::MalformedToken(m) => write!(f, "Malformed VP token: {m}"),
            Self::ForbiddenDidMethod(d) => write!(f, "Agent DID method not allowed: {d}"),
            Self::AgentKeyResolution(m) => write!(f, "Cannot resolve agent public key: {m}"),
            Self::VpSignatureInvalid => write!(f, "VP signature verification failed"),
            Self::NoCredential => write!(f, "No verifiable credential in VP"),
            Self::IssuerNotDidWeb(d) => write!(f, "Issuer must use did:web, got: {d}"),
            Self::IssuerResolution(m) => write!(f, "Cannot resolve issuer DID document: {m}"),
            Self::CredentialSignatureInvalid => {
                write!(f, "Credential signature verification failed")
            }
            Self::BindingMismatch { expected, got } => {
                write!(
                    f,
                    "Binding mismatch: credentialSubject.id='{got}' != agent_did='{expected}'"
                )
            }
            Self::TokenExpired(m) => write!(f, "Token expired: {m}"),
            Self::TokenNotYetValid(m) => write!(f, "Token not yet valid: {m}"),
            Self::AudienceMismatch { expected, got } => {
                write!(f, "Audience mismatch: expected '{expected}', got '{got}'")
            }
            Self::ReplayDetected(m) => write!(f, "Replay attack detected: {m}"),
            Self::UntrustedIssuer(i) => write!(f, "Issuer '{i}' is not in trusted allowlist"),
            Self::UnsupportedAlgorithm(a) => write!(f, "Unsupported cryptographic algorithm: {a}"),
        }
    }
}

// ─── Step 2: VP Detection ────────────────────────────────────

/// Peek at a JWT-encoded token to determine if it is a Verifiable Presentation.
///
/// Splits by `.`, base64url-decodes the payload segment, and checks for a `"vp"` field.
pub fn is_verifiable_presentation(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;

    let payload_bytes = b64.decode(parts[1]).or_else(|_| b64_pad.decode(parts[1]));

    if let Ok(payload_bytes) = payload_bytes {
        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
            return payload.get("vp").is_some();
        }
    }
    false
}

// ─── Full Verification Pipeline ──────────────────────────────

/// Check whether an issuer DID is permitted by TRUSTED_ISSUER_DOMAINS.
/// If unset or "*", defaults to permissive.
pub fn is_trusted_issuer(issuer_did: &str) -> bool {
    let allowed_env = match std::env::var("TRUSTED_ISSUER_DOMAINS") {
        Ok(val) => val,
        Err(_) => return true,
    };
    let trimmed = allowed_env.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return true;
    }
    let allowed_list: Vec<&str> = trimmed
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let domain_part = issuer_did.strip_prefix("did:web:").unwrap_or(issuer_did);
    let host = domain_part.split(':').next().unwrap_or(domain_part);

    allowed_list.iter().any(|&item| {
        item == host
            || item == domain_part
            || item == issuer_did
            || (item.starts_with("*.") && host.ends_with(&item[1..]))
    })
}

/// Verify a Verifiable Presentation JWT through the comprehensive verification pipeline:
///
/// 1. Decode VP envelope and header (EdDSA or ES256)
/// 2. Validate VP envelope temporal validity (exp, nbf with 60s tolerance)
/// 3. Validate VP audience (aud) if expected_audience is specified
/// 4. Extract + whitelist agent DID (did:key, did:jwk, did:twin)
/// 5. Resolve agent public key (zero-network, supports Ed25519 and P-256)
/// 6. Verify VP outer signature
/// 7. Check replay protection (nonce / jti / signature hash in JetStream KV)
/// 8. Extract inner Verifiable Credential and validate temporal validity (exp, nbf)
/// 9. Check issuer DID allowlist (SSRF / tenant quarantine protection)
/// 10. Resolve issuer public key (SSRF-guarded did:web resolution + JetStream KV cache)
/// 11. Verify inner VC signature (EdDSA or ES256)
/// 12. Binding check: credentialSubject.id == agent_did
/// 13. Tenant derivation: SHA256 of issuer DID
pub async fn verify_presentation_with_options(
    token: &str,
    http_client: &reqwest::Client,
    kv_store: Option<&async_nats::jetstream::kv::Store>,
    expected_audience: Option<&str>,
) -> Result<VerifiedPresentation, VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VpError::MalformedToken("Expected 3-part JWT".into()));
    }

    // ── Decode VP header ─────────────────────────────────────
    let header_bytes = b64
        .decode(parts[0])
        .or_else(|_| b64_pad.decode(parts[0]))
        .map_err(|e| VpError::MalformedToken(format!("header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| VpError::MalformedToken(format!("header JSON: {e}")))?;
    let vp_alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("EdDSA");

    // ── Decode VP payload ────────────────────────────────────
    let payload_bytes = b64
        .decode(parts[1])
        .or_else(|_| b64_pad.decode(parts[1]))
        .map_err(|e| VpError::MalformedToken(format!("payload base64: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("payload JSON: {e}")))?;

    if payload.get("vp").is_none() {
        return Err(VpError::NotAVp);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    const CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

    // ── Temporal validity: outer VP exp / nbf ────────────────
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now > exp + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(VpError::TokenExpired(format!(
                "VP envelope expired at {exp}, current time is {now}"
            )));
        }
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64()) {
        if now + CLOCK_SKEW_TOLERANCE_SECS < nbf {
            return Err(VpError::TokenNotYetValid(format!(
                "VP envelope not valid until {nbf}, current time is {now}"
            )));
        }
    }

    // ── Audience check: outer VP aud ─────────────────────────
    if let Some(expected_aud) = expected_audience {
        let aud_matches = match payload.get("aud") {
            Some(serde_json::Value::String(s)) => s == expected_aud,
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().any(|v| v.as_str() == Some(expected_aud))
            }
            _ => false,
        };
        if !aud_matches {
            let got = payload
                .get("aud")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string());
            return Err(VpError::AudienceMismatch {
                expected: expected_aud.to_string(),
                got,
            });
        }
    }

    // ── Step 3: Extract Agent DID ────────────────────────────
    let agent_did = payload
        .get("iss")
        .or_else(|| payload.get("sub"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| VpError::MalformedToken("No iss/sub in VP".into()))?
        .to_string();

    // ── Step 3.2: Enforce strict whitelist ────────────────────
    let allowed = agent_did.starts_with("did:twin:")
        || agent_did.starts_with("did:jwk:")
        || agent_did.starts_with("did:key:");
    if !allowed {
        return Err(VpError::ForbiddenDidMethod(agent_did));
    }

    // ── Step 3.3: Resolve agent public key (ZERO network!) ───
    let agent_pubkey = resolve_agent_public_key(&agent_did)?;

    // ── Step 3.4: Verify VP outer JWS signature ──────────────
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64
        .decode(parts[2])
        .or_else(|_| b64_pad.decode(parts[2]))
        .map_err(|_| VpError::VpSignatureInvalid)?;
    verify_agent_signature(&agent_pubkey, vp_alg, signing_input.as_bytes(), &sig_bytes)?;

    tracing::info!("✅ VP outer signature verified for agent: {}", agent_did);

    // ── Replay Protection: JetStream KV nonces ───────────────
    if let Some(kv) = kv_store {
        let replay_id = payload
            .get("jti")
            .or_else(|| payload.get("nonce"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                let mut hasher = Sha256::new();
                hasher.update(&sig_bytes);
                hex::encode(hasher.finalize())
            });

        // Invariant 3: JetStream keys MUST use '_' separator
        let replay_key = format!("vp_replay_{}", replay_id.replace([':', '.', '-'], "_"));

        match kv.get(&replay_key).await {
            Ok(Some(_)) => {
                return Err(VpError::ReplayDetected(format!(
                    "Replay detected for presentation key: {replay_key}"
                )));
            }
            Ok(None) => {
                if let Err(e) = kv.put(&replay_key, "used".into()).await {
                    tracing::warn!("Failed to store VP replay key '{}': {}", replay_key, e);
                } else {
                    tracing::debug!("Recorded VP replay key '{}'", replay_key);
                }
            }
            Err(e) => {
                tracing::warn!("Could not query replay KV store: {}", e);
            }
        }
    }

    // ── Step 4: Extract inner Verifiable Credential ──────────
    let vc_jwt = payload
        .get("vp")
        .and_then(|vp| vp.get("verifiableCredential"))
        .and_then(|vcs| {
            if let Some(arr) = vcs.as_array() {
                arr.first().and_then(|v| v.as_str())
            } else {
                vcs.as_str()
            }
        })
        .ok_or(VpError::NoCredential)?;

    // Decode the inner VC JWT header & payload
    let vc_parts: Vec<&str> = vc_jwt.split('.').collect();
    if vc_parts.len() != 3 {
        return Err(VpError::MalformedToken(
            "Inner VC is not a 3-part JWT".into(),
        ));
    }
    let vc_header_bytes = b64
        .decode(vc_parts[0])
        .or_else(|_| b64_pad.decode(vc_parts[0]))
        .map_err(|e| VpError::MalformedToken(format!("VC header base64: {e}")))?;
    let vc_header: serde_json::Value = serde_json::from_slice(&vc_header_bytes)
        .map_err(|e| VpError::MalformedToken(format!("VC header JSON: {e}")))?;
    let vc_alg = vc_header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("EdDSA");

    let vc_payload_bytes = b64
        .decode(vc_parts[1])
        .or_else(|_| b64_pad.decode(vc_parts[1]))
        .map_err(|e| VpError::MalformedToken(format!("VC payload base64: {e}")))?;
    let vc_payload: serde_json::Value = serde_json::from_slice(&vc_payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("VC payload JSON: {e}")))?;

    // ── Temporal validity: inner VC exp / nbf ────────────────
    let vc_exp = vc_payload.get("exp").and_then(|v| v.as_u64()).or_else(|| {
        vc_payload
            .get("vc")
            .and_then(|vc| vc.get("expirationDate"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp() as u64)
    });
    if let Some(exp) = vc_exp {
        if now > exp + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(VpError::TokenExpired(format!(
                "Inner VC expired at {exp}, current time is {now}"
            )));
        }
    }

    let vc_nbf = vc_payload.get("nbf").and_then(|v| v.as_u64()).or_else(|| {
        vc_payload
            .get("vc")
            .and_then(|vc| vc.get("validFrom").or_else(|| vc.get("issuanceDate")))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp() as u64)
    });
    if let Some(nbf) = vc_nbf {
        if now + CLOCK_SKEW_TOLERANCE_SECS < nbf {
            return Err(VpError::TokenNotYetValid(format!(
                "Inner VC not valid until {nbf}, current time is {now}"
            )));
        }
    }

    // ── Step 4.2: Extract issuer DID ─────────────────────────
    let issuer_did = vc_payload
        .get("iss")
        .and_then(|v| v.as_str())
        .or_else(|| {
            vc_payload
                .get("vc")
                .and_then(|vc| vc.get("issuer"))
                .and_then(|v| {
                    v.as_str()
                        .or_else(|| v.get("id").and_then(|id| id.as_str()))
                })
        })
        .ok_or_else(|| VpError::MalformedToken("No issuer in VC".into()))?
        .to_string();

    if !issuer_did.starts_with("did:web:") {
        return Err(VpError::IssuerNotDidWeb(issuer_did));
    }

    // ── Step 4.2.1: Enforce issuer trust allowlist ───────────
    if !is_trusted_issuer(&issuer_did) {
        return Err(VpError::UntrustedIssuer(issuer_did));
    }

    // ── Step 4.3: Resolve issuer public key (network call) ───
    let issuer_pubkey = resolve_did_web(&issuer_did, http_client, kv_store).await?;

    // ── Step 4.4: Verify inner VC signature ──────────────────
    let vc_signing_input = format!("{}.{}", vc_parts[0], vc_parts[1]);
    let vc_sig_bytes = b64
        .decode(vc_parts[2])
        .or_else(|_| b64_pad.decode(vc_parts[2]))
        .map_err(|_| VpError::CredentialSignatureInvalid)?;
    verify_issuer_signature(
        &issuer_pubkey,
        vc_alg,
        vc_signing_input.as_bytes(),
        &vc_sig_bytes,
    )?;

    tracing::info!("✅ Inner VC signature verified from issuer: {}", issuer_did);

    // ── Step 4.5: Binding check ──────────────────────────────
    let credential_subject = vc_payload
        .get("vc")
        .and_then(|vc| vc.get("credentialSubject"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let subject_id = credential_subject
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if subject_id != agent_did {
        return Err(VpError::BindingMismatch {
            expected: agent_did,
            got: subject_id.to_string(),
        });
    }

    tracing::info!("✅ Binding check passed: credential subject matches agent DID");

    // ── Step 6: Derive deterministic tenant_id ───────────────
    let tenant_id = derive_tenant_from_issuer(&issuer_did);

    Ok(VerifiedPresentation {
        agent_did,
        issuer_did,
        tenant_id,
        credential_subject,
    })
}

/// Verify a Verifiable Presentation JWT through the complete 6-step pipeline.
pub async fn verify_presentation(
    token: &str,
    http_client: &reqwest::Client,
    kv_store: Option<&async_nats::jetstream::kv::Store>,
) -> Result<VerifiedPresentation, VpError> {
    let expected_aud = std::env::var("TRUST_GATEWAY_AUDIENCE").ok();
    verify_presentation_with_options(token, http_client, kv_store, expected_aud.as_deref()).await
}

/// Verifies a standard session JWT signed with EdDSA (by a did:twin or did:jwk).
/// This is used when the Vault delegates a session token instead of issuing a Verifiable Presentation.
pub fn verify_eddsa_session_jwt(token: &str) -> Result<identity_context::jwt::JwtClaims, VpError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VpError::MalformedToken("Expected 3 parts in JWT".into()));
    }

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;

    let payload_bytes = b64
        .decode(parts[1])
        .or_else(|_| b64_pad.decode(parts[1]))
        .map_err(|e| VpError::MalformedToken(format!("payload base64: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("payload JSON: {e}")))?;

    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VpError::MalformedToken("Missing iss".into()))?
        .to_string();

    let agent_pubkey = resolve_agent_public_key(&iss)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64
        .decode(parts[2])
        .or_else(|_| b64_pad.decode(parts[2]))
        .map_err(|_| VpError::VpSignatureInvalid)?;

    verify_agent_signature(&agent_pubkey, "EdDSA", signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| VpError::VpSignatureInvalid)?;

    let claims: identity_context::jwt::JwtClaims = serde_json::from_value(payload)
        .map_err(|e| VpError::MalformedToken(format!("claims structure: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if let Some(exp) = claims.exp {
        if now > exp {
            return Err(VpError::MalformedToken("Token expired".into()));
        }
    }

    Ok(claims)
}

/// Verify an OAuth2 Bearer JWT signed using Ed25519 (EdDSA) via JWKS.
///
/// Used for B2B OAuth2 tokens issued by central identity servers.
pub async fn verify_oauth2_eddsa_jwt(
    token: &str,
    client: &reqwest::Client,
    jwks_url_override: Option<&str>,
) -> Result<IdentityContext, VpError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VpError::MalformedToken("Expected 3 parts in JWT".into()));
    }

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;

    let header_bytes = b64
        .decode(parts[0])
        .or_else(|_| b64_pad.decode(parts[0]))
        .map_err(|e| VpError::MalformedToken(format!("header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| VpError::MalformedToken(format!("header JSON: {e}")))?;

    let payload_bytes = b64
        .decode(parts[1])
        .or_else(|_| b64_pad.decode(parts[1]))
        .map_err(|e| VpError::MalformedToken(format!("payload base64: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("payload JSON: {e}")))?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "EdDSA" {
        return Err(VpError::MalformedToken(format!(
            "Unsupported algorithm '{alg}', expected 'EdDSA'"
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now > exp {
            return Err(VpError::MalformedToken("OAuth2 JWT expired".into()));
        }
    }

    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64()) {
        if now < nbf {
            return Err(VpError::MalformedToken("OAuth2 JWT not yet valid".into()));
        }
    }

    let iss = payload.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    let target_jwks_url = if let Some(override_url) = jwks_url_override {
        override_url.to_string()
    } else if iss.starts_with("http://") || iss.starts_with("https://") {
        format!("{}/.well-known/jwks.json", iss.trim_end_matches('/'))
    } else {
        std::env::var("OAUTH2_SERVICE_URL")
            .map(|u| format!("{}/.well-known/jwks.json", u.trim_end_matches('/')))
            .unwrap_or_else(|_| "http://127.0.0.1:3075/.well-known/jwks.json".to_string())
    };

    let jwks_res = match client.get(&target_jwks_url).send().await {
        Ok(res) if res.status().is_success() => Ok(res),
        other => {
            let local_jwks_url = std::env::var("OAUTH2_SERVICE_URL")
                .map(|u| format!("{}/.well-known/jwks.json", u.trim_end_matches('/')))
                .unwrap_or_else(|_| "http://127.0.0.1:3075/.well-known/jwks.json".to_string());
            if target_jwks_url != local_jwks_url {
                tracing::debug!(
                    "Primary JWKS fetch failed ({:?}), trying local fallback: {}",
                    other.as_ref().err(),
                    local_jwks_url
                );
                client.get(&local_jwks_url).send().await
            } else {
                other
            }
        }
    }
    .map_err(|e| {
        VpError::IssuerResolution(format!("Failed to fetch JWKS from {target_jwks_url}: {e}"))
    })?;

    if !jwks_res.status().is_success() {
        return Err(VpError::IssuerResolution(format!(
            "JWKS endpoint returned HTTP {}",
            jwks_res.status()
        )));
    }
    let jwks: serde_json::Value = jwks_res.json().await.map_err(|e| {
        VpError::IssuerResolution(format!(
            "Failed to parse JWKS JSON from {target_jwks_url}: {e}"
        ))
    })?;

    let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or_else(|| {
        VpError::IssuerResolution(format!("Invalid JWKS structure at {target_jwks_url}"))
    })?;

    let target_kid = header.get("kid").and_then(|k| k.as_str());
    let key_entry = if let Some(kid) = target_kid {
        keys.iter()
            .find(|k| k.get("kid").and_then(|id| id.as_str()) == Some(kid))
            .ok_or_else(|| VpError::IssuerResolution(format!("Key ID '{kid}' not found in JWKS")))?
    } else {
        keys.first()
            .ok_or_else(|| VpError::IssuerResolution("JWKS contains no keys".into()))?
    };

    let x_str = key_entry
        .get("x")
        .and_then(|x| x.as_str())
        .ok_or_else(|| VpError::IssuerResolution("Missing 'x' field in JWK".into()))?;

    let pub_key_bytes = b64
        .decode(x_str)
        .or_else(|_| b64_pad.decode(x_str))
        .map_err(|e| VpError::IssuerResolution(format!("Failed to decode JWK x field: {e}")))?;
    let pub_key_arr: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| VpError::IssuerResolution("Invalid public key length in JWK".into()))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64
        .decode(parts[2])
        .or_else(|_| b64_pad.decode(parts[2]))
        .map_err(|_| VpError::VpSignatureInvalid)?;

    verify_ed25519_signature(&pub_key_arr, signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| VpError::CredentialSignatureInvalid)?;

    let tenant_id = payload
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "default" && *s != "unknown")
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let sub = payload
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("tenant_{}", sub.replace(':', "_"))
        });

    let requester_did = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or(iss)
        .to_string();

    let oauth_scopes = match payload.get("scope") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(serde_json::Value::String(s)) => {
            s.split_whitespace().map(|item| item.to_string()).collect()
        }
        _ => Vec::new(),
    };

    Ok(IdentityContext {
        tenant_id,
        workspace_id: "default".to_string(),
        owner_did: iss.to_string(),
        requester_did,
        auth_level: trust_core::actor::AuthLevel::Level3Session,
        auth_method: AuthMethod::VpEdDsa,
        oauth_scopes,
        session_jwt: token.to_string(),
        source: SourceContext::default(),
    })
}

// ─── DID Resolution Helpers ──────────────────────────────────

/// Resolve an agent's public key (Ed25519 or P-256) from their self-certifying DID.
/// Zero network calls — the key is embedded in the DID itself.
pub fn resolve_agent_public_key(did: &str) -> Result<AgentPublicKey, VpError> {
    if did.starts_with("did:jwk:") {
        resolve_did_jwk(did)
    } else if did.starts_with("did:twin:") {
        resolve_did_twin(did)
    } else if did.starts_with("did:key:") {
        resolve_did_key(did)
    } else {
        Err(VpError::ForbiddenDidMethod(did.to_string()))
    }
}

/// Resolve public key from `did:jwk:<base64url-JWK>`.
/// Supports OKP/Ed25519 and EC/P-256.
pub fn resolve_did_jwk(did: &str) -> Result<AgentPublicKey, VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;
    let jwk_b64 = did
        .strip_prefix("did:jwk:")
        .ok_or_else(|| VpError::AgentKeyResolution("Not a did:jwk".into()))?;

    let jwk_bytes = b64
        .decode(jwk_b64)
        .or_else(|_| b64_pad.decode(jwk_b64))
        .map_err(|e| VpError::AgentKeyResolution(format!("did:jwk base64 decode: {e}")))?;
    let jwk: serde_json::Value = serde_json::from_slice(&jwk_bytes)
        .map_err(|e| VpError::AgentKeyResolution(format!("did:jwk JSON parse: {e}")))?;

    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");

    if kty == "OKP" && crv == "Ed25519" {
        let x_b64 = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VpError::AgentKeyResolution("Missing 'x' in JWK".into()))?;
        let x_bytes = b64
            .decode(x_b64)
            .or_else(|_| b64_pad.decode(x_b64))
            .map_err(|e| VpError::AgentKeyResolution(format!("JWK x decode: {e}")))?;
        let arr: [u8; 32] = x_bytes.try_into().map_err(|_| {
            VpError::AgentKeyResolution("Ed25519 public key must be 32 bytes".into())
        })?;
        Ok(AgentPublicKey::Ed25519(arr))
    } else if kty == "EC" && crv == "P-256" {
        let x_b64 = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VpError::AgentKeyResolution("Missing 'x' in P-256 JWK".into()))?;
        let y_b64 = jwk
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VpError::AgentKeyResolution("Missing 'y' in P-256 JWK".into()))?;
        let x_bytes = b64
            .decode(x_b64)
            .or_else(|_| b64_pad.decode(x_b64))
            .map_err(|e| VpError::AgentKeyResolution(format!("JWK x decode: {e}")))?;
        let y_bytes = b64
            .decode(y_b64)
            .or_else(|_| b64_pad.decode(y_b64))
            .map_err(|e| VpError::AgentKeyResolution(format!("JWK y decode: {e}")))?;
        if x_bytes.len() != 32 || y_bytes.len() != 32 {
            return Err(VpError::AgentKeyResolution(
                "P-256 coordinates must be 32 bytes each".into(),
            ));
        }
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&x_bytes);
        uncompressed.extend_from_slice(&y_bytes);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
            .map_err(|e| VpError::AgentKeyResolution(format!("Invalid P-256 SEC1 point: {e}")))?;
        Ok(AgentPublicKey::P256(vk))
    } else {
        Err(VpError::AgentKeyResolution(format!(
            "Unsupported JWK: kty={kty}, crv={crv} (expected OKP/Ed25519 or EC/P-256)"
        )))
    }
}

/// Resolve Ed25519 public key from `did:twin:z<hex>`.
pub fn resolve_did_twin(did: &str) -> Result<AgentPublicKey, VpError> {
    let pk = ssi_crypto::did::parse_did_twin_pubkey(did)
        .ok_or_else(|| VpError::AgentKeyResolution(format!("Invalid did:twin format: {did}")))?;
    Ok(AgentPublicKey::Ed25519(pk))
}

/// Resolve public key from `did:key:z<multibase>`.
/// Supports Ed25519 (0xed01) and P-256 (0x1200).
pub fn resolve_did_key(did: &str) -> Result<AgentPublicKey, VpError> {
    let key_part = did.strip_prefix("did:key:z").ok_or_else(|| {
        VpError::AgentKeyResolution("did:key must start with 'z' (base58btc)".into())
    })?;

    let decoded = bs58::decode(key_part)
        .into_vec()
        .map_err(|e| VpError::AgentKeyResolution(format!("did:key base58 decode: {e}")))?;

    // Ed25519 multicodec varint prefix: 0xed 0x01
    if decoded.len() >= 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        let arr: [u8; 32] = decoded[2..34].try_into().map_err(|_| {
            VpError::AgentKeyResolution("Ed25519 public key must be 32 bytes".into())
        })?;
        return Ok(AgentPublicKey::Ed25519(arr));
    }

    // P-256 multicodec varint prefix: 0x80 0x24 (0x1200)
    if decoded.len() >= 35 && decoded[0] == 0x80 && decoded[1] == 0x24 {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&decoded[2..])
            .map_err(|e| VpError::AgentKeyResolution(format!("Invalid P-256 did:key: {e}")))?;
        return Ok(AgentPublicKey::P256(vk));
    }

    Err(VpError::AgentKeyResolution(
        "did:key: expected Ed25519 (0xed01) or P-256 (0x1200) multicodec prefix".into(),
    ))
}

fn make_nats_key(did: &str) -> String {
    did.replace(':', "_")
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                is_private_ip(std::net::IpAddr::V4(ipv4))
            } else {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00 // Unique Local Address
                    || (ip.segments()[0] & 0xffc0) == 0xfe80 // Link-Local Unicast
                    || (ip.segments()[0] & 0xff00) == 0xff00 // Multicast
            }
        }
    }
}

/// Resolve an organization's public key (Ed25519 or P-256) from `did:web:<domain>`.
///
/// Translates `did:web:example.com` → `https://example.com/.well-known/did.json`,
/// fetches the DID Document, and extracts the first verification method's public key.
async fn resolve_did_web(
    did: &str,
    _http_client: &reqwest::Client,
    kv_store: Option<&async_nats::jetstream::kv::Store>,
) -> Result<IssuerPublicKey, VpError> {
    if let Some(kv) = kv_store {
        let key = make_nats_key(did);
        if let Ok(Some(entry)) = kv.get(&key).await {
            let bytes = entry.as_ref();
            if bytes.len() == 32 {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
                    tracing::info!("🎯 DID cache hit for {}: {}", did, key);
                    return Ok(IssuerPublicKey::Ed25519(arr));
                }
            } else if bytes.len() == 33 && bytes[0] == 0x01 {
                if let Ok(arr) = <[u8; 32]>::try_from(&bytes[1..]) {
                    tracing::info!("🎯 DID cache hit for {}: {}", did, key);
                    return Ok(IssuerPublicKey::Ed25519(arr));
                }
            } else if bytes.len() >= 34 && bytes[0] == 0x02 {
                if let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes[1..]) {
                    tracing::info!("🎯 DID cache hit for {}: {}", did, key);
                    return Ok(IssuerPublicKey::P256(vk));
                }
            }
        }
    }

    let domain_part = did
        .strip_prefix("did:web:")
        .ok_or_else(|| VpError::IssuerResolution("Not a did:web".into()))?;

    // did:web:example.com → https://example.com/.well-known/did.json
    // did:web:example.com:path:to → https://example.com/path/to/did.json
    let url = if domain_part.contains(':') {
        let segments: Vec<&str> = domain_part.split(':').collect();
        let domain = segments[0];
        let path = segments[1..].join("/");
        format!("https://{domain}/{path}/did.json")
    } else {
        format!("https://{domain_part}/.well-known/did.json")
    };

    let parsed_url = reqwest::Url::parse(&url)
        .map_err(|e| VpError::IssuerResolution(format!("Malformed URL: {e}")))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| VpError::IssuerResolution("Missing host in URL".into()))?;

    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".local") {
        return Err(VpError::IssuerResolution(
            "SSRF block: Local hostname not allowed".into(),
        ));
    }

    let port = parsed_url.port().unwrap_or(443);
    let resolve_target = format!("{host}:{port}");

    // Resolve domain/host asynchronously to get all IP addresses
    let addrs = tokio::net::lookup_host(&resolve_target)
        .await
        .map_err(|e| VpError::IssuerResolution(format!("Failed to resolve host '{host}': {e}")))?;

    let mut validated_ip = None;
    for addr in addrs {
        let ip = addr.ip();
        if is_private_ip(ip) {
            return Err(VpError::IssuerResolution(format!(
                "SSRF block: Access to private or loopback IP address '{ip}' is forbidden"
            )));
        }
        if validated_ip.is_none() {
            validated_ip = Some(ip);
        }
    }

    let ip =
        validated_ip.ok_or_else(|| VpError::IssuerResolution("No IP addresses resolved".into()))?;

    tracing::info!("🌐 Resolving issuer DID document: {} → {}", did, url);

    // Build custom client mapping host to the validated IP to prevent DNS rebinding TOCTOU
    let custom_client = reqwest::Client::builder()
        .resolve(host, std::net::SocketAddr::new(ip, port))
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            VpError::IssuerResolution(format!("Failed to build secure HTTP client: {e}"))
        })?;

    let resp = custom_client
        .get(&url)
        .send()
        .await
        .map_err(|e| VpError::IssuerResolution(format!("HTTP fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(VpError::IssuerResolution(format!(
            "DID document fetch returned {}",
            resp.status()
        )));
    }

    let did_doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VpError::IssuerResolution(format!("DID document parse failed: {e}")))?;

    // Extract public key from first verificationMethod
    let pubkey = extract_pubkey_from_did_document(&did_doc)?;

    if let Some(kv) = kv_store {
        let key = make_nats_key(did);
        let cache_bytes = match &pubkey {
            IssuerPublicKey::Ed25519(pk) => {
                let mut v = Vec::with_capacity(33);
                v.push(0x01);
                v.extend_from_slice(pk);
                v
            }
            IssuerPublicKey::P256(vk) => {
                let mut v = Vec::with_capacity(34);
                v.push(0x02);
                v.extend_from_slice(vk.to_encoded_point(true).as_bytes());
                v
            }
        };
        if let Err(e) = kv.put(&key, cache_bytes.into()).await {
            tracing::warn!("⚠️ Failed to write DID to cache: {}", e);
        } else {
            tracing::info!("💾 Cached resolved public key for DID: {}", did);
        }
    }

    Ok(pubkey)
}

/// Extract an Ed25519 or P-256 public key from a DID Document's verificationMethod array.
fn extract_pubkey_from_did_document(doc: &serde_json::Value) -> Result<IssuerPublicKey, VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64_pad = base64::engine::general_purpose::URL_SAFE;

    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| VpError::IssuerResolution("No verificationMethod in DID document".into()))?;

    for method in methods {
        // Try publicKeyJwk (JsonWebKey2020)
        if let Some(jwk) = method.get("publicKeyJwk") {
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty == "OKP" && crv == "Ed25519" {
                if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                    let bytes = b64
                        .decode(x)
                        .or_else(|_| b64_pad.decode(x))
                        .map_err(|e| VpError::IssuerResolution(format!("JWK x decode: {e}")))?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| VpError::IssuerResolution("Key must be 32 bytes".into()))?;
                    return Ok(IssuerPublicKey::Ed25519(arr));
                }
            } else if kty == "EC" && crv == "P-256" {
                if let (Some(x_str), Some(y_str)) = (
                    jwk.get("x").and_then(|v| v.as_str()),
                    jwk.get("y").and_then(|v| v.as_str()),
                ) {
                    let x_bytes = b64
                        .decode(x_str)
                        .or_else(|_| b64_pad.decode(x_str))
                        .map_err(|e| VpError::IssuerResolution(format!("JWK x decode: {e}")))?;
                    let y_bytes = b64
                        .decode(y_str)
                        .or_else(|_| b64_pad.decode(y_str))
                        .map_err(|e| VpError::IssuerResolution(format!("JWK y decode: {e}")))?;
                    if x_bytes.len() == 32 && y_bytes.len() == 32 {
                        let mut uncompressed = Vec::with_capacity(65);
                        uncompressed.push(0x04);
                        uncompressed.extend_from_slice(&x_bytes);
                        uncompressed.extend_from_slice(&y_bytes);
                        if let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed) {
                            return Ok(IssuerPublicKey::P256(vk));
                        }
                    }
                }
            }
        }

        // Try publicKeyHex (Ed25519VerificationKey2020)
        if let Some(hex_key) = method.get("publicKeyHex").and_then(|v| v.as_str()) {
            if let Ok(bytes) = hex::decode(hex_key) {
                if bytes.len() == 32 {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
                        return Ok(IssuerPublicKey::Ed25519(arr));
                    }
                }
            }
        }

        // Try publicKeyMultibase (z-prefixed base58btc)
        if let Some(mb) = method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            if let Some(b58_part) = mb.strip_prefix('z') {
                if let Ok(decoded) = bs58::decode(b58_part).into_vec() {
                    if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
                        if let Ok(arr) = <[u8; 32]>::try_from(&decoded[2..34]) {
                            return Ok(IssuerPublicKey::Ed25519(arr));
                        }
                    } else if decoded.len() == 32 {
                        if let Ok(arr) = <[u8; 32]>::try_from(decoded) {
                            return Ok(IssuerPublicKey::Ed25519(arr));
                        }
                    } else if decoded.len() >= 35 && decoded[0] == 0x80 && decoded[1] == 0x24 {
                        if let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&decoded[2..]) {
                            return Ok(IssuerPublicKey::P256(vk));
                        }
                    }
                }
            }
        }
    }

    Err(VpError::IssuerResolution(
        "No supported Ed25519 or P-256 key found in DID document".into(),
    ))
}

// ─── Cryptographic Helpers ───────────────────────────────────

/// Verify an Ed25519 signature.
fn verify_ed25519_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig_arr: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Signature must be 64 bytes".to_string())?;
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|e| format!("Invalid public key: {e}"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|e| format!("Signature verification failed: {e}"))
}

/// Verify a P-256 (ES256) signature.
fn verify_p256_signature(
    vk: &p256::ecdsa::VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    let sig = p256::ecdsa::Signature::from_slice(signature)
        .or_else(|_| p256::ecdsa::Signature::from_der(signature))
        .map_err(|e| format!("Invalid P-256 signature format: {e}"))?;
    vk.verify(message, &sig)
        .map_err(|e| format!("P-256 signature verification failed: {e}"))
}

/// Verify signature from an AgentPublicKey (Ed25519 or P-256).
fn verify_agent_signature(
    pubkey: &AgentPublicKey,
    alg: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VpError> {
    match pubkey {
        AgentPublicKey::Ed25519(pk) => {
            if !alg.is_empty() && alg != "EdDSA" {
                return Err(VpError::UnsupportedAlgorithm(format!(
                    "Algorithm {alg} does not match Ed25519 key"
                )));
            }
            verify_ed25519_signature(pk, message, signature)
                .map_err(|_| VpError::VpSignatureInvalid)
        }
        AgentPublicKey::P256(vk) => {
            if !alg.is_empty() && alg != "ES256" {
                return Err(VpError::UnsupportedAlgorithm(format!(
                    "Algorithm {alg} does not match P-256 key"
                )));
            }
            verify_p256_signature(vk, message, signature).map_err(|_| VpError::VpSignatureInvalid)
        }
    }
}

/// Verify signature from an IssuerPublicKey (Ed25519 or P-256).
fn verify_issuer_signature(
    pubkey: &IssuerPublicKey,
    alg: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VpError> {
    match pubkey {
        IssuerPublicKey::Ed25519(pk) => {
            if !alg.is_empty() && alg != "EdDSA" {
                return Err(VpError::UnsupportedAlgorithm(format!(
                    "Algorithm {alg} does not match Ed25519 key"
                )));
            }
            verify_ed25519_signature(pk, message, signature)
                .map_err(|_| VpError::CredentialSignatureInvalid)
        }
        IssuerPublicKey::P256(vk) => {
            if !alg.is_empty() && alg != "ES256" {
                return Err(VpError::UnsupportedAlgorithm(format!(
                    "Algorithm {alg} does not match P-256 key"
                )));
            }
            verify_p256_signature(vk, message, signature)
                .map_err(|_| VpError::CredentialSignatureInvalid)
        }
    }
}

/// Derive a deterministic tenant_id from an issuer DID via SHA256.
///
/// All agents presenting credentials from the same organization
/// (e.g., `did:web:partner-corp.com`) will share the same tenant namespace.
pub fn derive_tenant_from_issuer(issuer_did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(issuer_did.as_bytes());
    let hash = hasher.finalize();
    format!("ssi-{}", hex::encode(&hash[..16])) // 32-char hex prefix for readability
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;

    fn make_ed25519_keypair() -> (SigningKey, VerifyingKey) {
        // Use a fixed seed for testing
        let seed = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_did_jwk(vk: &VerifyingKey) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64.encode(vk.to_bytes())
        });
        format!("did:jwk:{}", b64.encode(serde_json::to_vec(&jwk).unwrap()))
    }

    #[test]
    fn test_is_verifiable_presentation_true() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(b"{\"alg\":\"EdDSA\"}");
        let payload = b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "did:jwk:test", "vp": {}
            }))
            .unwrap(),
        );
        let token = format!("{header}.{payload}.fake_sig");
        assert!(is_verifiable_presentation(&token));
    }

    #[test]
    fn test_is_verifiable_presentation_false() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(b"{\"alg\":\"HS256\"}");
        let payload = b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "did:twin:z1234", "sub": "user1"
            }))
            .unwrap(),
        );
        let token = format!("{header}.{payload}.fake_sig");
        assert!(!is_verifiable_presentation(&token));
    }

    #[test]
    fn test_resolve_did_jwk() {
        let (_, vk) = make_ed25519_keypair();
        let did = make_did_jwk(&vk);
        let resolved = resolve_did_jwk(&did).unwrap();
        assert_eq!(resolved, AgentPublicKey::Ed25519(vk.to_bytes()));
    }

    #[test]
    fn test_resolve_p256_did_jwk() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let sk = p256::ecdsa::SigningKey::from_slice(&[42u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64.encode(point.x().unwrap()),
            "y": b64.encode(point.y().unwrap()),
        });
        let did = format!("did:jwk:{}", b64.encode(serde_json::to_vec(&jwk).unwrap()));
        let resolved = resolve_did_jwk(&did).unwrap();
        assert_eq!(resolved, AgentPublicKey::P256(*vk));
    }

    #[test]
    fn test_resolve_p256_did_key() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[42u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(true); // compressed SEC1 (33 bytes)
        let mut mc_bytes = vec![0x80, 0x24];
        mc_bytes.extend_from_slice(point.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&mc_bytes).into_string());
        let resolved = resolve_did_key(&did).unwrap();
        assert_eq!(resolved, AgentPublicKey::P256(*vk));
    }

    #[test]
    fn test_resolve_did_twin() {
        let identity = ssi_crypto::did::create_did_twin();
        let resolved = resolve_did_twin(&identity.did).unwrap();
        assert_eq!(resolved, AgentPublicKey::Ed25519(identity.public_key));
    }

    #[test]
    fn test_resolve_did_key_ed25519() {
        let (_, vk) = make_ed25519_keypair();
        // Construct did:key with Ed25519 multicodec prefix
        let mut mc_bytes = vec![0xed, 0x01];
        mc_bytes.extend_from_slice(&vk.to_bytes());
        let encoded = bs58::encode(&mc_bytes).into_string();
        let did = format!("did:key:z{encoded}");
        let resolved = resolve_did_key(&did).unwrap();
        assert_eq!(resolved, AgentPublicKey::Ed25519(vk.to_bytes()));
    }

    #[test]
    fn test_forbidden_did_method() {
        let result = resolve_agent_public_key("did:web:example.com");
        assert!(matches!(result, Err(VpError::ForbiddenDidMethod(_))));
    }

    #[test]
    fn test_issuer_allowlist() {
        // Test default permissive when unset
        assert!(is_trusted_issuer("did:web:any-domain.com"));

        // Set allowlist
        std::env::set_var(
            "TRUSTED_ISSUER_DOMAINS",
            "partner-corp.com,*.trusted-ecosystem.io,did:web:special-org.net",
        );

        assert!(is_trusted_issuer("did:web:partner-corp.com"));
        assert!(is_trusted_issuer("did:web:partner-corp.com:subpath"));
        assert!(is_trusted_issuer("did:web:agent.trusted-ecosystem.io"));
        assert!(is_trusted_issuer("did:web:special-org.net"));
        assert!(!is_trusted_issuer("did:web:untrusted-attacker.com"));

        std::env::remove_var("TRUSTED_ISSUER_DOMAINS");
    }

    #[test]
    fn test_derive_tenant_deterministic() {
        let t1 = derive_tenant_from_issuer("did:web:partner-corp.com");
        let t2 = derive_tenant_from_issuer("did:web:partner-corp.com");
        assert_eq!(t1, t2);
        assert!(t1.starts_with("ssi-"));

        // Different issuers get different tenants
        let t3 = derive_tenant_from_issuer("did:web:other-corp.com");
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_make_nats_key() {
        assert_eq!(make_nats_key("did:web:example.com"), "did_web_example.com");
        assert_eq!(
            make_nats_key("did:web:example.com:path:to:did.json"),
            "did_web_example.com_path_to_did.json"
        );
    }

    #[tokio::test]
    async fn test_resolve_did_web_ssrf_block() {
        let client = reqwest::Client::new();

        let result_local = resolve_did_web("did:web:localhost", &client, None).await;
        assert!(result_local.is_err());
        if let Err(VpError::IssuerResolution(msg)) = result_local {
            assert!(msg.contains("SSRF block"));
        } else {
            panic!("Expected SSRF block error for localhost");
        }

        let result_ip = resolve_did_web("did:web:127.0.0.1", &client, None).await;
        assert!(result_ip.is_err());
        if let Err(VpError::IssuerResolution(msg)) = result_ip {
            assert!(msg.contains("SSRF block"));
        } else {
            panic!("Expected SSRF block error for 127.0.0.1");
        }

        let result_local_dns = resolve_did_web("did:web:my-router.local", &client, None).await;
        assert!(result_local_dns.is_err());
        if let Err(VpError::IssuerResolution(msg)) = result_local_dns {
            assert!(msg.contains("SSRF block"));
        } else {
            panic!("Expected SSRF block error for local domain");
        }
    }

    #[tokio::test]
    async fn test_verify_oauth2_eddsa_jwt_invalid_alg() {
        let client = reqwest::Client::new();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = b64.encode(b"{\"iss\":\"http://127.0.0.1:3075\",\"sub\":\"company-beta\"}");
        let token = format!("{header}.{payload}.fake_sig");

        let res = verify_oauth2_eddsa_jwt(&token, &client, None).await;
        assert!(res.is_err());
        if let Err(VpError::MalformedToken(msg)) = res {
            assert!(msg.contains("Unsupported algorithm"));
        } else {
            panic!("Expected Unsupported algorithm error");
        }
    }

    #[tokio::test]
    async fn test_verify_presentation_expired_envelope() {
        use ed25519_dalek::Signer;
        let client = reqwest::Client::new();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (sk, vk) = make_ed25519_keypair();
        let agent_did = make_did_jwk(&vk);

        let header = b64.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        let payload = b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": agent_did,
                "exp": 1000,
                "vp": {
                    "verifiableCredential": "fake.vc.jwt"
                }
            }))
            .unwrap(),
        );
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", b64.encode(sig.to_bytes()));

        let res = verify_presentation(&token, &client, None).await;
        assert!(matches!(res, Err(VpError::TokenExpired(_))));
    }

    #[tokio::test]
    async fn test_verify_presentation_audience_mismatch() {
        use ed25519_dalek::Signer;
        let client = reqwest::Client::new();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (sk, vk) = make_ed25519_keypair();
        let agent_did = make_did_jwk(&vk);

        let header = b64.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        let payload = b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": agent_did,
                "aud": "did:web:expected-gateway.com",
                "vp": {
                    "verifiableCredential": "fake.vc.jwt"
                }
            }))
            .unwrap(),
        );
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", b64.encode(sig.to_bytes()));

        let res = verify_presentation_with_options(
            &token,
            &client,
            None,
            Some("did:web:different-gateway.com"),
        )
        .await;
        assert!(matches!(res, Err(VpError::AudienceMismatch { .. })));
    }
}
