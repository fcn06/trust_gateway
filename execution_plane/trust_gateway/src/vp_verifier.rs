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

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Sha256, Digest};

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
#[derive(Debug)]
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
}

impl std::fmt::Display for VpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAVp => write!(f, "Token is not a Verifiable Presentation"),
            Self::MalformedToken(m) => write!(f, "Malformed VP token: {}", m),
            Self::ForbiddenDidMethod(d) => write!(f, "Agent DID method not allowed: {}", d),
            Self::AgentKeyResolution(m) => write!(f, "Cannot resolve agent public key: {}", m),
            Self::VpSignatureInvalid => write!(f, "VP signature verification failed"),
            Self::NoCredential => write!(f, "No verifiable credential in VP"),
            Self::IssuerNotDidWeb(d) => write!(f, "Issuer must use did:web, got: {}", d),
            Self::IssuerResolution(m) => write!(f, "Cannot resolve issuer DID document: {}", m),
            Self::CredentialSignatureInvalid => write!(f, "Credential signature verification failed"),
            Self::BindingMismatch { expected, got } => {
                write!(f, "Binding mismatch: credentialSubject.id='{}' != agent_did='{}'", got, expected)
            }
        }
    }
}

// ─── Step 2: VP Detection ────────────────────────────────────

/// Peek at a JWT-encoded token to determine if it is a Verifiable Presentation.
///
/// Splits by `.`, base64url-decodes the payload segment, and checks for a `"vp"` field.
pub fn is_verifiable_presentation(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { return false; }
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

/// Verify a Verifiable Presentation JWT through the complete 6-step pipeline.
///
/// 1. Decode VP envelope
/// 2. Extract + whitelist agent DID
/// 3. Resolve agent public key (zero-network)
/// 4. Verify VP JWS signature
/// 5. Extract + verify inner VC (issuer did:web resolution)
/// 6. Binding check + tenant derivation
pub async fn verify_presentation(
    token: &str,
    http_client: &reqwest::Client,
) -> Result<VerifiedPresentation, VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VpError::MalformedToken("Expected 3-part JWT".into()));
    }

    // ── Decode VP payload ────────────────────────────────────
    let payload_bytes = b64.decode(parts[1])
        .map_err(|e| VpError::MalformedToken(format!("payload base64: {}", e)))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("payload JSON: {}", e)))?;

    if payload.get("vp").is_none() {
        return Err(VpError::NotAVp);
    }

    // ── Step 3: Extract Agent DID ────────────────────────────
    let agent_did = payload.get("iss")
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
    let sig_bytes = b64.decode(parts[2])
        .map_err(|_| VpError::VpSignatureInvalid)?;
    verify_ed25519_signature(&agent_pubkey, signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| VpError::VpSignatureInvalid)?;

    tracing::info!("✅ VP outer signature verified for agent: {}", agent_did);

    // ── Step 4: Extract inner Verifiable Credential ──────────
    let vc_jwt = payload.get("vp")
        .and_then(|vp| vp.get("verifiableCredential"))
        .and_then(|vcs| {
            if let Some(arr) = vcs.as_array() {
                arr.first().and_then(|v| v.as_str())
            } else {
                vcs.as_str()
            }
        })
        .ok_or(VpError::NoCredential)?;

    // Decode the inner VC JWT payload
    let vc_parts: Vec<&str> = vc_jwt.split('.').collect();
    if vc_parts.len() != 3 {
        return Err(VpError::MalformedToken("Inner VC is not a 3-part JWT".into()));
    }
    let vc_payload_bytes = b64.decode(vc_parts[1])
        .map_err(|e| VpError::MalformedToken(format!("VC payload base64: {}", e)))?;
    let vc_payload: serde_json::Value = serde_json::from_slice(&vc_payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("VC payload JSON: {}", e)))?;

    // ── Step 4.2: Extract issuer DID ─────────────────────────
    let issuer_did = vc_payload.get("iss")
        .and_then(|v| v.as_str())
        .or_else(|| {
            vc_payload.get("vc")
                .and_then(|vc| vc.get("issuer"))
                .and_then(|v| v.as_str().or_else(|| v.get("id").and_then(|id| id.as_str())))
        })
        .ok_or_else(|| VpError::MalformedToken("No issuer in VC".into()))?
        .to_string();

    if !issuer_did.starts_with("did:web:") {
        return Err(VpError::IssuerNotDidWeb(issuer_did));
    }

    // ── Step 4.3: Resolve issuer public key (network call) ───
    let issuer_pubkey = resolve_did_web(&issuer_did, http_client).await?;

    // ── Step 4.4: Verify inner VC signature ──────────────────
    let vc_signing_input = format!("{}.{}", vc_parts[0], vc_parts[1]);
    let vc_sig_bytes = b64.decode(vc_parts[2])
        .map_err(|_| VpError::CredentialSignatureInvalid)?;
    verify_ed25519_signature(&issuer_pubkey, vc_signing_input.as_bytes(), &vc_sig_bytes)
        .map_err(|_| VpError::CredentialSignatureInvalid)?;

    tracing::info!("✅ Inner VC signature verified from issuer: {}", issuer_did);

    // ── Step 4.5: Binding check ──────────────────────────────
    let credential_subject = vc_payload.get("vc")
        .and_then(|vc| vc.get("credentialSubject"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let subject_id = credential_subject.get("id")
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

    let payload_bytes = b64.decode(parts[1])
        .or_else(|_| b64_pad.decode(parts[1]))
        .map_err(|e| VpError::MalformedToken(format!("payload base64: {}", e)))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VpError::MalformedToken(format!("payload JSON: {}", e)))?;

    let iss = payload.get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VpError::MalformedToken("Missing iss".into()))?
        .to_string();

    let agent_pubkey = resolve_agent_public_key(&iss)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64.decode(parts[2])
        .or_else(|_| b64_pad.decode(parts[2]))
        .map_err(|_| VpError::VpSignatureInvalid)?;

    verify_ed25519_signature(&agent_pubkey, signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| VpError::VpSignatureInvalid)?;

    let claims: identity_context::jwt::JwtClaims = serde_json::from_value(payload)
        .map_err(|e| VpError::MalformedToken(format!("claims structure: {}", e)))?;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    if let Some(exp) = claims.exp {
        if now > exp {
            return Err(VpError::MalformedToken("Token expired".into()));
        }
    }

    Ok(claims)
}

// ─── DID Resolution Helpers ──────────────────────────────────

/// Resolve an agent's Ed25519 public key from their self-certifying DID.
/// Zero network calls — the key is embedded in the DID itself.
fn resolve_agent_public_key(did: &str) -> Result<[u8; 32], VpError> {
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

/// Resolve Ed25519 public key from `did:jwk:<base64url-JWK>`.
///
/// Strips prefix → base64url-decode → parse JWK JSON → extract `x` field → decode to 32 bytes.
fn resolve_did_jwk(did: &str) -> Result<[u8; 32], VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk_b64 = did.strip_prefix("did:jwk:")
        .ok_or_else(|| VpError::AgentKeyResolution("Not a did:jwk".into()))?;

    let jwk_bytes = b64.decode(jwk_b64)
        .map_err(|e| VpError::AgentKeyResolution(format!("did:jwk base64 decode: {}", e)))?;
    let jwk: serde_json::Value = serde_json::from_slice(&jwk_bytes)
        .map_err(|e| VpError::AgentKeyResolution(format!("did:jwk JSON parse: {}", e)))?;

    // Validate key type: OKP + Ed25519
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if kty != "OKP" || crv != "Ed25519" {
        return Err(VpError::AgentKeyResolution(
            format!("Unsupported JWK: kty={}, crv={} (expected OKP/Ed25519)", kty, crv)
        ));
    }

    let x_b64 = jwk.get("x").and_then(|v| v.as_str())
        .ok_or_else(|| VpError::AgentKeyResolution("Missing 'x' in JWK".into()))?;
    let x_bytes = b64.decode(x_b64)
        .map_err(|e| VpError::AgentKeyResolution(format!("JWK x decode: {}", e)))?;

    x_bytes.try_into()
        .map_err(|_| VpError::AgentKeyResolution("Ed25519 public key must be 32 bytes".into()))
}

/// Resolve Ed25519 public key from `did:twin:z<hex>`.
fn resolve_did_twin(did: &str) -> Result<[u8; 32], VpError> {
    ssi_crypto::did::parse_did_twin_pubkey(did)
        .ok_or_else(|| VpError::AgentKeyResolution(format!("Invalid did:twin format: {}", did)))
}

/// Resolve Ed25519 public key from `did:key:z<multibase>`.
///
/// Strips the `z` multibase prefix (base58btc), decodes, checks for the
/// Ed25519 multicodec prefix (0xed 0x01), and extracts the 32-byte key.
fn resolve_did_key(did: &str) -> Result<[u8; 32], VpError> {
    let key_part = did.strip_prefix("did:key:z")
        .ok_or_else(|| VpError::AgentKeyResolution("did:key must start with 'z' (base58btc)".into()))?;

    let decoded = bs58::decode(key_part).into_vec()
        .map_err(|e| VpError::AgentKeyResolution(format!("did:key base58 decode: {}", e)))?;

    // Ed25519 multicodec varint prefix: 0xed 0x01
    if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(VpError::AgentKeyResolution(
            "did:key: expected Ed25519 multicodec prefix (0xed01)".into()
        ));
    }

    decoded[2..34].try_into()
        .map_err(|_| VpError::AgentKeyResolution("Ed25519 public key must be 32 bytes".into()))
}

/// Resolve an organization's Ed25519 public key from `did:web:<domain>`.
///
/// Translates `did:web:example.com` → `https://example.com/.well-known/did.json`,
/// fetches the DID Document, and extracts the first verification method's public key.
async fn resolve_did_web(
    did: &str,
    http_client: &reqwest::Client,
) -> Result<[u8; 32], VpError> {
    let domain_part = did.strip_prefix("did:web:")
        .ok_or_else(|| VpError::IssuerResolution("Not a did:web".into()))?;

    // did:web:example.com → https://example.com/.well-known/did.json
    // did:web:example.com:path:to → https://example.com/path/to/did.json
    let url = if domain_part.contains(':') {
        let segments: Vec<&str> = domain_part.split(':').collect();
        let domain = segments[0];
        let path = segments[1..].join("/");
        format!("https://{}/{}/did.json", domain, path)
    } else {
        format!("https://{}/.well-known/did.json", domain_part)
    };

    tracing::info!("🌐 Resolving issuer DID document: {} → {}", did, url);

    let resp = http_client.get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send().await
        .map_err(|e| VpError::IssuerResolution(format!("HTTP fetch failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(VpError::IssuerResolution(
            format!("DID document fetch returned {}", resp.status())
        ));
    }

    let did_doc: serde_json::Value = resp.json().await
        .map_err(|e| VpError::IssuerResolution(format!("DID document parse failed: {}", e)))?;

    // Extract public key from first verificationMethod
    extract_pubkey_from_did_document(&did_doc)
}

/// Extract an Ed25519 public key from a DID Document's verificationMethod array.
///
/// Supports both `publicKeyJwk` and `publicKeyHex` / `publicKeyMultibase` formats.
fn extract_pubkey_from_did_document(doc: &serde_json::Value) -> Result<[u8; 32], VpError> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let methods = doc.get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| VpError::IssuerResolution("No verificationMethod in DID document".into()))?;

    for method in methods {
        // Try publicKeyJwk (JsonWebKey2020)
        if let Some(jwk) = method.get("publicKeyJwk") {
            let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty == "OKP" && crv == "Ed25519" {
                if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                    let bytes = b64.decode(x)
                        .map_err(|e| VpError::IssuerResolution(format!("JWK x decode: {}", e)))?;
                    return bytes.try_into()
                        .map_err(|_| VpError::IssuerResolution("Key must be 32 bytes".into()));
                }
            }
        }

        // Try publicKeyHex (Ed25519VerificationKey2020)
        if let Some(hex_key) = method.get("publicKeyHex").and_then(|v| v.as_str()) {
            let bytes = hex::decode(hex_key)
                .map_err(|e| VpError::IssuerResolution(format!("publicKeyHex: {}", e)))?;
            if bytes.len() == 32 {
                return bytes.try_into()
                    .map_err(|_| VpError::IssuerResolution("Key must be 32 bytes".into()));
            }
        }

        // Try publicKeyMultibase (z-prefixed base58btc)
        if let Some(mb) = method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            if let Some(b58_part) = mb.strip_prefix('z') {
                if let Ok(decoded) = bs58::decode(b58_part).into_vec() {
                    // May have multicodec prefix 0xed 0x01
                    let key_bytes = if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
                        &decoded[2..34]
                    } else if decoded.len() == 32 {
                        &decoded[..]
                    } else {
                        continue;
                    };
                    return key_bytes.try_into()
                        .map_err(|_| VpError::IssuerResolution("Key must be 32 bytes".into()));
                }
            }
        }
    }

    Err(VpError::IssuerResolution("No supported Ed25519 key found in DID document".into()))
}

// ─── Cryptographic Helpers ───────────────────────────────────

/// Verify an Ed25519 signature.
fn verify_ed25519_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let sig_arr: [u8; 64] = signature.try_into()
        .map_err(|_| "Signature must be 64 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))
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
        let payload = b64.encode(serde_json::to_vec(&serde_json::json!({
            "iss": "did:jwk:test", "vp": {}
        })).unwrap());
        let token = format!("{}.{}.fake_sig", header, payload);
        assert!(is_verifiable_presentation(&token));
    }

    #[test]
    fn test_is_verifiable_presentation_false() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(b"{\"alg\":\"HS256\"}");
        let payload = b64.encode(serde_json::to_vec(&serde_json::json!({
            "iss": "did:twin:z1234", "sub": "user1"
        })).unwrap());
        let token = format!("{}.{}.fake_sig", header, payload);
        assert!(!is_verifiable_presentation(&token));
    }

    #[test]
    fn test_resolve_did_jwk() {
        let (_, vk) = make_ed25519_keypair();
        let did = make_did_jwk(&vk);
        let resolved = resolve_did_jwk(&did).unwrap();
        assert_eq!(resolved, vk.to_bytes());
    }

    #[test]
    fn test_resolve_did_twin() {
        let identity = ssi_crypto::did::create_did_twin();
        let resolved = resolve_did_twin(&identity.did).unwrap();
        assert_eq!(resolved, identity.public_key);
    }

    #[test]
    fn test_resolve_did_key_ed25519() {
        let (_, vk) = make_ed25519_keypair();
        // Construct did:key with Ed25519 multicodec prefix
        let mut mc_bytes = vec![0xed, 0x01];
        mc_bytes.extend_from_slice(&vk.to_bytes());
        let encoded = bs58::encode(&mc_bytes).into_string();
        let did = format!("did:key:z{}", encoded);
        let resolved = resolve_did_key(&did).unwrap();
        assert_eq!(resolved, vk.to_bytes());
    }

    #[test]
    fn test_forbidden_did_method() {
        let result = resolve_agent_public_key("did:web:example.com");
        assert!(matches!(result, Err(VpError::ForbiddenDidMethod(_))));
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
}
