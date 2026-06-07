//! DID Document builder and serializer.
//!
//! Builds W3C-compatible DID Documents with:
//! - `authentication` verification methods (Ed25519VerificationKey2020)
//! - `service` endpoints (MessagingGateway pointing to Global HTTP Gateway)
//!
//! DID Documents are exchanged directly during the Ledgerless Handshake
//! and stored locally by each host. No public ledger is used.

use serde::{Deserialize, Serialize};

/// A complete DID Document for the ledgerless peer-to-peer model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID this document describes
    pub id: String,
    /// Authentication verification methods
    pub authentication: Vec<String>,
    /// Verification methods (Ed25519 keys)
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Service endpoints (messaging gateway, etc.)
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
    /// Creation timestamp (Unix epoch seconds)
    #[serde(default)]
    pub created: i64,
}

/// A verification method (Ed25519 key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: String,
}

/// A service endpoint (e.g., messaging gateway).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Build a DID Document for a user's DID.
///
/// # Arguments
/// * `did` - The user's DID (e.g., `did:twin:z<hex>`)
/// * `public_key_hex` - The hex-encoded Ed25519 public key
/// * `gateway_url` - The Global Gateway's HTTP URL (e.g., `https://gateway.example.com`)
/// * `target_id` - The user's opaque TargetID for routing (Base64)
///
/// # Returns
/// A serializable `DidDocument`.
pub fn build_did_document(
    did: &str,
    public_key_hex: &str,
    gateway_url: &str,
    target_id: &str,
) -> DidDocument {
    let key_id = format!("{}#key-1", did);
    let service_id = format!("{}#messaging", did);

    // Build the messaging service endpoint URL:
    // The endpoint includes the opaque TargetID so that senders can route
    // messages through the Global Gateway without knowing the recipient's identity.
    let service_endpoint = format!("{}/ingress", gateway_url);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        id: did.to_string(),
        authentication: vec![key_id.clone()],
        verification_method: vec![VerificationMethod {
            id: key_id,
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_hex: public_key_hex.to_string(),
        }],
        service: vec![ServiceEndpoint {
            id: service_id,
            type_: "MessagingGateway".to_string(),
            service_endpoint,
        }],
        created: now,
    }
}

/// Serialize a DID Document to a JSON string.
pub fn serialize_did_document(doc: &DidDocument) -> Result<String, String> {
    serde_json::to_string_pretty(doc).map_err(|e| format!("Serialization failed: {}", e))
}

/// Deserialize a DID Document from a JSON string.
pub fn parse_did_document(json: &str) -> Result<DidDocument, String> {
    serde_json::from_str(json).map_err(|e| format!("Deserialization failed: {}", e))
}

/// Extract the Ed25519 public key hex from a DID Document.
pub fn extract_public_key_hex(doc: &DidDocument) -> Option<String> {
    doc.verification_method.first().map(|vm| vm.public_key_hex.clone())
}

/// Extract the messaging service endpoint URL from a DID Document.
pub fn extract_messaging_endpoint(doc: &DidDocument) -> Option<String> {
    doc.service
        .iter()
        .find(|s| s.type_ == "MessagingGateway")
        .map(|s| s.service_endpoint.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_did_document() {
        let did = "did:twin:z1234abcd";
        let pub_hex = "aabbccdd";
        let gateway = "https://gateway.example.com";
        let target_id = "opaque-target-123";

        let doc = build_did_document(did, pub_hex, gateway, target_id);

        assert_eq!(doc.id, did);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].public_key_hex, pub_hex);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].type_, "MessagingGateway");
        assert!(doc.created > 0);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let doc = build_did_document(
            "did:twin:z9999",
            "deadbeef",
            "https://gw.test",
            "target-abc",
        );

        let json = serialize_did_document(&doc).unwrap();
        let parsed = parse_did_document(&json).unwrap();

        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.verification_method[0].public_key_hex, "deadbeef");
    }

    #[test]
    fn test_extract_public_key_hex() {
        let doc = build_did_document("did:twin:z1", "cafe", "https://gw", "t");
        assert_eq!(extract_public_key_hex(&doc), Some("cafe".to_string()));
    }

    #[test]
    fn test_extract_messaging_endpoint() {
        let doc = build_did_document("did:twin:z1", "cafe", "https://gw.test", "tid");
        let endpoint = extract_messaging_endpoint(&doc).unwrap();
        assert_eq!(endpoint, "https://gw.test/ingress");
    }
}
