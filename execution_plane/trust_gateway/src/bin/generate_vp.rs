use base64::Engine;
use ed25519_dalek::SigningKey;
use trust_gateway::vp_verifier::is_verifiable_presentation;

fn main() {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // 1. Generate Issuer Keys (did:web:example.com)
    let issuer_seed = [42u8; 32];
    let issuer_sk = SigningKey::from_bytes(&issuer_seed);
    let issuer_vk = issuer_sk.verifying_key();

    // 2. Generate Agent Keys (did:jwk)
    let agent_seed = [77u8; 32];
    let agent_sk = SigningKey::from_bytes(&agent_seed);
    let agent_vk = agent_sk.verifying_key();

    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64.encode(agent_vk.to_bytes())
    });
    let agent_did = format!("did:jwk:{}", b64.encode(serde_json::to_vec(&jwk).unwrap()));

    // 3. Create Inner VC (Signed by Issuer)
    let vc_payload = serde_json::json!({
        "iss": "did:web:example.com",
        "nbf": 1600000000,
        "exp": 2000000000,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "EmployeeCredential"],
            "credentialSubject": {
                "id": agent_did,
                "role": "agent"
            }
        }
    });

    let vc_header = b64.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
    let vc_payload_str = b64.encode(serde_json::to_vec(&vc_payload).unwrap());
    let vc_signing_input = format!("{}.{}", vc_header, vc_payload_str);
    
    use ed25519_dalek::Signer;
    let vc_sig = issuer_sk.sign(vc_signing_input.as_bytes());
    let vc_jwt = format!("{}.{}", vc_signing_input, b64.encode(vc_sig.to_bytes()));

    // 4. Create Outer VP (Signed by Agent)
    let vp_payload = serde_json::json!({
        "iss": agent_did,
        "aud": "did:twin:z68d8e628fada7dc2c1e3c24ecd4b5f4b22156d94667bb2a23d7763e6aac7daba",
        "nbf": 1600000000,
        "exp": 2000000000,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [vc_jwt]
        }
    });

    let vp_header = b64.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
    let vp_payload_str = b64.encode(serde_json::to_vec(&vp_payload).unwrap());
    let vp_signing_input = format!("{}.{}", vp_header, vp_payload_str);
    let vp_sig = agent_sk.sign(vp_signing_input.as_bytes());
    let vp_jwt = format!("{}.{}", vp_signing_input, b64.encode(vp_sig.to_bytes()));

    // Verify it parses as a VP
    assert!(is_verifiable_presentation(&vp_jwt));

    println!("============================================================");
    println!("🔐 GENERATED VERIFIABLE PRESENTATION (VP) TOKEN");
    println!("============================================================");
    println!("Agent DID: {}", agent_did);
    println!("Issuer DID: did:web:example.com\n");
    println!("Token:\n{}\n", vp_jwt);
    println!("============================================================");
    println!("🚀 CURL TEST COMMAND (Against Trust Gateway)");
    println!("============================================================");
    println!("curl -X POST http://localhost:3060/v1/actions/propose \\");
    println!("  -H 'Authorization: Bearer {}' \\", vp_jwt);
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{\"action_name\": \"test_tool\", \"arguments\": {{}}}}'");
    println!("============================================================");
    println!("Note: The gateway will correctly intercept this as a VP token,");
    println!("verify the agent's zero-network DID, and then attempt to fetch");
    println!("https://example.com/.well-known/did.json to verify the issuer.");
    println!("Because example.com is a placeholder, it will return a 401");
    println!("with an 'IssuerResolution' error in the gateway logs.");
    println!("This perfectly demonstrates the SSI validation pipeline!");
}
