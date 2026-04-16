use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, KeyInit};
use chacha20poly1305::aead::Aead; // Fix: Import trait
use hkdf::Hkdf;
use sha2::Sha256;
use base64::Engine;
use futures::stream::StreamExt; // Fix: Import StreamExt

#[tokio::test]
async fn test_jit_routing_e2e() -> anyhow::Result<()> {
    // 1. Setup Gateway Key
    let gateway_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let gateway_public = PublicKey::from(&gateway_secret);
    let gateway_priv_b64 = base64::engine::general_purpose::STANDARD.encode(gateway_secret.to_bytes());
    
    // 2. Start Gateway
    // We assume public_gateway binary is buildable.
    println!("🚀 Starting Gateway...");
    let mut child = Command::new("../target/debug/public_gateway")
        .env("GATEWAY_PRIVATE_KEY", &gateway_priv_b64)
        .env("NATS_URL", "nats://localhost:4222")
        .env("PORT", "3009") // Use different port
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // .current_dir("../../global_domain/public_gateway") // Not needed if we use relative path from CWD
        .spawn()?;
        
    // Wait for startup
    sleep(Duration::from_secs(5)).await;
    
    // 2.5 Call /register to get opaque target
    let client = reqwest::Client::new();
    let reg_resp = client.post("http://localhost:3009/register")
        .json(&serde_json::json!({
            "node_id": "test_node_123",
            "target_id": "target_abc_789"
        }))
        .send()
        .await?;
    assert!(reg_resp.status().is_success());
    let reg_json: serde_json::Value = reg_resp.json().await?;
    let opaque_target = reg_json["target_id"].as_str().unwrap().to_string();

    // 3. Prepare JIT Token
    // Sender Ephemeral
    let sender_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let sender_public = PublicKey::from(&sender_secret);
    
    // ECDH
    let shared_secret = sender_secret.diffie_hellman(&gateway_public);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"sovereign:jit-routing", &mut key_bytes).unwrap();
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    
    // Encrypt the opaque_target
    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, opaque_target.as_bytes()).unwrap();
    
    // Pack
    let mut token_bytes = Vec::new();
    token_bytes.push(0x01);
    token_bytes.extend_from_slice(sender_public.as_bytes());
    token_bytes.extend_from_slice(&nonce_bytes);
    token_bytes.extend_from_slice(&ciphertext);
    
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
    println!("🎟️ JIT Token: {}", token);
    
    // 4. Subscribe NATS
    println!("🎧 Subscribing to NATS...");
    let nc = async_nats::connect("nats://localhost:4222").await?;
    let subject = "v1.test_node_123.didcomm.target_abc_789";
    let mut sub = nc.subscribe(subject.to_string()).await?;
    
    // 5. Send Request
    println!("📨 Sending HTTP Request...");
    let client = reqwest::Client::new();
    let body_content = "{\"foo\":\"bar\"}";
    let resp = client.post("http://localhost:3009/ingress")
        .header("X-Routing-Token", token)
        .body(body_content)
        .send()
        .await?;
        
    let status = resp.status();
    println!("📥 Response Status: {}", status);
    assert!(status.is_success());
    
    // 6. Receive NATS
    println!("⏳ Waiting for NATS message...");
    let msg_opt = tokio::time::timeout(Duration::from_secs(5), sub.next()).await?;
    assert!(msg_opt.is_some());
    let msg = msg_opt.unwrap();
    
    let received_payload = String::from_utf8_lossy(&msg.payload);
    println!("✅ Received NATS Message: {}", received_payload);
    
    assert_eq!(received_payload, body_content);
    
    // Cleanup
    child.kill()?;
    
    Ok(())
}
