//! Messaging handler — HTTP egress to Global Gateway
//!
//! In the hybrid architecture, inter-user messages are:
//! 1. Encrypted using OpenMLS (by the mls_session component)
//! 2. Sent via HTTP POST to the Global Gateway (not NATS)
//! 3. Routed by the Gateway using opaque TargetIDs
//!
//! This handler implements the messaging-sender WIT interface for the host.

use std::sync::Arc;
use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, ContactStoreCommand, MlsSessionCommand};
use tokio::sync::oneshot;

/// Send an MLS-encrypted message to a recipient via the Global Gateway.
///
/// Flow:
/// 1. Encrypt plaintext using mls_session::encrypt_message
/// 2. Look up recipient's DID Document from contact_store
/// 3. Extract the messaging service endpoint (Gateway URL + TargetID)
/// 4. POST to the Gateway's /ingress endpoint
pub async fn send_mls_message(
    shared: Arc<WebauthnSharedState>,
    group_id: &str,
    recipient_did: &str,
    plaintext: &[u8],
) -> Result<String, String> {
    // 1. Encrypt the message via MLS
    let (tx, rx) = oneshot::channel();
    shared.mls_cmd_tx.send(MlsSessionCommand::EncryptMessage {
        group_id: group_id.to_string(),
        plaintext: plaintext.to_vec(),
        resp: tx,
    }).await.map_err(|e| format!("MLS channel error: {}", e))?;

    let ciphertext = rx.await
        .map_err(|_| "MLS response channel closed")?
        .map_err(|e| format!("MLS encryption failed: {}", e))?;

    // 2. Look up recipient's DID Document
    let (tx, rx) = oneshot::channel();
    shared.contact_cmd_tx.send(ContactStoreCommand::GetContact {
        did: recipient_did.to_string(),
        resp: tx,
    }).await.map_err(|e| format!("Contact store channel error: {}", e))?;

    let did_doc = rx.await
        .map_err(|_| "Contact store response channel closed")?
        .ok_or_else(|| format!("No DID Document found for {}", recipient_did))?;

    // 3. Extract messaging endpoint
    let service_endpoint = did_doc.service_endpoints
        .iter()
        .find(|s| s.type_ == "MessagingGateway")
        .map(|s| s.endpoint.clone())
        .ok_or_else(|| format!("No MessagingGateway service endpoint in DID Document for {}", recipient_did))?;

    // 4. POST to the Gateway
    let payload = serde_json::json!({
        "group_id": group_id,
        "epoch": 0,
        "content_type": "application/mls-application",
        "ciphertext": ciphertext,
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&service_endpoint)
        .header("Content-Type", "application/mls-message")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if response.status().is_success() {
        Ok("sent".to_string())
    } else {
        Err(format!("Gateway returned {}", response.status()))
    }
}

/// Process an incoming MLS message received from the Gateway.
///
/// Decrypts the message and forwards to the messaging_service handler
/// for authorization checks.
pub async fn handle_incoming_mls(
    shared: Arc<WebauthnSharedState>,
    group_id: &str,
    ciphertext: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, String> {
    match content_type {
        "application/mls-welcome" => {
            // Process Welcome — join a new MLS group
            let (tx, rx) = oneshot::channel();
            shared.mls_cmd_tx.send(MlsSessionCommand::ProcessWelcome {
                welcome_bytes: ciphertext.to_vec(),
                resp: tx,
            }).await.map_err(|e| format!("MLS channel error: {}", e))?;

            let group_id = rx.await
                .map_err(|_| "MLS response channel closed")?
                .map_err(|e| format!("Welcome processing failed: {}", e))?;

            Ok(format!("Joined group: {}", group_id).into_bytes())
        }
        "application/mls-commit" => {
            // Process Commit — update group state
            let (tx, rx) = oneshot::channel();
            shared.mls_cmd_tx.send(MlsSessionCommand::ProcessCommit {
                group_id: group_id.to_string(),
                commit_bytes: ciphertext.to_vec(),
                resp: tx,
            }).await.map_err(|e| format!("MLS channel error: {}", e))?;

            let _ok = rx.await
                .map_err(|_| "MLS response channel closed")?
                .map_err(|e| format!("Commit processing failed: {}", e))?;

            Ok("Commit processed".as_bytes().to_vec())
        }
        "application/mls-application" | _ => {
            // Decrypt application message
            let (tx, rx) = oneshot::channel();
            shared.mls_cmd_tx.send(MlsSessionCommand::DecryptMessage {
                group_id: group_id.to_string(),
                ciphertext: ciphertext.to_vec(),
                resp: tx,
            }).await.map_err(|e| format!("MLS channel error: {}", e))?;

            rx.await
                .map_err(|_| "MLS response channel closed")?
                .map_err(|e| format!("MLS decryption failed: {}", e))
        }
    }
}
