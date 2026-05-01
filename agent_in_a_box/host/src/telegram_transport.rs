use std::sync::Arc;
use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use crate::shared_state::WebauthnSharedState;
use crate::commands::VaultCommand;
use tokio::sync::oneshot;

// --- Telegram Webhook Types ---

#[derive(Debug, Deserialize)]
pub struct TelegramUpdate {
    pub update_id: u64,
    pub message: Option<TelegramMessage>,
    pub callback_query: Option<TelegramCallbackQuery>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramMessage {
    pub message_id: u64,
    pub from: Option<TelegramUser>,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramCallbackQuery {
    pub id: String,
    pub from: TelegramUser,
    pub data: Option<String>,
    pub message: Option<TelegramMessage>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramUser {
    pub id: u64,
    pub is_bot: bool,
    pub first_name: String,
    pub username: Option<String>,
}

// --- Handler ---

pub async fn telegram_webhook_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    Json(update): Json<TelegramUpdate>,
) -> impl IntoResponse {
    let bot_token = match std::env::var("TELEGRAM_BOT_TOKEN") {
        Ok(t) => t,
        Err(_) => return StatusCode::OK.into_response(), // Ignore if not configured
    };

    if let Some(msg) = update.message {
        if let Some(user) = msg.from {
            if let Some(text) = msg.text {
                let telegram_id = user.id.to_string();
                
                // Handle /start command for linking
                if text.starts_with("/start ") {
                    let token = text.trim_start_matches("/start ");
                    if let Err(e) = link_telegram_user(&shared, &telegram_id, token).await {
                        tracing::error!("Telegram linking failed: {}", e);
                        let _ = send_telegram_message(&shared.http_client, &bot_token, &telegram_id, "Failed to link account. Invalid or expired token.").await;
                    } else {
                        let _ = send_telegram_message(&shared.http_client, &bot_token, &telegram_id, "✅ Account successfully linked! You will now receive agent notifications here.").await;
                    }
                } else {
                    // Normal message handling
                    if let Ok(Some(did)) = get_did_for_telegram(&shared, &telegram_id).await {
                        // Forward to agent
                        // For now, just echo back that we received it
                        let _ = send_telegram_message(&shared.http_client, &bot_token, &telegram_id, &format!("Agent received: {}", text)).await;
                    } else {
                        let _ = send_telegram_message(&shared.http_client, &bot_token, &telegram_id, "You are not linked. Please use a /start link from the portal.").await;
                    }
                }
            }
        }
    } else if let Some(cb) = update.callback_query {
        // Handle inline button presses (approvals/denials)
        if let Some(data) = cb.data {
            let telegram_id = cb.from.id.to_string();
            if let Ok(Some(did)) = get_did_for_telegram(&shared, &telegram_id).await {
                tracing::info!("Telegram callback from DID {}: {}", did, data);
                // Can hook into gateway NATS to approve/deny
            }
        }
    }

    StatusCode::OK.into_response()
}

async fn link_telegram_user(shared: &Arc<WebauthnSharedState>, telegram_id: &str, token: &str) -> anyhow::Result<()> {
    let kv_stores = shared.kv_stores.as_ref()
        .ok_or_else(|| anyhow::anyhow!("KV stores not available"))?;
    
    // We repurpose the provisioning store for telegram linking
    let provision_store = kv_stores.get("provisioning")
        .ok_or_else(|| anyhow::anyhow!("provisioning KV not available"))?;

    let entry = provision_store.get(token).await
        .map_err(|e| anyhow::anyhow!("Failed to look up token: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired token"))?;

    let record: crate::dto::RegistrationCookie = serde_json::from_slice(&entry)?;
    
    // The record contains the AID. We need to find the active DID for this user.
    // For simplicity, we can store `telegram_id` -> `uid` mapping in NATS KV.
    if let Some(uid) = &record.uid {
        // Get the real user ID from target_id_map or portal_id_map if needed.
        // Or store directly: telegram_to_uid.
        let telegram_kv = kv_stores.get("telegram_to_uid")
            .ok_or_else(|| anyhow::anyhow!("telegram_to_uid KV not available"))?;
            
        // For this to work, we need a way to reliably map back to DID.
        // Let's store `telegram_id` -> `record.aid` (Account ID)
        telegram_kv.put(telegram_id, record.aid.into()).await
            .map_err(|e| anyhow::anyhow!("KV put error: {}", e))?;
            
        // Delete the one-time token
        let _ = provision_store.delete(token).await;
    }

    Ok(())
}

async fn get_did_for_telegram(shared: &Arc<WebauthnSharedState>, telegram_id: &str) -> anyhow::Result<Option<String>> {
    let kv_stores = shared.kv_stores.as_ref()
        .ok_or_else(|| anyhow::anyhow!("KV stores not available"))?;
        
    let telegram_kv = kv_stores.get("telegram_to_uid")
        .ok_or_else(|| anyhow::anyhow!("telegram_to_uid KV not available"))?;

    if let Some(entry) = telegram_kv.get(telegram_id).await? {
        let aid = String::from_utf8(entry.to_vec())?;
        
        // Lookup UID from AID
        let map = shared.portal_id_map.read().await;
        if let Some(user_id) = map.get(&aid).cloned() {
            // Get Active DID
            let (tx, rx) = oneshot::channel();
            if let Ok(_) = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(user_id, tx)).await {
                if let Ok(did) = rx.await {
                    if !did.is_empty() {
                        return Ok(Some(did));
                    }
                }
            }
        }
    }
    
    Ok(None)
}

pub async fn send_telegram_message(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: &str,
    text: &str,
) -> anyhow::Result<()> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
    });

    let res = client.post(&url)
        .json(&payload)
        .send()
        .await?;

    if !res.status().is_success() {
        let err = res.text().await?;
        anyhow::bail!("Telegram API error: {}", err);
    }

    Ok(())
}
