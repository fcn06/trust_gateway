use std::sync::Arc;
use wasmtime::Engine;
use wasmtime::component::Linker;
use wasmtime_wasi::{WasiCtx, ResourceTable};
use futures::StreamExt;
use tokio::sync::oneshot;
use anyhow::{Result, Context};

use crate::shared_state::HostState;
use crate::commands::{VaultCommand, AclCommand, MlsSessionCommand, ContactStoreCommand};
use crate::sovereign::gateway::common_types::MlsMessage;

// Helper to bind persistence for specific stores (Vault, ACL, MLS, Contact Store)
async fn bind_persistence(
    linker: &mut Linker<HostState>, 
    store_selector: fn(&HostState) -> Option<async_nats::jetstream::kv::Store>
) -> Result<()> {
    let mut p_linker = linker.instance("sovereign:gateway/persistence")?;

    p_linker.func_wrap_async("get", move |caller, (key,): (String,)| {
        let store_opt = store_selector(caller.data());
        Box::new(Box::pin(async move {
            if let Some(store) = store_opt {
                let encoded_key = hex::encode(key);
                match store.get(encoded_key).await {
                    Ok(Some(entry)) => Ok((Some(entry.to_vec()),)),
                    Ok(None) => Ok((None,)),
                    Err(e) => Err(anyhow::anyhow!("KV Get Error: {}", e)),
                }
            } else {
                 Err(anyhow::anyhow!("KV Store not available"))
            }
        }))
    })?;

    p_linker.func_wrap_async("set", move |caller, (key, value): (String, Vec<u8>)| {
         let store_opt = store_selector(caller.data());
         Box::new(Box::pin(async move {
            if let Some(store) = store_opt {
                let encoded_key = hex::encode(key);
                let _ = store.put(encoded_key, value.into()).await.map_err(|e| anyhow::anyhow!("KV Put Error: {}", e))?;
                Ok(())
            } else {
                Err(anyhow::anyhow!("KV Store not available"))
            }
        }))
    })?;

    p_linker.func_wrap_async("list-keys", move |caller, (): ()| {
         let store_opt = store_selector(caller.data());
         Box::new(Box::pin(async move {
            if let Some(store) = store_opt {
                let mut keys = Vec::new();
                if let Ok(mut stream) = store.keys().await {
                     while let Some(k_res) = stream.next().await {
                         if let Ok(k) = k_res { 
                             if let Ok(decoded_bytes) = hex::decode(&k) {
                                 if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                                     keys.push(decoded_str);
                                 }
                             }
                         } 
                     }
                }
                Ok((keys,))
            } else {
                Err(anyhow::anyhow!("KV Store not available"))
            }
        }))
    })?;

    p_linker.func_wrap_async("get-house-salt", move |caller, (): ()| {
        let salt = caller.data().shared.house_salt.clone();
        Box::new(Box::pin(async move {
            Ok((salt,))
        }))
    })?;
    Ok(())
}

pub async fn setup_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker: Linker<HostState> = Linker::new(engine);
    
    // Add WASI to Linker
    wasmtime_wasi::add_to_linker_async(&mut linker)?;

    // === 1. Vault Interface Binding ===
    let mut vault_linker = linker.instance("sovereign:gateway/vault")?;
    
    vault_linker.func_wrap_async("create-identity", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(id, tx)).await;
            let did = rx.await.unwrap_or_default();
            Ok((did,))
        }))
    })?;

    vault_linker.func_wrap_async("resolve-did-to-user-id", |caller, (did,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::ResolveDid { did, resp: tx }).await;
            let user_id = rx.await.unwrap_or_default().unwrap_or_default();
            Ok((user_id,))
        }))
    })?;

    vault_linker.func_wrap_async("sign-message", |caller, (did, msg): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::SignMessage { did, msg, resp: tx }).await;
            match rx.await {
                Ok(Ok(sig)) => Ok((sig,)),
                Ok(Err(e)) => Err(anyhow::anyhow!(e)),
                Err(_) => Err(anyhow::anyhow!("Channel closed")),
            }
        }))
    })?;

    vault_linker.func_wrap_async("list-identities", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id, tx)).await;
            let dids = rx.await.unwrap_or_default();
            Ok((dids,))
        }))
    })?;

    vault_linker.func_wrap_async("get-active-did", |caller, (user_id,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(user_id, tx)).await;
            let did = rx.await.unwrap_or_default();
            Ok((did,))
        }))
    })?;

    vault_linker.func_wrap_async("set-active-did", |caller, (user_id, did): (String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::SetActiveDid(user_id, did, tx)).await;
            match rx.await {
                Ok(Ok(res)) => Ok((Ok(res),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Channel closed".to_string()),)),
            }
        }))
    })?;
    
    vault_linker.func_wrap_async("generate-master-seed", |caller, (uid, path): (String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::GenerateMasterSeed { user_id: uid, derivation_path: path, resp: tx }).await;
            match rx.await { Ok(Ok(s)) => Ok((s,)), _ => Err(anyhow::anyhow!("Error")), }
        }))
    })?;

    vault_linker.func_wrap_async("derive-link-nkey", |caller, (uid,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
             let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::DeriveLinkNkey { user_id: uid, resp: tx }).await;
            match rx.await { Ok(Ok(s)) => Ok((s,)), _ => Err(anyhow::anyhow!("Error")), }
        }))
    })?;

    vault_linker.func_wrap_async("get-hmac-secret", |caller, (uid,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let mut target_uid = uid.clone();
            
            if uid.starts_with("did:") {
                let (tx, rx) = oneshot::channel();
                let _ = shared.vault_cmd_tx.send(VaultCommand::ResolveDid { did: uid.clone(), resp: tx }).await;
                if let Ok(Some(resolved)) = rx.await {
                    tracing::debug!("🔗 Resolved DID {} to User ID {} for HMAC retrieval", uid, resolved);
                    target_uid = resolved;
                }
            }

            let (tx, rx) = oneshot::channel();
             let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { user_id: target_uid, resp: tx }).await;
            match rx.await { Ok(Ok(s)) => Ok((s,)), _ => Err(anyhow::anyhow!("Error")), }
        }))
    })?;

    vault_linker.func_wrap_async("unlock-vault", |caller, (uid, path): (String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::UnlockVault { user_id: uid, derivation_path: path, resp: tx }).await;
            match rx.await { Ok(res) => Ok((res,)), _ => Err(anyhow::anyhow!("Error")), }
        }))
    })?;

    vault_linker.func_wrap_async("is-unlocked", |caller, (uid,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::IsUnlocked { user_id: uid, resp: tx }).await;
            let res = rx.await.unwrap_or(false);
            Ok((res,))
        }))
    })?;

    vault_linker.func_wrap_async("encrypt-routing-token", |caller, (routing_key, target_id): (String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::EncryptRoutingToken { routing_key, target_id, resp: tx }).await;
            match rx.await {
                Ok(Ok(token)) => Ok((Ok(token),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Channel closed".to_string()),)),
            }
        }))
    })?;

    vault_linker.func_wrap_async("issue-session-jwt", |caller, (subject, scope, user_did, ttl_seconds, tenant_id): (String, Vec<String>, String, u32, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::IssueSessionJwt { subject, scope, user_did, ttl_seconds, tenant_id, resp: tx }).await;
            match rx.await {
                Ok(Ok(jwt)) => Ok((Ok(jwt),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Channel closed".to_string()),)),
            }
        }))
    })?;

    vault_linker.func_wrap_async("create-service-did", |caller, (tenant_id,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::CreateServiceDid { tenant_id, resp: tx }).await;
            match rx.await {
                Ok(Ok(did)) => Ok((Ok(did),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Channel closed".to_string()),)),
            }
        }))
    })?;

    // NEW: DID Document generation (Hybrid Architecture)
    vault_linker.func_wrap_async("create-did-document", |caller, (user_id, gateway_url, target_id): (String, String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.vault_cmd_tx.send(VaultCommand::CreateDidDocument { user_id, gateway_url, target_id, resp: tx }).await;
            match rx.await {
                Ok(Ok(doc)) => Ok((Ok(doc),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Channel closed".to_string()),)),
            }
        }))
    })?;

    // === 1b. Delegation Linker (UCAN — Unchanged) ===
    let mut delegation_linker = linker.instance("sovereign:gateway/delegation")?;

    delegation_linker.func_wrap("validate-ucan", |_caller, (token, resource, action): (String, String, String)| {
        let cap = ssi_crypto::ucan::Capability { resource, action };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match ssi_crypto::ucan::decode_ucan(&token) {
            Ok(ucan) => {
                match ssi_crypto::ucan::validate_ucan(&ucan, &cap, now) {
                    ssi_crypto::ucan::UcanValidationResult::Authorized => Ok((Ok::<String, String>("authorized".to_string()),)),
                    ssi_crypto::ucan::UcanValidationResult::RequiresApproval => Ok((Ok("requires_approval".to_string()),)),
                    ssi_crypto::ucan::UcanValidationResult::Denied(r) => Ok((Err(r),)),
                }
            }
            Err(e) => Ok((Err(e),)),
        }
    })?;

    delegation_linker.func_wrap("create-action-request", |_caller, (tool_name, args_hash, summary): (String, String, String)| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let req = ssi_crypto::ucan::create_action_request(&tool_name, &args_hash, &summary, 300, now);
        Ok(((req.request_id, req.tool_name, req.human_summary, req.payload_hash, req.expires_at),))
    })?;

    delegation_linker.func_wrap("verify-action-response", |_caller, (request_id, approved, signature, expected_hash, user_pubkey): (String, bool, Option<Vec<u8>>, String, Vec<u8>)| {
        let crypto_response = ssi_crypto::ucan::ActionResponse {
            request_id,
            approved,
            signature,
        };
        if user_pubkey.len() != 32 {
            return Ok((Err::<bool, String>(format!("Invalid pubkey length: {}", user_pubkey.len())),));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&user_pubkey);
        match ssi_crypto::ucan::verify_action_response(&crypto_response, &expected_hash, &pk) {
            Ok(v) => Ok((Ok(v),)),
            Err(e) => Ok((Err(e),)),
        }
    })?;

    // === 2. Identity Linker (Host-native — Wasm identity_server removed) ===
    let mut identity_linker = linker.instance("sovereign:gateway/identity")?;

    // NOTE: The identity_server Wasm component has been removed.
    // WebAuthn is handled natively by the Host (auth/logic.rs).
    // The WIT identity interface is still imported by the host-orchestrator world,
    // so we must provide linker bindings. These are now direct implementations.

    identity_linker.func_wrap_async("authenticate", |caller, (id,): (String,)| {
        Box::new(Box::pin(async move {
            // Inline: call VaultCommand::GetActiveDid directly instead of routing through identity loop
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(id.clone(), tx)).await;
            let nkey_seed = rx.await.unwrap_or_default();
            Ok((crate::sovereign::gateway::identity::AuthSession {
                user_id: id,
                nkey_seed,
            },))
        }))
    })?;

    // Global portal has been removed — process-global-login is a no-op error
    identity_linker.func_wrap_async("process-global-login", |_caller, (_assertion,): (Vec<u8>,)| {
        Box::new(Box::pin(async move {
            Ok((Err::<bool, String>("Global login not supported — global_ssi_portal has been removed".to_string()),))
        }))
    })?;
    
    identity_linker.func_wrap_async("start-registration", |caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            match crate::auth::start_registration_logic(&caller.data().shared, username, None).await {
                Ok((session_id, ccr)) => {
                    let res = serde_json::json!({ "session_id": session_id, "options": ccr });
                    Ok((serde_json::to_string(&res).unwrap(),))
                }
                Err(e) => {
                    tracing::error!("❌ start-registration error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("finish-registration", |caller, (session_id, response): (String, String)| {
        Box::new(Box::pin(async move {
            match crate::auth::finish_registration_logic(caller.data().shared.clone(), session_id, response).await {
                Ok((success, _, _)) => Ok((success,)),
                Err(e) => {
                    tracing::error!("❌ finish-registration error: {:?}", e);
                    Ok((false,))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("start-login", |caller, (username,): (String,)| {
        Box::new(Box::pin(async move {
            match crate::auth::start_login_logic(&caller.data().shared, username).await {
                Ok((session_id, rcr)) => {
                    let res = serde_json::json!({ "session_id": session_id, "options": rcr });
                    Ok((serde_json::to_string(&res).unwrap(),))
                }
                Err(e) => {
                    tracing::error!("❌ start-login error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    identity_linker.func_wrap_async("finish-login", |caller, (session_id, response): (String, String)| {
        Box::new(Box::pin(async move {
            match crate::auth::finish_login_logic(caller.data().shared.clone(), session_id, response).await {
                Ok((token, _uid, _username, _cookie)) => Ok((token,)),
                Err(e) => {
                    tracing::error!("❌ finish-login error: {:?}", e);
                    Ok(("error".to_string(),))
                }
            }
        }))
    })?;

    // === 3. Messaging Sender Linker (Pivoted: HTTP egress instead of NATS publish) ===
    let mut messaging_linker = linker.instance("sovereign:gateway/messaging-sender")?;
    messaging_linker.func_wrap_async("send", |caller, (msg,): (MlsMessage,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let target_id = &msg.sender_target_id;
            
            // In the hybrid architecture, messages are sent via HTTP to the Gateway
            // The gateway routes based on the TargetID
            tracing::info!("📤 Sending MLS message for group {} (target: {})", msg.group_id, target_id);
            
            // Use the HTTP egress to post to the gateway
            if let Some(ref gateway_url) = shared.gateway_url {
                let url = format!("{}/ingress", gateway_url);
                let payload = serde_json::to_vec(&serde_json::json!({
                    "target_id": target_id,
                    "group_id": msg.group_id,
                    "epoch": msg.epoch,
                    "content_type": msg.content_type,
                    "ciphertext": msg.ciphertext,
                })).unwrap_or_default();
                
                match reqwest::Client::new()
                    .post(&url)
                    .header("Content-Type", "application/mls-message")
                    .body(payload)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            Ok((Ok("sent".to_string()),))
                        } else {
                            Ok((Err(format!("Gateway returned {}", resp.status())),))
                        }
                    }
                    Err(e) => Ok((Err(format!("HTTP error: {}", e)),)),
                }
            } else {
                // Fallback: publish to local NATS for testing
                if let Some(nc) = &shared.nats {
                    let payload = serde_json::to_vec(&msg).unwrap_or_default();
                    match nc.publish("mls.messages.outgoing".to_string(), payload.into()).await {
                        Ok(_) => Ok((Ok("sent_local".to_string()),)),
                        Err(e) => Ok((Err(format!("NATS Error: {}", e)),)),
                    }
                } else {
                    Ok((Err("No transport available".to_string()),))
                }
            }
        }))
    })?;

    // === 4. MLS Session Linker (NEW — proxies to MLS Session loop) ===
    let mut mls_linker = linker.instance("sovereign:gateway/mls-session")?;
    
    mls_linker.func_wrap_async("create-group", |caller, (group_id, creator_did): (String, String)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::CreateGroup { group_id, creator_did, resp: tx }).await;
            match rx.await {
                Ok(Ok(info)) => Ok((Ok(info),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("generate-key-package", |caller, (did,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::GenerateKeyPackage { did, resp: tx }).await;
            match rx.await {
                Ok(Ok(kp)) => Ok((Ok(kp),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("add-member", |caller, (group_id, invitee_key_package): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::AddMember { group_id, invitee_key_package, resp: tx }).await;
            match rx.await {
                Ok(Ok((welcome, commit))) => Ok((Ok((welcome, commit)),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("process-welcome", |caller, (welcome_bytes,): (Vec<u8>,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::ProcessWelcome { welcome_bytes, resp: tx }).await;
            match rx.await {
                Ok(Ok(gid)) => Ok((Ok(gid),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("process-commit", |caller, (group_id, commit_bytes): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::ProcessCommit { group_id, commit_bytes, resp: tx }).await;
            match rx.await {
                Ok(Ok(ok)) => Ok((Ok(ok),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("encrypt-message", |caller, (group_id, plaintext): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::EncryptMessage { group_id, plaintext, resp: tx }).await;
            match rx.await {
                Ok(Ok(ct)) => Ok((Ok(ct),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    mls_linker.func_wrap_async("decrypt-message", |caller, (group_id, ciphertext): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.mls_cmd_tx.send(MlsSessionCommand::DecryptMessage { group_id, ciphertext, resp: tx }).await;
            match rx.await {
                Ok(Ok(pt)) => Ok((Ok(pt),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("MLS channel closed".to_string()),)),
            }
        }))
    })?;

    // === 5. Contact Store Linker (NEW — proxies to Contact Store loop) ===
    let mut contact_linker = linker.instance("sovereign:gateway/contact-store")?;

    contact_linker.func_wrap_async("store-contact", |caller, (did_doc,): (crate::sovereign::gateway::common_types::DidDocument,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.contact_cmd_tx.send(ContactStoreCommand::StoreContact { did_doc, resp: tx }).await;
            match rx.await {
                Ok(Ok(ok)) => Ok((Ok(ok),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Contact store channel closed".to_string()),)),
            }
        }))
    })?;

    contact_linker.func_wrap_async("get-contact", |caller, (did,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.contact_cmd_tx.send(ContactStoreCommand::GetContact { did, resp: tx }).await;
            let result = rx.await.unwrap_or(None);
            Ok((result,))
        }))
    })?;

    contact_linker.func_wrap_async("list-contacts", |caller, (): ()| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.contact_cmd_tx.send(ContactStoreCommand::ListContacts { resp: tx }).await;
            let result = rx.await.unwrap_or_default();
            Ok((result,))
        }))
    })?;

    contact_linker.func_wrap_async("delete-contact", |caller, (did,): (String,)| {
        Box::new(Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let _ = caller.data().shared.contact_cmd_tx.send(ContactStoreCommand::DeleteContact { did, resp: tx }).await;
            match rx.await {
                Ok(Ok(ok)) => Ok((Ok(ok),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("Contact store channel closed".to_string()),)),
            }
        }))
    })?;

    // === 6. HTTP Egress Linker (NEW — Host-provided for Wasm components) ===
    let mut egress_linker = linker.instance("sovereign:gateway/http-egress")?;

    egress_linker.func_wrap_async("post-to-gateway", |caller, (target_id, payload): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            if let Some(ref gateway_url) = shared.gateway_url {
                let url = format!("{}/ingress", gateway_url);
                match reqwest::Client::new()
                    .post(&url)
                    .header("X-Routing-Token", &target_id)
                    .header("Content-Type", "application/octet-stream")
                    .body(payload)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            Ok((Ok(format!("Delivered ({})", resp.status())),))
                        } else {
                            Ok((Err(format!("Gateway error: {}", resp.status())),))
                        }
                    }
                    Err(e) => Ok((Err(format!("HTTP error: {}", e)),)),
                }
            } else {
                Ok((Err("Gateway URL not configured".to_string()),))
            }
        }))
    })?;

    // === 7. ACL Linker (Unchanged) ===
    let mut acl_linker = linker.instance("sovereign:gateway/acl")?;
    acl_linker.func_wrap_async("check-permission", |caller, (owner_did, subject, perm): (String, String, crate::sovereign::gateway::common_types::Permission)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (a_tx, a_rx) = oneshot::channel();
            let _ = shared.acl_cmd_tx.send(AclCommand::CheckPermission { owner: owner_did, subject, perm, resp: a_tx }).await;
            match a_rx.await {
                Ok(res) => Ok((res,)),
                Err(_) => Err(anyhow::anyhow!("ACL task terminated")),
            }
        }))
    })?;

    acl_linker.func_wrap_async("update-policy", |caller, (owner_did, policy): (String, crate::sovereign::gateway::common_types::ConnectionPolicy)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.acl_cmd_tx.send(AclCommand::UpdatePolicy { owner: owner_did, policy, resp: tx }).await;
            match rx.await {
                Ok(Ok(_)) => Ok((Ok(true),)),
                Ok(Err(e)) => Ok((Err(e),)),
                Err(_) => Ok((Err("ACL task closed".to_string()),)),
            }
        }))
    })?;

    acl_linker.func_wrap_async("get-policies", |caller, (owner_did,): (String,)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            let (tx, rx) = oneshot::channel();
            let _ = shared.acl_cmd_tx.send(AclCommand::GetPolicies { owner: owner_did, resp: tx }).await;
            let policies = rx.await.unwrap_or_default();
            Ok((policies,))
        }))
    })?;

    Ok(linker)
}

// Helper to create specialized linkers for specific persistence stores
pub async fn create_specialized_linker(
    base_linker: &Linker<HostState>,
    store_selector: fn(&HostState) -> Option<async_nats::jetstream::kv::Store>
) -> Result<Linker<HostState>> {
    let mut specific = base_linker.clone();
    bind_persistence(&mut specific, store_selector).await?;
    Ok(specific)
}
