use std::sync::Arc;
use tokio::sync::oneshot;
use anyhow::Result;
use axum::http::StatusCode;
use axum::http::HeaderMap;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use webauthn_rs::prelude::*;
use jwt_simple::prelude::{MACLike, Duration};
use crate::shared_state::WebauthnSharedState;
use crate::commands::VaultCommand;
use super::handlers::subscribe_user_to_global_logins;
use crate::logic::compute_local_subject;
use crate::dto::{RegistrationCookie, MyClaims, TenantRecord, TenantMembership, TenantInvite};
use super::dtos::*;
pub async fn start_registration_logic(shared: &WebauthnSharedState, username: String, invite_code: Option<String>) -> Result<(String, CreationChallengeResponse)> {
    let user_unique_id = uuid::Uuid::new_v4();
    let user_id = user_unique_id.to_string();
    
    let (ccr, reg_state) = shared.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        None
    ).map_err(|e| anyhow::anyhow!("WebAuthn error: {:?}", e))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    shared.registration_sessions.write().await
        .insert(session_id.clone(), (reg_state, username, user_id, invite_code));

    Ok((session_id, ccr))
}

pub async fn finish_registration_logic(shared: Arc<WebauthnSharedState>, session_id: String, response: String) -> Result<(bool, String, Option<RegistrationCookie>)> {
    let (reg_state, username, user_id, invite_code) = match shared.registration_sessions.write().await.remove(&session_id) {
        Some(s) => s,
        None => return Ok((false, String::new(), None)),
    };

    let reg_response: RegisterPublicKeyCredential = serde_json::from_str(&response)?;
    
    let passkey = match shared.webauthn.finish_passkey_registration(&reg_response, &reg_state) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("❌ WebAuthn Registration Failed: {:?}", e);
            return Ok((false, String::new(), None));
        }
    };

    // Update in-memory store
    let credentials = {
        let mut creds_map = shared.user_credentials.write().await;
        let user_creds = creds_map.entry(user_id.clone()).or_default();
        user_creds.push(passkey);
        user_creds.clone()
    };

    // Persist to NATS KV
    if let Some(kv_stores) = &shared.kv_stores {
        // 1. Update username -> user_id mapping
        if let Some(map_store) = kv_stores.get("username_to_userid") {
            let encoded_username = hex::encode(username.clone());
            map_store.put(encoded_username, user_id.clone().into()).await
                .map_err(|e| anyhow::anyhow!("KV Put Error: {}", e))?;
        }

        // 2. Update user_id -> credentials
        if let Some(cred_store) = kv_stores.get("user_credentials") {
            let json_bytes = serde_json::to_vec(&credentials)?;
            cred_store.put(user_id.clone(), json_bytes.into()).await
                .map_err(|e| anyhow::anyhow!("KV Put Error: {}", e))?;
        }
        tracing::info!("💾 Persisted credentials and mapping for user: {} ({}) to NATS", username, user_id);
    } else {
        tracing::warn!("⚠️ KV Stores not available, cannot persist credentials!");
        return Ok((false, user_id, None));
    }

    // === Blueprint: Generate Master Seed and Registration Cookie ===
    
    // 1. Request Master Seed generation from Vault
    let derivation_path = compute_local_subject(&user_id, &shared.house_salt);
    
    let (seed_tx, seed_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::GenerateMasterSeed { 
        user_id: user_id.clone(), 
        derivation_path: derivation_path.clone(),
        resp: seed_tx 
    }).await;
    
    let seed_result = match seed_rx.await {
        Ok(res) => res,
        Err(_) => Err("Vault channel closed".to_string()),
    };
    
    if let Err(e) = &seed_result {
        tracing::warn!("⚠️ Master Seed generation failed: {}", e);
        // Fallback to old behavior - still create identity
        let (create_tx, create_rx) = oneshot::channel();
        let _ = shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(user_id.clone(), create_tx)).await;
        let _ = create_rx.await;
        return Ok((true, user_id, None));
    }
    
    // 4. Process Tenant: join via invite code or auto-create personal tenant
    let tenant_id = if let Some(code) = invite_code {
        match resolve_tenant_from_invite(&shared, &code, &user_id).await {
            Ok(tid) => Some(tid),
            Err(e) => {
                tracing::warn!("⚠️ Invite code processing failed: {}. Creating personal tenant.", e);
                Some(create_personal_tenant(&shared, &user_id, &username).await?)
            }
        }
    } else {
        Some(create_personal_tenant(&shared, &user_id, &username).await?)
    };

    // 5. Derive Registration Cookie (with tenant_id)
    let cookie = derive_registration_cookie(shared.clone(), &user_id, &username, tenant_id).await?;
    
    tracing::info!("🍪 Generated Registration Cookie for user: {} -> aid={}, tenant={:?}", user_id, cookie.aid, cookie.tenant_id);
    
    // 5. Unlock the vault immediately after generation
    let (unlock_tx, unlock_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::UnlockVault { 
        user_id: user_id.clone(), 
        derivation_path: derivation_path.clone(),
        resp: unlock_tx 
    }).await;
    let _ = unlock_rx.await;

    // 6. Create first identity for user
    let (create_tx, create_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::CreateIdentity(user_id.clone(), create_tx)).await;
    let _ = create_rx.await;

    // 6. Dynamically subscribe this user to global login requests
    #[cfg(feature = "messaging")]
    subscribe_user_to_global_logins(shared.clone(), user_id.clone()).await;

    Ok((true, user_id, Some(cookie)))
}

pub async fn derive_registration_cookie(shared: Arc<WebauthnSharedState>, user_id: &str, username: &str, tenant_id: Option<String>) -> Result<RegistrationCookie> {
    // 2. Derive Link NKey from Master Seed
    let (nkey_tx, nkey_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::DeriveLinkNkey { 
        user_id: user_id.to_string(), 
        resp: nkey_tx 
    }).await;
    
    let link_public_key = match nkey_rx.await {
        Ok(Ok(pk)) => pk,
        _ => String::new(),
    };
    
    // 3. Generate NATS Account ID from HMAC (Subject Obfuscation)
    let (hmac_tx, hmac_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { 
        user_id: user_id.to_string(), 
        resp: hmac_tx 
    }).await;
    
    let account_id = match hmac_rx.await {
        Ok(Ok(secret)) => {
             let mut mac = <hmac::Hmac::<sha2::Sha256> as hmac::Mac>::new_from_slice(&secret).unwrap();
             hmac::Mac::update(&mut mac, b"login");
             let result = mac.finalize();
             let aid = hex::encode(result.into_bytes());
             
             // Persist AID to local KV for reliable startup subscriptions (bypass vault lock)
             if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("userid_to_aid")) {
                 let _ = kv.put(user_id, aid.clone().into()).await;
             }
             
             aid
        },
        _ => {
            // Check fallback from KV if vault is locked but we have it persisted
            let mut aid = format!("ACC_{}", &user_id[..8].to_uppercase());
            if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("userid_to_aid")) {
                 if let Ok(Some(entry)) = kv.get(user_id).await {
                      if let Ok(val) = String::from_utf8(entry.to_vec()) {
                          aid = val;
                      }
                 }
            }
            aid
        }
    };

    Ok(RegistrationCookie {
        aid: account_id,
        lpk: link_public_key,
        rly: shared.config.service_gateway_base_url.clone(),
        nid: crate::logic::compute_node_id(&shared.house_salt),
        uid: Some(hex::encode(sha2::Sha256::digest(username.as_bytes()))[..16].to_string()),
        tenant_id,
    })
}

// === Multi-Tenant Helper Functions ===

/// Look up the user's primary tenant membership.
pub async fn lookup_user_tenant(shared: &Arc<WebauthnSharedState>, user_id: &str) -> Option<String> {
    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("user_tenant_membership")) {
        if let Ok(Some(entry)) = kv.get(user_id).await {
            if let Ok(memberships) = serde_json::from_slice::<Vec<TenantMembership>>(&entry) {
                if let Some(first) = memberships.first() {
                    return Some(first.tenant_id.clone());
                }
            }
        }
    }

    // Migration logic: If user has no tenant, auto-create one on the fly.
    tracing::info!("⚠️ User {} has no tenant. Running on-the-fly migration.", user_id);
    if let Ok(tenant_id) = create_personal_tenant(shared, user_id, "User").await {
        return Some(tenant_id);
    }

    None
}

/// Create a personal tenant for a newly registered user.
async fn create_personal_tenant(shared: &std::sync::Arc<WebauthnSharedState>, user_id: &str, username: &str) -> anyhow::Result<String> {
    let tenant_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let record = TenantRecord {
        tenant_id: tenant_id.clone(),
        display_name: format!("{}'s workspace", username),
        owner_user_id: user_id.to_string(),
        created_at: now,
    };

    let membership = TenantMembership {
        tenant_id: tenant_id.clone(),
        role: "owner".to_string(),
        joined_at: now,
    };

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(reg_store) = kv_stores.get("tenant_registry") {
            reg_store.put(&tenant_id, serde_json::to_vec(&record)?.into()).await
                .map_err(|e| anyhow::anyhow!("Failed to create tenant: {}", e))?;
        }
        if let Some(mem_store) = kv_stores.get("user_tenant_membership") {
            let memberships = vec![membership];
            mem_store.put(user_id, serde_json::to_vec(&memberships)?.into()).await
                .map_err(|e| anyhow::anyhow!("Failed to create membership: {}", e))?;
        }
    }

    tracing::info!("🏢 Created personal tenant {} for user {}", tenant_id, user_id);
    Ok(tenant_id)
}

/// Resolve tenant from invite code, consume the invite, and create membership.
async fn resolve_tenant_from_invite(shared: &std::sync::Arc<WebauthnSharedState>, code: &str, user_id: &str) -> anyhow::Result<String> {
    let kv_stores = shared.kv_stores.as_ref()
        .ok_or_else(|| anyhow::anyhow!("KV stores not available"))?;
    let invite_store = kv_stores.get("tenant_invites")
        .ok_or_else(|| anyhow::anyhow!("tenant_invites KV not available"))?;

    let entry = invite_store.get(code).await
        .map_err(|e| anyhow::anyhow!("Failed to look up invite: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("Invalid invite code: {}", code))?;

    let invite: TenantInvite = serde_json::from_slice(&entry)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if now > invite.expires_at {
        anyhow::bail!("Invite code has expired");
    }

    // Create membership for this user in the invite's tenant
    let membership = TenantMembership {
        tenant_id: invite.tenant_id.clone(),
        role: invite.role.clone(),
        joined_at: now,
    };

    if let Some(mem_store) = kv_stores.get("user_tenant_membership") {
        let mut memberships = if let Ok(Some(existing)) = mem_store.get(user_id).await {
            serde_json::from_slice::<Vec<TenantMembership>>(&existing).unwrap_or_default()
        } else {
            Vec::new()
        };
        memberships.push(membership);
        mem_store.put(user_id, serde_json::to_vec(&memberships)?.into()).await
            .map_err(|e| anyhow::anyhow!("Failed to create membership: {}", e))?;
    }

    // Consume the invite (one-time use)
    let _ = invite_store.delete(code).await;

    tracing::info!("🤝 User {} joined tenant {} via invite code {}", user_id, invite.tenant_id, code);
    Ok(invite.tenant_id)
}


pub async fn start_login_logic(shared: &WebauthnSharedState, username: String) -> Result<(String, RequestChallengeResponse)> {
    let user_id = {
        // Look up in KV
        if let Some(kv_stores) = &shared.kv_stores {
            if let Some(map_store) = kv_stores.get("username_to_userid") {
                 let encoded_username = hex::encode(&username);
                 match map_store.get(encoded_username).await.map_err(|e| anyhow::anyhow!("KV Get Error: {}", e))? {
                    Some(entry) => String::from_utf8(entry.to_vec())?,
                    None => anyhow::bail!("User mapping not found for {}", username),
                 }
            } else {
                anyhow::bail!("KV Store not available");
            }
        } else {
            anyhow::bail!("KV Stores not initialized");
        }
    };

    // Load credentials (lazy load from KV if missing in memory)
    let user_creds = {
        let creds_opt = {
            let creds_map = shared.user_credentials.read().await;
            creds_map.get(&user_id).cloned()
        };

        if let Some(c) = creds_opt {
            c
        } else {
            let mut fetched_creds = Vec::new();
            if let Some(kv_stores) = &shared.kv_stores {
                if let Some(cred_store) = kv_stores.get("user_credentials") {
                    if let Some(entry) = cred_store.get(&user_id).await.map_err(|e| anyhow::anyhow!("KV Get Error: {}", e))? {
                        fetched_creds = serde_json::from_slice(&entry)?;
                    }
                }
            }
            
            if fetched_creds.is_empty() {
                anyhow::bail!("User credentials not found for {}", user_id);
            }
            
            // Re-acquire lock and insert
            {
                let mut creds_map = shared.user_credentials.write().await;
                creds_map.insert(user_id.clone(), fetched_creds.clone());
            }
            fetched_creds
        }
    };

    let (rcr, auth_state) = shared.webauthn.start_passkey_authentication(&user_creds)
        .map_err(|e| anyhow::anyhow!("WebAuthn error: {:?}", e))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    shared.authentication_sessions.write().await
        .insert(session_id.clone(), (auth_state, username, user_id));

    Ok((session_id, rcr))
}

pub async fn finish_login_logic(shared: Arc<WebauthnSharedState>, session_id: String, response: String) -> Result<(String, String, String, RegistrationCookie)> {
    tracing::info!("🔐 Finishing login for session: {}", session_id);
    
    let auth_response: PublicKeyCredential = match serde_json::from_str(&response) {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("❌ Failed to parse WebAuthn response: {:?}", e);
            anyhow::bail!("Invalid response format");
        }
    };
    
    let (auth_state, username, user_id) = {
        let mut sessions = shared.authentication_sessions.write().await;
        match sessions.remove(&session_id) {
            Some(s) => s,
            None => {
                tracing::error!("❌ Session not found: {}", session_id);
                anyhow::bail!("Session not found")
            }
        }
    };

    match shared.webauthn.finish_passkey_authentication(&auth_response, &auth_state) {
        Ok(_) => {
            tracing::info!("✅ WebAuthn Login Successful for user: {} ({})", username, user_id);
            
            // Unlock Vault
            let derivation_path = compute_local_subject(&user_id, &shared.house_salt);
            let (unlock_tx, unlock_rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::UnlockVault { 
                user_id: user_id.clone(), 
                derivation_path, 
                resp: unlock_tx 
            }).await;
            
            match unlock_rx.await {
                Ok(Ok(true)) => {
                    tracing::info!("🔓 Vault unlocked for session");
                    // Subscribe to DIDComm for all user's DIDs now that vault is unlocked
                    // Note: O(1) Wildcard Subscription covers all DIDs.
                    // However, we might need to ensure target_id_map is up to date?
                    // The VaultCommand::ListIdentities loop in loops.rs populates map on startup.
                    // Creating new identity populates map.
                    // Unlocked vault doesn't change the map unless we load DIDs we didn't know about?
                    // Map population relies on listing identities. If vault was locked, maybe we couldn't list them?
                    // In loops.rs `populate_target_id_map` spawns a task. If vault is locked, `ListIdentities` might fail or return empty?
                    // If so, we should re-populate map here!
                    
                    let (did_tx, did_rx) = oneshot::channel();
                    let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.clone(), did_tx)).await;
                    let user_dids = did_rx.await.unwrap_or_default();
                    
                    let mut map = shared.target_id_map.write().await;
                    for did in user_dids {
                        let target_id = compute_local_subject(&did, &shared.house_salt);
                        map.insert(target_id, did);
                    }
                },
                Ok(Ok(false)) => tracing::warn!("⚠️ Failed to unlock vault for {}: Logic returned false", user_id),
                Ok(Err(e)) => tracing::error!("⚠️ Failed to unlock vault for {}: {}", user_id, e),
                Err(e) => tracing::error!("⚠️ Failed to unlock vault for {}: Channel error: {:?}", user_id, e),
            }
            
            // Look up user's existing tenant membership
            let tenant_id = lookup_user_tenant(&shared, &user_id).await;

            // Generate random JTI for session correlation
            let session_jti = uuid::Uuid::new_v4().to_string();

            // Generate JWT
            let my_claims = MyClaims {
                user_id: user_id.clone(),
                username: username.clone(),
                tenant_id: tenant_id.clone(),
                jti: None,
            };
            
            // Resolve primary DID for issuer
            let (tx_did, rx_did) = tokio::sync::oneshot::channel();
            let _ = shared.vault_cmd_tx.send(crate::commands::VaultCommand::ListIdentities(user_id.clone(), tx_did)).await;
            let my_dids = rx_did.await.unwrap_or_default();
            let issuer = my_dids.first().cloned().unwrap_or_else(|| user_id.clone());

            let claims = jwt_simple::prelude::Claims::with_custom_claims(my_claims, Duration::from_hours(24))
                .with_subject(user_id.clone())
                .with_issuer(issuer)
                .with_jwt_id(session_jti);
            let token = shared.jwt_key.authenticate(claims).unwrap_or_else(|_| "error".to_string());
            
            let cookie = derive_registration_cookie(shared.clone(), &user_id, &username, tenant_id).await?;
            
            // Trigger global subscriptions if not already active
            tracing::info!("🌍 Triggering global NATS subscriptions for user: {}", user_id);
            #[cfg(feature = "messaging")]
            subscribe_user_to_global_logins(shared.clone(), user_id.clone()).await;

            Ok((token, user_id, username, cookie))
        },
        Err(e) => {
            tracing::error!("❌ WebAuthn Login Failed for session {}: {:?}", session_id, e);
            anyhow::bail!("Authentication failed")
        }
    }
}

pub async fn extract_claims(shared: &WebauthnSharedState, headers: &HeaderMap) -> Result<MyClaims, StatusCode> {
    let token = if let Some(auth_header) = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty()) 
    {
        auth_header
    } else if let Some(cookie_header) = headers.get("Cookie") {
        let cookie_str = cookie_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
        cookie_str.split(';').find(|s| s.trim().starts_with("ssi_token="))
            .and_then(|s| s.split('=').nth(1))
            .ok_or(StatusCode::UNAUTHORIZED)?
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };
        
    let claims = shared.jwt_key.verify_token::<MyClaims>(token, None)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    let mut custom = claims.custom;
    custom.jti = claims.jwt_id;
        
    Ok(custom)
}

pub async fn resolve_active_did(shared: Arc<WebauthnSharedState>, headers: &HeaderMap) -> Result<String, StatusCode> {
    let claims = extract_claims(&shared, headers).await?;
    resolve_active_did_for_user(shared, &claims.user_id).await
}

pub async fn resolve_active_did_for_user(shared: Arc<WebauthnSharedState>, user_id: &str) -> Result<String, StatusCode> {
    // Attempt 1: Check if already unlocked
    let (tx, rx) = oneshot::channel();
    if let Err(_) = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(user_id.to_string(), tx)).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    if let Ok(did) = rx.await {
        if !did.is_empty() {
            return Ok(did);
        }
    }

    // Attempt 2: Stateless Auto-Unlock (Session Recovery)
    tracing::info!("🔓 Auto-Unlock: Attempting to restore session for locked user {}", user_id);
    
    let derivation_path = compute_local_subject(user_id, &shared.house_salt);
    let (unlock_tx, unlock_rx) = oneshot::channel();
    
    let _ = shared.vault_cmd_tx.send(VaultCommand::UnlockVault { 
        user_id: user_id.to_string(), 
        derivation_path, 
        resp: unlock_tx 
    }).await;
    
    // Wait for unlock
    match unlock_rx.await {
        Ok(Ok(true)) => {
            tracing::info!("✅ Auto-Unlock: Successfully restored session for {}", user_id);
            
            // Subscribe to DIDComm for all user's DIDs now that vault is unlocked
            let (did_tx, did_rx) = oneshot::channel();
            let _ = shared.vault_cmd_tx.send(VaultCommand::ListIdentities(user_id.to_string(), did_tx)).await;
            let user_dids = did_rx.await.unwrap_or_default();
            
            let mut map = shared.target_id_map.write().await;
            for did in user_dids {
                let target_id = compute_local_subject(&did, &shared.house_salt);
                map.insert(target_id, did);
            }
            
            // Retry Fetching Active DID
            let (tx2, rx2) = oneshot::channel();
            if let Ok(_) = shared.vault_cmd_tx.send(VaultCommand::GetActiveDid(user_id.to_string(), tx2)).await {
                 match rx2.await {
                    Ok(did) if !did.is_empty() => return Ok(did),
                    _ => return Err(StatusCode::NOT_FOUND),
                }
            }
        },
        _ => {
            tracing::error!("❌ Auto-Unlock: Failed to restore session for {}", user_id);
        }
    }
    
    Err(StatusCode::NOT_FOUND)
}


