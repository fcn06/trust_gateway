use std::sync::Arc;
use std::collections::HashMap;
use axum::{
    extract::{State, Json, Path as AxumPath, Query},
    http::{StatusCode, HeaderMap, Method},
    response::IntoResponse,
    Router, routing::post,
};
use serde::Deserialize;
// use serde_json::Value;
use webauthn_rs::prelude::*;
use jwt_simple::prelude::Duration;
use tokio::sync::oneshot;
use anyhow::Result;
use hex;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::RngCore;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key, KeyInit, aead::Aead};
use futures::StreamExt;
use jwt_simple::prelude::MACLike; 

use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, AclCommand};
use crate::logic::{compute_local_subject, calculate_blind_key};
use crate::dto::{RegistrationCookie, LinkRemoteResponse, MyClaims, TenantRecord, TenantMembership, TenantInvite}; 
#[cfg(feature = "messaging")]
use crate::handlers::api::{process_accept_invitation_logic, process_send_message_logic, process_get_messages_logic};
#[cfg(not(feature = "messaging"))]
use crate::handlers::api::process_accept_invitation_logic;
#[cfg(feature = "messaging")]
use crate::dto::OobInvitation;

// --- DTOs ---
pub mod dtos;
pub mod logic;
pub mod handlers;
pub mod authenticator;
pub use dtos::*;
pub use logic::*;
pub use handlers::*;
pub use authenticator::WebAuthnAuthenticator;
