//! SSI-related types for DIDComm and identity.
//!
//! Contains types used for SSI delegation and DIDComm message handling.

use serde::{Deserialize, Serialize};

/// Decentralized Identifier wrapper type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Did(pub String);

/// Plain DIDComm message structure.
///
/// Represents an unsigned DIDComm message with routing information
/// and a JSON body payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlainDidcomm {
    pub id: String,
    pub thid: Option<String>,
    pub from: Option<Did>,
    pub to: Option<Vec<Did>>,
    #[serde(rename = "type")]
    pub type_: String,
    pub body: serde_json::Value,
    pub created_time: Option<i64>,
    pub expires_time: Option<i64>,
}
