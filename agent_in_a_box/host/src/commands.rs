//! Command enums for inter-component communication via channels.
//!
//! These commands are sent from HTTP handlers and WIT linker bindings
//! to the Wasm component processing loops.
//!
//! HYBRID PIVOT: Removed DIDComm (PackSigned, PackEncrypted, UnpackEncrypted,
//! VerifySigned) and Beacon commands. Added MLS session and Contact Store commands.

use tokio::sync::oneshot;

// Re-export generated types from bindgen
use crate::sovereign::gateway::common_types::{ConnectionPolicy, Permission, DidDocument};
use crate::sovereign::gateway::identity::AuthSession;

/// Commands for the Vault component (SSI operations, key management).
pub enum VaultCommand {
    CreateIdentity(String, oneshot::Sender<String>),
    CreatePeerIdentity(String, oneshot::Sender<String>),
    ListIdentities(String, oneshot::Sender<Vec<String>>),
    GetPublishedDids(String, oneshot::Sender<Vec<String>>),
    GetActiveDid(String, oneshot::Sender<String>),
    SetActiveDid(String, String, oneshot::Sender<Result<bool, String>>),
    ResolveDid {
        did: String,
        resp: oneshot::Sender<Option<String>>,
    },
    SignMessage {
        did: String,
        msg: Vec<u8>,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    // Master Seed commands
    GenerateMasterSeed {
        user_id: String,
        derivation_path: String,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    DeriveLinkNkey {
        user_id: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
    UnlockVault {
        user_id: String,
        derivation_path: String,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    IsUnlocked {
        user_id: String,
        resp: oneshot::Sender<bool>,
    },
    GetHmacSecret {
        user_id: String,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    EncryptRoutingToken {
        routing_key: String,
        target_id: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
    // Agent Delegation
    IssueSessionJwt {
        subject: String,
        scope: Vec<String>,
        user_did: String,
        ttl_seconds: u32,
        tenant_id: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
    // Connection Model (V6)
    CreateServiceDid {
        tenant_id: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
    RegisterConnection {
        pairwise_did: String,
        ucan_token: String,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    ListConnections {
        resp: oneshot::Sender<Vec<String>>,
    },
    RevokeConnection {
        pairwise_did: String,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    // NEW: DID Document generation (Hybrid Architecture)
    CreateDidDocument {
        user_id: String,
        gateway_url: String,
        target_id: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
}

/// Commands for the ACL component (access control policies).
pub enum AclCommand {
    UpdatePolicy {
        owner: String,
        policy: ConnectionPolicy,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    GetPolicies {
        owner: String,
        resp: oneshot::Sender<Vec<ConnectionPolicy>>,
    },
    CheckPermission {
        owner: String,
        subject: String,
        perm: Permission,
        resp: oneshot::Sender<bool>,
    },
}

/// Commands for the Identity component (WebAuthn authentication).
pub enum IdentityCommand {
    ProcessGlobalLogin {
        assertion: Vec<u8>,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    Authenticate {
        id: String,
        resp: oneshot::Sender<AuthSession>,
    },
}

/// Commands for the MLS Session component (OpenMLS group management).
pub enum MlsSessionCommand {
    CreateGroup {
        group_id: String,
        creator_did: String,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    GenerateKeyPackage {
        did: String,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    AddMember {
        group_id: String,
        invitee_key_package: Vec<u8>,
        resp: oneshot::Sender<Result<(Vec<u8>, Vec<u8>), String>>,
    },
    ProcessWelcome {
        welcome_bytes: Vec<u8>,
        resp: oneshot::Sender<Result<String, String>>,
    },
    ProcessCommit {
        group_id: String,
        commit_bytes: Vec<u8>,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    EncryptMessage {
        group_id: String,
        plaintext: Vec<u8>,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    DecryptMessage {
        group_id: String,
        ciphertext: Vec<u8>,
        resp: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}

/// Commands for the Contact Store component (ledgerless DID Document storage).
pub enum ContactStoreCommand {
    StoreContact {
        did_doc: DidDocument,
        resp: oneshot::Sender<Result<bool, String>>,
    },
    GetContact {
        did: String,
        resp: oneshot::Sender<Option<DidDocument>>,
    },
    ListContacts {
        resp: oneshot::Sender<Vec<DidDocument>>,
    },
    DeleteContact {
        did: String,
        resp: oneshot::Sender<Result<bool, String>>,
    },
}
