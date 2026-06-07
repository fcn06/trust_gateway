//! Shared cryptographic primitives for the Agent-in-a-Box platform.
//!
//! This crate provides pure functions for:
//! - DID creation and pairwise derivation
//! - DID Document building (W3C format, ledgerless model)
//! - Symmetric encryption (XChaCha20Poly1305 for vault/routing)
//! - Ed25519 signing/verification (SSI key authentication)
//! - Blind persistence key derivation
//! - UCAN token types and validation
//!
//! It has NO dependency on WIT or wasmtime, making it compilable to
//! both `wasm32-wasip2` (Host/Vault) and `wasm32-unknown-unknown` (Browser Wallet).
//!
//! NOTE: Inter-user E2E encryption is handled by OpenMLS (in mls_session crate).
//! This crate only provides symmetric encryption for vault internals.

pub mod did;
pub mod did_document;
pub mod encryption;
pub mod signing;
pub mod blind;
pub mod ucan;

