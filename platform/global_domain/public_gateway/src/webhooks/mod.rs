//! Web2 ingress webhooks — Twilio SMS / WhatsApp adapters.
//!
//! Receives incoming messages from Web2 channels, generates deterministic
//! shadow DIDs per sender, wraps content into DIDComm v2 format, and
//! routes through the tenant NATS namespace.

pub mod shadow_identity;
pub mod twilio;
pub mod whatsapp;
