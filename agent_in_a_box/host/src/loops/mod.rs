// ─────────────────────────────────────────────────────────────
// Host event loops — Split into focused modules (Phase 4.1)
//
// Each Wasm component gets its own event loop file:
//   vault_loop.rs      — SSI Vault (keys, DIDs, JWTs, connections)
//   acl_loop.rs        — Access Control List
//   contact_loop.rs    — Contact Store
//   messaging_loop.rs  — DIDComm message handling & agent dispatch
//   routing.rs         — O(1) NATS wildcard routing & target ID maps
//   escalation.rs      — MCP escalation, OID4VP, discovery requests
//
// NOTE: identity_loop was removed — WebAuthn is handled natively
//       by the Host (auth/logic.rs). The Wasm identity_server
//       plugin was vestigial and has been deleted.
// ─────────────────────────────────────────────────────────────

mod vault_loop;
mod acl_loop;
mod escalation;

// Re-export public functions
pub use vault_loop::spawn_vault_loop;
pub use acl_loop::spawn_acl_loop;
pub use escalation::{spawn_mcp_escalation_loop, subscribe_to_escalation_requests, subscribe_to_discovery_requests, subscribe_to_escalation_results};

use std::sync::Arc;
use wasmtime::{Engine, Store};
use crate::shared_state::{HostState, WebauthnSharedState};

// Helper to create a WASI store for each Wasm component loop.
// Shared across all loop modules.
pub(crate) fn create_store(engine: &Engine, shared: Arc<WebauthnSharedState>) -> Store<HostState> {
    use wasmtime_wasi::{WasiCtxBuilder, ResourceTable};

    let mut builder = WasiCtxBuilder::new();
    builder.inherit_stdout()
           .inherit_stderr();

    // STRICT INJECTION: Only pass explicitly allowed environment variables into the WASI sandbox.
    let allowed_keys = vec![
        "LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "RUST_LOG"
    ];
    for key in allowed_keys {
        if let Ok(val) = std::env::var(key) {
            builder.env(key, &val);
        }
    }

    let wasi = builder.preopened_dir(".", ".", wasmtime_wasi::DirPerms::all(), wasmtime_wasi::FilePerms::all())
        .expect("WASI error")
        .build();

    Store::new(engine, HostState {
        wasi,
        table: ResourceTable::new(),
        vault: None,
        acl: None,
        vault_store: shared.kv_stores.as_ref().and_then(|m| m.get("vault").cloned()),
        acl_store: shared.kv_stores.as_ref().and_then(|m| m.get("acl").cloned()),
        messaging: None,
        contact_store: None,
        shared: shared.clone(),
    })
}
