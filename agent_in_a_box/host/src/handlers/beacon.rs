//! Beacon WIT interface bindings.
//!
//! Implements the `sovereign:gateway/beacon-sender` interface for recovery beacons.

use anyhow::Result;
use wasmtime::component::Linker;

use crate::shared_state::HostState;

/// Bind beacon sender interface functions to the linker.
pub fn bind_beacon_interface(linker: &mut Linker<HostState>) -> Result<()> {
    let mut beacon_linker = linker.instance("sovereign:gateway/beacon-sender")?;

    beacon_linker.func_wrap_async("publish-beacon", |caller, (subject, payload): (String, Vec<u8>)| {
        Box::new(Box::pin(async move {
            let shared = caller.data().shared.clone();
            
            if let Some(nc) = &shared.nats {
                tracing::info!("🛰️ Publishing BEACON to {}", subject);
                match nc.publish(subject, payload.into()).await {
                    Ok(_) => Ok((Ok(true),)),
                    Err(e) => Ok((Err(format!("NATS Error: {}", e)),)),
                }
            } else {
                Ok((Err("NATS not connected".to_string()),))
            }
        }))
    })?;

    Ok(())
}
