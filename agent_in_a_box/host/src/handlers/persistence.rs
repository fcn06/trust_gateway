//! Persistence WIT interface bindings.
//!
//! Implements the `sovereign:gateway/persistence` interface for KV store operations.

use anyhow::Result;
use futures::StreamExt;
use wasmtime::component::Linker;

use crate::shared_state::HostState;

/// Bind persistence interface functions to the linker.
/// 
/// # Arguments
/// * `linker` - The wasmtime linker to add bindings to
/// * `store_selector` - Function to select the appropriate KV store from HostState
pub fn bind_persistence(
    linker: &mut Linker<HostState>, 
    store_selector: fn(&HostState) -> Option<async_nats::jetstream::kv::Store>
) -> Result<()> {
    let mut p_linker = linker.instance("sovereign:gateway/persistence")?;

    p_linker.func_wrap_async("get", move |caller, (key,): (String,)| {
        let store_opt = store_selector(caller.data());
        Box::new(Box::pin(async move {
            if let Some(store) = store_opt {
                let encoded_key = hex::encode(&key);
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
                let encoded_key = hex::encode(&key);
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
                            // Decode hex-encoded keys
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
