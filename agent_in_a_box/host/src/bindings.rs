pub mod vault_bindgen {
    wasmtime::component::bindgen!({
        world: "ssi-vault",
        path: "../wit",
        async: true,
    });
}


pub mod messaging_bindgen {
    wasmtime::component::bindgen!({
        world: "messaging-service",
        path: "../wit",
        async: true,
        with: {
            "sovereign:gateway/common-types": crate::sovereign::gateway::common_types,
        },
    });
}

pub mod mls_session_bindgen {
    wasmtime::component::bindgen!({
        world: "mls-session-component",
        path: "../wit",
        async: true,
    });
}

pub mod contact_store_bindgen {
    wasmtime::component::bindgen!({
        world: "contact-store-component",
        path: "../wit",
        async: true,
        with: {
            "sovereign:gateway/common-types": crate::sovereign::gateway::common_types,
        },
    });
}
