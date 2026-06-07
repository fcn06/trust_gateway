// Sovereign Host Library Target
pub mod commands;
pub mod shared_state;
pub mod dto;
pub mod handlers;
pub mod registry;
pub mod logic;
pub mod auth;
pub mod loops;
pub mod linker;
pub mod init;
pub mod audit;
pub mod bindings;
pub mod test_helpers;

wasmtime::component::bindgen!({
    interfaces: "
        import sovereign:gateway/vault;
        import sovereign:gateway/identity;
        import sovereign:gateway/messaging-sender;
        import sovereign:gateway/messaging-handler;
        import sovereign:gateway/acl;
        import sovereign:gateway/persistence;
        import sovereign:gateway/delegation;
        import sovereign:gateway/mls-session;
        import sovereign:gateway/contact-store;
        import sovereign:gateway/http-egress;
    ",
    path: "../wit",
    async: true,
    additional_derives: [serde::Serialize, serde::Deserialize],
});
