# Edition Boundaries and Open-Core Architecture

This document defines the architectural boundaries and rules separating the **Lianxi Community Edition (CE)** (`lianxi-community`) from the **Professional/Enterprise Edition (PE)** (`lianxi-professional`).

---

## 1. Architectural Principles

1. **Compilation Features and Separation**: 
   The core execution loop and logic (`host` / `trust_gateway`) reside in the public repository and are uncoupled from enterprise features (OpenMLS messaging, Telegram notifications, standalone OAuth2 server). Separation is achieved at compile-time through Cargo features, separate binary targets (`host` vs `professional_host`), and build-time WASM guest component linking. The shared library `trust_core` defines traits (ports) like `ApprovalNotifier` for integration, which professional modules implement as adapters.

2. **No Upward Dependencies**:
   The community codebase must **NEVER** depend on, reference, or link against professional crates, directories, or modules. The boundary is strictly enforced.
   ```
   lianxi-professional ──> lianxi-community (Allowed)
   lianxi-community    ──x lianxi-professional (Strictly Forbidden)
   ```

3. **CI Guardrail Enforcement**:
   Every pull request and commit to the community codebase is automatically validated by the `.github/workflows/edition_guard.yml` guardrail. If any references to professional-only modules or keywords (e.g. `telegram`, `openmls`, `twin_mediator`, `b2b_agent`, `oauth2_service`) contaminate the community workspace, the pipeline fails immediately.

---

## 2. Shared Kernel (`trust_core`)

To ensure API and schema stability across both repositories, shared DTOs, traits, and NATS message schemas are defined in `trust_core` (located in `lianxi-community/execution_plane/shared_libs/trust_core`). Both CE and PE crates depend on `trust_core`.

---

## 3. Community Edition Shims and Stubs

To avoid conditional compilation complexity (i.e. `#[cfg(feature = "messaging")]`) and preserve code integrity, the community components utilize dynamic runtime injection and minimal compatibility shims:

- **OAuth2 Configuration Stub**:
  The `trust_gateway` maintains an `Option<OAuthConfig>` field inside its state to avoid breaking serialization. However, the internal OAuth2 endpoints are omitted in the CE build, and `oauth_config` is set to `None`.
- **Proxy/Delegation Gateways**:
  When a user attempts to hit OIDC/OAuth discovery or token endpoints, `trust_gateway` acts as a generic reverse proxy. If the `OAUTH2_SERVICE_URL` environment variable is configured (running the PE standalone service), traffic is proxied to it. Otherwise, a `501 Not Implemented` response is returned, indicating that OAuth2 is a professional-only feature.
- **Messaging Sender Linker**:
  The community component linker in `agent_in_a_box/host/src/linker.rs` redirects guest-component calls to `sovereign:gateway/messaging-sender` to a minimal no-op shim that logs the action and returns `Ok("disabled")`. In the Professional Edition (PE), this interface is dynamically bound to the proprietary `messaging_service` component, facilitating military-grade end-to-end encrypted OpenMLS message streams and peer-to-peer Twin Mediator routing.

---

## 4. Professional-Only Crates (`lianxi-professional/`)

The proprietary features are developed in an isolated repository workspace containing:

| Crate | Description |
|---|---|
| `professional_host` | The professional composition root which wires together the core `host` logic with PE adapters. |
| `host_adapters` | Contains professional adapters: `TelegramApprovalNotifier`. |
| `oauth2_service` | The standalone OAuth2/OIDC Authorization Server running on a separate port (`3075`). |
| `twin_mediator` | Proprietary managed P2P routing and DIDComm inbox transit. |
| `b2b_agent` | Professional Agent-as-a-Service infrastructure. |
| `messaging_service` | Enterprise OpenMLS component for encrypted messaging group orchestration. |
| `contact_store` | Advanced component storing contact identities and certificates. |

---

## 5. Build and Execution Modes

The startup script `start_dev.sh` uses the `EDITION` environment variable to determine which services to launch:

- **CE Mode (`EDITION=community`)**:
  - Launches standard `host` binary.
  - Excludes `twin_mediator`, `b2b_agent`, and `oauth2_service`.
- **PE Mode (`EDITION=professional` or `EDITION=entreprise`)**:
  - Launches `professional_host` binary.
  - Launches `twin_mediator`, `b2b_agent`, and `oauth2_service` (port `3075`).
  - Passes `OAUTH2_SERVICE_URL` to `trust_gateway` to enable OIDC proxying.
