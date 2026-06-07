// ─────────────────────────────────────────────────────────────
// community_adapters — Local-only, boring adapter implementations
// for the edition port traits defined in trust_core::ports.
//
// These adapters are used by the Community edition of the Host
// and Trust Gateway. They provide safe defaults:
//   - No external HTTP calls
//   - No third-party service dependencies
//   - No Telegram, Slack, or OAuth integrations
//
// Professional adapters live in the private professional
// repository and override these at composition time.
// ─────────────────────────────────────────────────────────────

pub mod notifier;
pub mod identity;
pub mod transport;
pub mod tenant;
pub mod credentials;
