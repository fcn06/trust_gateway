// ─────────────────────────────────────────────────────────────
// NoopTransportIngress — Community edition transport ingress.
//
// No external message transport. start() and stop() are no-ops.
// The community edition does not support DIDComm, Telegram, etc.
// ─────────────────────────────────────────────────────────────

use async_trait::async_trait;
use trust_core::ports::TransportIngress;

/// Community edition transport — no external ingress.
pub struct NoopTransportIngress;

impl NoopTransportIngress {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopTransportIngress {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportIngress for NoopTransportIngress {
    async fn start(&self) -> anyhow::Result<()> {
        tracing::debug!("NoopTransportIngress: start() called (no-op)");
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        tracing::debug!("NoopTransportIngress: stop() called (no-op)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_transport_start_stop() {
        let transport = NoopTransportIngress::new();
        assert!(transport.start().await.is_ok());
        assert!(transport.stop().await.is_ok());
    }

    #[test]
    fn test_transport_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopTransportIngress>();
    }
}
