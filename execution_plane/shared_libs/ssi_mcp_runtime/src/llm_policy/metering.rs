//! Per-tenant usage metering — tracks token usage, tool calls, and escalations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Usage metrics snapshot for a tenant, used by the policy router.
#[derive(Debug, Clone, Default)]
pub struct UsageMetrics {
    /// Total tokens consumed this billing period.
    pub tokens_used: u64,
    /// Tool calls in the last 60 seconds.
    pub tool_calls_last_minute: u32,
    /// Escalations in the last 60 minutes.
    pub escalations_last_hour: u32,
}

/// In-memory usage meter for a single tenant.
///
/// Tracks rolling window counters for rate limiting and cumulative counters
/// for budget enforcement. In production, these would be backed by NATS KV
/// for persistence across restarts.
#[derive(Debug)]
pub struct TenantMeter {
    pub tenant_id: String,
    /// Cumulative token count for the current billing period.
    pub tokens_used: u64,
    /// Rolling window of tool call timestamps (last 60 seconds).
    tool_call_timestamps: Vec<Instant>,
    /// Rolling window of escalation timestamps (last 60 minutes).
    escalation_timestamps: Vec<Instant>,
}

impl TenantMeter {
    pub fn new(tenant_id: String) -> Self {
        Self {
            tenant_id,
            tokens_used: 0,
            tool_call_timestamps: Vec::new(),
            escalation_timestamps: Vec::new(),
        }
    }

    /// Record token usage from an LLM response.
    pub fn record_tokens(&mut self, count: u64) {
        self.tokens_used += count;
    }

    /// Record a tool call event.
    pub fn record_tool_call(&mut self) {
        self.tool_call_timestamps.push(Instant::now());
    }

    /// Record an escalation event.
    pub fn record_escalation(&mut self) {
        self.escalation_timestamps.push(Instant::now());
    }

    /// Get current usage metrics with rolling window pruning.
    pub fn snapshot(&mut self) -> UsageMetrics {
        let now = Instant::now();

        // Prune tool calls older than 60 seconds
        self.tool_call_timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));

        // Prune escalations older than 60 minutes
        self.escalation_timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(3600));

        UsageMetrics {
            tokens_used: self.tokens_used,
            tool_calls_last_minute: self.tool_call_timestamps.len() as u32,
            escalations_last_hour: self.escalation_timestamps.len() as u32,
        }
    }
}

/// Global meter registry — maps tenant_id to their meter.
///
/// Thread-safe via `Arc<Mutex<...>>`. Each ssi_agent instance maintains
/// its own meter registry. In production, the cumulative counters would
/// sync to NATS KV periodically for cross-instance consistency.
#[derive(Debug, Clone)]
pub struct MeterRegistry {
    meters: Arc<Mutex<HashMap<String, TenantMeter>>>,
}

impl MeterRegistry {
    pub fn new() -> Self {
        Self {
            meters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create a meter for a tenant.
    pub fn get_or_create(&self, tenant_id: &str) -> UsageMetrics {
        let mut map = self.meters.lock().unwrap();
        let meter = map
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantMeter::new(tenant_id.to_string()));
        meter.snapshot()
    }

    /// Record token usage for a tenant.
    pub fn record_tokens(&self, tenant_id: &str, count: u64) {
        let mut map = self.meters.lock().unwrap();
        let meter = map
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantMeter::new(tenant_id.to_string()));
        meter.record_tokens(count);
    }

    /// Record a tool call for a tenant.
    pub fn record_tool_call(&self, tenant_id: &str) {
        let mut map = self.meters.lock().unwrap();
        let meter = map
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantMeter::new(tenant_id.to_string()));
        meter.record_tool_call();
    }

    /// Record an escalation for a tenant.
    pub fn record_escalation(&self, tenant_id: &str) {
        let mut map = self.meters.lock().unwrap();
        let meter = map
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantMeter::new(tenant_id.to_string()));
        meter.record_escalation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meter_records_tokens() {
        let mut meter = TenantMeter::new("t1".to_string());
        meter.record_tokens(100);
        meter.record_tokens(200);
        let snap = meter.snapshot();
        assert_eq!(snap.tokens_used, 300);
    }

    #[test]
    fn test_meter_rolling_window() {
        let mut meter = TenantMeter::new("t1".to_string());
        meter.record_tool_call();
        meter.record_tool_call();
        let snap = meter.snapshot();
        assert_eq!(snap.tool_calls_last_minute, 2);
    }

    #[test]
    fn test_registry_creates_meters() {
        let registry = MeterRegistry::new();
        registry.record_tokens("t1", 500);
        let metrics = registry.get_or_create("t1");
        assert_eq!(metrics.tokens_used, 500);
    }
}
