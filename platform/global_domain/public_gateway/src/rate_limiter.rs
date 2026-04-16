//! Per-tenant and per-sender rate limiter for the public gateway.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per minute per tenant.
    pub tenant_rpm: u32,
    /// Max requests per minute per sender (shadow DID).
    pub sender_rpm: u32,
    /// Max payload size in bytes.
    pub max_payload_bytes: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            tenant_rpm: 1000,
            sender_rpm: 30,
            max_payload_bytes: 64 * 1024, // 64KB
        }
    }
}

/// Rolling-window rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// (entity_key) → Vec<Instant>
    windows: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request should be allowed.
    /// Returns Ok(()) if allowed, Err(reason) if denied.
    pub fn check_tenant(&self, tenant_id: &str) -> Result<(), String> {
        let key = format!("tenant:{}", tenant_id);
        self.check_rate(&key, self.config.tenant_rpm)
    }

    /// Check per-sender rate limit.
    pub fn check_sender(&self, sender_id: &str) -> Result<(), String> {
        let key = format!("sender:{}", sender_id);
        self.check_rate(&key, self.config.sender_rpm)
    }

    /// Check payload size.
    pub fn check_payload_size(&self, size: usize) -> Result<(), String> {
        if size > self.config.max_payload_bytes {
            Err(format!(
                "Payload too large: {} bytes (max: {})",
                size, self.config.max_payload_bytes
            ))
        } else {
            Ok(())
        }
    }

    fn check_rate(&self, key: &str, max_rpm: u32) -> Result<(), String> {
        let now = Instant::now();
        let window = Duration::from_secs(60);

        let mut map = self.windows.lock().unwrap();
        let timestamps = map.entry(key.to_string()).or_insert_with(Vec::new);

        // Prune old entries
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() as u32 >= max_rpm {
            return Err(format!("Rate limit exceeded for {}", key));
        }

        timestamps.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            tenant_rpm: 5,
            sender_rpm: 3,
            max_payload_bytes: 1024,
        });
        for _ in 0..5 {
            assert!(limiter.check_tenant("t1").is_ok());
        }
        // 6th should fail
        assert!(limiter.check_tenant("t1").is_err());
    }

    #[test]
    fn test_payload_size_check() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_payload_bytes: 100,
            ..Default::default()
        });
        assert!(limiter.check_payload_size(50).is_ok());
        assert!(limiter.check_payload_size(200).is_err());
    }
}
