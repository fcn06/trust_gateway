use serde::{Deserialize, Serialize};
use thiserror::Error;
use trust_model::CallChainContext;

/// Configuration for Layer 0 Call-Chain Guard evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallChainPolicy {
    pub max_depth: usize,
    pub max_frequency_per_tool: u32,
    pub allow_cycles: bool,
}

impl Default for CallChainPolicy {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_frequency_per_tool: 3,
            allow_cycles: false,
        }
    }
}

/// Errors raised when an action violates call-chain governance invariants
#[derive(Debug, Error, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum CallChainError {
    #[error("Execution depth {current} exceeds max configured limit {max}")]
    DepthExceeded { current: usize, max: usize },

    #[error("Cycle detected: tool '{tool_id}' already called in stack {stack:?}")]
    CycleDetected { tool_id: String, stack: Vec<String> },

    #[error("Tool '{tool_id}' called {count} times, exceeding frequency limit of {max}")]
    FrequencyExceeded {
        tool_id: String,
        count: u32,
        max: u32,
    },

    #[error("Call-chain divergence: {0}")]
    ChainDivergence(String),
}

/// Evaluates proposed tool invocation against a CallChainContext and advances state if valid.
pub fn evaluate_and_advance(
    context: &mut CallChainContext,
    tool_id: &str,
    policy: &CallChainPolicy,
) -> Result<(), CallChainError> {
    // 1. Depth verification
    let next_depth = context.call_stack.len() + 1;
    if next_depth > policy.max_depth {
        return Err(CallChainError::DepthExceeded {
            current: next_depth,
            max: policy.max_depth,
        });
    }

    // 2. Cycle detection
    if !policy.allow_cycles && context.call_stack.iter().any(|t| t == tool_id) {
        return Err(CallChainError::CycleDetected {
            tool_id: tool_id.to_string(),
            stack: context.call_stack.clone(),
        });
    }

    // 3. Frequency detection
    let next_count = context.invocation_counts.get(tool_id).copied().unwrap_or(0) + 1;
    if next_count > policy.max_frequency_per_tool {
        return Err(CallChainError::FrequencyExceeded {
            tool_id: tool_id.to_string(),
            count: next_count,
            max: policy.max_frequency_per_tool,
        });
    }

    // Advance state
    context.call_stack.push(tool_id.to_string());
    context
        .invocation_counts
        .insert(tool_id.to_string(), next_count);

    Ok(())
}

/// Validates that an untrusted client's inbound CallChainContext does not conflict with
/// or attempt to rewind the Gateway's authoritative tracked state for the given trace_id.
pub fn validate_context_integrity(
    inbound: Option<&CallChainContext>,
    tracked: Option<&CallChainContext>,
) -> Result<CallChainContext, CallChainError> {
    match (inbound, tracked) {
        (None, None) => Ok(CallChainContext::new("")),
        (Some(in_ctx), None) => Ok(in_ctx.clone()),
        (None, Some(tr_ctx)) => Ok(tr_ctx.clone()),
        (Some(in_ctx), Some(tr_ctx)) => {
            // Assert that tracked stack is a prefix of inbound stack (no history truncation/rewind)
            if in_ctx.call_stack.len() < tr_ctx.call_stack.len() {
                return Err(CallChainError::ChainDivergence(format!(
                    "Inbound call stack length ({}) is less than tracked server state ({})",
                    in_ctx.call_stack.len(),
                    tr_ctx.call_stack.len()
                )));
            }

            for (i, tool) in tr_ctx.call_stack.iter().enumerate() {
                if in_ctx.call_stack.get(i) != Some(tool) {
                    return Err(CallChainError::ChainDivergence(format!(
                        "Inbound call stack diverged from tracked state at position {}: expected '{}', got '{:?}'",
                        i,
                        tool,
                        in_ctx.call_stack.get(i)
                    )));
                }
            }

            // Verify invocation counts are monotonically non-decreasing
            for (tool, tr_count) in &tr_ctx.invocation_counts {
                let in_count = in_ctx.invocation_counts.get(tool).copied().unwrap_or(0);
                if in_count < *tr_count {
                    return Err(CallChainError::ChainDivergence(format!(
                        "Inbound invocation count for '{}' ({}) is lower than tracked server count ({})",
                        tool, in_count, tr_count
                    )));
                }
            }

            Ok(in_ctx.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_chain_depth_limit_boundary() {
        let policy = CallChainPolicy {
            max_depth: 3,
            max_frequency_per_tool: 10,
            allow_cycles: true,
        };

        let mut ctx = CallChainContext::new("trace-1");
        assert!(evaluate_and_advance(&mut ctx, "tool.a", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.b", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.c", &policy).is_ok());
        assert_eq!(ctx.call_stack.len(), 3);

        // 4th call exceeds max_depth 3
        let err = evaluate_and_advance(&mut ctx, "tool.d", &policy).unwrap_err();
        assert_eq!(err, CallChainError::DepthExceeded { current: 4, max: 3 });
    }

    #[test]
    fn test_call_chain_cycle_detection_rejection() {
        let policy = CallChainPolicy {
            max_depth: 10,
            max_frequency_per_tool: 10,
            allow_cycles: false,
        };

        let mut ctx = CallChainContext::new("trace-2");
        assert!(evaluate_and_advance(&mut ctx, "tool.search", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.analyze", &policy).is_ok());

        // Calling tool.search again detects a cycle
        let err = evaluate_and_advance(&mut ctx, "tool.search", &policy).unwrap_err();
        assert_eq!(
            err,
            CallChainError::CycleDetected {
                tool_id: "tool.search".to_string(),
                stack: vec!["tool.search".to_string(), "tool.analyze".to_string()],
            }
        );
    }

    #[test]
    fn test_call_chain_frequency_limit_without_strict_cycle() {
        let policy = CallChainPolicy {
            max_depth: 20,
            max_frequency_per_tool: 2,
            allow_cycles: true, // allow repeating in stack, but capped at frequency 2
        };

        let mut ctx = CallChainContext::new("trace-3");
        assert!(evaluate_and_advance(&mut ctx, "tool.calc", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.other", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.calc", &policy).is_ok());

        // 3rd invocation of tool.calc exceeds max_frequency_per_tool 2
        let err = evaluate_and_advance(&mut ctx, "tool.calc", &policy).unwrap_err();
        assert_eq!(
            err,
            CallChainError::FrequencyExceeded {
                tool_id: "tool.calc".to_string(),
                count: 3,
                max: 2,
            }
        );
    }

    #[test]
    fn test_call_chain_server_state_divergence_rejection() {
        let mut tracked = CallChainContext::new("trace-4");
        tracked.call_stack = vec!["tool.a".to_string(), "tool.b".to_string()];
        tracked.invocation_counts.insert("tool.a".to_string(), 1);
        tracked.invocation_counts.insert("tool.b".to_string(), 1);

        // Client attempts to rewind stack to only ["tool.a"]
        let mut tampered = CallChainContext::new("trace-4");
        tampered.call_stack = vec!["tool.a".to_string()];
        tampered.invocation_counts.insert("tool.a".to_string(), 1);

        let err = validate_context_integrity(Some(&tampered), Some(&tracked)).unwrap_err();
        assert!(matches!(err, CallChainError::ChainDivergence(_)));

        // Client presents valid continuation
        let mut valid_inbound = CallChainContext::new("trace-4");
        valid_inbound.call_stack = vec![
            "tool.a".to_string(),
            "tool.b".to_string(),
            "tool.c".to_string(),
        ];
        valid_inbound
            .invocation_counts
            .insert("tool.a".to_string(), 1);
        valid_inbound
            .invocation_counts
            .insert("tool.b".to_string(), 1);
        valid_inbound
            .invocation_counts
            .insert("tool.c".to_string(), 1);

        assert!(validate_context_integrity(Some(&valid_inbound), Some(&tracked)).is_ok());
    }
}
