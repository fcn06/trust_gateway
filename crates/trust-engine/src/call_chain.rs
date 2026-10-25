use crate::traits::EngineError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trust_sdk::model::CallChainContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Error, PartialEq, Eq)]
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

impl From<CallChainError> for EngineError {
    fn from(err: CallChainError) -> Self {
        EngineError::CallChainViolation(err.to_string())
    }
}

pub fn evaluate_and_advance(
    context: &mut CallChainContext,
    tool_id: &str,
    policy: &CallChainPolicy,
) -> Result<(), CallChainError> {
    let next_depth = context.call_stack.len() + 1;
    if next_depth > policy.max_depth {
        return Err(CallChainError::DepthExceeded {
            current: next_depth,
            max: policy.max_depth,
        });
    }

    if !policy.allow_cycles && context.call_stack.iter().any(|t| t == tool_id) {
        return Err(CallChainError::CycleDetected {
            tool_id: tool_id.to_string(),
            stack: context.call_stack.clone(),
        });
    }

    let next_count = context.invocation_counts.get(tool_id).copied().unwrap_or(0) + 1;
    if next_count > policy.max_frequency_per_tool {
        return Err(CallChainError::FrequencyExceeded {
            tool_id: tool_id.to_string(),
            count: next_count,
            max: policy.max_frequency_per_tool,
        });
    }

    context.call_stack.push(tool_id.to_string());
    context
        .invocation_counts
        .insert(tool_id.to_string(), next_count);

    Ok(())
}

pub fn validate_context_integrity(
    inbound: Option<&CallChainContext>,
    tracked: Option<&CallChainContext>,
) -> Result<CallChainContext, CallChainError> {
    match (inbound, tracked) {
        (None, None) => Ok(CallChainContext::new("")),
        (Some(in_ctx), None) => Ok(in_ctx.clone()),
        (None, Some(tr_ctx)) => Ok(tr_ctx.clone()),
        (Some(in_ctx), Some(tr_ctx)) => {
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
                        "Inbound call stack diverged at position {}: expected '{}', got '{:?}'",
                        i,
                        tool,
                        in_ctx.call_stack.get(i)
                    )));
                }
            }

            for (tool, tr_count) in &tr_ctx.invocation_counts {
                let in_count = in_ctx.invocation_counts.get(tool).copied().unwrap_or(0);
                if in_count < *tr_count {
                    return Err(CallChainError::ChainDivergence(format!(
                        "Inbound invocation count for '{}' ({}) is lower than tracked count ({})",
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
    fn test_call_chain_depth_limit() {
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

        let err = evaluate_and_advance(&mut ctx, "tool.d", &policy).unwrap_err();
        assert_eq!(err, CallChainError::DepthExceeded { current: 4, max: 3 });
    }

    #[test]
    fn test_call_chain_cycle_detection() {
        let policy = CallChainPolicy {
            max_depth: 10,
            max_frequency_per_tool: 10,
            allow_cycles: false,
        };

        let mut ctx = CallChainContext::new("trace-2");
        assert!(evaluate_and_advance(&mut ctx, "tool.search", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.analyze", &policy).is_ok());

        let err = evaluate_and_advance(&mut ctx, "tool.search", &policy).unwrap_err();
        assert!(matches!(err, CallChainError::CycleDetected { .. }));
    }

    #[test]
    fn test_call_chain_frequency_limit() {
        let policy = CallChainPolicy {
            max_depth: 20,
            max_frequency_per_tool: 2,
            allow_cycles: true,
        };

        let mut ctx = CallChainContext::new("trace-3");
        assert!(evaluate_and_advance(&mut ctx, "tool.calc", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.other", &policy).is_ok());
        assert!(evaluate_and_advance(&mut ctx, "tool.calc", &policy).is_ok());

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
}
