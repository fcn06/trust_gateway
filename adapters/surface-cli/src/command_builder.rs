use anyhow::{bail, Context, Result};
use clap::{Arg, ArgAction, Command};
use serde_json::{Map, Value};
use trust_core::tool_registry::ToolDescriptor;

/// Dynamically derives a clap::Command from a ToolDescriptor's JSON Schema.
pub fn build_dynamic_tool_command(tool: &ToolDescriptor) -> Command {
    let name = if !tool.mcp_name.is_empty() {
        tool.mcp_name.as_str()
    } else {
        tool.tool_id.as_str()
    };

    let desc = if !tool.description.is_empty() {
        tool.description.as_str()
    } else {
        tool.display_name.as_str()
    };

    let mut cmd = Command::new(name.to_string()).about(desc.to_string());

    if let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    {
        for (prop_name, prop_meta) in properties {
            let desc = prop_meta
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let required = tool
                .input_schema
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().any(|v| v.as_str() == Some(prop_name)))
                .unwrap_or(false);

            let prop_type = prop_meta
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("string");

            let mut arg = Arg::new(prop_name.clone())
                .long(prop_name.replace('_', "-"))
                .help(desc.to_string())
                .required(required);

            if prop_type == "boolean" {
                arg = arg.action(ArgAction::SetTrue);
            } else {
                arg = arg.num_args(1).action(ArgAction::Set);
            }

            cmd = cmd.arg(arg);
        }
    }

    cmd
}

/// Extracts parsed arguments from clap::ArgMatches according to the tool's input schema.
pub fn extract_tool_arguments(tool: &ToolDescriptor, matches: &clap::ArgMatches) -> Result<Value> {
    let mut map = Map::new();

    if let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    {
        for (prop_name, prop_meta) in properties {
            let prop_type = prop_meta
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("string");

            if prop_type == "boolean" {
                let val = matches.get_flag(prop_name);
                map.insert(prop_name.clone(), Value::Bool(val));
            } else if let Some(val_str) = matches.get_one::<String>(prop_name) {
                match prop_type {
                    "integer" => {
                        let parsed: i64 = val_str.parse().with_context(|| {
                            format!(
                                "Flag '--{}' expected an integer",
                                prop_name.replace('_', "-")
                            )
                        })?;
                        map.insert(prop_name.clone(), Value::Number(parsed.into()));
                    }
                    "number" => {
                        let parsed: f64 = val_str.parse().with_context(|| {
                            format!("Flag '--{}' expected a number", prop_name.replace('_', "-"))
                        })?;
                        let num = serde_json::Number::from_f64(parsed).with_context(|| {
                            format!(
                                "Invalid float value for flag '--{}'",
                                prop_name.replace('_', "-")
                            )
                        })?;
                        map.insert(prop_name.clone(), Value::Number(num));
                    }
                    "object" | "array" => {
                        // Attempt parsing JSON string; fallback to string if invalid
                        let json_val = serde_json::from_str(val_str)
                            .unwrap_or_else(|_| Value::String(val_str.clone()));
                        map.insert(prop_name.clone(), json_val);
                    }
                    _ => {
                        map.insert(prop_name.clone(), Value::String(val_str.clone()));
                    }
                }
            } else {
                // Check if field was required
                let required = tool
                    .input_schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some(prop_name)))
                    .unwrap_or(false);

                if required {
                    bail!(
                        "Missing required argument: '--{}'",
                        prop_name.replace('_', "-")
                    );
                }
            }
        }
    }

    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_core::tool_registry::{EgressClass, ExecutorProfile, RiskTier};

    fn sample_tool() -> ToolDescriptor {
        let mut tool = ToolDescriptor::new(
            "io.lianxi.stripe.refund@v1",
            "Stripe Refund",
            "stripe_refund",
            RiskTier::Financial,
            ExecutorProfile::Connector,
            EgressClass::B2b,
        );
        tool.description = "Refund a credit card charge".to_string();
        tool.input_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "description": "Unique order identifier"
                },
                "amount": {
                    "type": "integer",
                    "description": "Refund amount in cents"
                },
                "force": {
                    "type": "boolean",
                    "description": "Force refund without receipt"
                }
            },
            "required": ["order_id", "amount"]
        });
        tool
    }

    #[test]
    fn test_cli_subcommand_generation_from_registry() {
        let tool = sample_tool();
        let cmd = build_dynamic_tool_command(&tool);

        assert_eq!(cmd.get_name(), "stripe_refund");
        assert_eq!(
            cmd.get_about().unwrap().to_string(),
            "Refund a credit card charge"
        );

        let args: Vec<&str> = cmd.get_arguments().map(|a| a.get_id().as_str()).collect();
        assert!(args.contains(&"order_id"));
        assert!(args.contains(&"amount"));
        assert!(args.contains(&"force"));
    }

    #[test]
    fn test_extract_tool_arguments_with_types() {
        let tool = sample_tool();
        let cmd = build_dynamic_tool_command(&tool);

        let matches = cmd
            .try_get_matches_from(vec![
                "stripe_refund",
                "--order-id",
                "ord_999",
                "--amount",
                "5000",
                "--force",
            ])
            .unwrap();

        let extracted = extract_tool_arguments(&tool, &matches).unwrap();
        assert_eq!(extracted["order_id"], "ord_999");
        assert_eq!(extracted["amount"], 5000);
        assert_eq!(extracted["force"], true);
    }

    #[test]
    fn test_missing_required_argument_fails() {
        let tool = sample_tool();
        let cmd = build_dynamic_tool_command(&tool);

        // Missing --amount
        let matches = cmd.try_get_matches_from(vec!["stripe_refund", "--order-id", "ord_123"]);
        assert!(matches.is_err());
    }
}
