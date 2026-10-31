use crate::ir::{CastType, ConcatPart, MappingOp, MappingRule, MappingRuleSet};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum InterpreterError {
    #[error("Fuel exhausted during mapping execution (consumed maximum allotted budget)")]
    FuelExhausted,
    #[error("Source path not found: {0}")]
    PathNotFound(String),
    #[error("Type cast failed: cannot cast {from:?} to {target:?}")]
    CastFailed { from: String, target: String },
    #[error("Target path invalid: {0}")]
    InvalidTargetPath(String),
    #[error("Source value is not an array for ArrayMap at: {0}")]
    NotAnArray(String),
}

pub struct Interpreter {
    pub default_fuel: u64,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self { default_fuel: 10_000 }
    }
}

impl Interpreter {
    pub fn new(fuel: u64) -> Self {
        Self { default_fuel: fuel }
    }

    pub fn execute(
        &self,
        rule_set: &MappingRuleSet,
        source: &Value,
    ) -> Result<Value, InterpreterError> {
        let mut fuel = self.default_fuel;
        let mut target = Value::Object(serde_json::Map::new());

        for rule in &rule_set.rules {
            self.execute_rule(rule, source, &mut target, &mut fuel)?;
        }

        Ok(target)
    }

    fn consume_fuel(&self, fuel: &mut u64, amount: u64) -> Result<(), InterpreterError> {
        if *fuel < amount {
            *fuel = 0;
            return Err(InterpreterError::FuelExhausted);
        }
        *fuel = fuel.saturating_sub(amount);
        Ok(())
    }

    fn execute_rule(
        &self,
        rule: &MappingRule,
        source: &Value,
        target: &mut Value,
        fuel: &mut u64,
    ) -> Result<(), InterpreterError> {
        self.consume_fuel(fuel, 1)?;

        let value_opt = match &rule.operation {
            MappingOp::Copy { from_path } => self.get_path(source, from_path).cloned(),
            MappingOp::Constant { value } => Some(value.clone()),
            MappingOp::Concat { parts } => {
                let mut out = String::new();
                for part in parts {
                    self.consume_fuel(fuel, 1)?;
                    match part {
                        ConcatPart::Literal { value } => out.push_str(value),
                        ConcatPart::Field { from_path } => {
                            if let Some(val) = self.get_path(source, from_path) {
                                match val {
                                    Value::String(s) => out.push_str(s),
                                    Value::Number(n) => out.push_str(&n.to_string()),
                                    Value::Bool(b) => out.push_str(&b.to_string()),
                                    _ => out.push_str(&val.to_string()),
                                }
                            }
                        }
                    }
                }
                Some(Value::String(out))
            }
            MappingOp::Cast { from_path, target_type } => {
                let source_val = self.get_path(source, from_path);
                if let Some(val) = source_val {
                    Some(self.cast_value(val, *target_type)?)
                } else {
                    None
                }
            }
            MappingOp::Scale {
                from_path,
                multiplier,
                clamp_min,
                clamp_max,
            } => {
                if let Some(val) = self.get_path(source, from_path) {
                    let num = match val {
                        Value::Number(n) => n.as_f64().unwrap_or(0.0),
                        Value::String(s) => s.trim().parse::<f64>().unwrap_or(0.0),
                        _ => 0.0,
                    };
                    let mut scaled = num * multiplier;
                    if let Some(min) = clamp_min {
                        scaled = scaled.max(*min);
                    }
                    if let Some(max) = clamp_max {
                        scaled = scaled.min(*max);
                    }
                    if scaled.fract() == 0.0 {
                        Some(Value::Number((scaled as i64).into()))
                    } else if let Some(n) = serde_json::Number::from_f64(scaled) {
                        Some(Value::Number(n))
                    } else {
                        Some(Value::Number((scaled as i64).into()))
                    }
                } else {
                    None
                }
            }
            MappingOp::LookupTable {
                from_path,
                table,
                default_value,
            } => {
                let key_opt = self.get_path(source, from_path).and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                });

                if let Some(key) = key_opt {
                    table.get(&key).cloned().or_else(|| default_value.clone())
                } else {
                    default_value.clone()
                }
            }
            MappingOp::ArrayMap { from_path, sub_rules } => {
                let source_array = self.get_path(source, from_path).ok_or_else(|| {
                    InterpreterError::PathNotFound(from_path.clone())
                })?;

                match source_array {
                    Value::Array(items) => {
                        let mut output_arr = Vec::with_capacity(items.len());
                        for item in items {
                            self.consume_fuel(fuel, 1)?;
                            let mut item_target = Value::Object(serde_json::Map::new());
                            for sub in sub_rules {
                                self.execute_rule(sub, item, &mut item_target, fuel)?;
                            }
                            output_arr.push(item_target);
                        }
                        Some(Value::Array(output_arr))
                    }
                    _ => return Err(InterpreterError::NotAnArray(from_path.clone())),
                }
            }
        };

        if let Some(val) = value_opt {
            self.set_path(target, &rule.target_path, val)?;
        }

        Ok(())
    }

    pub fn get_path<'a>(&self, val: &'a Value, path: &str) -> Option<&'a Value> {
        let clean = path.trim().trim_start_matches("$.");
        if clean.is_empty() {
            return Some(val);
        }
        let segments = clean.split('.');
        let mut curr = val;
        for seg in segments {
            match curr {
                Value::Object(map) => {
                    curr = map.get(seg)?;
                }
                Value::Array(arr) => {
                    let idx: usize = seg.parse().ok()?;
                    curr = arr.get(idx)?;
                }
                _ => return None,
            }
        }
        Some(curr)
    }

    pub fn set_path(
        &self,
        target: &mut Value,
        path: &str,
        val: Value,
    ) -> Result<(), InterpreterError> {
        let clean = path.trim().trim_start_matches("$.");
        if clean.is_empty() {
            return Err(InterpreterError::InvalidTargetPath(path.to_string()));
        }
        let segments: Vec<&str> = clean.split('.').collect();
        let mut curr = target;

        for (i, &seg) in segments.iter().enumerate() {
            let is_last = i == segments.len() - 1;
            if is_last {
                if let Value::Object(ref mut map) = curr {
                    map.insert(seg.to_string(), val);
                    return Ok(());
                } else {
                    return Err(InterpreterError::InvalidTargetPath(path.to_string()));
                }
            } else {
                if !curr.is_object() {
                    *curr = Value::Object(serde_json::Map::new());
                }
                let map = curr.as_object_mut().expect("checked is_object");
                if !map.contains_key(seg) {
                    map.insert(seg.to_string(), Value::Object(serde_json::Map::new()));
                }
                curr = map.get_mut(seg).expect("inserted or exists");
            }
        }
        Ok(())
    }

    fn cast_value(&self, val: &Value, target_type: CastType) -> Result<Value, InterpreterError> {
        match target_type {
            CastType::String => match val {
                Value::String(s) => Ok(Value::String(s.clone())),
                Value::Number(n) => Ok(Value::String(n.to_string())),
                Value::Bool(b) => Ok(Value::String(b.to_string())),
                _ => Ok(Value::String(val.to_string())),
            },
            CastType::Integer => match val {
                Value::Number(n) => n
                    .as_i64()
                    .map(|i| Value::Number(i.into()))
                    .or_else(|| n.as_f64().map(|f| Value::Number((f as i64).into())))
                    .ok_or_else(|| InterpreterError::CastFailed {
                        from: val.to_string(),
                        target: "integer".to_string(),
                    }),
                Value::String(s) => s
                    .trim()
                    .parse::<i64>()
                    .map(|i| Value::Number(i.into()))
                    .or_else(|_| s.trim().parse::<f64>().map(|f| Value::Number((f as i64).into())))
                    .map_err(|_| InterpreterError::CastFailed {
                        from: val.to_string(),
                        target: "integer".to_string(),
                    }),
                Value::Bool(b) => Ok(Value::Number((if *b { 1 } else { 0 }).into())),
                _ => Err(InterpreterError::CastFailed {
                    from: val.to_string(),
                    target: "integer".to_string(),
                }),
            },
            CastType::Float => match val {
                Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        serde_json::Number::from_f64(f)
                            .map(Value::Number)
                            .ok_or_else(|| InterpreterError::CastFailed {
                                from: val.to_string(),
                                target: "float".to_string(),
                            })
                    } else {
                        Err(InterpreterError::CastFailed {
                            from: val.to_string(),
                            target: "float".to_string(),
                        })
                    }
                }
                Value::String(s) => s
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
                    .ok_or_else(|| InterpreterError::CastFailed {
                        from: val.to_string(),
                        target: "float".to_string(),
                    }),
                _ => Err(InterpreterError::CastFailed {
                    from: val.to_string(),
                    target: "float".to_string(),
                }),
            },
            CastType::Boolean => match val {
                Value::Bool(b) => Ok(Value::Bool(*b)),
                Value::String(s) => match s.trim().to_lowercase().as_str() {
                    "true" | "1" | "yes" => Ok(Value::Bool(true)),
                    "false" | "0" | "no" => Ok(Value::Bool(false)),
                    _ => Err(InterpreterError::CastFailed {
                        from: val.to_string(),
                        target: "boolean".to_string(),
                    }),
                },
                Value::Number(n) => Ok(Value::Bool(n.as_i64().unwrap_or(0) != 0)),
                _ => Err(InterpreterError::CastFailed {
                    from: val.to_string(),
                    target: "boolean".to_string(),
                }),
            },
        }
    }
}

