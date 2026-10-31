use crate::classifier::{ClassifiedOperation, OperationClassifier};
use openapiv3::{OpenAPI, Operation, PathItem, ReferenceOr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenApiError {
    #[error("Failed to parse OpenAPI JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Failed to parse OpenAPI specification: {0}")]
    SpecError(String),
}

pub struct OpenApiInspector {
    classifier: OperationClassifier,
}

impl Default for OpenApiInspector {
    fn default() -> Self {
        Self::new(OperationClassifier::default())
    }
}

impl OpenApiInspector {
    pub fn new(classifier: OperationClassifier) -> Self {
        Self { classifier }
    }

    pub fn inspect_spec_str(&self, raw: &str) -> Result<Vec<ClassifiedOperation>, OpenApiError> {
        // Try parsing as JSON first
        let openapi: OpenAPI = match serde_json::from_str(raw) {
            Ok(spec) => spec,
            Err(json_err) => {
                // If not JSON, try parsing via YAML if available, or return clear error
                match serde_yaml::from_str::<OpenAPI>(raw) {
                    Ok(spec) => spec,
                    Err(_) => return Err(OpenApiError::JsonParseError(json_err)),
                }
            }
        };

        self.inspect_openapi(&openapi)
    }

    pub fn inspect_openapi(&self, spec: &OpenAPI) -> Result<Vec<ClassifiedOperation>, OpenApiError> {
        let mut results = Vec::new();

        for (path, item_ref) in &spec.paths.paths {
            let path_item = match item_ref {
                ReferenceOr::Item(item) => item,
                ReferenceOr::Reference { .. } => continue,
            };

            let operations = [
                ("GET", path_item.get.as_ref()),
                ("POST", path_item.post.as_ref()),
                ("PUT", path_item.put.as_ref()),
                ("DELETE", path_item.delete.as_ref()),
                ("PATCH", path_item.patch.as_ref()),
                ("HEAD", path_item.head.as_ref()),
                ("OPTIONS", path_item.options.as_ref()),
            ];

            for (method, op_opt) in operations {
                if let Some(op) = op_opt {
                    let classified = self.classify_single_operation(path, method, op, path_item);
                    results.push(classified);
                }
            }
        }

        // Sort by path, then method for determinism
        results.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));
        Ok(results)
    }

    fn classify_single_operation(
        &self,
        path: &str,
        method: &str,
        op: &Operation,
        path_item: &PathItem,
    ) -> ClassifiedOperation {
        let operation_id = op
            .operation_id
            .clone()
            .unwrap_or_else(|| format!("{}_{}", method.to_lowercase(), path.replace(['/', '{', '}', '-'], "_")));

        let summary = op.summary.clone();
        let description = op.description.clone();

        // Collect all parameter and body fields
        let mut param_names = Vec::new();
        let mut required_params = Vec::new();

        // 1. Path item level parameters
        for p_ref in &path_item.parameters {
            if let ReferenceOr::Item(param) = p_ref {
                let data = match param {
                    openapiv3::Parameter::Query { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Header { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Path { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Cookie { parameter_data, .. } => parameter_data,
                };
                param_names.push(data.name.clone());
                if data.required {
                    required_params.push(data.name.clone());
                }
            }
        }

        // 2. Operation level parameters
        for p_ref in &op.parameters {
            if let ReferenceOr::Item(param) = p_ref {
                let data = match param {
                    openapiv3::Parameter::Query { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Header { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Path { parameter_data, .. } => parameter_data,
                    openapiv3::Parameter::Cookie { parameter_data, .. } => parameter_data,
                };
                if !param_names.contains(&data.name) {
                    param_names.push(data.name.clone());
                }
                if data.required && !required_params.contains(&data.name) {
                    required_params.push(data.name.clone());
                }
            }
        }

        // 3. Extract request body fields (if object schema present)
        if let Some(ReferenceOr::Item(req_body)) = &op.request_body {
            if let Some(media) = req_body.content.get("application/json") {
                if let Some(ReferenceOr::Item(openapiv3::Schema {
                    schema_kind: openapiv3::SchemaKind::Type(openapiv3::Type::Object(obj)),
                    ..
                })) = &media.schema
                {
                    for (prop_name, _) in &obj.properties {
                        if !param_names.contains(prop_name) {
                            param_names.push(prop_name.clone());
                        }
                    }
                    for req in &obj.required {
                        if !required_params.contains(req) {
                            required_params.push(req.clone());
                        }
                    }
                }
            }
        }

        // Build mock arguments json from parameter names for deterministic metrics extraction
        let mut mock_args = serde_json::Map::new();
        for param in &param_names {
            mock_args.insert(param.clone(), serde_json::Value::String("param_placeholder".to_string()));
        }
        let args_val = serde_json::Value::Object(mock_args);

        // Run classifier with composite name: {method}_{operation_id}_{path}
        let composite_name = format!("{}_{}_{}", method, operation_id, path);
        let mut metrics = self.classifier.inspect(
            &composite_name,
            &method.to_lowercase(),
            &args_val,
            None,
        );

        // --- OpenAPI x-trust Annotations (v0.1) ---
        // If the author has explicitly specified x-trust extensions, incorporate them
        if let Some(x_trust) = op.extensions.get("x-trust") {
            if let Some(kind) = x_trust.get("operation_kind").and_then(|v| v.as_str()) {
                metrics.operation_kind = kind.to_string();
                if kind == "mutation" || kind == "destructive" {
                    metrics.is_mutation = true;
                } else if kind == "read" {
                    metrics.is_mutation = false;
                }
            }
            if let Some(idemp) = x_trust.get("is_idempotent").and_then(|v| v.as_bool()) {
                metrics.is_idempotent = idemp;
            }
            if let Some(fin) = x_trust.get("max_financial_exposure").and_then(|v| v.as_u64()) {
                metrics.financial_exposure_cents = fin;
                metrics.financial_indeterminate = false;
            }
        }

        // --- 100% DESTRUCTIVE RECALL SECURITY GATE ---
        // Even if method is GET or POST (e.g. Hostile Spec with GET /purge-all or POST /drop-table),
        // or summary mentions destructive operations, FORCE classification to DESTRUCTIVE!
        let full_text = format!(
            "{} {} {} {} {}",
            method.to_lowercase(),
            path.to_lowercase(),
            operation_id.to_lowercase(),
            summary.as_deref().unwrap_or("").to_lowercase(),
            description.as_deref().unwrap_or("").to_lowercase()
        );

        let is_destructive_override = method == "DELETE"
            || full_text.contains("delete")
            || full_text.contains("drop")
            || full_text.contains("purge")
            || full_text.contains("destroy")
            || full_text.contains("wipe")
            || full_text.contains("terminate")
            || full_text.contains("truncate")
            || full_text.contains("revoke_all");

        if is_destructive_override {
            metrics.operation_kind = "destructive".to_string();
            metrics.is_mutation = true;
            metrics.is_idempotent = false;
            metrics.reversibility = "Irreversible".to_string();
            metrics.risk_classification = "Critical".to_string();
            if !metrics.touched_iam_scopes.contains(&"system:destructive_purge".to_string()) {
                metrics.touched_iam_scopes.push("system:destructive_purge".to_string());
            }
        }

        let detected_pii_fields = self.classifier.detect_pii_fields(&param_names);

        let recommended_action = if metrics.operation_kind == "destructive" {
            "deny".to_string()
        } else if metrics.is_mutation
            || metrics.financial_exposure_cents > 0
            || metrics.financial_indeterminate
            || metrics.touched_iam_scopes.iter().any(|s| s.contains("manage") || s.contains("disburse"))
        {
            "require_approval".to_string()
        } else {
            "allow".to_string()
        };

        ClassifiedOperation {
            operation_id,
            method: method.to_string(),
            path: path.to_string(),
            summary,
            description,
            metrics,
            detected_pii_fields,
            required_params,
            recommended_action,
        }
    }
}
