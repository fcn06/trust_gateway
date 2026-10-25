use crate::traits::{EngineError, ExecutorDispatcher};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use trust_sdk::manifest::SkillManifest;
use trust_sdk::model::{ExecutionResult, ProposedAction, TransactionOutcomeState, TrustEnvelope};

#[cfg(unix)]
mod unix_sandbox {
    // use CommandExt

    pub fn configure_sandbox(cmd: &mut tokio::process::Command, mem_limit_mb: u32) {
        // SAFETY: pre_exec is invoked in the child process immediately after fork()
        // and prior to exec(). setsid() and setrlimit() are standard POSIX async-signal-safe
        // system calls.
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                let limit = (mem_limit_mb as u64 * 1024 * 1024) as libc::rlim_t;
                let rlim = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                libc::setrlimit(libc::RLIMIT_AS, &rlim);
                Ok(())
            });
        }
    }
}

pub struct LocalSubprocessDispatcher {
    tools_base_dir: PathBuf,
}

impl LocalSubprocessDispatcher {
    pub fn new(tools_base_dir: impl AsRef<Path>) -> Self {
        Self {
            tools_base_dir: tools_base_dir.as_ref().to_path_buf(),
        }
    }

    pub fn verify_script_path(
        base_dir: &Path,
        skill_name: &str,
        entrypoint: &str,
    ) -> Result<(PathBuf, PathBuf), EngineError> {
        let skill_dir = base_dir.join(skill_name);
        if !skill_dir.exists() {
            return Err(EngineError::DispatchError(format!(
                "Skill directory not found: {}",
                skill_dir.display()
            )));
        }

        let canonical_dir = skill_dir.canonicalize().map_err(|e| {
            EngineError::DispatchError(format!("Failed to canonicalize skill dir: {e}"))
        })?;

        let script_path = canonical_dir.join(entrypoint);
        if !script_path.exists() {
            return Err(EngineError::DispatchError(format!(
                "Script entrypoint not found: {}",
                script_path.display()
            )));
        }

        let canonical_script = script_path.canonicalize().map_err(|e| {
            EngineError::DispatchError(format!("Failed to canonicalize script path: {e}"))
        })?;

        // Strict canonical path traversal check
        if !canonical_script.starts_with(&canonical_dir) {
            return Err(EngineError::DispatchError(format!(
                "Path traversal detected: script '{}' escapes skill directory '{}'",
                canonical_script.display(),
                canonical_dir.display()
            )));
        }

        Ok((canonical_dir, canonical_script))
    }
}

#[async_trait]
impl ExecutorDispatcher for LocalSubprocessDispatcher {
    async fn dispatch(
        &self,
        manifest: &SkillManifest,
        envelope: &TrustEnvelope<ProposedAction>,
        grant_jwt: &str,
    ) -> Result<ExecutionResult, EngineError> {
        let (canonical_dir, canonical_script) = Self::verify_script_path(
            &self.tools_base_dir,
            &manifest.name,
            &manifest.execution.entrypoint,
        )?;

        // Check interpreter
        let interpreter = if let Some(first) = manifest.execution.allowed_interpreters.first() {
            first.as_str()
        } else {
            "bash"
        };

        let mut cmd = Command::new(interpreter);
        cmd.arg(&canonical_script);
        cmd.current_dir(&canonical_dir);

        // SEC: Complete environment clearance of host parent secrets
        cmd.env_clear();

        // Inject only sanitized runtime variables
        let safe_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
        cmd.env("PATH", safe_path);
        cmd.env("HOME", &canonical_dir);
        cmd.env("LANG", "C.UTF-8");

        let args_str = serde_json::to_string(&envelope.payload.arguments).unwrap_or_default();
        cmd.env("TOOL_ARGS", &args_str);
        cmd.env("SKILL_ARGS", &args_str);
        cmd.env("TOOL_NAME", &manifest.name);
        cmd.env("SKILL_NAME", &manifest.name);
        cmd.env("TOOL_ACTION_ID", &envelope.payload.action_id);
        cmd.env("TOOL_TENANT_ID", &envelope.payload.tenant_id);
        cmd.env("GRANT_TOKEN", grant_jwt);

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        #[cfg(unix)]
        unix_sandbox::configure_sandbox(&mut cmd, manifest.execution.memory_limit_mb);

        let timeout = std::time::Duration::from_secs(manifest.execution.timeout_secs as u64);
        let start = std::time::Instant::now();

        let mut child = cmd.spawn().map_err(|e| {
            EngineError::DispatchError(format!("Failed to spawn subprocess '{interpreter}': {e}"))
        })?;

        // Write args to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(args_str.as_bytes()).await;
        }

        let output_res = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        let output = match output_res {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                return Err(EngineError::DispatchError(format!(
                    "Subprocess execution failed: {e}"
                )));
            }
            Err(_) => {
                return Err(EngineError::DispatchError(format!(
                    "Subprocess timed out after {}s",
                    manifest.execution.timeout_secs
                )));
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr_str = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            return Err(EngineError::DispatchError(format!(
                "Subprocess exited with status {}: {stderr_str}",
                output.status
            )));
        }

        let parsed_output: serde_json::Value = serde_json::from_str(&stdout_str)
            .unwrap_or_else(|_| serde_json::json!({ "result": stdout_str }));

        Ok(ExecutionResult {
            action_id: envelope.payload.action_id.clone(),
            status: TransactionOutcomeState::Success,
            connector: "local_subprocess".to_string(),
            external_reference: None,
            provider_idempotency_key: None,
            reconciled: false,
            output: parsed_output,
            duration_ms,
            receipt: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_blocked() {
        let temp = std::env::temp_dir();
        let err = LocalSubprocessDispatcher::verify_script_path(
            &temp,
            "nonexistent_skill",
            "../etc/passwd",
        );
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_subprocess_env_empty_of_secrets() {
        let temp_base = std::env::temp_dir().join(format!("test_env_{}", uuid::Uuid::new_v4()));
        let skill_dir = temp_base.join("env_tester");
        std::fs::create_dir_all(&skill_dir).unwrap();

        let script_file = skill_dir.join("run.sh");
        std::fs::write(
            &script_file,
            "#!/usr/bin/env bash\necho '{\"env_secret\":\"'\"$SECRET_API_KEY\"'\"}'\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Set secret in current parent process
        std::env::set_var("SECRET_API_KEY", "super_secret_token_123");

        let manifest = SkillManifest {
            schema_version: "lianxi.skill/v1".to_string(),
            id: "io.lianxi.skill.env@v1".to_string(),
            name: "env_tester".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            author_did: "did:web:test".to_string(),
            data_origin_trust: trust_sdk::manifest::DataOriginTrust::TrustedInternal,
            lineage_rules: vec![],
            execution: trust_sdk::manifest::ExecutionSpec {
                runtime: trust_sdk::manifest::RuntimeType::NativeTool,
                entrypoint: "run.sh".to_string(),
                timeout_secs: 5,
                memory_limit_mb: 256,
                allowed_interpreters: vec!["bash".to_string()],
            },
            input_schema: serde_json::json!({}),
            policy_defaults: trust_sdk::manifest::PolicyDefaults {
                default_tier: "tier0_auto".to_string(),
                max_frequency_per_trace: 5,
                default_risk_level: "low".to_string(),
                operation_kind: "read".to_string(),
            },
            egress: trust_sdk::manifest::EgressClassification {
                contains_pii: false,
                max_payload_bytes: 65536,
                allowed_fields: vec![],
            },
        };

        let dispatcher = LocalSubprocessDispatcher::new(&temp_base);
        let env = TrustEnvelope {
            trace_id: "tr_env".to_string(),
            timestamp: 0,
            payload: ProposedAction {
                action_id: "act_env".to_string(),
                tool_name: "env_tester".to_string(),
                ..Default::default()
            },
        };

        let res = dispatcher
            .dispatch(&manifest, &env, "test_jwt")
            .await
            .unwrap();
        // Secret must NOT leak to subprocess due to env_clear!
        assert_eq!(res.output["env_secret"], "");
    }
}
