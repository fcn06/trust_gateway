// ─────────────────────────────────────────────────────────────
// Skill executor — spawns CLI scripts with argument injection
//
// Executes the skill's script via the configured interpreter,
// passes arguments as JSON on stdin, captures stdout/stderr,
// and wraps the result in an InvokeResponse.
//
// OAuth tokens and tenant-scoped secrets are injected as
// environment variables per the skill manifest's `env` mapping.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::registry::LoadedSkill;

/// Request payload for POST /invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// Optional action ID from the gateway.
    pub action_id: Option<String>,
    /// Skill name to invoke.
    pub skill_name: String,
    /// Arguments to pass to the skill.
    pub arguments: serde_json::Value,
    /// Tenant ID for scoping.
    #[serde(default)]
    pub tenant_id: String,
    /// ExecutionGrant JWT for validation.
    pub execution_grant: Option<String>,
}

/// Response from skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    pub action_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub skill_name: String,
}

impl InvokeResponse {
    pub fn error(action_id: &str, msg: String) -> Self {
        Self {
            action_id: action_id.to_string(),
            success: false,
            output: serde_json::Value::Null,
            error: Some(msg),
            exit_code: None,
            skill_name: String::new(),
        }
    }
}

/// Execute a loaded skill by spawning its script.
pub async fn execute_skill(
    skill: &LoadedSkill,
    req: &InvokeRequest,
    timeout: std::time::Duration,
) -> Result<InvokeResponse> {
    let action_id = req.action_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let manifest = &skill.manifest;

    // Use custom timeout if manifest has one
    let effective_timeout = manifest.timeout_seconds
        .map(std::time::Duration::from_secs)
        .unwrap_or(timeout);

    // Build the command
    let mut cmd = Command::new(&manifest.interpreter);
    cmd.arg(&skill.script_path);

    // Set working directory to the skill's directory
    cmd.current_dir(&skill.dir);

    // ── Security: Clear inherited environment ─────────────────
    // Prevents skills from reading JWT_SECRET, NATS_URL, or other
    // service-level secrets. Only explicitly declared env vars
    // from the skill manifest are injected.
    cmd.env_clear();

    // Inject minimal safe environment
    cmd.env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string()));
    cmd.env("HOME", std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()));
    cmd.env("LANG", "en_US.UTF-8");

    // Inject structured skill arguments
    let args_json = serde_json::to_string(&req.arguments)?;
    cmd.env("SKILL_ARGS", &args_json);
    cmd.env("SKILL_NAME", &manifest.name);
    cmd.env("SKILL_ACTION_ID", &action_id);
    cmd.env("SKILL_TENANT_ID", &req.tenant_id);

    // Inject custom env vars from manifest
    // These are typically OAuth token env var names that the
    // deployment environment has set for this tenant.
    for (key, env_var_name) in &manifest.env {
        if let Ok(val) = std::env::var(env_var_name) {
            cmd.env(key, val);
        } else {
            tracing::debug!("Env var '{}' not set for skill env key '{}'", env_var_name, key);
        }
    }

    // Pipe arguments as JSON on stdin
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    tracing::info!(
        "🦞 Executing skill '{}': {} {} (timeout: {:?})",
        manifest.name,
        manifest.interpreter,
        skill.script_path.display(),
        effective_timeout,
    );

    // ── WS7: Process group isolation ──────────────────────────
    // Spawn the child in its own process group (setsid) so that
    // SIGKILL on timeout kills the entire subprocess tree, not
    // just the top-level process.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `setsid()` is async-signal-safe per POSIX and only affects the
        // calling process's session/group membership. It is called in the
        // pre_exec hook which runs after fork() but before exec(), in a
        // single-threaded context. No shared state is mutated.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()
                    .map(|_| ())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
        }
    }

    // Pipe stdout/stderr so we can capture them while retaining
    // ownership of the child handle for timeout kill.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    let child_pid = child.id();

    // Take the stdout/stderr handles before waiting
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Wait with timeout — child.wait() borrows &mut, so we keep ownership
    let wait_result = tokio::time::timeout(effective_timeout, child.wait()).await;

    match wait_result {
        Ok(Ok(status)) => {
            // Process exited within timeout — read captured output
            let stdout = if let Some(mut h) = stdout_handle {
                let mut buf = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut h, &mut buf).await.ok();
                String::from_utf8_lossy(&buf).to_string()
            } else { String::new() };

            let stderr = if let Some(mut h) = stderr_handle {
                let mut buf = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut h, &mut buf).await.ok();
                String::from_utf8_lossy(&buf).to_string()
            } else { String::new() };

            let exit_code = status.code();
            let success = status.success();

            if !stderr.is_empty() {
                tracing::debug!("Skill '{}' stderr: {}", manifest.name, stderr);
            }

            let output_value = serde_json::from_str::<serde_json::Value>(&stdout)
                .unwrap_or_else(|_| serde_json::Value::String(stdout.trim().to_string()));

            tracing::info!(
                "🦞 Skill '{}' completed: success={}, exit_code={:?}",
                manifest.name, success, exit_code
            );

            Ok(InvokeResponse {
                action_id,
                success,
                output: output_value,
                error: if success { None } else { Some(stderr) },
                exit_code,
                skill_name: manifest.name.clone(),
            })
        }
        Ok(Err(e)) => {
            Err(anyhow::anyhow!("Failed to execute skill '{}': {}", manifest.name, e))
        }
        Err(_timeout) => {
            // ── WS7: Kill-on-timeout ────────────────────────────
            // The timeout fired. Kill the entire process group to
            // prevent orphaned subprocesses from lingering.
            tracing::error!(
                "⏰ Skill '{}' timed out after {:?} — killing process group",
                manifest.name, effective_timeout
            );

            #[cfg(unix)]
            if let Some(pid) = child_pid {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let pgid = Pid::from_raw(-(pid as i32));
                if let Err(e) = kill(pgid, Signal::SIGKILL) {
                    tracing::warn!(
                        "⚠️ Failed to kill process group {} for skill '{}': {}",
                        pid, manifest.name, e
                    );
                }
            }

            // Fallback: direct kill (also handles non-Unix)
            let _ = child.kill().await;
            // Reap the zombie to prevent resource leaks
            let _ = child.wait().await;

            Ok(InvokeResponse {
                action_id,
                success: false,
                output: serde_json::Value::Null,
                error: Some(format!("Execution timed out after {:?}", effective_timeout)),
                exit_code: None,
                skill_name: manifest.name.clone(),
            })
        }
    }
}
