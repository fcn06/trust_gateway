// ─────────────────────────────────────────────────────────────
// Skill registry — scans /skills/*/manifest.json
//
// Each skill directory contains:
//   manifest.json   — skill metadata (name, description, args, script)
//   run.sh / run.py — the actual script to execute
//   README.md       — (optional) rich skill documentation
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A skill loaded from its manifest.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    pub description: String,
    /// The script to run, relative to the skill directory.
    pub script: String,
    /// Interpreter to use (e.g. "bash", "python3"). Defaults to "bash".
    #[serde(default = "default_interpreter")]
    pub interpreter: String,
    /// Input arguments schema (JSON Schema).
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// Environment variables to inject (key → env var name).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Tags for policy matching.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Maximum execution time in seconds (overrides global default).
    pub timeout_seconds: Option<u64>,

    // ── Extended fields (skills.md philosophy) ──────────────
    /// Skill category (e.g. "utility", "operations", "diagnostics").
    #[serde(default)]
    pub category: Option<String>,
    /// Hint for the LLM: "native" means prefer this over external alternatives.
    #[serde(default)]
    pub priority_hint: Option<String>,
    /// "atomic" (single call) or "multi_step" (requires read-then-execute).
    #[serde(default)]
    pub procedure_type: Option<String>,
}

fn default_interpreter() -> String {
    "bash".to_string()
}

/// In-memory skill registry (thread-safe for hot-reload).
pub struct SkillRegistry {
    skills: std::sync::RwLock<HashMap<String, LoadedSkill>>,
    skills_dir: PathBuf,
}

/// A skill with its resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedSkill {
    pub manifest: SkillManifest,
    /// Absolute path to the skill directory.
    pub dir: PathBuf,
    /// Absolute path to the script file.
    pub script_path: PathBuf,
}

/// Public-facing skill info for the GET /skills endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInfo {
    pub name: String,
    pub description: String,
    pub interpreter: String,
    pub tags: Vec<String>,
    pub input_schema: serde_json::Value,
    /// Skill category (e.g. "utility", "operations").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Whether rich documentation (README.md) is available.
    #[serde(default)]
    pub documentation_available: bool,
    /// "atomic" or "multi_step".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procedure_type: Option<String>,
    /// "native" priority hint for LLM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_hint: Option<String>,
}

/// Documentation response for the `GET /skills/{name}/docs` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDocs {
    pub name: String,
    pub description: String,
    /// Full markdown documentation content (from README.md/SKILL.md).
    pub documentation: Option<String>,
    pub input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procedure_type: Option<String>,
}

impl SkillRegistry {
    /// Scan a directory for skill manifests.
    ///
    /// Expects the structure:
    /// ```
    /// skills/
    ///   my_skill/
    ///     manifest.json
    ///     run.sh
    ///     README.md       (optional)
    ///   another_skill/
    ///     manifest.json
    ///     run.py
    /// ```
    pub fn scan(skills_dir: &str) -> Result<Self> {
        let dir = Path::new(skills_dir);
        let skills = Self::scan_dir(dir)?;
        Ok(Self {
            skills: std::sync::RwLock::new(skills),
            skills_dir: dir.to_path_buf(),
        })
    }

    /// Internal: scan a directory and return a map of loaded skills.
    fn scan_dir(dir: &Path) -> Result<HashMap<String, LoadedSkill>> {
        let mut skills = HashMap::new();

        if !dir.exists() {
            tracing::warn!("⚠️ Skills directory '{}' does not exist — no skills loaded", dir.display());
            return Ok(skills);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let skill_dir = entry.path();
            let manifest_path = skill_dir.join("manifest.json");

            if !manifest_path.exists() {
                tracing::debug!("Skipping {}: no manifest.json", skill_dir.display());
                continue;
            }

            match Self::load_skill(&skill_dir, &manifest_path) {
                Ok(loaded) => {
                    tracing::info!(
                        "   🦞 Loaded skill '{}' from {}",
                        loaded.manifest.name,
                        skill_dir.display()
                    );
                    skills.insert(loaded.manifest.name.clone(), loaded);
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to load skill from {}: {}",
                        skill_dir.display(),
                        e
                    );
                }
            }
        }

        Ok(skills)
    }

    fn load_skill(skill_dir: &Path, manifest_path: &Path) -> Result<LoadedSkill> {
        let contents = std::fs::read_to_string(manifest_path)?;
        let manifest: SkillManifest = serde_json::from_str(&contents)?;

        // ── Security: Interpreter allow-list ────────────────────
        // Only allow known safe interpreters. This prevents malicious
        // manifests from running arbitrary binaries.
        const ALLOWED_INTERPRETERS: &[&str] = &[
            "bash", "sh", "python3", "python", "node", "deno", "ruby",
        ];
        if !ALLOWED_INTERPRETERS.contains(&manifest.interpreter.as_str()) {
            anyhow::bail!(
                "Interpreter '{}' is not in the allow-list {:?}",
                manifest.interpreter, ALLOWED_INTERPRETERS
            );
        }

        let script_path = skill_dir.join(&manifest.script);
        if !script_path.exists() {
            anyhow::bail!(
                "Script '{}' not found in {}",
                manifest.script,
                skill_dir.display()
            );
        }

        // ── Security: Path traversal prevention ─────────────────
        // Canonicalize both paths and verify the script stays within
        // the skill directory. Prevents manifest.script = "../../etc/passwd".
        let canonical_script = script_path.canonicalize()?;
        let canonical_dir = skill_dir.canonicalize()?;
        if !canonical_script.starts_with(&canonical_dir) {
            anyhow::bail!(
                "Script path '{}' escapes skill directory '{}' — possible path traversal",
                canonical_script.display(),
                canonical_dir.display()
            );
        }

        Ok(LoadedSkill {
            manifest,
            dir: skill_dir.to_path_buf(),
            script_path: canonical_script,
        })
    }

    /// Get a loaded skill by name (returns a clone for thread safety).
    pub fn get(&self, name: &str) -> Option<LoadedSkill> {
        self.skills.read().unwrap().get(name).cloned()
    }

    /// Number of loaded skills.
    pub fn count(&self) -> usize {
        self.skills.read().unwrap().len()
    }

    /// List all loaded skills (public info only).
    pub fn list(&self) -> Vec<SkillInfo> {
        self.skills.read().unwrap().values().map(|s| {
            let has_docs = s.dir.join("README.md").exists()
                || s.dir.join("SKILL.md").exists()
                || s.dir.join("docs.md").exists();
            SkillInfo {
                name: s.manifest.name.clone(),
                description: s.manifest.description.clone(),
                interpreter: s.manifest.interpreter.clone(),
                tags: s.manifest.tags.clone(),
                input_schema: s.manifest.input_schema.clone(),
                category: s.manifest.category.clone(),
                documentation_available: has_docs,
                procedure_type: s.manifest.procedure_type.clone(),
                priority_hint: s.manifest.priority_hint.clone(),
            }
        }).collect()
    }

    /// Get the full documentation for a skill.
    ///
    /// Reads README.md, SKILL.md, or docs.md from the skill directory.
    /// Returns None if the skill doesn't exist.
    pub fn get_docs(&self, name: &str) -> Option<SkillDocs> {
        let skills = self.skills.read().unwrap();
        let skill = skills.get(name)?;

        // Try README.md, SKILL.md, docs.md in order of preference
        let docs_content = ["README.md", "SKILL.md", "docs.md"]
            .iter()
            .find_map(|filename| {
                let path = skill.dir.join(filename);
                std::fs::read_to_string(&path).ok()
            });

        Some(SkillDocs {
            name: skill.manifest.name.clone(),
            description: skill.manifest.description.clone(),
            documentation: docs_content,
            input_schema: skill.manifest.input_schema.clone(),
            category: skill.manifest.category.clone(),
            tags: skill.manifest.tags.clone(),
            procedure_type: skill.manifest.procedure_type.clone(),
        })
    }

    /// Rescan the skills directory for new or updated skills.
    ///
    /// Returns the names of newly discovered skills (not previously loaded).
    /// Existing skills are also refreshed with updated manifests.
    pub fn rescan(&self) -> Vec<String> {
        match Self::scan_dir(&self.skills_dir) {
            Ok(new_skills) => {
                let mut current = self.skills.write().unwrap();
                let new_names: Vec<String> = new_skills.keys()
                    .filter(|k| !current.contains_key(*k))
                    .cloned()
                    .collect();
                let total = new_skills.len();
                *current = new_skills;
                if !new_names.is_empty() {
                    tracing::info!("🔄 Rescan found {} new skills: {:?} (total: {})", new_names.len(), new_names, total);
                }
                new_names
            }
            Err(e) => {
                tracing::error!("❌ Skill rescan failed: {}", e);
                vec![]
            }
        }
    }

    /// Return the path to the skills directory.
    pub fn skills_dir(&self) -> &Path {
        &self.skills_dir
    }
}
