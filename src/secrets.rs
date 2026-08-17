//! Switchboard's own secret store, used to resolve `${secret.NAME}` references
//! that appear in an app manifest's `env:` map.
//!
//! Secrets are switchboard operator configuration — they are loaded from
//! switchboard's OWN config (a secrets file and/or environment), NEVER from the
//! application repository being deployed. Resolution is **fail-safe**: a
//! missing secret logs a name-only warning and substitutes the empty string
//! rather than crashing the deploy, and a resolved value is never written to a
//! log.
//!
//! # Secrets file format (YAML)
//!
//! ```yaml
//! # Applied to every repo.
//! default:
//!   some_key: "s3cr3t"
//! # Per-repo overrides, keyed by "owner/repo" (the GitHub full_name).
//! repos:
//!   "ephpm/wordpress-sample":
//!     some_key: "repo-specific"
//! ```
//!
//! # Environment fallback
//!
//! Any `SWITCHBOARD_SECRET_<NAME>` environment variable is folded into the
//! default scope at load time, with the `<NAME>` suffix lowercased (so
//! `SWITCHBOARD_SECRET_SOME_KEY` supplies `some_key`). The secrets file takes
//! precedence over the environment for the same name.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

/// Prefix for environment-provided secrets.
const ENV_PREFIX: &str = "SWITCHBOARD_SECRET_";

/// A resolved secret store: a default scope plus optional per-repo overrides.
#[derive(Debug, Default, Deserialize)]
pub struct Secrets {
    /// Secrets applied to every repo.
    #[serde(default)]
    default: BTreeMap<String, String>,
    /// Per-repo overrides, keyed by GitHub `owner/repo` full name.
    #[serde(default)]
    repos: BTreeMap<String, BTreeMap<String, String>>,
}

impl Secrets {
    /// Load secrets from an optional YAML file, then fold in any
    /// `SWITCHBOARD_SECRET_*` environment variables (file wins on conflict).
    ///
    /// # Errors
    ///
    /// Returns an error only if the secrets file exists but cannot be read or
    /// parsed. A `None` path (or absent file) yields an env-only store.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut secrets = match path {
            Some(p) if p.exists() => {
                let contents = std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read secrets file {}", p.display()))?;
                let parsed: Self = serde_yml::from_str(&contents)
                    .with_context(|| format!("failed to parse secrets file {}", p.display()))?;
                tracing::info!(path = %p.display(), "loaded switchboard secrets file");
                parsed
            }
            _ => Self::default(),
        };
        secrets.fold_env(std::env::vars());
        secrets
            .redacted_summary()
            .into_iter()
            .for_each(|(scope, count)| tracing::info!(scope, count, "secret store scope"));
        Ok(secrets)
    }

    /// Fold `SWITCHBOARD_SECRET_*` variables into the default scope. Existing
    /// (file-provided) names are not overwritten. Public for testability
    /// without mutating the real process environment.
    pub fn fold_env<I>(&mut self, vars: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (key, value) in vars {
            if let Some(name) = key.strip_prefix(ENV_PREFIX) {
                if name.is_empty() {
                    continue;
                }
                self.default
                    .entry(name.to_ascii_lowercase())
                    .or_insert(value);
            }
        }
    }

    /// Build a store directly from maps (test helper / programmatic config).
    #[cfg(test)]
    #[must_use]
    pub fn from_maps(
        default: BTreeMap<String, String>,
        repos: BTreeMap<String, BTreeMap<String, String>>,
    ) -> Self {
        Self { default, repos }
    }

    /// Look up a single secret for a repo: per-repo scope first, then default.
    #[must_use]
    pub fn get(&self, repo_full_name: &str, name: &str) -> Option<&str> {
        self.repos
            .get(repo_full_name)
            .and_then(|scope| scope.get(name))
            .or_else(|| self.default.get(name))
            .map(String::as_str)
    }

    /// Resolve every `${secret.NAME}` reference in `raw`, appending the names of
    /// any missing secrets to `missing` (missing references expand to empty).
    ///
    /// Text that is not a `${secret.NAME}` reference passes through literally.
    #[must_use]
    pub fn substitute(&self, repo_full_name: &str, raw: &str, missing: &mut Vec<String>) -> String {
        const OPEN: &str = "${secret.";
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(start) = rest.find(OPEN) {
            out.push_str(&rest[..start]);
            let after = &rest[start + OPEN.len()..];
            let Some(end) = after.find('}') else {
                // Unterminated reference — emit the remainder literally.
                out.push_str(&rest[start..]);
                return out;
            };
            let name = &after[..end];
            match self.get(repo_full_name, name) {
                Some(value) => out.push_str(value),
                None => missing.push(name.to_string()),
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// Non-secret summary (scope → count) for startup logging. Never exposes
    /// names or values.
    fn redacted_summary(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("default", self.default.len()),
            ("repo-scoped", self.repos.values().map(BTreeMap::len).sum()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Secrets {
        let mut default = BTreeMap::new();
        default.insert("some_key".to_string(), "default-value".to_string());
        default.insert("shared".to_string(), "d".to_string());
        let mut repo = BTreeMap::new();
        repo.insert("some_key".to_string(), "repo-value".to_string());
        let mut repos = BTreeMap::new();
        repos.insert("ephpm/wordpress-sample".to_string(), repo);
        Secrets::from_maps(default, repos)
    }

    #[test]
    fn resolves_present_secret() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute("ephpm/other", "${secret.some_key}", &mut missing);
        assert_eq!(out, "default-value");
        assert!(missing.is_empty());
    }

    #[test]
    fn per_repo_overrides_default() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute("ephpm/wordpress-sample", "${secret.some_key}", &mut missing);
        assert_eq!(out, "repo-value");
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_secret_expands_empty_and_reports() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute("ephpm/other", "x=${secret.nope}", &mut missing);
        assert_eq!(out, "x=");
        assert_eq!(missing, vec!["nope".to_string()]);
    }

    #[test]
    fn non_secret_literal_passthrough() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute("ephpm/other", "staging", &mut missing);
        assert_eq!(out, "staging");
        assert!(missing.is_empty());
    }

    #[test]
    fn embedded_reference_substituted_in_place() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute(
            "ephpm/other",
            "prefix-${secret.shared}-suffix",
            &mut missing,
        );
        assert_eq!(out, "prefix-d-suffix");
        assert!(missing.is_empty());
    }

    #[test]
    fn unterminated_reference_is_literal() {
        let s = store();
        let mut missing = Vec::new();
        let out = s.substitute("ephpm/other", "oops ${secret.unclosed", &mut missing);
        assert_eq!(out, "oops ${secret.unclosed");
        assert!(missing.is_empty());
    }

    #[test]
    fn env_folds_into_default_lowercased() {
        let mut s = Secrets::default();
        s.fold_env(vec![(
            "SWITCHBOARD_SECRET_API_TOKEN".to_string(),
            "abc".to_string(),
        )]);
        let mut missing = Vec::new();
        assert_eq!(
            s.substitute("any/repo", "${secret.api_token}", &mut missing),
            "abc"
        );
        assert!(missing.is_empty());
    }

    #[test]
    fn file_wins_over_env() {
        let mut default = BTreeMap::new();
        default.insert("shared".to_string(), "from-file".to_string());
        let mut s = Secrets::from_maps(default, BTreeMap::new());
        s.fold_env(vec![(
            "SWITCHBOARD_SECRET_SHARED".to_string(),
            "from-env".to_string(),
        )]);
        let mut missing = Vec::new();
        assert_eq!(
            s.substitute("any/repo", "${secret.shared}", &mut missing),
            "from-file"
        );
    }
}
