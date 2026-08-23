//! Passing the installation token to `git` without ever putting it in argv or
//! on disk.
//!
//! `git` prompts for a password when a remote needs credentials. `GIT_ASKPASS`
//! names a program `git` runs to answer that prompt; we point it at a tiny
//! helper script whose only job is to print `$SWITCHBOARD_GIT_TOKEN`. The token
//! itself lives only in the environment of the `git` child (and thus its
//! askpass child) — never in argv (world-visible via `ps`), never in a file.
//!
//! The helper *script* contains no secret: it reads the token from the
//! environment at run time, so the file on disk is inert. The clone URL is
//! rewritten to carry the non-secret username `x-access-token`, which makes
//! `git` ask only for the password, which the helper supplies.
//!
//! Linux-only in practice (the daemon runs as a systemd unit beside ePHPm). The
//! module compiles everywhere but the script is only made executable on Unix.

use std::process::Command;

use anyhow::Context;
use tempfile::NamedTempFile;

use crate::app_auth::InstallationToken;

/// Environment variable the helper script reads the token from.
const TOKEN_ENV: &str = "SWITCHBOARD_GIT_TOKEN";

/// A `GIT_ASKPASS` helper backed by a private temp file, kept alive for the
/// daemon's lifetime.
pub struct Askpass {
    file: NamedTempFile,
}

impl Askpass {
    /// Write the helper script to a private temp file (`0700` on Unix).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or made executable.
    pub fn create() -> anyhow::Result<Self> {
        let mut file = NamedTempFile::new().context("failed to create askpass helper file")?;
        {
            use std::io::Write;
            // Print the token for any prompt. With `x-access-token` as the URL
            // username, git only ever asks for the password.
            writeln!(file, "#!/bin/sh\nprintf '%s' \"${TOKEN_ENV}\"")
                .context("failed to write askpass helper")?;
            file.flush().ok();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o700))
                .context("failed to chmod askpass helper")?;
        }
        Ok(Self { file })
    }

    /// Configure a `git` command to authenticate with `token`: set
    /// `GIT_ASKPASS` at the helper, pass the token in the environment, and
    /// disable any interactive terminal prompt so a missing/expired credential
    /// fails fast instead of hanging.
    pub fn apply(&self, cmd: &mut Command, token: &InstallationToken) {
        cmd.env("GIT_ASKPASS", self.file.path());
        cmd.env(TOKEN_ENV, token.expose());
        cmd.env("GIT_TERMINAL_PROMPT", "0");
    }
}

/// Rewrite an `https://host/...` URL to `https://x-access-token@host/...` so
/// `git` supplies the App username itself and prompts only for the password.
/// Returns the input unchanged if it is not a plain `https://` URL or already
/// carries a userinfo component.
#[must_use]
pub fn authenticated_url(https_url: &str) -> String {
    const PREFIX: &str = "https://";
    match https_url.strip_prefix(PREFIX) {
        Some(rest) if !rest.contains('@') => format!("{PREFIX}x-access-token@{rest}"),
        _ => https_url.to_string(),
    }
}

/// The helper script path (test-only introspection). Not the token.
#[cfg(test)]
#[must_use]
fn helper_path(askpass: &Askpass) -> &std::path::Path {
    askpass.file.path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_url_injects_username() {
        assert_eq!(
            authenticated_url("https://github.com/ephpm/wordpress-sample.git"),
            "https://x-access-token@github.com/ephpm/wordpress-sample.git"
        );
    }

    #[test]
    fn authenticated_url_leaves_userinfo_urls_alone() {
        let already = "https://x-access-token@github.com/x.git";
        assert_eq!(authenticated_url(already), already);
    }

    #[test]
    fn authenticated_url_leaves_non_https_alone() {
        assert_eq!(
            authenticated_url("git@github.com:x.git"),
            "git@github.com:x.git"
        );
    }

    #[test]
    fn helper_script_contains_no_secret_and_reads_env() {
        let askpass = Askpass::create().unwrap();
        let body = std::fs::read_to_string(helper_path(&askpass)).unwrap();
        assert!(
            body.contains(TOKEN_ENV),
            "helper must read the token from env"
        );
        // The script is inert: it holds no token, only the env var name.
        assert!(!body.contains("ghs_"));
    }

    #[test]
    fn apply_sets_env_without_leaking_into_args() {
        let askpass = Askpass::create().unwrap();
        let token = InstallationToken::from_raw_for_test("ghs_secret");
        let mut cmd = Command::new("git");
        cmd.arg("fetch");
        askpass.apply(&mut cmd, &token);
        // The token is in the env, never the args.
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a.contains("ghs_secret")));
        let has_token_env = cmd
            .get_envs()
            .any(|(k, v)| k == TOKEN_ENV && v.is_some_and(|v| v == "ghs_secret"));
        assert!(has_token_env);
    }
}
