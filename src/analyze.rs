//! The pre-serve static-analysis gate.
//!
//! A preview builds and serves **untrusted code from a pull request**. Before a
//! preview's checkout is swapped into `sites_dir` and made routable — and before
//! `build:`/`seed:` execute any of it — switchboard can run
//!
//! ```text
//! ephpm analyze <checkout> --config <operator-config> --format sarif
//! ```
//!
//! over the materialized tree and refuse to publish on a bad verdict.
//!
//! # The gate is off until an operator turns it on
//!
//! With no `--analyze-config` the gate is **disabled** and a deploy behaves
//! exactly as it did before this module existed. That is the safe rollout
//! default: the analyzers this depends on ship in a recent `ephpm`, and a node
//! running an older binary must not have every preview blocked by a gate it
//! cannot satisfy. Turning the gate on is a deliberate, per-fleet decision.
//!
//! # The operator config is explicit, never the PR's own
//!
//! `--config <path>` is **security-critical** and always passed. `ephpm analyze`
//! otherwise auto-discovers a `.ephpm-analyze.yml` inside the tree it scans — and
//! the tree is the pull request, which could ship `enable: []` to neuter its own
//! gate. The explicit `--config` overrides that discovery, so the policy is the
//! operator's file (which lives outside any tenant docroot) and nothing the PR
//! can influence. For the same reason the analyzer is never run with the checkout
//! as its working directory.
//!
//! # Every failure blocks (fail closed)
//!
//! A gate exists to stop bad code from being served, so anything short of a clean
//! pass is a block: a quarantine/deny verdict, an analyzer that errored, a run
//! that timed out, and a binary that could not be spawned all refuse the publish.
//! A gate that cannot run must not wave code through. The decision is a pure
//! function of the run outcome ([`decide`]) so it is exhaustively unit-tested
//! without a real `ephpm`.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

/// How many findings switchboard keeps from a blocked run's SARIF. The PR
/// comment renders a smaller top-N slice of these; the cap only bounds memory on
/// a pathological run that reports thousands.
const MAX_STORED_FINDINGS: usize = 50;

/// The verdict `ephpm analyze` communicates through its process exit code.
///
/// The mapping is ePHPm's, documented on `ephpm analyze`: `0` passed, `2`
/// quarantine, `3` deny, `1` an internal analyzer error. Anything else is
/// unrecognised and — like every non-zero, non-pass outcome — treated as a
/// block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzeVerdict {
    /// Exit `0` — the tree passed the configured gate.
    Pass,
    /// Exit `2` — findings crossed the quarantine threshold.
    Quarantine,
    /// Exit `3` — findings crossed the deny threshold.
    Deny,
    /// Exit `1` — the analyzer itself failed (bad config, crash, …). Fail closed.
    AnalyzerError,
    /// Any other exit code. Unrecognised, so fail closed.
    Unrecognised(i32),
}

impl AnalyzeVerdict {
    /// Classify an `ephpm analyze` process exit code.
    #[must_use]
    pub fn from_exit_code(code: i32) -> Self {
        match code {
            0 => Self::Pass,
            1 => Self::AnalyzerError,
            2 => Self::Quarantine,
            3 => Self::Deny,
            other => Self::Unrecognised(other),
        }
    }

    /// Whether this verdict refuses the publish. Everything but [`Self::Pass`]
    /// blocks.
    #[must_use]
    pub fn blocks(self) -> bool {
        !matches!(self, Self::Pass)
    }

    /// A short machine label for the PR comment and deployment status
    /// (`deny` / `quarantine` / `error`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Quarantine => "quarantine",
            Self::Deny => "deny",
            Self::AnalyzerError | Self::Unrecognised(_) => "error",
        }
    }
}

/// What happened when switchboard tried to run `ephpm analyze`.
///
/// This is the *entire* input to [`decide`], which is why the gate decision is a
/// pure function: every real-world outcome (a clean exit, a timeout, a binary
/// that would not spawn) reduces to one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeOutcome {
    /// The process ran to completion with this exit code.
    Exited(i32),
    /// The wall-clock timeout elapsed before the process finished. Fail closed.
    TimedOut,
    /// The process could not be spawned or waited on (missing binary, OS
    /// error). Fail closed — the reason is carried for the operator.
    Unrunnable(String),
}

/// The gate's decision for one deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Publish the preview.
    Proceed,
    /// Refuse to publish. `verdict` is a short machine label
    /// (`deny`/`quarantine`/`error`/`timeout`) and `reason` is one operator- and
    /// reviewer-facing sentence.
    Block {
        /// Short machine label for logs, the PR comment, and the deployment
        /// status.
        verdict: String,
        /// One-sentence human explanation, logged verbatim and shown on the PR.
        reason: String,
    },
}

/// Map a run outcome to a gate decision. **Pure** — this is the whole policy, so
/// it is tested exhaustively without spawning anything.
///
/// * exit `0` → proceed;
/// * exit `2` (quarantine) / `3` (deny) → block, named by verdict;
/// * exit `1` (analyzer error) or any other code → block (fail closed);
/// * timeout → block (fail closed);
/// * could-not-run → block (fail closed).
#[must_use]
pub fn decide(outcome: &AnalyzeOutcome) -> GateDecision {
    match outcome {
        AnalyzeOutcome::Exited(code) => {
            let verdict = AnalyzeVerdict::from_exit_code(*code);
            if !verdict.blocks() {
                return GateDecision::Proceed;
            }
            let reason = match verdict {
                AnalyzeVerdict::Quarantine => {
                    "ephpm analyze reached the quarantine threshold (exit 2)".to_string()
                }
                AnalyzeVerdict::Deny => {
                    "ephpm analyze reached the deny threshold (exit 3)".to_string()
                }
                AnalyzeVerdict::AnalyzerError => {
                    "ephpm analyze reported an internal error (exit 1) — a gate that \
                     cannot run must not wave code through, so the preview is blocked \
                     (fail closed)"
                        .to_string()
                }
                AnalyzeVerdict::Unrecognised(other) => format!(
                    "ephpm analyze exited with an unrecognised code {other} — treated as \
                     a block (fail closed)"
                ),
                AnalyzeVerdict::Pass => unreachable!("Pass does not block"),
            };
            GateDecision::Block {
                verdict: verdict.label().to_string(),
                reason,
            }
        }
        AnalyzeOutcome::TimedOut => GateDecision::Block {
            verdict: "timeout".to_string(),
            reason: "ephpm analyze exceeded its wall-clock timeout and was killed — a \
                     gate that cannot finish must not wave code through, so the preview \
                     is blocked (fail closed)"
                .to_string(),
        },
        AnalyzeOutcome::Unrunnable(err) => GateDecision::Block {
            verdict: "error".to_string(),
            reason: format!(
                "ephpm analyze could not be run ({err}) — the preview is blocked (fail closed)"
            ),
        },
    }
}

/// One finding lifted from the analyzer's SARIF output, reduced to what the PR
/// comment shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The SARIF `ruleId` (e.g. `dangerous-sinks/eval`).
    pub rule_id: String,
    /// The file the finding is in, relative to the scanned tree.
    pub file: String,
    /// 1-based line, when the SARIF carried a region.
    pub line: Option<u64>,
    /// The finding's message text.
    pub message: String,
}

/// A blocked run's detail, threaded into the PR comment and the deployment
/// status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzeBlock {
    /// Short machine label (`deny`/`quarantine`/`error`/`timeout`).
    pub verdict: String,
    /// One-sentence human reason.
    pub reason: String,
    /// Findings parsed from SARIF, capped at [`MAX_STORED_FINDINGS`]. Empty when
    /// the run produced no parseable SARIF (a timeout, a spawn failure, or a
    /// verdict-only exit).
    pub findings: Vec<Finding>,
    /// The true number of findings the analyzer reported, even if more than were
    /// stored.
    pub total_findings: usize,
}

/// The gate's result for one deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeGateResult {
    /// The gate is not configured — nothing ran, deploy proceeds as before.
    Skipped,
    /// The analyzer ran and the tree passed — proceed to publish.
    Passed,
    /// The publish is refused. Carries the verdict and findings for the PR
    /// comment and the deployment status.
    Blocked(AnalyzeBlock),
}

/// Run the pre-serve analyze gate over a materialized preview tree.
///
/// Returns [`AnalyzeGateResult::Skipped`] immediately when `analyze_config` is
/// `None` (the gate is disabled) — it does not even look at `ephpm_bin`, so a
/// node with the gate off never depends on the binary supporting `analyze`.
///
/// Otherwise it runs `ephpm_bin analyze <target> --config <analyze_config>
/// --format sarif` with a wall-clock `timeout`, captures stdout (SARIF), and maps
/// the outcome through [`decide`]. Every non-pass outcome — a bad verdict, an
/// analyzer error, a timeout, a binary that will not spawn — is a
/// [`AnalyzeGateResult::Blocked`]; this function never returns an error, so the
/// fail-closed contract cannot be bypassed by a `?` in the caller.
///
/// `target` is the tree to scan; `hostname` is only for logging.
pub async fn run_gate(
    ephpm_bin: &Path,
    analyze_config: Option<&Path>,
    timeout: Duration,
    target: &Path,
    hostname: &str,
) -> AnalyzeGateResult {
    let Some(config) = analyze_config else {
        // Say it once at startup, not per deploy — main.rs already warns that the
        // gate is disabled. Here it is only worth a debug line.
        tracing::debug!(
            %hostname,
            "pre-serve analyze gate is disabled (--analyze-config unset) — publishing \
             without static-analysis screening"
        );
        return AnalyzeGateResult::Skipped;
    };

    tracing::info!(
        %hostname,
        target = %target.display(),
        config = %config.display(),
        timeout_secs = timeout.as_secs(),
        "running pre-serve analyze gate"
    );

    // Keep the raw stdout so we can parse findings for a block; the decision is
    // made from the process outcome alone.
    let (analyze_outcome, sarif) = run_analyze(ephpm_bin, config, timeout, target).await;
    let decision = decide(&analyze_outcome);

    match decision {
        GateDecision::Proceed => {
            tracing::info!(%hostname, "analyze gate passed");
            AnalyzeGateResult::Passed
        }
        GateDecision::Block { verdict, reason } => {
            let (findings, total_findings) = sarif
                .as_deref()
                .map_or((Vec::new(), 0), parse_sarif_findings);
            tracing::warn!(
                %hostname,
                %verdict,
                total_findings,
                %reason,
                "analyze gate BLOCKED the preview — it will not be published"
            );
            AnalyzeGateResult::Blocked(AnalyzeBlock {
                verdict,
                reason,
                findings,
                total_findings,
            })
        }
    }
}

/// Spawn `ephpm analyze`, enforce the timeout, and return the outcome alongside
/// captured stdout (the SARIF document, when the process produced one).
async fn run_analyze(
    ephpm_bin: &Path,
    config: &Path,
    timeout: Duration,
    target: &Path,
) -> (AnalyzeOutcome, Option<String>) {
    // SECURITY: `--config <operator file>` is explicit and overrides `ephpm
    // analyze`'s auto-discovery of a `.ephpm-analyze.yml` inside `target` (the
    // untrusted PR tree). The current directory is deliberately left as
    // switchboard's own, never `target`, so no cwd-relative discovery is
    // reintroduced.
    let mut cmd = Command::new(ephpm_bin);
    cmd.arg("analyze")
        .arg(target)
        .arg("--config")
        .arg(config)
        .arg("--format")
        .arg("sarif")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // On timeout the `wait_with_output` future (which owns the child) is
        // dropped; kill-on-drop then reaps the analyzer rather than leaving it
        // running against the checkout after we have already blocked.
        .kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return (
                AnalyzeOutcome::Unrunnable(format!("failed to spawn {}: {e}", ephpm_bin.display())),
                None,
            );
        }
    };

    let waited = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match waited {
        // Ran to completion.
        Ok(Ok(output)) => {
            let code = output.status.code().unwrap_or_else(|| {
                // No exit code means the process was killed by a signal; that is
                // not a clean pass, so map it to a non-zero code that blocks.
                tracing::warn!("ephpm analyze terminated without an exit code (signal?)");
                -1
            });
            if !output.stderr.is_empty() {
                tracing::debug!(
                    stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                    "ephpm analyze stderr"
                );
            }
            let sarif = String::from_utf8_lossy(&output.stdout).into_owned();
            let sarif = (!sarif.trim().is_empty()).then_some(sarif);
            (AnalyzeOutcome::Exited(code), sarif)
        }
        // Waiting on the process itself failed.
        Ok(Err(e)) => (
            AnalyzeOutcome::Unrunnable(format!("failed to wait on ephpm analyze: {e}")),
            None,
        ),
        // The timeout elapsed. The child was moved into `wait_with_output`;
        // dropping that future here drops the child, and `kill_on_drop(true)`
        // above reaps it.
        Err(_elapsed) => (AnalyzeOutcome::TimedOut, None),
    }
}

/// Parse SARIF 2.1.0 into a flat finding list plus the true total.
///
/// Deliberately lenient (`serde_json::Value`, not a typed schema): a findings
/// list for a PR comment must never be the thing that turns a clean block into a
/// hard error, and SARIF has many optional shapes. Anything missing is skipped;
/// a document that does not parse yields no findings and a zero total, and the
/// block still stands on its exit code. Returns `(findings, total)` where
/// `findings` is capped at [`MAX_STORED_FINDINGS`] and `total` is the full count.
#[must_use]
pub fn parse_sarif_findings(sarif: &str) -> (Vec<Finding>, usize) {
    let Ok(root) = serde_json::from_str::<Value>(sarif) else {
        return (Vec::new(), 0);
    };
    let mut findings = Vec::new();
    let mut total = 0usize;

    let runs = root.get("runs").and_then(Value::as_array);
    for run in runs.into_iter().flatten() {
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };
        for result in results {
            total += 1;
            if findings.len() >= MAX_STORED_FINDINGS {
                continue;
            }
            findings.push(finding_from_result(result));
        }
    }
    (findings, total)
}

/// Lift one SARIF `result` object into a [`Finding`], filling sensible
/// placeholders for any absent field.
fn finding_from_result(result: &Value) -> Finding {
    let rule_id = result
        .get("ruleId")
        .and_then(Value::as_str)
        .unwrap_or("(unknown rule)")
        .to_string();

    let message = result
        .get("message")
        .and_then(|m| m.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    // First physical location, if any.
    let physical = result
        .get("locations")
        .and_then(Value::as_array)
        .and_then(|locs| locs.first())
        .and_then(|loc| loc.get("physicalLocation"));

    let file = physical
        .and_then(|p| p.get("artifactLocation"))
        .and_then(|a| a.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or("(unknown file)")
        .to_string();

    let line = physical
        .and_then(|p| p.get("region"))
        .and_then(|r| r.get("startLine"))
        .and_then(Value::as_u64);

    Finding {
        rule_id,
        file,
        line,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the pure decision (0→proceed, 1/2/3/other→block, timeout→block) ──

    #[test]
    fn exit_zero_proceeds() {
        assert_eq!(decide(&AnalyzeOutcome::Exited(0)), GateDecision::Proceed);
    }

    #[test]
    fn quarantine_exit_two_blocks() {
        let d = decide(&AnalyzeOutcome::Exited(2));
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "quarantine");
                assert!(reason.contains("quarantine"), "{reason}");
            }
            GateDecision::Proceed => panic!("exit 2 must block"),
        }
    }

    #[test]
    fn deny_exit_three_blocks() {
        let d = decide(&AnalyzeOutcome::Exited(3));
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "deny");
                assert!(reason.contains("deny"), "{reason}");
            }
            GateDecision::Proceed => panic!("exit 3 must block"),
        }
    }

    /// Exit 1 is the analyzer itself failing — the gate could not render a
    /// verdict, so the preview is blocked rather than waved through.
    #[test]
    fn analyzer_error_exit_one_blocks_fail_closed() {
        let d = decide(&AnalyzeOutcome::Exited(1));
        assert!(
            matches!(d, GateDecision::Block { .. }),
            "an analyzer error must fail closed"
        );
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "error");
                assert!(reason.contains("fail closed"), "{reason}");
            }
            GateDecision::Proceed => unreachable!(),
        }
    }

    /// An exit code ePHPm never documents is still a block — the gate defaults
    /// to refusing, not to trusting an outcome it does not understand.
    #[test]
    fn unrecognised_exit_code_blocks_fail_closed() {
        let d = decide(&AnalyzeOutcome::Exited(42));
        assert!(matches!(d, GateDecision::Block { .. }));
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "error");
                assert!(reason.contains("42"), "the code is named: {reason}");
            }
            GateDecision::Proceed => unreachable!(),
        }
    }

    /// A timeout is fail-closed: a gate that cannot finish must not let the
    /// preview through.
    #[test]
    fn timeout_blocks_fail_closed() {
        let d = decide(&AnalyzeOutcome::TimedOut);
        assert!(matches!(d, GateDecision::Block { .. }));
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "timeout");
                assert!(reason.contains("fail closed"), "{reason}");
            }
            GateDecision::Proceed => unreachable!(),
        }
    }

    /// A binary that will not spawn is fail-closed for the same reason.
    #[test]
    fn unrunnable_blocks_fail_closed() {
        let d = decide(&AnalyzeOutcome::Unrunnable("no such file".to_string()));
        assert!(matches!(d, GateDecision::Block { .. }));
        match d {
            GateDecision::Block { verdict, reason } => {
                assert_eq!(verdict, "error");
                assert!(reason.contains("no such file"), "{reason}");
            }
            GateDecision::Proceed => unreachable!(),
        }
    }

    #[test]
    fn verdict_classification_matches_ephpm_exit_codes() {
        assert_eq!(AnalyzeVerdict::from_exit_code(0), AnalyzeVerdict::Pass);
        assert_eq!(
            AnalyzeVerdict::from_exit_code(1),
            AnalyzeVerdict::AnalyzerError
        );
        assert_eq!(
            AnalyzeVerdict::from_exit_code(2),
            AnalyzeVerdict::Quarantine
        );
        assert_eq!(AnalyzeVerdict::from_exit_code(3), AnalyzeVerdict::Deny);
        assert_eq!(
            AnalyzeVerdict::from_exit_code(9),
            AnalyzeVerdict::Unrecognised(9)
        );
        assert!(!AnalyzeVerdict::Pass.blocks());
        assert!(AnalyzeVerdict::Quarantine.blocks());
        assert!(AnalyzeVerdict::Deny.blocks());
        assert!(AnalyzeVerdict::AnalyzerError.blocks());
    }

    // ── the disabled gate skips without touching the binary ─────────────

    /// `analyze_config: None` disables the gate. It must not even attempt to run
    /// the binary — proven here by passing a path that does not exist and still
    /// getting `Skipped`, never a `Blocked` for a spawn failure.
    #[tokio::test]
    async fn none_config_skips_without_running_the_binary() {
        let result = run_gate(
            Path::new("/nonexistent/ephpm-binary-that-cannot-spawn"),
            None,
            Duration::from_secs(1),
            Path::new("/tmp"),
            "pr-1.app.preview.ephpm.dev",
        )
        .await;
        assert_eq!(result, AnalyzeGateResult::Skipped);
    }

    // ── SARIF parsing ───────────────────────────────────────────────────

    #[test]
    fn parses_findings_from_sarif() {
        let sarif = r#"{
            "version": "2.1.0",
            "runs": [{
                "results": [
                    {
                        "ruleId": "dangerous-sinks/eval",
                        "message": { "text": "use of eval() on request data" },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": "wp-content/themes/x/functions.php" },
                                "region": { "startLine": 42 }
                            }
                        }]
                    },
                    {
                        "ruleId": "secrets-scan/aws-access-key-id",
                        "message": { "text": "AWS access key id committed" },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": ".env.example" },
                                "region": { "startLine": 3 }
                            }
                        }]
                    }
                ]
            }]
        }"#;
        let (findings, total) = parse_sarif_findings(sarif);
        assert_eq!(total, 2);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "dangerous-sinks/eval");
        assert_eq!(findings[0].file, "wp-content/themes/x/functions.php");
        assert_eq!(findings[0].line, Some(42));
        assert!(findings[0].message.contains("eval()"));
        assert_eq!(findings[1].rule_id, "secrets-scan/aws-access-key-id");
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        // A result with no message, no locations, no region: every absent field
        // gets a placeholder rather than dropping the finding.
        let sarif = r#"{"runs":[{"results":[{"ruleId":"writable-exec"}]}]}"#;
        let (findings, total) = parse_sarif_findings(sarif);
        assert_eq!(total, 1);
        assert_eq!(findings[0].rule_id, "writable-exec");
        assert_eq!(findings[0].file, "(unknown file)");
        assert_eq!(findings[0].line, None);
        assert_eq!(findings[0].message, "");
    }

    #[test]
    fn unparseable_or_empty_sarif_yields_no_findings() {
        assert_eq!(parse_sarif_findings("not json at all"), (Vec::new(), 0));
        assert_eq!(parse_sarif_findings(""), (Vec::new(), 0));
        // Well-formed JSON with no runs is simply zero findings, not an error.
        assert_eq!(parse_sarif_findings("{}"), (Vec::new(), 0));
    }

    /// The stored slice is capped, but the reported total is the true count — so
    /// a comment can say "showing 10 of 137".
    #[test]
    fn stored_findings_are_capped_but_total_is_honest() {
        let mut results = String::new();
        let n = MAX_STORED_FINDINGS + 20;
        for i in 0..n {
            if i > 0 {
                results.push(',');
            }
            results.push_str(&format!(
                r#"{{"ruleId":"r{i}","message":{{"text":"m"}},"locations":[]}}"#
            ));
        }
        let sarif = format!(r#"{{"runs":[{{"results":[{results}]}}]}}"#);
        let (findings, total) = parse_sarif_findings(&sarif);
        assert_eq!(total, n, "the total must be the true count");
        assert_eq!(
            findings.len(),
            MAX_STORED_FINDINGS,
            "the stored slice is bounded"
        );
    }
}
