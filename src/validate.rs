//! Re-validating a claimed job against **current** reality (issue #18).
//!
//! A job file records what was true when switchboard-api wrote it. Nothing
//! re-checks that when the daemon finally gets to it, and the gap can be days:
//! a `pull_request/opened` job received Sep 1 sat unclaimed in node-3's queue
//! and was applied during a restart, provisioning a preview for a PR that had
//! already **merged**. Restarts are exactly when this fires — a drained backlog
//! is a queue of statements about the past, replayed as if current.
//!
//! Two checks, deliberately different in kind:
//!
//! * **age** ([`age_verdict`]) — cheap, offline, unconditional. A deploy job
//!   that has been sitting in the queue longer than the configured bound is
//!   discarded without asking anyone. This is the only check available on a
//!   node with no GitHub App configured (the e2e cluster runs that way).
//! * **PR state** ([`pr_state_verdict`]) — authoritative but needs a network
//!   call and an installation token. GitHub is asked what the pull request is
//!   *now*; merged or closed means the deploy is no longer wanted.
//!
//! # Only deploys are validated
//!
//! A teardown is idempotent, removes drift rather than creating it, and is
//! never wrong to apply late — the preview it names should not exist either
//! way. Refusing a stale teardown would strand exactly the artifacts issue #17
//! is about. So neither check applies to [`crate::job::Intent::Teardown`], for
//! the same reason the fork gate does not.
//!
//! # Which way each check fails
//!
//! The age bound is unconditional because it cannot fail: it is arithmetic on a
//! timestamp the daemon already has. The state check **fails open** — a GitHub
//! outage, a rate limit, or a state string this daemon does not recognise
//! applies the job with a `WARN` rather than dropping it. Dropping deploys
//! because a third party is unreachable trades one silent drift for another;
//! the age bound is what still holds in that case.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What to do with a claimed job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run it.
    Apply,
    /// Do not run it. The job is *resolved*, not failed: it is removed from
    /// `claimed/` like a successful one, with `reason` logged.
    Discard {
        /// Operator-facing explanation, logged verbatim.
        reason: String,
    },
}

impl Verdict {
    /// Whether this verdict discards the job.
    #[must_use]
    pub fn is_discard(&self) -> bool {
        matches!(self, Self::Discard { .. })
    }
}

/// A pull request's state as GitHub reports it *now*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullRequestState {
    /// Still open — the preview is still wanted.
    Open,
    /// Closed by merging.
    Merged,
    /// Closed without merging.
    Closed,
    /// A `state` value this daemon does not recognise. Treated as "still
    /// wanted" rather than guessed at; the caller logs it.
    Unknown(String),
}

/// Classify GitHub's `state` + `merged` pair from the pull request API.
///
/// `merged` wins: GitHub reports a merged PR as `state: "closed"`, and the two
/// are worth distinguishing in the log an operator reads.
#[must_use]
pub fn classify_pull_request(state: &str, merged: bool) -> PullRequestState {
    if merged {
        return PullRequestState::Merged;
    }
    match state {
        "open" => PullRequestState::Open,
        "closed" => PullRequestState::Closed,
        other => PullRequestState::Unknown(other.to_string()),
    }
}

/// Should a **deploy** job still run, given how long it waited in the queue?
///
/// `age` is `None` when the enqueue time could not be determined at all (an
/// unparseable filename *and* an unreadable mtime), and `max_age` is `None`
/// when the bound is disabled. Either way the job is applied: a bound that
/// cannot be evaluated must not silently eat work.
#[must_use]
pub fn age_verdict(age: Option<Duration>, max_age: Option<Duration>) -> Verdict {
    match (age, max_age) {
        (Some(age), Some(max)) if age > max => Verdict::Discard {
            reason: format!(
                "job waited {}s in the queue, past the --max-job-age-secs bound of {}s — \
                 a deploy this old describes a pull request as it was, not as it is",
                age.as_secs(),
                max.as_secs()
            ),
        },
        _ => Verdict::Apply,
    }
}

/// Should a **deploy** job still run, given the pull request's current state?
#[must_use]
pub fn pr_state_verdict(state: &PullRequestState) -> Verdict {
    match state {
        PullRequestState::Open => Verdict::Apply,
        PullRequestState::Merged => Verdict::Discard {
            reason: "the pull request has since been merged — a preview for it \
                     would be drift the teardown path exists to prevent"
                .to_string(),
        },
        PullRequestState::Closed => Verdict::Discard {
            reason: "the pull request has since been closed".to_string(),
        },
        // Fail open: an unrecognised state is not evidence the deploy is
        // unwanted, and this daemon should not invent policy for a GitHub
        // field it does not understand.
        PullRequestState::Unknown(_) => Verdict::Apply,
    }
}

/// Wall-clock milliseconds since the Unix epoch.
///
/// A clock before the epoch yields `0`, which makes every job look brand new —
/// the same fail-open choice as an unknown enqueue time.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// How long a job has been waiting, from its enqueue timestamp to `now_ms`.
///
/// A timestamp in the future (clock skew between the API's node and this one)
/// saturates to zero rather than wrapping — skew must not make a job look
/// ancient.
#[must_use]
pub fn queue_age(enqueued_at_ms: Option<u64>, now_ms: u64) -> Option<Duration> {
    enqueued_at_ms.map(|then| Duration::from_millis(now_ms.saturating_sub(then)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_fresh_job_is_applied() {
        assert_eq!(
            age_verdict(Some(Duration::from_secs(3)), Some(HOUR)),
            Verdict::Apply
        );
    }

    /// The observed incident: a job received Sep 1, applied Sep 3 by a restart.
    #[test]
    fn a_two_day_old_deploy_job_is_discarded() {
        let age = Duration::from_secs(2 * 24 * 3600);
        let v = age_verdict(Some(age), Some(HOUR));
        assert!(v.is_discard());
        match v {
            Verdict::Discard { reason } => {
                assert!(reason.contains("172800s"), "{reason}");
                assert!(reason.contains("3600s"), "the bound is named: {reason}");
            }
            Verdict::Apply => unreachable!(),
        }
    }

    #[test]
    fn the_bound_is_exclusive_at_the_boundary() {
        assert_eq!(age_verdict(Some(HOUR), Some(HOUR)), Verdict::Apply);
        assert!(age_verdict(Some(HOUR + Duration::from_millis(1)), Some(HOUR)).is_discard());
    }

    #[test]
    fn a_disabled_bound_applies_everything() {
        let ancient = Duration::from_secs(400 * 24 * 3600);
        assert_eq!(age_verdict(Some(ancient), None), Verdict::Apply);
    }

    /// A bound that cannot be evaluated must not eat work: an unknown enqueue
    /// time applies the job (and the caller warns), it does not discard it.
    #[test]
    fn an_unknown_enqueue_time_applies_the_job() {
        assert_eq!(age_verdict(None, Some(HOUR)), Verdict::Apply);
    }

    #[test]
    fn clock_skew_does_not_age_a_job() {
        // The API's node is 5 minutes ahead of ours: the job's timestamp is in
        // our future. Saturating to zero beats wrapping to ~584 million years.
        let now = 1_787_456_737_243;
        let enqueued = now + 300_000;
        assert_eq!(
            queue_age(Some(enqueued), now),
            Some(Duration::from_millis(0))
        );
        assert_eq!(queue_age(None, now), None);
        assert_eq!(
            queue_age(Some(now - 90_000), now),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn merged_and_closed_pull_requests_are_distinguished() {
        // GitHub reports a merged PR as state:"closed" with merged:true.
        assert_eq!(
            classify_pull_request("closed", true),
            PullRequestState::Merged
        );
        assert_eq!(
            classify_pull_request("closed", false),
            PullRequestState::Closed
        );
        assert_eq!(classify_pull_request("open", false), PullRequestState::Open);
        // Nothing sets merged:true on an open PR, but the field is the
        // authority if it ever does.
        assert_eq!(
            classify_pull_request("open", true),
            PullRequestState::Merged
        );
        assert_eq!(
            classify_pull_request("locked", false),
            PullRequestState::Unknown("locked".to_string())
        );
    }

    #[test]
    fn only_an_open_pull_request_keeps_its_deploy() {
        assert_eq!(pr_state_verdict(&PullRequestState::Open), Verdict::Apply);
        assert!(pr_state_verdict(&PullRequestState::Merged).is_discard());
        assert!(pr_state_verdict(&PullRequestState::Closed).is_discard());
    }

    /// The exact shape of the incident, stated as a test: a merged PR must not
    /// get a preview, and the reason must say why.
    #[test]
    fn a_merged_pull_request_names_the_merge_in_its_reason() {
        match pr_state_verdict(&PullRequestState::Merged) {
            Verdict::Discard { reason } => assert!(reason.contains("merged"), "{reason}"),
            Verdict::Apply => panic!("a merged PR must not get a preview"),
        }
    }

    /// Fail open on a state this daemon does not understand — the age bound is
    /// what still holds.
    #[test]
    fn an_unrecognised_state_is_applied_not_guessed_at() {
        assert_eq!(
            pr_state_verdict(&PullRequestState::Unknown("draft-ish".into())),
            Verdict::Apply
        );
    }

    #[test]
    fn now_is_after_the_epoch_and_before_the_heat_death() {
        let now = now_ms();
        assert!(now > 1_700_000_000_000, "clock looks wrong: {now}");
    }
}
