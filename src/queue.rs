//! The on-disk job queue the daemon consumes.
//!
//! Layout (owned by `switchboard-api`, created here if absent so the daemon can
//! start first):
//!
//! ```text
//! <state_dir>/
//!   queue/           jobs waiting to be picked up      API → daemon
//!   queue/claimed/   jobs this daemon is working on
//! ```
//!
//! The four rules that make this safe, per the API's README:
//!
//! 1. **Sort is arrival order.** Filenames are `<13-digit millis>-<16 hex>.json`
//!    and the timestamp stays fixed-width until 2286, so a lexicographic sort of
//!    `readdir` output is chronological — no need to open every file to order
//!    the work.
//! 2. **Claim with `link()`, not `rename()`.** `link()` fails with `EEXIST` when
//!    another worker already claimed the job; `rename()` would silently
//!    overwrite and both workers would believe they won.
//! 3. **Coalescing is the daemon's job.** Rapid pushes produce several
//!    `synchronize` jobs for one `preview.label`; only the newest is worth
//!    running. The API deliberately does not do this, because superseding a job
//!    races with the claim.
//! 4. **Delete on success, leave on failure.** A failed job stays in `claimed/`
//!    for inspection rather than being retried forever.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::job::Job;

/// Most jobs claimed in a single pass. A backlog is drained over several
/// passes rather than in one unbounded burst.
const MAX_BATCH: usize = 256;

/// A job this daemon has claimed: the queue filename, its path under
/// `claimed/`, and the parsed document.
#[derive(Debug)]
pub struct ClaimedJob {
    /// The queue filename, e.g. `1787456737243-b81167e5b47a38b9.json`.
    pub name: String,
    /// Where the claimed file now lives (`queue/claimed/<name>`).
    pub path: PathBuf,
    /// The parsed, schema-validated document.
    pub job: Job,
}

/// The queue directories under a state dir.
#[derive(Debug, Clone)]
pub struct Queue {
    queue_dir: PathBuf,
    claimed_dir: PathBuf,
}

impl Queue {
    /// Build a queue rooted at `<state_dir>/queue`.
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        let queue_dir = state_dir.join("queue");
        let claimed_dir = queue_dir.join("claimed");
        Self {
            queue_dir,
            claimed_dir,
        }
    }

    /// The directory the API writes jobs into.
    #[must_use]
    pub fn queue_dir(&self) -> &Path {
        &self.queue_dir
    }

    /// The directory claimed jobs are linked into.
    #[must_use]
    pub fn claimed_dir(&self) -> &Path {
        &self.claimed_dir
    }

    /// Create both directories if they do not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the directories cannot be created.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.claimed_dir).with_context(|| {
            format!(
                "failed to create queue directory {}",
                self.claimed_dir.display()
            )
        })?;
        Ok(())
    }

    /// Pending job filenames in arrival order (lexicographic = chronological),
    /// capped at [`MAX_BATCH`].
    ///
    /// A missing `queue/` yields an empty list rather than an error — the API
    /// may not have written its first job yet.
    ///
    /// # Errors
    ///
    /// Returns an error if `queue/` exists but cannot be read.
    pub fn pending(&self) -> anyhow::Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.queue_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read queue {}", self.queue_dir.display()));
            }
        };

        let mut names: Vec<String> = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                // A job can be claimed by a concurrent worker mid-scan; that is
                // not an error, it is the design.
                Err(_) => continue,
            };
            // `claimed/` is a subdirectory of `queue/`; skip it and anything
            // else that is not a plain `*.json` file.
            if !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") {
                names.push(name);
            }
        }

        names.sort();
        names.truncate(MAX_BATCH);
        Ok(names)
    }

    /// Claim one job by hard-linking it into `claimed/` and unlinking the
    /// original.
    ///
    /// Returns `Ok(None)` when the claim was lost — either another worker got
    /// there first (`EEXIST` on the link) or the file is already gone.
    ///
    /// # Errors
    ///
    /// Returns an error for any other filesystem failure.
    pub fn claim(&self, name: &str) -> anyhow::Result<Option<PathBuf>> {
        let src = self.queue_dir.join(name);
        let dst = self.claimed_dir.join(name);

        match std::fs::hard_link(&src, &dst) {
            Ok(()) => {}
            // Another worker claimed it first. `link()` reporting this is
            // exactly why it is used instead of `rename()`.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(None),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to claim {name} into {}", self.claimed_dir.display())
                });
            }
        }

        // The link is the claim; failing to unlink the queue entry would only
        // cause a later pass to re-attempt the (now EEXIST) claim, so a warning
        // is enough.
        if let Err(e) = std::fs::remove_file(&src) {
            if e.kind() != ErrorKind::NotFound {
                tracing::warn!(job = name, %e, "claimed job but failed to unlink the queue entry");
            }
        }

        Ok(Some(dst))
    }

    /// Claim every pending job, parse it, and return the claims in arrival
    /// order. Jobs that fail to parse or carry an unknown schema are rejected:
    /// they stay in `claimed/` for inspection and are not returned.
    ///
    /// # Errors
    ///
    /// Returns an error only if the queue directory cannot be read.
    pub fn claim_pending(&self) -> anyhow::Result<Vec<ClaimedJob>> {
        let mut claimed = Vec::new();
        for name in self.pending()? {
            let Some(path) = self.claim(&name)? else {
                tracing::debug!(job = %name, "claim lost to another worker");
                continue;
            };
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(job = %name, %e, "claimed job could not be read — left in claimed/");
                    continue;
                }
            };
            match Job::parse(&bytes) {
                Ok(job) => {
                    // The contract says job_id equals the filename minus
                    // `.json`. A mismatch is not fatal — the filename is what
                    // ordering and claiming use — but it means the producer and
                    // this daemon disagree, which is worth seeing.
                    let stem = name.trim_end_matches(".json");
                    if job.job_id != stem {
                        tracing::warn!(
                            job = %name,
                            job_id = %job.job_id,
                            "job_id does not match its filename"
                        );
                    }
                    claimed.push(ClaimedJob { name, path, job });
                }
                Err(e) => {
                    tracing::error!(job = %name, %e, "rejecting job — left in claimed/ for inspection");
                }
            }
        }
        Ok(claimed)
    }

    /// Remove a finished job from `claimed/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be removed.
    pub fn complete(&self, name: &str) -> anyhow::Result<()> {
        match std::fs::remove_file(self.claimed_dir.join(name)) {
            Ok(()) => Ok(()),
            // Already gone (a crash between the delete and the next pass) is
            // success, not an error.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("failed to remove claimed job {name}")),
        }
    }
}

/// The result of coalescing a batch of claimed jobs.
pub struct Coalesced {
    /// One job per `preview.label` — the newest — in arrival order.
    pub run: Vec<ClaimedJob>,
    /// Older jobs for a label that a newer job supersedes. These are done with:
    /// running them would only deploy a commit that is already stale.
    pub superseded: Vec<ClaimedJob>,
}

/// Keep the newest job per `preview.label` and discard the rest.
///
/// `claimed` must be in arrival order (as [`Queue::claim_pending`] returns it);
/// the last job seen for a label wins.
#[must_use]
pub fn coalesce(claimed: Vec<ClaimedJob>) -> Coalesced {
    let mut newest: BTreeMap<String, ClaimedJob> = BTreeMap::new();
    let mut superseded = Vec::new();

    for job in claimed {
        let label = job.job.label().to_string();
        if let Some(older) = newest.insert(label, job) {
            superseded.push(older);
        }
    }

    // Back to arrival order: the map is keyed by label, not by time.
    let mut run: Vec<ClaimedJob> = newest.into_values().collect();
    run.sort_by(|a, b| a.name.cmp(&b.name));

    Coalesced { run, superseded }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::sample_json;

    fn write_job(q: &Queue, name: &str, label: &str, intent: &str) {
        std::fs::write(q.queue_dir().join(name), sample_json(label, intent)).unwrap();
    }

    fn queue() -> (tempfile::TempDir, Queue) {
        let dir = tempfile::tempdir().unwrap();
        let q = Queue::new(dir.path());
        q.ensure_dirs().unwrap();
        (dir, q)
    }

    #[test]
    fn pending_is_sorted_and_therefore_chronological() {
        let (_d, q) = queue();
        // Written out of order; 13-digit millis keep lexicographic == temporal.
        write_job(&q, "1787456737243-bbbbbbbbbbbbbbbb.json", "a", "deploy");
        write_job(&q, "1787456737100-aaaaaaaaaaaaaaaa.json", "a", "deploy");
        write_job(&q, "1787456800000-cccccccccccccccc.json", "b", "deploy");

        assert_eq!(
            q.pending().unwrap(),
            vec![
                "1787456737100-aaaaaaaaaaaaaaaa.json".to_string(),
                "1787456737243-bbbbbbbbbbbbbbbb.json".to_string(),
                "1787456800000-cccccccccccccccc.json".to_string(),
            ]
        );
    }

    #[test]
    fn pending_ignores_non_json_and_the_claimed_dir() {
        let (_d, q) = queue();
        write_job(&q, "1787456737243-bbbbbbbbbbbbbbbb.json", "a", "deploy");
        std::fs::write(q.queue_dir().join("README"), "not a job").unwrap();
        std::fs::write(q.queue_dir().join("half-written.json.tmp"), "{}").unwrap();
        // `claimed/` lives inside `queue/` and must never be scanned as a job.
        std::fs::write(q.claimed_dir().join("999-x.json"), "{}").unwrap();

        assert_eq!(
            q.pending().unwrap(),
            vec!["1787456737243-bbbbbbbbbbbbbbbb.json".to_string()]
        );
    }

    #[test]
    fn pending_on_a_missing_queue_dir_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let q = Queue::new(&dir.path().join("never-created"));
        assert!(q.pending().unwrap().is_empty());
    }

    #[test]
    fn claim_moves_the_job_and_is_exclusive() {
        let (_d, q) = queue();
        let name = "1787456737243-bbbbbbbbbbbbbbbb.json";
        write_job(&q, name, "a", "deploy");

        let claimed = q.claim(name).unwrap().expect("first claim must win");
        assert!(claimed.exists(), "claimed file must exist under claimed/");
        assert!(
            !q.queue_dir().join(name).exists(),
            "the queue entry must be unlinked once claimed"
        );

        // A second worker re-creating the queue entry (e.g. GitHub redelivery)
        // must lose the claim rather than double-deploy: link() reports EEXIST
        // where rename() would silently overwrite.
        write_job(&q, name, "a", "deploy");
        assert!(
            q.claim(name).unwrap().is_none(),
            "a job already in claimed/ must not be claimable again"
        );
    }

    #[test]
    fn claim_of_a_vanished_job_is_not_an_error() {
        let (_d, q) = queue();
        assert!(q.claim("1787456737243-gone.json").unwrap().is_none());
    }

    #[test]
    fn claim_pending_parses_and_rejects() {
        let (_d, q) = queue();
        write_job(
            &q,
            "1787456737100-aaaaaaaaaaaaaaaa.json",
            "site-a",
            "deploy",
        );
        // Unknown schema: claimed, rejected, and left behind for inspection.
        std::fs::write(
            q.queue_dir().join("1787456737200-bbbbbbbbbbbbbbbb.json"),
            sample_json("site-b", "deploy").replace("\"schema\": 1", "\"schema\": 9"),
        )
        .unwrap();

        let claimed = q.claim_pending().unwrap();
        assert_eq!(claimed.len(), 1, "only the schema-1 job is returned");
        assert_eq!(claimed[0].job.label(), "site-a");
        assert!(
            q.claimed_dir()
                .join("1787456737200-bbbbbbbbbbbbbbbb.json")
                .exists(),
            "a rejected job stays in claimed/ for inspection"
        );
        assert!(q.pending().unwrap().is_empty(), "queue/ is drained");
    }

    #[test]
    fn coalesce_keeps_the_newest_job_per_label() {
        let (_d, q) = queue();
        // Three pushes to one PR plus one job for a different preview.
        write_job(
            &q,
            "1787456737100-aaaaaaaaaaaaaaaa.json",
            "site-a",
            "deploy",
        );
        write_job(
            &q,
            "1787456737200-bbbbbbbbbbbbbbbb.json",
            "site-a",
            "deploy",
        );
        write_job(
            &q,
            "1787456737300-cccccccccccccccc.json",
            "site-a",
            "teardown",
        );
        write_job(
            &q,
            "1787456737150-dddddddddddddddd.json",
            "site-b",
            "deploy",
        );

        let out = coalesce(q.claim_pending().unwrap());

        assert_eq!(out.run.len(), 2, "one job per label survives");
        // Arrival order is preserved across labels.
        assert_eq!(out.run[0].name, "1787456737150-dddddddddddddddd.json");
        assert_eq!(out.run[0].job.label(), "site-b");
        // The newest job for site-a wins — here a teardown that supersedes two
        // deploys, which is the whole point of coalescing.
        assert_eq!(out.run[1].name, "1787456737300-cccccccccccccccc.json");
        assert_eq!(
            out.run[1].job.intent().unwrap(),
            crate::job::Intent::Teardown
        );

        assert_eq!(out.superseded.len(), 2);
        let mut stale: Vec<&str> = out.superseded.iter().map(|c| c.name.as_str()).collect();
        stale.sort_unstable();
        assert_eq!(
            stale,
            vec![
                "1787456737100-aaaaaaaaaaaaaaaa.json",
                "1787456737200-bbbbbbbbbbbbbbbb.json"
            ]
        );
    }

    #[test]
    fn coalesce_of_an_empty_batch_is_empty() {
        let out = coalesce(Vec::new());
        assert!(out.run.is_empty());
        assert!(out.superseded.is_empty());
    }

    #[test]
    fn complete_removes_the_claim_and_is_idempotent() {
        let (_d, q) = queue();
        let name = "1787456737243-bbbbbbbbbbbbbbbb.json";
        write_job(&q, name, "a", "deploy");
        q.claim(name).unwrap().unwrap();

        q.complete(name).unwrap();
        assert!(!q.claimed_dir().join(name).exists());
        // Completing twice (crash between remove and bookkeeping) is a no-op.
        q.complete(name).unwrap();
    }
}
