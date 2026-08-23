//! The job queue watcher — the daemon's entry point, replacing the webhook
//! handler.
//!
//! switchboard-api writes jobs into `queue/` by `rename()` (atomic within the
//! filesystem), so a scan never sees a partial file. Filenames are
//! `<13-digit millis>-<16 hex>.json`, which makes lexicographic order equal
//! arrival order — the daemon processes in order with a plain scan + sort.
//!
//! Claiming uses `link()` then `unlink()`, never `rename()`: `rename()`
//! overwrites silently, so two workers would both believe they won; `link()`
//! fails with `EEXIST`, which is the atomic "someone else has it" the contract
//! requires. A processed job is deleted from `claimed/` on success and left
//! there for inspection on failure.
//!
//! **Coalescing** is the daemon's job: rapid pushes produce several
//! `synchronize` jobs for the same `preview.label`, and only the newest matters.
//! Among a batch, the newest file per label is dispatched and the older ones are
//! claimed and dropped without acting. Because filenames sort chronologically,
//! "newest" is just the maximum filename. The API deliberately does not coalesce
//! (superseding a queued job races the daemon's claim).

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::job::Job;

/// What the daemon decided to do with a claimed job's file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleOutcome {
    /// Processed to completion — delete the claimed file.
    Done,
    /// Processing failed — keep the claimed file for inspection.
    Retain,
}

/// A consumer of validated jobs. Implemented by the daemon orchestrator (which
/// mints a token, reports to GitHub, and provisions/tears down the preview) and
/// by tests.
pub trait JobSink {
    /// Handle one job. The returned [`HandleOutcome`] decides whether the
    /// claimed file is removed (success) or retained (failure).
    fn handle(&self, job: Job) -> impl std::future::Future<Output = HandleOutcome>;
}

/// Queue directory layout.
#[derive(Debug, Clone)]
pub struct QueuePaths {
    /// The directory the API writes jobs into.
    pub queue: PathBuf,
    /// `queue/claimed/` — jobs in flight.
    pub claimed: PathBuf,
}

impl QueuePaths {
    /// Derive the layout from the configured queue directory.
    #[must_use]
    pub fn from_queue_dir(queue: &Path) -> Self {
        Self {
            queue: queue.to_path_buf(),
            claimed: queue.join("claimed"),
        }
    }

    /// Ensure `claimed/` exists (the API creates `queue/`; the daemon owns
    /// `claimed/`).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn ensure(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.claimed)
            .with_context(|| format!("failed to create {}", self.claimed.display()))?;
        Ok(())
    }
}

/// The watcher: polls `queue/`, coalesces, claims, and dispatches to a sink.
pub struct QueueWatcher {
    paths: QueuePaths,
    github_host: String,
    poll: Duration,
}

impl QueueWatcher {
    /// Build a watcher for a queue directory.
    #[must_use]
    pub fn new(queue_dir: &Path, github_host: String, poll: Duration) -> Self {
        Self {
            paths: QueuePaths::from_queue_dir(queue_dir),
            github_host,
            poll,
        }
    }

    /// Run until `shutdown` resolves, scanning every `poll` interval.
    pub async fn run<S: JobSink>(&self, sink: &S, mut shutdown: impl Future<Output = ()> + Unpin) {
        if let Err(e) = self.paths.ensure() {
            tracing::error!(%e, "cannot prepare claimed/ directory");
            return;
        }
        tracing::info!(queue = %self.paths.queue.display(), poll_s = self.poll.as_secs(), "watching job queue");
        loop {
            self.run_once(sink).await;
            tokio::select! {
                () = &mut shutdown => {
                    tracing::info!("queue watcher shutting down");
                    return;
                }
                () = tokio::time::sleep(self.poll) => {}
            }
        }
    }

    /// One scan/claim/dispatch pass over the current queue contents.
    pub async fn run_once<S: JobSink>(&self, sink: &S) {
        let pending = match pending_sorted(&self.paths.queue) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%e, "failed to scan queue");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }

        // Read + parse each pending file, then compute the newest filename per
        // label so older same-label jobs can be superseded.
        let mut parsed: Vec<(String, Option<Job>)> = Vec::with_capacity(pending.len());
        let mut newest_for_label: HashMap<String, String> = HashMap::new();
        for filename in pending {
            let job = self.read_job(&filename);
            if let Some(job) = &job {
                newest_for_label
                    .entry(job.preview.label.clone())
                    .and_modify(|cur| {
                        if filename > *cur {
                            *cur = filename.clone();
                        }
                    })
                    .or_insert_with(|| filename.clone());
            }
            parsed.push((filename, job));
        }

        for (filename, job) in parsed {
            // Claim first. If someone else already has it (or it was consumed
            // this pass), skip.
            match self.claim(&filename) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(file = %filename, %e, "failed to claim job");
                    continue;
                }
            }

            let Some(job) = job else {
                tracing::warn!(file = %filename, "unparseable/invalid job — quarantined in claimed/");
                continue; // retained for inspection
            };

            // Coalesce: only the newest file per label is acted on.
            if newest_for_label.get(&job.preview.label) != Some(&filename) {
                tracing::info!(file = %filename, label = %job.preview.label, "superseded by a newer job — dropping");
                self.drop_claimed(&filename);
                continue;
            }

            tracing::info!(
                file = %filename,
                label = %job.preview.label,
                intent = %job.intent,
                delivery = %job.delivery_id,
                "dispatching job"
            );
            match sink.handle(job).await {
                HandleOutcome::Done => self.drop_claimed(&filename),
                HandleOutcome::Retain => {
                    tracing::warn!(file = %filename, "job retained in claimed/ after failure");
                }
            }
        }
    }

    /// Read and validate a job file. `None` on any read/parse/validation error.
    fn read_job(&self, filename: &str) -> Option<Job> {
        let path = self.paths.queue.join(filename);
        let bytes = std::fs::read(&path).ok()?;
        match Job::parse(&bytes, &self.github_host) {
            Ok(job) => Some(job),
            Err(e) => {
                tracing::warn!(file = %filename, %e, "invalid job");
                None
            }
        }
    }

    /// Claim a job by hard-linking it into `claimed/` then unlinking the
    /// original. Returns `Ok(false)` if it was already claimed.
    fn claim(&self, filename: &str) -> std::io::Result<bool> {
        let src = self.paths.queue.join(filename);
        let dst = self.paths.claimed.join(filename);
        match std::fs::hard_link(&src, &dst) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(false),
            // The source vanished — another pass consumed it.
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
        // Best-effort unlink of the queue entry; the claim already succeeded.
        let _ = std::fs::remove_file(&src);
        Ok(true)
    }

    /// Remove a completed job's claimed file.
    fn drop_claimed(&self, filename: &str) {
        let path = self.paths.claimed.join(filename);
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != ErrorKind::NotFound
        {
            tracing::warn!(file = %filename, %e, "failed to remove claimed job");
        }
    }
}

/// Pending `*.json` job filenames in `queue/`, sorted ascending (= arrival
/// order). `claimed/` (a subdirectory) is skipped naturally — it is not a
/// `.json` file.
fn pending_sorted(queue_dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut jobs = Vec::new();
    let entries = match std::fs::read_dir(queue_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(jobs),
        Err(e) => return Err(e).context("read queue dir"),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.ends_with(".json") && entry.file_type().is_ok_and(|t| t.is_file()) {
            jobs.push(name.to_string());
        }
    }
    jobs.sort();
    Ok(jobs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording sink. Records handled labels+intents in order and can be told
    /// to fail (Retain) for a given label.
    #[derive(Default)]
    struct Recorder {
        handled: Mutex<Vec<(String, String)>>,
        fail_label: Option<String>,
    }

    impl JobSink for Recorder {
        async fn handle(&self, job: Job) -> HandleOutcome {
            self.handled
                .lock()
                .unwrap()
                .push((job.preview.label.clone(), job.intent.clone()));
            if self.fail_label.as_deref() == Some(job.preview.label.as_str()) {
                HandleOutcome::Retain
            } else {
                HandleOutcome::Done
            }
        }
    }

    fn job_json(label: &str, number: u64, intent: &str, action: &str) -> String {
        serde_json::json!({
            "schema": 1,
            "job_id": "x",
            "delivery_id": "d",
            "event": "pull_request",
            "action": action,
            "intent": intent,
            "preview": { "label": label },
            "repository": {
                "full_name": "ephpm/app",
                "owner": "ephpm",
                "name": "app",
                "clone_url": "https://github.com/ephpm/app.git"
            },
            "pull_request": {
                "number": number,
                "fork": false,
                "head": {
                    "ref": "feature/x",
                    "sha": "0123456789abcdef0123456789abcdef01234567",
                    "clone_url": "https://github.com/ephpm/app.git",
                    "repo_full_name": "ephpm/app",
                    "pull_ref": format!("refs/pull/{number}/head")
                },
                "base": { "ref": "main" }
            },
            "installation_id": 1
        })
        .to_string()
    }

    fn write_job(queue: &Path, filename: &str, body: &str) {
        std::fs::write(queue.join(filename), body).unwrap();
    }

    fn watcher(queue: &Path) -> QueueWatcher {
        let w = QueueWatcher::new(queue, "github.com".to_string(), Duration::from_millis(1));
        w.paths.ensure().unwrap();
        w
    }

    #[test]
    fn pending_sorted_is_chronological_and_filters() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        std::fs::create_dir_all(q.join("claimed")).unwrap();
        write_job(q, "0000000000002-bbbb.json", "{}");
        write_job(q, "0000000000001-aaaa.json", "{}");
        std::fs::write(q.join("not-a-job.txt"), "x").unwrap();
        let pending = pending_sorted(q).unwrap();
        assert_eq!(
            pending,
            vec!["0000000000001-aaaa.json", "0000000000002-bbbb.json"]
        );
    }

    #[tokio::test]
    async fn dispatches_a_valid_job_and_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        write_job(
            q,
            "0000000000001-aaaa.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "opened"),
        );
        let rec = Recorder::default();
        w.run_once(&rec).await;
        assert_eq!(rec.handled.lock().unwrap().len(), 1);
        // Consumed from queue and from claimed (success).
        assert!(!q.join("0000000000001-aaaa.json").exists());
        assert!(!q.join("claimed/0000000000001-aaaa.json").exists());
    }

    #[tokio::test]
    async fn coalesces_older_same_label_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        // Three synchronize jobs for one label; only the newest should run.
        write_job(
            q,
            "0000000000001-aaaa.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "synchronize"),
        );
        write_job(
            q,
            "0000000000002-bbbb.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "synchronize"),
        );
        write_job(
            q,
            "0000000000003-cccc.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "synchronize"),
        );
        // A different label runs independently.
        write_job(
            q,
            "0000000000002-dddd.json",
            &job_json("ephpm-other-pr-2", 2, "deploy", "opened"),
        );
        let rec = Recorder::default();
        w.run_once(&rec).await;
        let handled = rec.handled.lock().unwrap();
        // pr-1 handled exactly once; pr-2 once.
        assert_eq!(
            handled
                .iter()
                .filter(|(l, _)| l == "ephpm-app-pr-1")
                .count(),
            1
        );
        assert_eq!(
            handled
                .iter()
                .filter(|(l, _)| l == "ephpm-other-pr-2")
                .count(),
            1
        );
        // All queue files consumed; none linger.
        assert!(pending_sorted(q).unwrap().is_empty());
        assert!(
            std::fs::read_dir(q.join("claimed"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[tokio::test]
    async fn newest_teardown_supersedes_earlier_deploy() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        write_job(
            q,
            "0000000000001-aaaa.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "synchronize"),
        );
        write_job(
            q,
            "0000000000002-bbbb.json",
            &job_json("ephpm-app-pr-1", 1, "teardown", "closed"),
        );
        let rec = Recorder::default();
        w.run_once(&rec).await;
        let handled = rec.handled.lock().unwrap();
        assert_eq!(handled.len(), 1);
        assert_eq!(handled[0].1, "teardown", "the newest (teardown) must win");
    }

    #[tokio::test]
    async fn failed_job_is_retained_in_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        write_job(
            q,
            "0000000000001-aaaa.json",
            &job_json("ephpm-app-pr-1", 1, "deploy", "opened"),
        );
        let rec = Recorder {
            fail_label: Some("ephpm-app-pr-1".into()),
            ..Recorder::default()
        };
        w.run_once(&rec).await;
        // Removed from queue, retained in claimed for inspection.
        assert!(!q.join("0000000000001-aaaa.json").exists());
        assert!(q.join("claimed/0000000000001-aaaa.json").exists());
    }

    #[tokio::test]
    async fn invalid_job_is_quarantined_not_dispatched() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        write_job(q, "0000000000001-aaaa.json", "{ not valid json");
        let rec = Recorder::default();
        w.run_once(&rec).await;
        assert!(
            rec.handled.lock().unwrap().is_empty(),
            "invalid job must not dispatch"
        );
        // Claimed (quarantined), removed from queue.
        assert!(q.join("claimed/0000000000001-aaaa.json").exists());
        assert!(!q.join("0000000000001-aaaa.json").exists());
    }

    #[tokio::test]
    async fn a_claimed_job_is_not_reprocessed() {
        // Simulate a prior crash: the file exists in BOTH queue and claimed.
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let w = watcher(q);
        let body = job_json("ephpm-app-pr-1", 1, "deploy", "opened");
        write_job(q, "0000000000001-aaaa.json", &body);
        std::fs::write(q.join("claimed/0000000000001-aaaa.json"), &body).unwrap();
        let rec = Recorder::default();
        w.run_once(&rec).await;
        assert!(
            rec.handled.lock().unwrap().is_empty(),
            "already-claimed job must not be reprocessed"
        );
    }
}
