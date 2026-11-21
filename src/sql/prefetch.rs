//! Concurrent first GETs of a finished multi-statement request's children (ADR 0004,
//! Amendment 1).
//!
//! Every child has finished once the parent answers, so their first GETs are independent reads.
//! Worker threads send them in step order; at most [`CHILD_PREFETCH_WINDOW`] are requested and
//! not yet taken at once. The consumer takes the replies strictly in order, so which reply
//! arrives first never changes the output. Taking a reply frees a slot for the next handle.

use super::client::{Inner, Posted, malformed};
use crate::error::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};

/// Child first GETs requested and not yet taken, at most (Amendment 1: 16 meets the 3× target
/// with margin; beyond it each worker is one more TLS connection for little gain).
pub(super) const CHILD_PREFETCH_WINDOW: usize = 16;

/// One child GET; the worker answers on `reply`.
struct Job {
    handle: String,
    reply: SyncSender<Result<Posted>>,
}

/// The replies of a run's child handles, in order.
pub(super) struct Prefetch {
    /// Handles not dispatched yet, in order.
    queued: VecDeque<String>,
    /// Replies of the dispatched handles not taken yet, in order.
    pending: VecDeque<Receiver<Result<Posted>>>,
    jobs: Option<Sender<Job>>,
    cancel: Arc<AtomicBool>,
}

impl Prefetch {
    /// Starts the first `window` GETs of `handles`. No handle, no worker.
    pub(super) fn new(inner: &Arc<Inner>, handles: Vec<String>, window: usize) -> Self {
        let workers = window.max(1).min(handles.len());
        let mut prefetch = Self {
            queued: handles.into(),
            pending: VecDeque::new(),
            jobs: None,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        if workers > 0 {
            prefetch.jobs = Some(spawn_workers(workers, inner, &prefetch.cancel));
            for _ in 0..workers {
                prefetch.dispatch();
            }
        }
        prefetch
    }

    /// The reply of the next handle in order, waiting for it if needed; then dispatches the
    /// next queued handle.
    pub(super) fn take(&mut self) -> Result<Posted> {
        let receiver = self
            .pending
            .pop_front()
            .ok_or_else(|| malformed("a statement result was never requested"))?;
        let reply = receiver
            .recv()
            .map_err(|_| malformed("a statement result download stopped"))?;
        self.dispatch();
        reply
    }

    /// Dispatches nothing more; outstanding GETs finish and are discarded (they have no side
    /// effects).
    pub(super) fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs = None;
        self.queued.clear();
        self.pending.clear();
    }

    fn dispatch(&mut self) {
        let Some(jobs) = &self.jobs else { return };
        let Some(handle) = self.queued.pop_front() else {
            return;
        };
        let (reply, receiver) = mpsc::sync_channel(1);
        // Workers only stop once `cancel` is set or the channel is closed, both by us.
        if jobs.send(Job { handle, reply }).is_ok() {
            self.pending.push_back(receiver);
        }
    }
}

impl Drop for Prefetch {
    /// Workers exit after their current request; they are not joined (as ADR 0002's).
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_workers(count: usize, inner: &Arc<Inner>, cancel: &Arc<AtomicBool>) -> Sender<Job> {
    let (jobs, receiver) = mpsc::channel::<Job>();
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..count {
        let receiver = Arc::clone(&receiver);
        let inner = Arc::clone(inner);
        let cancel = Arc::clone(cancel);
        std::thread::spawn(move || {
            loop {
                // The lock is held only while waiting for the next job.
                let job = match receiver.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => return,
                };
                let Ok(job) = job else { return };
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let reply = inner.get_statement(&job.handle);
                // The run may be gone already; nothing to do then.
                let _ = job.reply.send(reply);
            }
        });
    }
    jobs
}
