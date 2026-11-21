//! The session heartbeat (ADR 0005, Decision 3): one std thread that calls
//! `POST /session/heartbeat` every interval while the session is open, when
//! `client_session_keep_alive` is on.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

/// The server's default `CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY`.
const DEFAULT_FREQUENCY: u64 = 3600;
/// Master-token validity when the server does not say (4 hours).
const DEFAULT_MASTER_VALIDITY: u64 = 14400;

/// The connector's `_validate_client_session_keep_alive_heartbeat_frequency`: the configured
/// value, else the server's parameter, clamped to [validity / 16, validity / 4].
pub(super) fn interval(
    configured: Option<u64>,
    parameters: &serde_json::Value,
    master_validity: Option<u64>,
) -> u64 {
    let from_server = parameters.as_array().and_then(|list| {
        list.iter()
            .find(|p| p["name"] == "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY")
            .and_then(|p| p["value"].as_u64())
    });
    let value = configured.or(from_server).unwrap_or(DEFAULT_FREQUENCY);
    let max = master_validity.unwrap_or(DEFAULT_MASTER_VALIDITY) / 4;
    let min = max / 4;
    value.clamp(min, max.max(min)).max(1)
}

/// A running heartbeat; dropping it (or [`Heartbeat::stop`]) ends the thread.
pub(super) struct Heartbeat {
    stop: mpsc::Sender<()>,
    handle: JoinHandle<()>,
}

impl Heartbeat {
    /// Calls `beat` every `every` until stopped or until `beat` returns `false` (the session is
    /// gone).
    pub fn start(every: Duration, beat: impl Fn() -> bool + Send + 'static) -> Self {
        let (stop, stopped) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(every) {
                log::debug!("heartbeating");
                if !beat() {
                    break;
                }
            }
        });
        Self { stop, handle }
    }

    pub fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn the_interval_is_clamped_like_the_connector() {
        let none = serde_json::Value::Null;
        assert_eq!(interval(None, &none, None), 3600);
        assert_eq!(interval(Some(10), &none, None), 900);
        assert_eq!(interval(Some(99999), &none, None), 3600);
        assert_eq!(interval(Some(1200), &none, Some(14400)), 1200);
        let params = serde_json::json!([
            {"name": "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY", "value": 1800}
        ]);
        assert_eq!(interval(None, &params, None), 1800);
        assert_eq!(interval(Some(1000), &params, None), 1000);
        assert_eq!(interval(None, &none, Some(0)), 1);
    }

    #[test]
    fn it_beats_until_stopped_or_the_session_is_gone() {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let heartbeat = Heartbeat::start(Duration::from_millis(5), move || {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        });
        while count.load(Ordering::SeqCst) < 2 {
            std::thread::sleep(Duration::from_millis(5));
        }
        heartbeat.stop();
        let after = count.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(count.load(Ordering::SeqCst), after, "stopped");

        let gone = Heartbeat::start(Duration::from_millis(1), || false);
        gone.handle.join().unwrap();
    }
}
