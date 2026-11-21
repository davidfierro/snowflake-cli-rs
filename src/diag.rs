//! Diagnostics: the stderr logger behind the `log` facade.
//!
//! Every module logs through `log::{warn,info,debug}!`; this module decides what reaches stderr.
//! Log messages are built from names, paths and codes only, never from credential values.

use std::io::Write;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Normal,
    Verbose,
    Debug,
}

impl Verbosity {
    fn level(self) -> log::LevelFilter {
        match self {
            Verbosity::Normal => log::LevelFilter::Warn,
            Verbosity::Verbose => log::LevelFilter::Info,
            Verbosity::Debug => log::LevelFilter::Debug,
        }
    }
}

type Sink = Box<dyn Write + Send>;

struct DiagLogger {
    /// `None` writes to stderr; tests install a buffer.
    sink: Mutex<Option<Sink>>,
}

static LOGGER: DiagLogger = DiagLogger {
    sink: Mutex::new(None),
};

impl log::Log for DiagLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} [{}] {}\n",
            record.level(),
            record.target(),
            record.args()
        );
        // A poisoned lock only means another thread panicked mid-write; keep logging.
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        // Diagnostics are best effort: a closed stderr must not turn into an error.
        let _ = match sink.as_mut() {
            Some(w) => w.write_all(line.as_bytes()),
            None => std::io::stderr().write_all(line.as_bytes()),
        };
    }

    fn flush(&self) {
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = match sink.as_mut() {
            Some(w) => w.flush(),
            None => std::io::stderr().flush(),
        };
    }
}

/// Installs the stderr logger: Normal = warn, Verbose = info, Debug = debug.
/// Idempotent (tests call it repeatedly).
pub fn init(verbosity: Verbosity) {
    install(verbosity, None);
}

/// Test seam: like [`init`], but log lines go to `sink` instead of stderr.
pub fn init_with_sink(verbosity: Verbosity, sink: Box<dyn Write + Send>) {
    install(verbosity, Some(sink));
}

fn install(verbosity: Verbosity, sink: Option<Sink>) {
    // Fails only when a logger is already set: ours from an earlier call, which is fine.
    let _ = log::set_logger(&LOGGER);
    *LOGGER.sink.lock().unwrap_or_else(|e| e.into_inner()) = sink;
    log::set_max_level(verbosity.level());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    // One test for the global logger, so parallel tests cannot race on its level.
    #[test]
    fn levels_follow_verbosity_and_init_is_idempotent() {
        let buf = Buffer::default();

        init_with_sink(Verbosity::Normal, Box::new(buf.clone()));
        log::warn!(target: "t", "w1");
        log::info!(target: "t", "i1");
        log::debug!(target: "t", "d1");

        init_with_sink(Verbosity::Verbose, Box::new(buf.clone()));
        log::info!(target: "t", "i2");
        log::debug!(target: "t", "d2");

        init_with_sink(Verbosity::Debug, Box::new(buf.clone()));
        log::debug!(target: "t", "d3");
        log::logger().flush();

        // Other tests may log concurrently into the same global logger: keep only ours.
        let ours: Vec<String> = buf
            .text()
            .lines()
            .filter(|l| l.contains(" [t] "))
            .map(String::from)
            .collect();
        assert_eq!(ours, ["WARN [t] w1", "INFO [t] i2", "DEBUG [t] d3"]);

        // Back to stderr: must not panic.
        init(Verbosity::Normal);
        log::warn!(target: "t", "to stderr");
        log::logger().flush();
        assert_eq!(log::max_level(), log::LevelFilter::Warn);
    }
}
