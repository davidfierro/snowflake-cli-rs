//! Secrets never reach `--debug`/`--verbose` output (ADR 0001, Decision 7).
//!
//! The logger is process-global: the test holds `common::logger_guard`.

use snowflake_cli_rs::cli::{ConnectionOptions, GlobalOptions};
use snowflake_cli_rs::config::{ConfigPaths, ConfigSource, resolve_connection};
use snowflake_cli_rs::diag::{self, Verbosity};
use snowflake_cli_rs::env::Env;
use std::io::Write;
use std::sync::{Arc, Mutex};

const PEM: &str = "-----BEGIN PRIVATE KEY-----\nKEYMATERIAL-MARKER\n-----END PRIVATE KEY-----";
const MARKERS: [&str; 6] = [
    "KEYMATERIAL-MARKER",
    "FILE-PASS-MARKER",
    "ENV-PASS-MARKER",
    "CONN-ENV-PASS-MARKER",
    "PASSWORD-MARKER",
    "TOKEN-MARKER",
];

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

fn write_private(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn debug_and_verbose_logs_never_contain_key_material_or_passphrases() {
    let _log = crate::common::logger_guard();
    let home = tempfile::TempDir::new().unwrap();
    write_private(
        &home.path().join("config.toml"),
        &format!(
            "[connections.dev]\naccount = \"acct\"\nuser = \"usr\"\nauthenticator = \"SNOWFLAKE_JWT\"\n\
             private_key_raw = '''{PEM}'''\nprivate_key_passphrase = \"FILE-PASS-MARKER\"\n\
             password = \"PASSWORD-MARKER\"\nmaster_token = \"MASTER-MARKER\"\n\
             [connections.badport]\nport = \"KEYMATERIAL-MARKER\"\n\
             [cli]\noutput_format = \"json\"\n"
        ),
    );
    let env = Env::from_pairs([
        ("SNOWFLAKE_HOME", home.path().to_str().unwrap()),
        (
            "SNOWFLAKE_CONNECTIONS_DEV_PRIVATE_KEY_PASSPHRASE",
            "CONN-ENV-PASS-MARKER",
        ),
        ("SNOWFLAKE_CONNECTIONS_DEV_TOKEN", "TOKEN-MARKER"),
        ("SNOWFLAKE_PRIVATE_KEY_RAW", "KEYMATERIAL-MARKER"),
        ("PRIVATE_KEY_PASSPHRASE", "ENV-PASS-MARKER"),
    ]);

    for verbosity in [Verbosity::Verbose, Verbosity::Debug] {
        let buf = Buffer::default();
        diag::init_with_sink(verbosity, Box::new(buf.clone()));

        let paths = ConfigPaths::discover(&env, None).unwrap();
        let source = ConfigSource::load(&paths).unwrap();
        let options = ConnectionOptions {
            connection: Some("dev".into()),
            ..Default::default()
        };
        let conn = resolve_connection(&source, &options, &env).unwrap();
        assert_eq!(
            conn.private_key_passphrase.as_ref().unwrap().expose(),
            "ENV-PASS-MARKER"
        );
        assert!(
            conn.private_key_raw
                .as_ref()
                .unwrap()
                .expose()
                .contains("KEYMATERIAL-MARKER")
        );
        GlobalOptions::default()
            .output_format(&source, &env)
            .unwrap();

        // Everything a caller could log or print about the run.
        let bad = ConnectionOptions {
            connection: Some("badport".into()),
            ..Default::default()
        };
        let err = resolve_connection(&source, &bad, &env).unwrap_err();
        log::debug!("connection: {conn:?}");
        log::debug!("env: {env:?}");
        log::debug!("source: {source:?}");
        log::debug!("error: {err} / {err:?}");
        log::logger().flush();

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        for marker in MARKERS {
            assert!(
                !out.contains(marker),
                "{marker} leaked at {verbosity:?}:\n{out}"
            );
        }
        // The logs did run: the unsupported keys are named (names only).
        assert!(
            out.contains("Ignoring unsupported connection key 'master_token' in connection 'dev'")
        );
        assert_eq!(conn.password.as_ref().unwrap().expose(), "PASSWORD-MARKER");
        assert_eq!(conn.token.as_ref().unwrap().expose(), "TOKEN-MARKER");
        if verbosity == Verbosity::Debug {
            assert!(
                out.contains(
                    "Resolved token of connection 'dev' from SNOWFLAKE_CONNECTIONS_DEV_TOKEN"
                ),
                "{out}"
            );
            assert!(out.contains("Resolved private_key_passphrase of connection 'dev' from PRIVATE_KEY_PASSPHRASE"), "{out}");
            assert!(out.contains("Resolved private_key_raw of connection 'dev' from key 'private_key_raw' in the config file"), "{out}");
        }
    }
}
