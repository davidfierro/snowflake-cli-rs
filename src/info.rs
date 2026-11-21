//! `snow --info` and `snow --version`.

use crate::config::ConfigPaths;
use crate::env::Env;
use crate::error::Result;
use serde::Serialize;

/// The snow release this binary is compatible with.
pub const SNOW_VERSION: &str = "3.34.0";

/// `snow --version`.
pub fn version_line() -> String {
    format!("Snowflake CLI version: {}\n", env!("CARGO_PKG_VERSION"))
}

#[derive(Serialize)]
struct Entry {
    key: &'static str,
    value: serde_json::Value,
}

/// `snow --info`: a JSON list of `{key, value}` (always JSON, as snow). It has snow's keys that
/// apply to a native binary; the Python ones (`python_version`, the connector version) are
/// replaced by `compatible_snow_version`.
pub fn info_json(env: &Env) -> Result<String> {
    let paths = ConfigPaths::discover(env, None)?;
    let text = |s: String| serde_json::Value::String(s);
    let entries = [
        Entry {
            key: "version",
            value: text(env!("CARGO_PKG_VERSION").into()),
        },
        Entry {
            key: "compatible_snow_version",
            value: text(SNOW_VERSION.into()),
        },
        Entry {
            key: "default_config_file_path",
            value: text(paths.config_file.display().to_string()),
        },
        Entry {
            key: "system_info",
            value: text(format!(
                "{}-{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
        },
        Entry {
            key: "installation_source",
            value: text("native".into()),
        },
        Entry {
            key: "feature_flags",
            value: serde_json::json!({}),
        },
        Entry {
            key: "SNOWFLAKE_HOME",
            value: env
                .get("SNOWFLAKE_HOME")
                .map_or(serde_json::Value::Null, |h| text(h.to_string())),
        },
    ];
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    // Serializing plain values into a Vec cannot fail.
    if entries.serialize(&mut ser).is_err() {
        return Ok(String::new());
    }
    let mut text = String::from_utf8_lossy(&out).into_owned();
    text.push('\n');
    Ok(text)
}
