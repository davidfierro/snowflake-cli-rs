//! Connection resolution: snow's `resolve_connection_parameters` (ADR 0001, Decision 3).
//!
//! Precedence, highest first: CLI flags > `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` > the connection's
//! table in the file > `SNOWFLAKE_<KEY>` (only for keys still unset). `PRIVATE_KEY_PASSPHRASE`,
//! when set, replaces the passphrase from any layer.

use super::ConfigSource;
use super::paths::expand_user;
use crate::cli::ConnectionOptions;
use crate::connection::ConnectionConfig;
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Connection keys this CLI uses (canonical names, after aliases).
const SUPPORTED_KEYS: [&str; 33] = [
    "account",
    "user",
    "host",
    "port",
    "protocol",
    "authenticator",
    "private_key_file",
    "private_key_raw",
    "private_key_passphrase",
    "token",
    "token_file_path",
    "workload_identity_provider",
    "secondary_roles",
    "database",
    "schema",
    "role",
    "warehouse",
    "password",
    "passcode",
    "passcode_in_password",
    "oauth_client_id",
    "oauth_client_secret",
    "oauth_authorization_url",
    "oauth_token_request_url",
    "oauth_redirect_uri",
    "oauth_scope",
    "oauth_disable_pkce",
    "oauth_enable_refresh_tokens",
    "oauth_enable_single_use_refresh_tokens",
    "client_store_temporary_credential",
    "client_session_keep_alive",
    "client_session_keep_alive_heartbeat_frequency",
    "server_session_keep_alive",
];

/// Keys snow also reads from generic `SNOWFLAKE_<KEY>` variables (its `SUPPORTED_ENV_OVERRIDES`,
/// restricted to the keys this CLI uses), in snow's order: `SNOWFLAKE_PRIVATE_KEY_FILE` wins over
/// `SNOWFLAKE_PRIVATE_KEY_PATH`.
const GENERIC_ENV_KEYS: [&str; 29] = [
    "account",
    "user",
    "password",
    "host",
    "port",
    "protocol",
    "authenticator",
    "workload_identity_provider",
    "private_key_file",
    "private_key_path",
    "private_key_raw",
    "database",
    "schema",
    "role",
    "warehouse",
    "token",
    "token_file_path",
    "oauth_client_id",
    "oauth_client_secret",
    "oauth_authorization_url",
    "oauth_token_request_url",
    "oauth_redirect_uri",
    "oauth_scope",
    "oauth_disable_pkce",
    "oauth_enable_refresh_tokens",
    "oauth_enable_single_use_refresh_tokens",
    "client_store_temporary_credential",
    "secondary_roles",
    "server_session_keep_alive",
];

/// snow's `ApiFederatedAuthenticationType` values.
const WIF_PROVIDERS: [&str; 4] = ["AWS", "AZURE", "GCP", "OIDC"];

/// Where a value came from; used in debug logs and error messages (never the value itself).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    Flag,
    File,
    /// The full variable name.
    Env(String),
}

impl Origin {
    fn describe(&self, raw_key: &str) -> String {
        match self {
            Origin::Flag => format!("flag --{}", raw_key.replace('_', "-")),
            Origin::File => format!("key '{raw_key}' in the config file"),
            Origin::Env(var) => var.clone(),
        }
    }
}

#[derive(Debug, Clone)]
enum RawValue {
    Toml(toml::Value),
    Text(String),
    Path(PathBuf),
}

#[derive(Debug, Clone)]
struct Entry {
    raw_key: String,
    value: RawValue,
    origin: Origin,
}

/// Applies the precedence of Decision 3 and returns the connection B uses.
pub fn resolve_connection(
    source: &ConfigSource,
    options: &ConnectionOptions,
    env: &Env,
) -> Result<ConnectionConfig> {
    if options.temporary_connection && options.connection.is_some() {
        return Err(Error::new(
            ErrorKind::Usage,
            "Can't use connection name and temporary connection.",
        ));
    }
    if let Some(provider) = &options.workload_identity_provider
        && !WIF_PROVIDERS.contains(&provider.as_str())
    {
        // snow's option callback: the flag (not the config value) must be spelled exactly.
        return Err(Error::new(
            ErrorKind::Client,
            format!(
                "Invalid workload identity provider '{provider}'. Valid values are: {}",
                WIF_PROVIDERS.join(", ")
            ),
        ));
    }
    let name = if options.temporary_connection {
        None
    } else {
        Some(match &options.connection {
            Some(name) => name.clone(),
            None => {
                let name = source.default_connection_name(env);
                if source.connection(&name).is_none() {
                    return Err(Error::new(
                        ErrorKind::Client,
                        format!(
                            "Couldn't find connection for default connection `{name}`. Specify connection name or configure default connection."
                        ),
                    ));
                }
                name
            }
        })
    };
    let label = match &name {
        Some(name) => format!("connection '{name}'"),
        None => "the temporary connection".to_string(),
    };

    let mut params: BTreeMap<&'static str, Entry> = BTreeMap::new();
    if let Some(name) = &name {
        for entry in file_and_connection_env(source, name, env)? {
            let Some(key) = supported_key(&entry.raw_key) else {
                log::info!(
                    "Ignoring unsupported connection key '{}' in connection '{name}'",
                    entry.raw_key
                );
                continue;
            };
            params.insert(key, entry);
        }
    }

    for (key, value) in flag_values(options) {
        params.insert(
            key,
            Entry {
                raw_key: key.to_string(),
                value,
                origin: Origin::Flag,
            },
        );
    }

    for raw_key in GENERIC_ENV_KEYS {
        let Some(key) = supported_key(raw_key) else {
            continue;
        };
        let var = format!("SNOWFLAKE_{}", raw_key.to_ascii_uppercase());
        if params.contains_key(key) {
            continue;
        }
        if let Some(value) = env.get_non_empty(&var) {
            params.insert(
                key,
                Entry {
                    raw_key: raw_key.to_string(),
                    value: RawValue::Text(value.to_string()),
                    origin: Origin::Env(var),
                },
            );
        }
    }

    if let Some(passphrase) = env.get("PRIVATE_KEY_PASSPHRASE") {
        params.insert(
            "private_key_passphrase",
            Entry {
                raw_key: "private_key_passphrase".to_string(),
                value: RawValue::Text(passphrase.to_string()),
                origin: Origin::Env("PRIVATE_KEY_PASSPHRASE".to_string()),
            },
        );
    }

    for (key, entry) in &params {
        log::debug!(
            "Resolved {key} of {label} from {}",
            entry.origin.describe(&entry.raw_key)
        );
    }
    build(name, params, &label, env)
}

/// The connection's file table updated with its `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` variables,
/// in snow's order: a variable replaces the same raw key in place, new keys are appended, and
/// `private_key_path` is applied last so it wins over `private_key_file` (snow keeps it among the
/// "other" settings, which come after the known ones).
fn file_and_connection_env(source: &ConfigSource, name: &str, env: &Env) -> Result<Vec<Entry>> {
    let table = match source.connection(name) {
        Some(toml::Value::Table(table)) => table,
        Some(_) => {
            return Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Connection {name} is not a TOML table with key/value pairs (e.g. `[connections.{name}]`)."
                ),
            ));
        }
        None => {
            return Err(Error::new(
                ErrorKind::Client,
                format!("Connection {name} is not configured"),
            ));
        }
    };
    let mut entries: Vec<Entry> = table
        .iter()
        .map(|(k, v)| Entry {
            raw_key: k.clone(),
            value: RawValue::Toml(v.clone()),
            origin: Origin::File,
        })
        .collect();

    let prefix = format!("SNOWFLAKE_CONNECTIONS_{}_", name.to_uppercase());
    for (suffix, value) in env.with_prefix(&prefix) {
        let entry = Entry {
            raw_key: suffix.to_lowercase(),
            value: RawValue::Text(value.to_string()),
            origin: Origin::Env(format!("{prefix}{suffix}")),
        };
        match entries.iter_mut().find(|e| e.raw_key == entry.raw_key) {
            Some(existing) => *existing = entry,
            None => entries.push(entry),
        }
    }

    entries.sort_by_key(|e| e.raw_key == "private_key_path");
    Ok(entries)
}

/// The canonical stage-0 key for `raw_key`, or `None` when it is not supported.
fn supported_key(raw_key: &str) -> Option<&'static str> {
    let key = match raw_key {
        "private_key_path" => "private_key_file",
        "private_key_file_pwd" => "private_key_passphrase",
        other => other,
    };
    SUPPORTED_KEYS.iter().copied().find(|k| *k == key)
}

fn flag_values(options: &ConnectionOptions) -> Vec<(&'static str, RawValue)> {
    let text = |key, value: &Option<String>| value.clone().map(|v| (key, RawValue::Text(v)));
    let secret = |key, value: &Option<Secret>| {
        value
            .as_ref()
            .map(|v| (key, RawValue::Text(v.expose().to_string())))
    };
    // A click flag left out is `None`, so the connection's value stays.
    let flag = |key, on: bool| on.then(|| (key, RawValue::Toml(toml::Value::Boolean(true))));
    [
        text("account", &options.account),
        text("user", &options.user),
        text("host", &options.host),
        options
            .port
            .map(|p| ("port", RawValue::Text(p.to_string()))),
        text("authenticator", &options.authenticator),
        text(
            "workload_identity_provider",
            &options.workload_identity_provider,
        ),
        options
            .private_key_file
            .clone()
            .map(|p| ("private_key_file", RawValue::Path(p))),
        text("database", &options.database),
        text("schema", &options.schema),
        text("role", &options.role),
        text("warehouse", &options.warehouse),
        options
            .token
            .as_ref()
            .map(|t| ("token", RawValue::Text(t.expose().to_string()))),
        options
            .token_file_path
            .clone()
            .map(|p| ("token_file_path", RawValue::Path(p))),
        text("secondary_roles", &options.secondary_roles),
        secret("password", &options.password),
        // `--mfa-passcode` without a value is prompted for by the command, before resolution.
        secret(
            "passcode",
            &options.mfa_passcode.clone().unwrap_or_default(),
        ),
        text("protocol", &options.protocol),
        text("oauth_client_id", &options.oauth_client_id),
        secret("oauth_client_secret", &options.oauth_client_secret),
        text("oauth_authorization_url", &options.oauth_authorization_url),
        text("oauth_token_request_url", &options.oauth_token_request_url),
        text("oauth_redirect_uri", &options.oauth_redirect_uri),
        text("oauth_scope", &options.oauth_scope),
        flag("oauth_disable_pkce", options.oauth_disable_pkce),
        flag(
            "oauth_enable_refresh_tokens",
            options.oauth_enable_refresh_tokens,
        ),
        flag(
            "oauth_enable_single_use_refresh_tokens",
            options.oauth_enable_single_use_refresh_tokens,
        ),
        flag(
            "client_store_temporary_credential",
            options.client_store_temporary_credential,
        ),
        flag(
            "server_session_keep_alive",
            options.server_session_keep_alive,
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn build(
    name: Option<String>,
    mut params: BTreeMap<&'static str, Entry>,
    label: &str,
    env: &Env,
) -> Result<ConnectionConfig> {
    let mut text = |key: &str| -> Result<Option<String>> {
        params
            .remove(key)
            .map(|entry| entry_text(entry, label))
            .transpose()
    };
    let account = text("account")?;
    let user = text("user")?;
    let host = text("host")?;
    let protocol = text("protocol")?;
    let authenticator = text("authenticator")?;
    let private_key_raw = text("private_key_raw")?.map(Secret::new);
    let private_key_passphrase = text("private_key_passphrase")?.map(Secret::new);
    let token = text("token")?.map(Secret::new);
    let token_file_path = text("token_file_path")?.map(PathBuf::from);
    let workload_identity_provider = text("workload_identity_provider")?;
    let secondary_roles = text("secondary_roles")?;
    let database = text("database")?;
    let schema = text("schema")?;
    let role = text("role")?;
    let warehouse = text("warehouse")?;
    let password = text("password")?.map(Secret::new);
    let passcode = text("passcode")?.map(Secret::new);
    let oauth_client_id = text("oauth_client_id")?;
    let oauth_client_secret = text("oauth_client_secret")?.map(Secret::new);
    let oauth_authorization_url = text("oauth_authorization_url")?;
    let oauth_token_request_url = text("oauth_token_request_url")?;
    let oauth_redirect_uri = text("oauth_redirect_uri")?;
    let oauth_scope = text("oauth_scope")?;
    let mut boolean = |key: &str| -> Result<Option<bool>> {
        params
            .remove(key)
            .map(|entry| entry_bool(entry, label))
            .transpose()
    };
    let passcode_in_password = boolean("passcode_in_password")?;
    let oauth_disable_pkce = boolean("oauth_disable_pkce")?;
    let oauth_enable_refresh_tokens = boolean("oauth_enable_refresh_tokens")?;
    let oauth_enable_single_use_refresh_tokens = boolean("oauth_enable_single_use_refresh_tokens")?;
    let client_store_temporary_credential = boolean("client_store_temporary_credential")?;
    let client_session_keep_alive = boolean("client_session_keep_alive")?;
    let server_session_keep_alive = boolean("server_session_keep_alive")?;
    let client_session_keep_alive_heartbeat_frequency = params
        .remove("client_session_keep_alive_heartbeat_frequency")
        .map(|entry| parse_seconds(entry, label))
        .transpose()?;
    let port = params
        .remove("port")
        .map(|entry| parse_port(entry, label))
        .transpose()?;
    let private_key_file = params
        .remove("private_key_file")
        .map(|entry| key_file_path(entry, label, env))
        .transpose()?;
    Ok(ConnectionConfig {
        name,
        account,
        user,
        host,
        port,
        protocol,
        authenticator,
        private_key_file,
        private_key_raw,
        private_key_passphrase,
        token,
        token_file_path,
        workload_identity_provider,
        secondary_roles,
        database,
        schema,
        role,
        warehouse,
        password,
        passcode,
        passcode_in_password,
        oauth_client_id,
        oauth_client_secret,
        oauth_authorization_url,
        oauth_token_request_url,
        oauth_redirect_uri,
        oauth_scope,
        oauth_disable_pkce,
        oauth_enable_refresh_tokens,
        oauth_enable_single_use_refresh_tokens,
        client_store_temporary_credential,
        client_session_keep_alive,
        client_session_keep_alive_heartbeat_frequency,
        server_session_keep_alive,
    })
}

/// A boolean key: a TOML boolean, or snow's `try_cast_to_bool` spellings (`true`/`false`/`1`/`0`,
/// any case) from a string or an integer. Anything else is rejected naming the key, never the
/// value.
fn entry_bool(entry: Entry, label: &str) -> Result<bool> {
    let what = entry.origin.describe(&entry.raw_key);
    if let RawValue::Toml(toml::Value::Boolean(b)) = entry.value {
        return Ok(b);
    }
    let text = entry_text(entry, label).unwrap_or_default();
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(Error::new(
            ErrorKind::Client,
            format!("Invalid value for {what} of {label}: expected a boolean."),
        )),
    }
}

/// A whole number of seconds (`client_session_keep_alive_heartbeat_frequency`).
fn parse_seconds(entry: Entry, label: &str) -> Result<u64> {
    let what = entry.origin.describe(&entry.raw_key);
    entry_text(entry, label)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                format!("Invalid value for {what} of {label}: expected a number of seconds."),
            )
        })
}

/// The value as text. TOML integers are accepted (as snow, which passes them on); other TOML
/// types are rejected naming the key and its origin, never the value.
fn entry_text(entry: Entry, label: &str) -> Result<String> {
    match entry.value {
        RawValue::Text(s) | RawValue::Toml(toml::Value::String(s)) => Ok(s),
        RawValue::Toml(toml::Value::Integer(i)) => Ok(i.to_string()),
        RawValue::Path(p) => Ok(p.to_string_lossy().into_owned()),
        RawValue::Toml(_) => Err(Error::new(
            ErrorKind::Client,
            format!(
                "Invalid value for {} of {label}: expected a string.",
                entry.origin.describe(&entry.raw_key)
            ),
        )),
    }
}

fn parse_port(entry: Entry, label: &str) -> Result<u16> {
    let what = entry.origin.describe(&entry.raw_key);
    let invalid = || {
        Error::new(
            ErrorKind::Client,
            format!("Invalid port in {what} of {label}: expected an integer from 0 to 65535."),
        )
    };
    entry_text(entry, label)
        .map_err(|_| invalid())?
        .trim()
        .parse::<u16>()
        .map_err(|_| invalid())
}

/// snow opens the key with `os.path.expanduser`; B never reads env, so `~` is expanded here.
fn key_file_path(entry: Entry, label: &str, env: &Env) -> Result<PathBuf> {
    let path = match entry.value {
        RawValue::Path(path) => path,
        _ => PathBuf::from(entry_text(entry, label)?),
    };
    match path.to_str() {
        Some(s) if s.starts_with('~') => expand_user(s, env),
        _ => Ok(path),
    }
}

#[cfg(test)]
mod tests;
