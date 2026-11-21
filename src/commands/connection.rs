//! `snow connection`: add, list, remove, set-default, test, generate-jwt,
//! generate-workload-identity-token (snow 3.34.0).

use super::Context;
use crate::auth::wif::{self, Attester, AwsToken, Endpoints, Provider, WifError};
use crate::auth::{
    Authenticator, Credential, KeyPairAuthenticator, Method, TokenAuthenticator,
    is_missing_passphrase, token,
};
use crate::cli::{ConnectionOptions, GlobalOptions};
use crate::config::{ConfigPaths, ConfigSource, ConfigValue, ConfigWriter, resolve_connection};
use crate::connection::ConnectionConfig;
use crate::diagnostics::connector::ConnectorDiag;
use crate::diagnostics::net::{Network, SystemNetwork};
use crate::diagnostics::{DiagOptions, Query, snow};
use crate::error::{Error, ErrorKind, Result};
use crate::output::format::OutputFormat;
use crate::output::result::{CommandResult, Field};
use crate::secret::Secret;
use crate::sql::executor::SignInIo;
use crate::sql::{ClientOptions, Executor, RunNeeds, ScriptOptions};
use clap::{ArgAction, Args, Subcommand};
use std::path::PathBuf;

/// `snow connection`.
#[derive(Debug, Args)]
#[command(
    about = "Manages connections to Snowflake.",
    arg_required_else_help = true
)]
pub struct ConnectionArgs {
    #[command(subcommand)]
    pub command: ConnectionCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConnectionCommand {
    /// Adds a connection to configuration file.
    Add(Box<AddArgs>),
    /// Lists configured connections.
    List(ListArgs),
    /// Removes a connection from configuration file.
    Remove(RemoveArgs),
    /// Changes default connection to provided value.
    SetDefault(SetDefaultArgs),
    /// Tests the connection to Snowflake.
    Test(TestArgs),
    /// Generate a JWT token, which will be printed out and displayed..
    GenerateJwt(GenerateJwtArgs),
    /// Generate a workload identity token for authenticating to Snowflake via a Workload Identity
    /// Federation (WIF) provider (AWS, AZURE, GCP, or OIDC). The token is printed to stdout.
    GenerateWorkloadIdentityToken(GenerateJwtArgs),
}

fn secret_parser(value: &str) -> std::result::Result<Secret, String> {
    Ok(Secret::new(value))
}

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct AddArgs {
    /// Name of the new connection.
    #[arg(short = 'n', long)]
    pub connection_name: Option<String>,
    /// Account name to use when authenticating with Snowflake.
    #[arg(short = 'a', long, visible_alias = "accountname")]
    pub account: Option<String>,
    /// Username to connect to Snowflake.
    #[arg(short = 'u', long, visible_alias = "username")]
    pub user: Option<String>,
    /// Snowflake password.
    #[arg(short = 'p', long, value_parser = secret_parser)]
    pub password: Option<Secret>,
    /// Role to use on Snowflake.
    #[arg(short = 'r', long, visible_alias = "rolename")]
    pub role: Option<String>,
    /// Warehouse to use on Snowflake.
    #[arg(short = 'w', long)]
    pub warehouse: Option<String>,
    /// Database to use on Snowflake.
    #[arg(short = 'd', long, visible_alias = "dbname")]
    pub database: Option<String>,
    /// Schema to use on Snowflake.
    #[arg(short = 's', long, visible_alias = "schemaname")]
    pub schema: Option<String>,
    /// Host name the connection attempts to connect to Snowflake.
    #[arg(short = 'h', long)]
    pub host: Option<String>,
    /// Port to communicate with on the host.
    #[arg(short = 'P', long)]
    pub port: Option<i64>,
    /// Protocol to use for the connection, for example `https`.
    #[arg(long)]
    pub protocol: Option<String>,
    /// Region name if not the default Snowflake deployment.
    #[arg(short = 'R', long)]
    pub region: Option<String>,
    /// Chosen authenticator, if other than password-based
    #[arg(short = 'A', long)]
    pub authenticator: Option<String>,
    /// Workload identity provider type
    #[arg(short = 'W', long)]
    pub workload_identity_provider: Option<String>,
    /// Path to file containing private key
    #[arg(short = 'k', long, visible_aliases = ["private-key", "private-key-path"])]
    pub private_key_file: Option<String>,
    /// Path to file with an OAuth token that should be used when connecting to Snowflake
    #[arg(short = 't', long)]
    pub token_file_path: Option<String>,
    /// Secondary roles mode applied when the session starts. Supported values are `ALL` and
    /// `NONE`; pass `NONE` to run the session only with the primary role.
    #[arg(long)]
    pub secondary_roles: Option<String>,
    /// Enable server-side session keep-alive to prevent the session from timing out during long
    /// operations.
    #[arg(long)]
    pub server_session_keep_alive: bool,
    /// Store the temporary credential.
    #[arg(long)]
    pub client_store_temporary_credential: bool,
    /// If provided the connection will be configured as default connection.
    #[arg(long = "default")]
    pub set_as_default: bool,
    /// Disable prompting.
    #[arg(long)]
    pub no_interactive: bool,
    /// Show this message and exit.
    #[arg(long, action = ArgAction::Help)]
    pub help: Option<bool>,
    #[command(flatten)]
    pub global: GlobalOptions,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Include connections from all sources (environment variables, SnowSQL config). By default,
    /// only shows connections from configuration files.
    #[arg(short = 'a', long = "all")]
    pub all_sources: bool,
    #[command(flatten)]
    pub global: GlobalOptions,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Name of the connection to remove.
    pub connection_name: String,
    #[command(flatten)]
    pub global: GlobalOptions,
}

#[derive(Debug, Args)]
pub struct SetDefaultArgs {
    /// Name of the connection, as defined in your `config.toml` file
    pub name: String,
    #[command(flatten)]
    pub global: GlobalOptions,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Print the full per-endpoint diagnostic to stdout. Without this flag, `--enable-diag`
    /// writes that diagnostic only to the report file.
    #[arg(long)]
    pub print_diag: bool,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[command(flatten)]
    pub global: GlobalOptions,
}

#[derive(Debug, Args)]
pub struct GenerateJwtArgs {
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[command(flatten)]
    pub global: GlobalOptions,
}

impl ConnectionCommand {
    pub fn global(&self) -> &GlobalOptions {
        match self {
            ConnectionCommand::Add(a) => &a.global,
            ConnectionCommand::List(a) => &a.global,
            ConnectionCommand::Remove(a) => &a.global,
            ConnectionCommand::SetDefault(a) => &a.global,
            ConnectionCommand::Test(a) => &a.global,
            ConnectionCommand::GenerateJwt(a)
            | ConnectionCommand::GenerateWorkloadIdentityToken(a) => &a.global,
        }
    }

    /// Runs the command on the real network.
    pub fn run(
        &self,
        paths: &ConfigPaths,
        source: &ConfigSource,
        format: OutputFormat,
        ctx: &mut Context<'_>,
    ) -> Result<CommandResult> {
        let net = SystemNetwork::new(&ctx.env);
        self.run_with_network(paths, source, format, &net, ctx)
    }

    /// Runs the command; `net` is what the connection diagnostics probe with.
    pub fn run_with_network(
        &self,
        paths: &ConfigPaths,
        source: &ConfigSource,
        format: OutputFormat,
        net: &dyn Network,
        ctx: &mut Context<'_>,
    ) -> Result<CommandResult> {
        match self {
            ConnectionCommand::Add(args) => add(args, paths, source, ctx),
            ConnectionCommand::List(args) => Ok(list(args, paths, source, format, ctx)),
            ConnectionCommand::Remove(args) => remove(args, paths, source, ctx),
            ConnectionCommand::SetDefault(args) => set_default(args, paths, source),
            ConnectionCommand::Test(args) => test(args, source, format, net, ctx),
            ConnectionCommand::GenerateJwt(args) => generate_jwt(&args.connection, source, ctx),
            ConnectionCommand::GenerateWorkloadIdentityToken(args) => {
                generate_workload_identity_token(&args.connection, source, ctx)
            }
        }
    }
}

// ---------------------------------------------------------------- add

const PASSWORD_WARNING: &str =
    "WARNING! Using --password via the CLI is insecure. Use environment variables instead.";

/// The values `add` may prompt for. The port is kept as typed until all prompts are done, so
/// an invalid one is reported after them.
struct Answers {
    connection_name: Option<String>,
    account: Option<String>,
    user: Option<String>,
    password: Option<String>,
    role: Option<String>,
    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,
    host: Option<String>,
    port: Option<Port>,
    protocol: Option<String>,
    region: Option<String>,
    authenticator: Option<String>,
    workload_identity_provider: Option<String>,
    private_key_file: Option<String>,
    token_file_path: Option<String>,
    secondary_roles: Option<String>,
}

/// The port from `--port`, or what was typed at its prompt.
enum Port {
    Given(i64),
    Typed(String),
}

impl Answers {
    fn from_args(args: &AddArgs) -> Self {
        Self {
            connection_name: args.connection_name.clone(),
            account: args.account.clone(),
            user: args.user.clone(),
            password: args.password.as_ref().map(|p| p.expose().to_string()),
            role: args.role.clone(),
            warehouse: args.warehouse.clone(),
            database: args.database.clone(),
            schema: args.schema.clone(),
            host: args.host.clone(),
            port: args.port.map(Port::Given),
            protocol: args.protocol.clone(),
            region: args.region.clone(),
            authenticator: args.authenticator.clone(),
            workload_identity_provider: args.workload_identity_provider.clone(),
            private_key_file: args.private_key_file.clone(),
            token_file_path: args.token_file_path.clone(),
            secondary_roles: args.secondary_roles.clone(),
        }
    }

    /// Prompts for every value the command line did not give, in snow's prompt order.
    fn prompt_missing(&mut self, ctx: &mut Context<'_>) -> Result<()> {
        fn ask(
            ctx: &mut Context<'_>,
            key: &str,
            slot: &mut Option<String>,
            secret: bool,
        ) -> Result<()> {
            if slot.is_none() {
                let label = format!("Enter {}: ", key.replace('_', " "));
                let answer = ctx.prompter.prompt(&label, secret)?;
                // snow trims every answer; a secret is kept exactly as typed.
                let answer = if secret {
                    answer
                } else {
                    answer.trim().to_string()
                };
                *slot = Some(answer).filter(|a| !a.is_empty());
            }
            Ok(())
        }
        ask(ctx, "connection_name", &mut self.connection_name, false)?;
        ask(ctx, "account", &mut self.account, false)?;
        ask(ctx, "user", &mut self.user, false)?;
        ask(ctx, "password", &mut self.password, true)?;
        ask(ctx, "role", &mut self.role, false)?;
        ask(ctx, "warehouse", &mut self.warehouse, false)?;
        ask(ctx, "database", &mut self.database, false)?;
        ask(ctx, "schema", &mut self.schema, false)?;
        ask(ctx, "host", &mut self.host, false)?;
        if self.port.is_none() {
            let mut typed = None;
            ask(ctx, "port", &mut typed, false)?;
            self.port = typed.map(Port::Typed);
        }
        ask(ctx, "protocol", &mut self.protocol, false)?;
        ask(ctx, "region", &mut self.region, false)?;
        ask(ctx, "authenticator", &mut self.authenticator, false)?;
        ask(
            ctx,
            "workload_identity_provider",
            &mut self.workload_identity_provider,
            false,
        )?;
        ask(ctx, "private_key_file", &mut self.private_key_file, false)?;
        ask(ctx, "token_file_path", &mut self.token_file_path, false)?;
        ask(ctx, "secondary_roles", &mut self.secondary_roles, false)
    }

    /// The port as a number: `--port` is one already; a typed one must parse.
    fn port(&self) -> Result<Option<i64>> {
        match &self.port {
            None => Ok(None),
            Some(Port::Given(port)) => Ok(Some(*port)),
            Some(Port::Typed(text)) => text.trim().parse::<i64>().map(Some).map_err(|_| {
                Error::new(
                    ErrorKind::Usage,
                    format!("Invalid value for '-P' / '--port': '{text}' is not a valid integer."),
                )
            }),
        }
    }
}

fn add(
    args: &AddArgs,
    paths: &ConfigPaths,
    source: &ConfigSource,
    ctx: &mut Context<'_>,
) -> Result<CommandResult> {
    if args.password.is_some() {
        // snow prints this warning on stdout (ADR 0003). A failing write is not worth failing the
        // command.
        let _ = writeln!(ctx.stdout, "{PASSWORD_WARNING}");
    }
    let mut answers = Answers::from_args(args);
    if !args.no_interactive && ctx.stdin_is_tty {
        answers.prompt_missing(ctx)?;
    }
    let port = answers.port()?;
    for path in [&answers.private_key_file, &answers.token_file_path]
        .into_iter()
        .flatten()
    {
        if !std::path::Path::new(path).exists() {
            return Err(Error::new(
                ErrorKind::Usage,
                format!("Path {path} does not exist."),
            ));
        }
    }
    let name = answers.connection_name.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::Usage,
            "Missing option '--connection-name' / '-n'.",
        )
    })?;
    if source.connection_names().contains(&name) {
        return Err(Error::new(
            ErrorKind::Usage,
            format!("Connection {name} already exists"),
        ));
    }

    // The order of snow's `ConnectionConfig` fields.
    let text = |key: &'static str, value: &Option<String>| {
        value.clone().map(|v| (key, ConfigValue::Str(v)))
    };
    let flag = |key: &'static str, on: bool| on.then_some((key, ConfigValue::Bool(true)));
    let entries: Vec<(&str, ConfigValue)> = [
        text("account", &answers.account),
        text("user", &answers.user),
        text("password", &answers.password),
        text("host", &answers.host),
        text("region", &answers.region),
        port.map(|p| ("port", ConfigValue::Int(p))),
        text("protocol", &answers.protocol),
        text("database", &answers.database),
        text("schema", &answers.schema),
        text("warehouse", &answers.warehouse),
        text("role", &answers.role),
        text("authenticator", &answers.authenticator),
        text(
            "workload_identity_provider",
            &answers.workload_identity_provider,
        ),
        text("private_key_file", &answers.private_key_file),
        text("token_file_path", &answers.token_file_path),
        flag(
            "client_store_temporary_credential",
            args.client_store_temporary_credential,
        ),
        text("secondary_roles", &answers.secondary_roles),
        flag("server_session_keep_alive", args.server_session_keep_alive),
    ]
    .into_iter()
    .flatten()
    .collect();

    let writer = ConfigWriter::new(paths);
    let file = writer.add_connection(&name, &entries)?;
    if args.set_as_default {
        writer.set_default_connection(&name)?;
    }
    Ok(CommandResult::Message(format!(
        "Wrote new connection {name} to {}",
        file.display()
    )))
}

// ---------------------------------------------------------------- list

/// The keys snow's `ConnectionConfig` knows, in its field order. Others are not listed.
const KNOWN_KEYS: [&str; 32] = [
    "account",
    "user",
    "password",
    "host",
    "region",
    "port",
    "protocol",
    "database",
    "schema",
    "warehouse",
    "role",
    "authenticator",
    "workload_identity_provider",
    "private_key_file",
    "private_key_raw",
    "private_key_passphrase",
    "token",
    "session_token",
    "master_token",
    "token_file_path",
    "oauth_client_id",
    "oauth_client_secret",
    "oauth_authorization_url",
    "oauth_token_request_url",
    "oauth_redirect_uri",
    "oauth_scope",
    "oauth_enable_pkce",
    "oauth_enable_refresh_tokens",
    "oauth_enable_single_use_refresh_tokens",
    "client_store_temporary_credential",
    "secondary_roles",
    "server_session_keep_alive",
];

const ENV_PREFIX: &str = "SNOWFLAKE_CONNECTIONS_";

fn list(
    args: &ListArgs,
    paths: &ConfigPaths,
    source: &ConfigSource,
    format: OutputFormat,
    ctx: &mut Context<'_>,
) -> CommandResult {
    let default = source.default_connection_name(&ctx.env);
    let mut connections: Vec<(String, Vec<(String, Field)>)> = Vec::new();
    for name in source.connection_names() {
        let mut raw: Vec<(String, Field)> = source
            .connection(&name)
            .and_then(toml::Value::as_table)
            .map(|t| t.iter().map(|(k, v)| (k.clone(), field(v))).collect())
            .unwrap_or_default();
        // `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` overrides the file.
        let prefix = format!("{ENV_PREFIX}{}_", name.to_uppercase());
        for (key, value) in ctx.env.with_prefix(&prefix) {
            set(&mut raw, &key.to_lowercase(), Field::str(value));
        }
        connections.push((name, raw));
    }
    if args.all_sources {
        for (name, key, value) in env_only_entries(&ctx.env) {
            if !source.connection_names().contains(&name) {
                match connections.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, raw)) => set(raw, &key, Field::str(value)),
                    None => connections.push((name, vec![(key, Field::str(value))])),
                }
            }
        }
    }
    // Intermediate output is muted for JSON, JSON_EXT and CSV, as in snow.
    let muted = format.is_json() || format == OutputFormat::Csv;
    if paths.connections_file.exists() && !muted && !args.global.silent {
        let _ = writeln!(
            ctx.stdout,
            "Reading connections from {}. Entries from config.toml are ignored.",
            paths.connections_file.display()
        );
    }
    CommandResult::Collection(
        connections
            .into_iter()
            .map(|(name, raw)| {
                vec![
                    ("connection_name".to_string(), Field::str(name.as_str())),
                    ("parameters".to_string(), Field::Map(known_masked(raw))),
                    ("is_default".to_string(), Field::Bool(name == default)),
                ]
            })
            .collect(),
    )
}

fn set(raw: &mut Vec<(String, Field)>, key: &str, value: Field) {
    match raw.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) => *v = value,
        None => raw.push((key.to_string(), value)),
    }
}

fn field(value: &toml::Value) -> Field {
    match value {
        toml::Value::String(s) => Field::str(s.as_str()),
        toml::Value::Integer(i) => Field::Int(*i),
        toml::Value::Boolean(b) => Field::Bool(*b),
        other => Field::str(other.to_string()),
    }
}

/// `(name, key, value)` of the `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` variables, `<KEY>` being one
/// of snow's connection keys (the longest match, since both parts may contain `_`).
fn env_only_entries(env: &crate::env::Env) -> Vec<(String, String, String)> {
    env.with_prefix(ENV_PREFIX)
        .filter_map(|(rest, value)| {
            let rest = rest.to_lowercase();
            KNOWN_KEYS
                .iter()
                .chain(&["private_key_file_pwd"])
                .filter(|key| {
                    rest.strip_suffix(*key)
                        .is_some_and(|n| n.ends_with('_') && n.len() > 1)
                })
                .max_by_key(|key| key.len())
                .map(|key| {
                    let name = &rest[..rest.len() - key.len() - 1];
                    (name.to_string(), (*key).to_string(), value.to_string())
                })
        })
        .collect()
}

/// Known, non-empty keys in snow's field order, `private_key_file_pwd` normalized, sensitive
/// values masked.
fn known_masked(raw: Vec<(String, Field)>) -> Vec<(String, Field)> {
    let canonical = |key: &str| {
        if key == "private_key_file_pwd" {
            "private_key_passphrase".to_string()
        } else {
            key.to_string()
        }
    };
    KNOWN_KEYS
        .iter()
        .filter_map(|&key| {
            let value = raw
                .iter()
                .rev()
                .find(|(k, _)| canonical(k) == key)
                .map(|(_, v)| v.clone())?;
            let value = if should_mask(key) {
                Field::str("****")
            } else {
                value
            };
            Some((key.to_string(), value))
        })
        .collect()
}

/// snow's `should_mask_value`: key paths are not secrets, anything that looks like a credential
/// is.
fn should_mask(key: &str) -> bool {
    const PATHS: [&str; 3] = ["private_key_file", "private_key_path", "token_file_path"];
    const SENSITIVE: [&str; 10] = [
        "password",
        "pwd",
        "oauth_client_secret",
        "token",
        "session_token",
        "master_token",
        "mfa_passcode",
        "private_key",
        "passphrase",
        "secret",
    ];
    !PATHS.iter().any(|p| key.contains(p)) && SENSITIVE.iter().any(|s| key.contains(s))
}

// ------------------------------------------------- remove, set-default

fn remove(
    args: &RemoveArgs,
    paths: &ConfigPaths,
    source: &ConfigSource,
    ctx: &mut Context<'_>,
) -> Result<CommandResult> {
    let name = &args.connection_name;
    if !source.connection_names().contains(name) {
        return Err(Error::new(
            ErrorKind::Usage,
            format!("Connection {name} does not exist."),
        ));
    }
    let writer = ConfigWriter::new(paths);
    // As snow: the env override counts (verified against snow 3.34.0).
    let is_default = source.default_connection_name(&ctx.env) == *name;
    let file = writer.remove_connection(name, is_default)?;
    let note = if is_default {
        " It was the default connection, so default connection is now unset."
    } else {
        ""
    };
    Ok(CommandResult::Message(format!(
        "Removed connection {name} from {}.{note}",
        file.display()
    )))
}

fn set_default(
    args: &SetDefaultArgs,
    paths: &ConfigPaths,
    source: &ConfigSource,
) -> Result<CommandResult> {
    if !source.connection_names().contains(&args.name) {
        return Err(Error::new(
            ErrorKind::Client,
            format!("Connection {} is not configured", args.name),
        ));
    }
    ConfigWriter::new(paths).set_default_connection(&args.name)?;
    Ok(CommandResult::Message(format!(
        "Default connection set to: {}",
        args.name
    )))
}

// ------------------------------------------------ test, generate-jwt

/// How `conn` signs in ([`Method::of`]): a bearer credential the SQL API takes, or a connector
/// flow that needs a session. Asks for the passphrase of an encrypted key on a terminal.
pub(crate) fn credential(conn: &ConnectionConfig, ctx: &mut Context<'_>) -> Result<Credential> {
    let bearer: Box<dyn Authenticator> = match Method::of(conn)? {
        Method::KeyPair => Box::new(key_pair(conn.clone(), ctx)?),
        Method::OAuth => Box::new(TokenAuthenticator::from_connection(conn, token::OAUTH)?),
        Method::ProgrammaticAccessToken => Box::new(TokenAuthenticator::from_connection(
            conn,
            token::PROGRAMMATIC_ACCESS_TOKEN,
        )?),
        Method::WorkloadIdentity => {
            let host = crate::sql::client::host(conn)?;
            let attester = Attester::new(&ctx.env, Endpoints::default());
            Box::new(wif::authenticator(conn, &host, &attester)?)
        }
        Method::Password
        | Method::UsernamePasswordMfa
        | Method::ExternalBrowser
        | Method::Okta
        | Method::OAuthAuthorizationCode
        | Method::OAuthClientCredentials => return Ok(Credential::Connector),
    };
    Ok(Credential::Bearer(bearer))
}

/// The connection of a command that signs in: `snow`'s `--password` warning first, then the
/// `--mfa-passcode` prompt when the flag has no value (click's `prompt_required=False`).
pub(crate) fn resolve_for_sign_in(
    source: &ConfigSource,
    options: &ConnectionOptions,
    ctx: &mut Context<'_>,
) -> Result<ConnectionConfig> {
    if options.password.is_some() {
        // snow prints this warning on stdout. A failing write is not worth failing the command.
        let _ = writeln!(ctx.stdout, "{PASSWORD_WARNING}");
    }
    let mut conn = resolve_connection(source, options, &ctx.env)?;
    if matches!(options.mfa_passcode, Some(None)) {
        conn.passcode = Some(Secret::new(ctx.prompter.prompt("MFA passcode: ", false)?));
    }
    Ok(conn)
}

/// Signs in on the transport the run needs (ADR 0005, Decision 1), with the terminal, the
/// system browser and the file credential cache as the sign-in's seams.
pub(crate) fn connect(
    conn: &ConnectionConfig,
    needs: RunNeeds,
    options: ClientOptions,
    script: &ScriptOptions,
    transfer: crate::transfer::TransferOptions,
    ctx: &mut Context<'_>,
) -> Result<Executor> {
    let credential = credential(conn, ctx)?;
    let cache = crate::session::FileCache::from_env(&ctx.env);
    let session = crate::session::SessionOptions::default().with_connection(conn, &ctx.env);
    let prompt = crate::commands::PromptBridge::new(&mut *ctx.prompter, &mut *ctx.stderr);
    let io = SignInIo {
        prompt: &prompt,
        browser: &crate::session::SystemBrowser,
        cache: &cache,
        session,
    };
    Executor::connect(conn, needs, credential, options, script, transfer, &io)
}

/// `--secondary-roles` / `secondary_roles`: `ALL` or `NONE`, case-insensitive.
pub(crate) fn script_options(conn: &ConnectionConfig) -> Result<ScriptOptions> {
    let secondary_roles = match conn.secondary_roles.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) if value.eq_ignore_ascii_case("ALL") => Some("ALL"),
        Some(value) if value.eq_ignore_ascii_case("NONE") => Some("NONE"),
        Some(value) => {
            return Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Invalid secondary_roles value '{value}'. Supported values are ALL and NONE."
                ),
            ));
        }
    };
    Ok(ScriptOptions {
        secondary_roles,
        ..ScriptOptions::default()
    })
}

/// The key-pair authenticator of `conn`; asks for the passphrase of an encrypted key on a
/// terminal when none was given.
pub(crate) fn key_pair(
    mut conn: ConnectionConfig,
    ctx: &mut Context<'_>,
) -> Result<KeyPairAuthenticator> {
    match KeyPairAuthenticator::from_connection(&conn) {
        Err(err) if is_missing_passphrase(&err) && ctx.stdin_is_tty => {
            let answer = ctx.prompter.prompt(
                "Enter private key file password (press enter for empty): ",
                true,
            )?;
            conn.private_key_passphrase = Some(Secret::new(answer));
            KeyPairAuthenticator::from_connection(&conn)
        }
        other => other,
    }
}

/// `snow connection test`, with the diagnostics of `--enable-diag` and `--print-diag`.
fn test(
    args: &TestArgs,
    source: &ConfigSource,
    format: OutputFormat,
    net: &dyn Network,
    ctx: &mut Context<'_>,
) -> Result<CommandResult> {
    let options = &args.connection;
    let diag = DiagOptions::resolve(options)?;
    let conn = resolve_for_sign_in(source, options, ctx)?;
    let script = script_options(&conn)?;
    let transfer = crate::transfer::TransferOptions::new(None);
    let client = connect(
        &conn,
        RunNeeds::default(),
        ClientOptions::default(),
        &script,
        transfer,
        ctx,
    )?;
    // Progress lines: TABLE and PLAIN only, and not with `--silent`.
    let verbose_progress = args.print_diag
        && matches!(format, OutputFormat::Table | OutputFormat::Plain)
        && !args.global.silent;
    let mut say = |ctx: &mut Context<'_>, line: &str| {
        if verbose_progress {
            // Progress is best effort, like snow's console.
            let _ = writeln!(ctx.stdout, "{line}");
        }
    };
    let host = connection_host(&conn);

    if diag.enabled && args.print_diag {
        say(ctx, "Running connector connectivity probe...");
    }
    let mut connector = diag.enabled.then(|| {
        let mut d = ConnectorDiag::new(
            net,
            &ctx.env,
            conn.account.as_deref().unwrap_or_default(),
            &host,
            &diag.log_dir,
            diag.allowlist_path.clone(),
        );
        d.run_test();
        d
    });
    // The role, database, schema and warehouse travel with the statement: the server rejects
    // the ones that do not exist, as snow's `USE` statements do. Secondary roles, when set,
    // are applied first in the same session, as snow applies them at sign-in.
    let connected = client
        .run_script(&["SELECT 1".to_string()], &script)
        .and_then(|run| {
            for result in run {
                result?.into_result()?;
            }
            Ok(())
        });
    if let Some(d) = connector.as_mut() {
        d.run_post_test(connected.is_ok().then_some(&client as &dyn Query));
        let written = d.generate_report();
        // A failed sign-in is the error to show; a write failure only counts after a good one.
        connected?;
        written.map_err(|e| {
            Error::new(
                ErrorKind::Client,
                format!("Could not write the diagnostic report: {e}"),
            )
        })?;
    } else {
        connected?;
    }

    let set = |value: &Option<String>| match value.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => Field::str(v),
        None => Field::str("not set"),
    };
    let host = match conn.host.as_deref().filter(|h| !h.is_empty()) {
        Some(host) => Field::str(host),
        None => conn.account.as_deref().map_or(Field::Null, |account| {
            Field::str(format!("{account}.snowflakecomputing.com"))
        }),
    };
    let text = |value: &Option<String>| value.as_deref().map_or(Field::Null, Field::str);
    let mut summary: Vec<(String, Field)> = vec![
        ("Connection name".into(), text(&conn.name)),
        ("Status".into(), Field::str("OK")),
        ("Host".into(), host),
        ("Account".into(), text(&conn.account)),
        ("User".into(), text(&conn.user)),
        ("Role".into(), set(&conn.role)),
        ("Database".into(), set(&conn.database)),
        ("Warehouse".into(), set(&conn.warehouse)),
    ];
    if diag.enabled {
        summary.push((
            "Diag Report Location".into(),
            Field::str(diag.report_path().display().to_string()),
        ));
    }
    if !diag.enabled && !args.print_diag {
        let _ = client.close();
        return Ok(CommandResult::Object(summary));
    }
    let result = snow_diagnostic(
        args, &diag, &client, net, &conn, format, &mut say, ctx, summary,
    );
    let _ = client.close();
    result
}

fn generate_jwt(
    options: &ConnectionOptions,
    source: &ConfigSource,
    ctx: &mut Context<'_>,
) -> Result<CommandResult> {
    let mut conn = resolve_for_sign_in(source, options, ctx)?;
    let required = |value: &Option<String>, what: &str| match value.as_deref() {
        Some(v) if !v.is_empty() => Ok(()),
        _ => Err(Error::new(
            ErrorKind::Usage,
            format!(
                "{what} is not set in the connection context, but required for JWT generation."
            ),
        )),
    };
    required(&conn.user, "User")?;
    required(&conn.account, "Account")?;
    let key_file: Option<String> = conn
        .private_key_file
        .as_ref()
        .map(|p: &PathBuf| p.display().to_string());
    required(&key_file, "Private key file")?;
    // The key is the only input of a JWT: as in snow, the authenticator setting does not matter.
    conn.private_key_raw = None;
    let auth = key_pair(conn, ctx)?;
    let header = auth.authorization()?;
    Ok(CommandResult::Message(header.token.expose().to_string()))
}

/// The host the connector would dial: `host`, else `<account>.snowflakecomputing.com`.
fn connection_host(conn: &ConnectionConfig) -> String {
    match conn.host.as_deref().filter(|h| !h.is_empty()) {
        Some(host) => host.to_string(),
        None => format!(
            "{}.snowflakecomputing.com",
            conn.account.as_deref().unwrap_or_default()
        ),
    }
}

/// snow's `_connection_test_with_diag`: probe the allowlist endpoints, snapshot the network
/// policy, append both to the report and, with `--print-diag`, print them.
#[allow(clippy::too_many_arguments)] // one call site; a struct would only rename the arguments
fn snow_diagnostic(
    args: &TestArgs,
    diag: &DiagOptions,
    client: &Executor,
    net: &dyn Network,
    conn: &ConnectionConfig,
    format: OutputFormat,
    say: &mut dyn FnMut(&mut Context<'_>, &str),
    ctx: &mut Context<'_>,
    mut summary: Vec<(String, Field)>,
) -> Result<CommandResult> {
    use std::cell::RefCell;
    let print = args.print_diag;
    if print {
        say(ctx, "Fetching allowlist from Snowflake...");
    }
    // The callbacks run while `ctx` is lent out, so they collect lines first.
    let lines = RefCell::new(Vec::<String>::new());
    let progress = snow::Progress {
        on_start: print.then(|| {
            Box::new(|n: usize| {
                lines.borrow_mut().push(format!(
                    "Discovered {n} endpoint(s). Running diagnostics..."
                ));
            }) as Box<dyn FnMut(usize)>
        }),
        on_skip: print.then(|| {
            Box::new(|n: usize| {
                lines
                    .borrow_mut()
                    .push(format!("Skipping {n} non-resolvable pattern(s)."));
            }) as Box<dyn FnMut(usize)>
        }),
        on_check: print.then(|| {
            Box::new(|c: &snow::EndpointCheck| lines.borrow_mut().push(c.status_line()))
                as Box<dyn FnMut(&snow::EndpointCheck)>
        }),
    };
    let report = snow::run(
        net,
        client,
        diag.allowlist_path.as_deref(),
        &connection_host(conn),
        progress,
        snow::DEFAULT_TIMEOUT,
    )?;
    for line in lines.take() {
        say(ctx, &line);
    }
    if print {
        say(ctx, "Inspecting network policies...");
    }
    let policy = snow::collect_network_policy(client, conn.user.as_deref());
    if diag.enabled {
        snow::append_report(&diag.log_dir, &report, &policy)?;
    }
    if !print {
        return Ok(CommandResult::Object(summary));
    }
    match format {
        OutputFormat::Json | OutputFormat::JsonExt => {
            summary.push(("Diagnostic".into(), report.to_dict(&policy)));
            Ok(CommandResult::Object(summary))
        }
        OutputFormat::Csv => {
            summary.extend(report.csv_summary(&policy));
            Ok(CommandResult::Object(summary))
        }
        OutputFormat::Table | OutputFormat::Plain => {
            let mut results = vec![CommandResult::Object(summary)];
            let rows = report.tested_rows();
            if !rows.is_empty() {
                results.push(CommandResult::Collection(rows));
            }
            if policy.has_policy() {
                results.push(CommandResult::Object(policy.summary_object()));
                if !policy.rules.is_empty() {
                    results.push(CommandResult::Collection(
                        policy.rules.iter().map(snow::NetworkRule::to_row).collect(),
                    ));
                }
            } else if let Some(message) = policy.no_policy_message() {
                results.push(CommandResult::Message(message));
            }
            results.push(CommandResult::Message(report.summary_line()));
            Ok(CommandResult::Multiple(results))
        }
    }
}

fn generate_workload_identity_token(
    options: &ConnectionOptions,
    source: &ConfigSource,
    ctx: &mut Context<'_>,
) -> Result<CommandResult> {
    let conn = resolve_for_sign_in(source, options, ctx)?;
    let provider = conn
        .workload_identity_provider
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                "Workload identity provider is not set in the connection context, but required for workload identity token generation.",
            )
        })?;
    let provider = Provider::parse(provider).map_err(WifError::into_generate_error)?;
    let mut oidc_token = None;
    if provider == Provider::Oidc {
        // snow's order here: `token` first, then the file (stripped).
        oidc_token = Some(match (&conn.token, &conn.token_file_path) {
            (Some(t), _) if !t.expose().is_empty() => t.clone(),
            (_, Some(path)) => token::trimmed(&token::read_token_file(path)?),
            _ => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    "OIDC provider requires a token. Set --token-file-path or configure 'token' in the connection.",
                ));
            }
        });
    }
    // As the connector: the signed request, unless the outbound token is switched on.
    let aws = match ctx.env.get("SNOWFLAKE_ENABLE_AWS_WIF_OUTBOUND_TOKEN") {
        Some(v) if v.eq_ignore_ascii_case("true") => AwsToken::OutboundJwt,
        _ => AwsToken::PresignedRequest,
    };
    let attestation = Attester::new(&ctx.env, Endpoints::default())
        .attest(provider, oidc_token.as_ref(), aws)
        .map_err(WifError::into_generate_error)?;
    Ok(CommandResult::Message(
        attestation.credential.expose().to_string(),
    ))
}
