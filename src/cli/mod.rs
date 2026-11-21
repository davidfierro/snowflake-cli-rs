//! Global and connection flags that every command flattens (spellings and aliases are snow's).

use crate::config::ConfigSource;
use crate::diag::Verbosity;
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use crate::output::format::OutputFormat;
use crate::secret::Secret;
use std::path::PathBuf;

/// Output and logging flags.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct GlobalOptions {
    /// Specifies the output format. [env var: SNOWFLAKE_CLI_OUTPUT_FORMAT | config: cli.output_format]
    #[arg(long, value_enum, ignore_case = true)]
    pub format: Option<OutputFormat>,
    /// Displays log entries for log levels `info` and higher.
    #[arg(short = 'v', long)]
    pub verbose: bool,
    /// Displays log entries for log levels `debug` and higher; debug logs contain additional information.
    #[arg(long)]
    pub debug: bool,
    /// Turns off intermediate output to console.
    #[arg(long)]
    pub silent: bool,
    /// Differentiate exit error codes based on failure type. [env var: SNOWFLAKE_ENHANCED_EXIT_CODES]
    #[arg(long)]
    pub enhanced_exit_codes: bool,
    /// Number of decimal places to display for decimal values. Uses Python's default precision if not specified. [env var: SNOWFLAKE_DECIMAL_PRECISION]
    #[arg(long, value_name = "INTEGER", allow_negative_numbers = true)]
    pub decimal_precision: Option<i64>,
}

impl GlobalOptions {
    /// --format > env SNOWFLAKE_CLI_OUTPUT_FORMAT > config `[cli] output_format` > TABLE.
    /// An invalid env/config value is a Usage error (exit 2), as in snow.
    pub fn output_format(&self, source: &ConfigSource, env: &Env) -> Result<OutputFormat> {
        if let Some(format) = self.format {
            return Ok(format);
        }
        let (value, origin) = match env.get_non_empty("SNOWFLAKE_CLI_OUTPUT_FORMAT") {
            Some(v) => (v, "SNOWFLAKE_CLI_OUTPUT_FORMAT"),
            None => match source.cli_output_format()? {
                Some(v) => (v, "cli.output_format"),
                None => return Ok(OutputFormat::Table),
            },
        };
        parse_output_format(value, origin)
    }

    /// `--enhanced-exit-codes`, or a true `SNOWFLAKE_ENHANCED_EXIT_CODES` (click's boolean
    /// spellings). An invalid value is a Usage error, as in snow.
    pub fn enhanced_exit_codes(&self, env: &Env) -> Result<bool> {
        if self.enhanced_exit_codes {
            return Ok(true);
        }
        let Some(value) = env.get_non_empty("SNOWFLAKE_ENHANCED_EXIT_CODES") else {
            return Ok(false);
        };
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "t" | "yes" | "y" | "on" => Ok(true),
            "0" | "false" | "f" | "no" | "n" | "off" => Ok(false),
            _ => Err(Error::new(
                ErrorKind::Usage,
                format!(
                    "Invalid value for '--enhanced-exit-codes': '{value}' is not a valid boolean."
                ),
            )),
        }
    }

    /// `--decimal-precision` > env SNOWFLAKE_DECIMAL_PRECISION > config `[cli] decimal_precision`.
    /// Anything but a positive integer from the environment or config is a Client error, as
    /// in snow (a bad flag value is rejected earlier by the parser, exit 2).
    pub fn decimal_precision(&self, source: &ConfigSource, env: &Env) -> Result<Option<usize>> {
        let text = match self.decimal_precision {
            Some(n) => n.to_string(),
            None => match env
                .get_non_empty("SNOWFLAKE_DECIMAL_PRECISION")
                .map(str::to_string)
                .or_else(|| source.cli_decimal_precision())
            {
                Some(text) => text,
                None => return Ok(None),
            },
        };
        match text.trim().parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Invalid value for decimal_precision: '{text}'. Must be a positive integer."
                ),
            )),
        }
    }

    pub fn verbosity(&self) -> Verbosity {
        if self.debug {
            Verbosity::Debug
        } else if self.verbose {
            Verbosity::Verbose
        } else {
            Verbosity::Normal
        }
    }
}

/// snow's `OutputFormat.from_string`: trimmed, case-insensitive.
fn parse_output_format(value: &str, origin: &str) -> Result<OutputFormat> {
    // As snow: an output format is not a secret, so the value is echoed.
    OutputFormat::from_name(value).ok_or_else(|| {
        Error::new(
            ErrorKind::Usage,
            format!(
                "Invalid output format: '{value}' (from {origin}). Must be one of: {}.",
                OutputFormat::ALLOWED
            ),
        )
    })
}

/// Connection flags; each overrides the same key of the selected connection.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ConnectionOptions {
    /// Name of the connection, as defined in your `config.toml` file. Default: `default`.
    #[arg(
        short = 'c',
        long,
        visible_alias = "environment",
        conflicts_with = "temporary_connection"
    )]
    pub connection: Option<String>,
    /// Uses a connection defined with command line parameters, instead of one defined in config.
    #[arg(short = 'x', long)]
    pub temporary_connection: bool,
    /// Name assigned to your Snowflake account. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "accountname")]
    pub account: Option<String>,
    /// Username to connect to Snowflake. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "username")]
    pub user: Option<String>,
    /// Host address for the connection. Overrides the value specified for the connection.
    #[arg(long)]
    pub host: Option<String>,
    /// Port for the connection. Overrides the value specified for the connection.
    #[arg(long)]
    pub port: Option<u16>,
    /// Protocol to use for the connection, for example `https`. Overrides the value specified for the connection.
    #[arg(long)]
    pub protocol: Option<String>,
    /// Snowflake password. Overrides the value specified for the connection.
    #[arg(long, value_parser = secret_parser)]
    pub password: Option<Secret>,
    /// Snowflake authenticator. Overrides the value specified for the connection.
    #[arg(long)]
    pub authenticator: Option<String>,
    /// Workload identity provider (AWS, AZURE, GCP, OIDC). Overrides the value specified for the connection
    #[arg(long)]
    pub workload_identity_provider: Option<String>,
    /// Snowflake private key file path. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "private-key-path")]
    pub private_key_file: Option<PathBuf>,
    /// OAuth token to use when connecting to Snowflake.
    #[arg(long, value_parser = secret_parser)]
    pub token: Option<Secret>,
    /// Path to file with an OAuth token to use when connecting to Snowflake.
    #[arg(long)]
    pub token_file_path: Option<PathBuf>,
    /// Database to use. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "dbname")]
    pub database: Option<String>,
    /// Database schema to use. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "schemaname")]
    pub schema: Option<String>,
    /// Role to use. Overrides the value specified for the connection.
    #[arg(long, visible_alias = "rolename")]
    pub role: Option<String>,
    /// Warehouse to use. Overrides the value specified for the connection.
    #[arg(long)]
    pub warehouse: Option<String>,
    /// Whether to generate a connection diagnostic report.
    #[arg(long)]
    pub enable_diag: bool,
    /// Path for the generated report. Defaults to system temporary directory.
    #[arg(long)]
    pub diag_log_path: Option<PathBuf>,
    /// Path to a JSON file that contains allowlist parameters.
    #[arg(long)]
    pub diag_allowlist_path: Option<PathBuf>,
    /// Token to use for multi-factor authentication (MFA). Given without a value, it is
    /// prompted for.
    #[arg(long, value_parser = secret_parser, num_args = 0..=1)]
    pub mfa_passcode: Option<Option<Secret>>,
    /// Value of client id provided by the Identity Provider for Snowflake integration.
    #[arg(long)]
    pub oauth_client_id: Option<String>,
    /// Value of the client secret provided by the Identity Provider for Snowflake integration.
    #[arg(long, value_parser = secret_parser)]
    pub oauth_client_secret: Option<Secret>,
    /// Identity Provider endpoint supplying the authorization code to the driver.
    #[arg(long)]
    pub oauth_authorization_url: Option<String>,
    /// Identity Provider endpoint supplying the access tokens to the driver.
    #[arg(long)]
    pub oauth_token_request_url: Option<String>,
    /// URI to use for authorization code redirection.
    #[arg(long)]
    pub oauth_redirect_uri: Option<String>,
    /// Scope requested in the Identity Provider authorization request.
    #[arg(long)]
    pub oauth_scope: Option<String>,
    /// Disables Proof Key for Code Exchange (PKCE). Default: `False`.
    #[arg(long)]
    pub oauth_disable_pkce: bool,
    /// Enables a silent re-authentication when the actual access token becomes outdated. Default: `False`.
    #[arg(long)]
    pub oauth_enable_refresh_tokens: bool,
    /// Whether to opt-in to single-use refresh token semantics. Default: `False`.
    #[arg(long)]
    pub oauth_enable_single_use_refresh_tokens: bool,
    /// Store the temporary credential.
    #[arg(long)]
    pub client_store_temporary_credential: bool,
    /// Keep the session active indefinitely, even if there is no activity from the user.
    #[arg(long)]
    pub server_session_keep_alive: bool,
    /// Secondary roles mode applied when the session starts. Supported values are `ALL` and
    /// `NONE`; pass `NONE` to run the session only with the primary role.
    #[arg(long)]
    pub secondary_roles: Option<String>,
}

/// Keeps `--token` out of `Debug` output.
fn secret_parser(value: &str) -> std::result::Result<Secret, String> {
    Ok(Secret::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigPaths, ConfigSource};
    use clap::Parser;
    use tempfile::TempDir;

    /// What a future command looks like: both option groups flattened.
    #[derive(Debug, Parser)]
    struct TestCommand {
        #[command(flatten)]
        global: GlobalOptions,
        #[command(flatten)]
        connection: ConnectionOptions,
    }

    fn parse(args: &[&str]) -> std::result::Result<TestCommand, clap::Error> {
        TestCommand::try_parse_from(std::iter::once("cmd").chain(args.iter().copied()))
    }

    fn source_with_config(config: &str) -> (TempDir, ConfigSource) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let paths = ConfigPaths {
            config_file: path,
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        };
        let source = ConfigSource::load(&paths).unwrap();
        (dir, source)
    }

    #[test]
    fn global_flags_parse() {
        let cmd = parse(&["--format", "json", "-v", "--debug", "--silent"]).unwrap();
        assert_eq!(cmd.global.format, Some(OutputFormat::Json));
        assert!(cmd.global.verbose && cmd.global.debug && cmd.global.silent);
        for (value, format) in [
            ("TABLE", OutputFormat::Table),
            ("Csv", OutputFormat::Csv),
            ("plain", OutputFormat::Plain),
            ("json_ext", OutputFormat::JsonExt),
            ("JSON_EXT", OutputFormat::JsonExt),
        ] {
            assert_eq!(
                parse(&["--format", value]).unwrap().global.format,
                Some(format)
            );
        }
    }

    #[test]
    fn invalid_format_flag_is_a_usage_error() {
        for value in ["xml", "json-ext", "JSONEXT"] {
            let err = parse(&["--format", value]).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{value}");
        }
    }

    #[test]
    fn verbosity_from_flags() {
        assert_eq!(parse(&[]).unwrap().global.verbosity(), Verbosity::Normal);
        assert_eq!(
            parse(&["-v"]).unwrap().global.verbosity(),
            Verbosity::Verbose
        );
        assert_eq!(
            parse(&["--verbose"]).unwrap().global.verbosity(),
            Verbosity::Verbose
        );
        assert_eq!(
            parse(&["--debug"]).unwrap().global.verbosity(),
            Verbosity::Debug
        );
        assert_eq!(
            parse(&["-v", "--debug"]).unwrap().global.verbosity(),
            Verbosity::Debug
        );
    }

    #[test]
    fn connection_flags_and_aliases_parse() {
        let cmd = parse(&[
            "-c",
            "dev",
            "--accountname",
            "a",
            "--username",
            "u",
            "--host",
            "h",
            "--port",
            "443",
            "--authenticator",
            "SNOWFLAKE_JWT",
            "--private-key-path",
            "/k.p8",
            "--dbname",
            "d",
            "--schemaname",
            "s",
            "--rolename",
            "r",
            "--warehouse",
            "w",
        ])
        .unwrap();
        let c = cmd.connection;
        assert_eq!(c.connection.as_deref(), Some("dev"));
        assert_eq!(c.account.as_deref(), Some("a"));
        assert_eq!(c.user.as_deref(), Some("u"));
        assert_eq!(c.host.as_deref(), Some("h"));
        assert_eq!(c.port, Some(443));
        assert_eq!(c.authenticator.as_deref(), Some("SNOWFLAKE_JWT"));
        assert_eq!(c.private_key_file, Some(PathBuf::from("/k.p8")));
        assert_eq!(c.database.as_deref(), Some("d"));
        assert_eq!(c.schema.as_deref(), Some("s"));
        assert_eq!(c.role.as_deref(), Some("r"));
        assert_eq!(c.warehouse.as_deref(), Some("w"));

        let long = parse(&[
            "--connection",
            "x",
            "--account",
            "a",
            "--user",
            "u",
            "--private-key-file",
            "/f",
            "--database",
            "d",
            "--schema",
            "s",
            "--role",
            "r",
        ])
        .unwrap();
        assert_eq!(long.connection.connection.as_deref(), Some("x"));
        assert_eq!(long.connection.private_key_file, Some(PathBuf::from("/f")));
        assert_eq!(
            parse(&["--environment", "e"])
                .unwrap()
                .connection
                .connection
                .as_deref(),
            Some("e")
        );
        assert!(parse(&["-x"]).unwrap().connection.temporary_connection);
        assert!(
            parse(&["--temporary-connection"])
                .unwrap()
                .connection
                .temporary_connection
        );
    }

    #[test]
    fn connection_with_temporary_connection_is_rejected_by_clap() {
        assert_eq!(parse(&["-c", "dev", "-x"]).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn invalid_port_and_other_auth_flags_are_usage_errors() {
        assert_eq!(parse(&["--port", "70000"]).unwrap_err().exit_code(), 2);
        assert_eq!(parse(&["--port", "abc"]).unwrap_err().exit_code(), 2);
        assert_eq!(
            parse(&["--enhanced-exit-codes", "x"])
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn connector_sign_in_flags_parse() {
        let cmd = parse(&[
            "--password",
            "pw",
            "--protocol",
            "http",
            "--mfa-passcode",
            "123456",
            "--oauth-client-id",
            "id",
            "--oauth-client-secret",
            "sec",
            "--oauth-authorization-url",
            "https://a",
            "--oauth-token-request-url",
            "https://t",
            "--oauth-redirect-uri",
            "http://127.0.0.1:1",
            "--oauth-scope",
            "s",
            "--oauth-disable-pkce",
            "--oauth-enable-refresh-tokens",
            "--oauth-enable-single-use-refresh-tokens",
            "--client-store-temporary-credential",
            "--server-session-keep-alive",
        ])
        .unwrap();
        let c = cmd.connection;
        assert_eq!(c.password.unwrap().expose(), "pw");
        assert_eq!(c.protocol.as_deref(), Some("http"));
        assert_eq!(c.mfa_passcode.unwrap().unwrap().expose(), "123456");
        assert_eq!(c.oauth_client_secret.unwrap().expose(), "sec");
        assert!(c.oauth_disable_pkce && c.oauth_enable_refresh_tokens);
        assert!(c.oauth_enable_single_use_refresh_tokens);
        assert!(c.client_store_temporary_credential && c.server_session_keep_alive);
        // Without a value, the passcode is prompted for.
        let c = parse(&["--mfa-passcode"]).unwrap().connection;
        assert!(matches!(c.mfa_passcode, Some(None)));
        assert!(parse(&[]).unwrap().connection.mfa_passcode.is_none());
        // Secrets stay out of Debug output.
        let debug = format!("{:?}", parse(&["--password", "pw-MARKER"]).unwrap());
        assert!(!debug.contains("pw-MARKER"));
    }

    #[test]
    fn output_format_precedence() {
        let (_d, src) = source_with_config("[cli]\noutput_format = \"csv\"\n");
        let (_e, empty) = source_with_config("");
        let none = Env::default();
        let env_json = Env::from_pairs([("SNOWFLAKE_CLI_OUTPUT_FORMAT", " json ")]);
        let flag_plain = GlobalOptions {
            format: Some(OutputFormat::Plain),
            ..Default::default()
        };
        let no_flag = GlobalOptions::default();

        assert_eq!(
            flag_plain.output_format(&src, &env_json).unwrap(),
            OutputFormat::Plain
        );
        assert_eq!(
            no_flag.output_format(&src, &env_json).unwrap(),
            OutputFormat::Json
        );
        assert_eq!(
            no_flag.output_format(&src, &none).unwrap(),
            OutputFormat::Csv
        );
        assert_eq!(
            no_flag.output_format(&empty, &none).unwrap(),
            OutputFormat::Table
        );
        // An empty variable is ignored, as snow.
        let env_empty = Env::from_pairs([("SNOWFLAKE_CLI_OUTPUT_FORMAT", "")]);
        assert_eq!(
            no_flag.output_format(&src, &env_empty).unwrap(),
            OutputFormat::Csv
        );
        let env_table = Env::from_pairs([("SNOWFLAKE_CLI_OUTPUT_FORMAT", "Table")]);
        assert_eq!(
            no_flag.output_format(&src, &env_table).unwrap(),
            OutputFormat::Table
        );
    }

    #[test]
    fn invalid_env_or_config_format_is_a_usage_error() {
        let (_e, empty) = source_with_config("");
        let no_flag = GlobalOptions::default();
        let err = no_flag
            .output_format(
                &empty,
                &Env::from_pairs([("SNOWFLAKE_CLI_OUTPUT_FORMAT", "xml")]),
            )
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert!(err.message().contains("SNOWFLAKE_CLI_OUTPUT_FORMAT"));

        assert!(err.message().contains("TABLE, JSON, JSON_EXT, CSV, PLAIN"));

        let (_d, json_ext) = source_with_config("[cli]\noutput_format = \"json_ext\"\n");
        assert_eq!(
            no_flag.output_format(&json_ext, &Env::default()).unwrap(),
            OutputFormat::JsonExt
        );

        let (_f, wrong_type) = source_with_config("[cli]\noutput_format = 3\n");
        let err = no_flag
            .output_format(&wrong_type, &Env::default())
            .unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }
}
