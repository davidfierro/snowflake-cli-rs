use super::*;
use crate::config::ConfigPaths;
use crate::config::source::tests::home_with;
use std::path::Path;

/// Loads a source from the given files in a temp SNOWFLAKE_HOME.
fn source(files: &[(&str, &str)]) -> ConfigSource {
    let (_dir, paths): (_, ConfigPaths) = home_with(files);
    ConfigSource::load(&paths).unwrap()
}

fn env(pairs: &[(&str, &str)]) -> Env {
    Env::from_pairs(pairs.iter().copied())
}

fn named(name: &str) -> ConnectionOptions {
    ConnectionOptions {
        connection: Some(name.to_string()),
        ..Default::default()
    }
}

const DEV: &str = r#"
[connections.dev]
account = "file_account"
user = "file_user"
role = "file_role"
database = "file_db"
"#;

#[test]
fn file_values_are_used() {
    let conn =
        resolve_connection(&source(&[("config.toml", DEV)]), &named("dev"), &env(&[])).unwrap();
    assert_eq!(
        conn,
        ConnectionConfig {
            name: Some("dev".into()),
            account: Some("file_account".into()),
            user: Some("file_user".into()),
            role: Some("file_role".into()),
            database: Some("file_db".into()),
            ..Default::default()
        }
    );
}

#[test]
fn every_precedence_level_in_order() {
    let src = source(&[("config.toml", DEV)]);
    let env = env(&[
        ("SNOWFLAKE_CONNECTIONS_DEV_ACCOUNT", "conn_env_account"),
        ("SNOWFLAKE_CONNECTIONS_DEV_USER", "conn_env_user"),
        ("SNOWFLAKE_ACCOUNT", "generic_account"),
        ("SNOWFLAKE_USER", "generic_user"),
        ("SNOWFLAKE_ROLE", "generic_role"),
        ("SNOWFLAKE_WAREHOUSE", "generic_wh"),
    ]);
    let options = ConnectionOptions {
        account: Some("flag_account".into()),
        ..named("dev")
    };
    let conn = resolve_connection(&src, &options, &env).unwrap();
    // 1. flag beats everything
    assert_eq!(conn.account.as_deref(), Some("flag_account"));
    // 2. SNOWFLAKE_CONNECTIONS_<NAME>_<KEY> beats the file and the generic env
    assert_eq!(conn.user.as_deref(), Some("conn_env_user"));
    // 3. the file beats the generic env
    assert_eq!(conn.role.as_deref(), Some("file_role"));
    // 4. the generic env fills keys nobody else set
    assert_eq!(conn.warehouse.as_deref(), Some("generic_wh"));
}

#[test]
fn every_flag_overrides_the_file() {
    let src = source(&[(
        "config.toml",
        r#"
[connections.dev]
account = "a"
user = "u"
host = "h"
port = 1
authenticator = "x"
private_key_file = "/f"
database = "d"
schema = "s"
role = "r"
warehouse = "w"
"#,
    )]);
    let options = ConnectionOptions {
        connection: Some("dev".into()),
        temporary_connection: false,
        account: Some("A".into()),
        user: Some("U".into()),
        host: Some("H".into()),
        port: Some(2),
        authenticator: Some("SNOWFLAKE_JWT".into()),
        workload_identity_provider: Some("OIDC".into()),
        private_key_file: Some("/F".into()),
        token: Some(Secret::new("TOK")),
        token_file_path: Some("/T".into()),
        database: Some("D".into()),
        schema: Some("S".into()),
        role: Some("R".into()),
        warehouse: Some("W".into()),
        secondary_roles: Some("NONE".into()),
        ..ConnectionOptions::default()
    };
    let conn = resolve_connection(&src, &options, &env(&[])).unwrap();
    assert_eq!(
        conn,
        ConnectionConfig {
            name: Some("dev".into()),
            account: Some("A".into()),
            user: Some("U".into()),
            host: Some("H".into()),
            port: Some(2),
            protocol: None,
            authenticator: Some("SNOWFLAKE_JWT".into()),
            private_key_file: Some("/F".into()),
            private_key_raw: None,
            private_key_passphrase: None,
            token: Some(Secret::new("TOK")),
            token_file_path: Some("/T".into()),
            workload_identity_provider: Some("OIDC".into()),
            secondary_roles: Some("NONE".into()),
            database: Some("D".into()),
            schema: Some("S".into()),
            role: Some("R".into()),
            warehouse: Some("W".into()),
            ..Default::default()
        }
    );
}

#[test]
fn generic_env_only_fills_unset_keys_and_reads_every_stage0_key() {
    let src = source(&[("config.toml", "[connections.empty]\n")]);
    let env = env(&[
        ("SNOWFLAKE_ACCOUNT", "a"),
        ("SNOWFLAKE_USER", "u"),
        ("SNOWFLAKE_HOST", "h"),
        ("SNOWFLAKE_PORT", "8080"),
        ("SNOWFLAKE_PROTOCOL", "http"),
        ("SNOWFLAKE_AUTHENTICATOR", "SNOWFLAKE_JWT"),
        ("SNOWFLAKE_PRIVATE_KEY_FILE", "/k.p8"),
        ("SNOWFLAKE_PRIVATE_KEY_RAW", "pem"),
        ("SNOWFLAKE_DATABASE", "d"),
        ("SNOWFLAKE_SCHEMA", "s"),
        ("SNOWFLAKE_ROLE", "r"),
        ("SNOWFLAKE_WAREHOUSE", "w"),
        ("SNOWFLAKE_TOKEN", "t"),
        ("SNOWFLAKE_TOKEN_FILE_PATH", "/t"),
        ("SNOWFLAKE_WORKLOAD_IDENTITY_PROVIDER", "aws"),
        ("SNOWFLAKE_SECONDARY_ROLES", "all"),
        // Not read from the generic env, as snow.
        ("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "nope"),
    ]);
    let conn = resolve_connection(&src, &named("empty"), &env).unwrap();
    assert_eq!(
        conn,
        ConnectionConfig {
            name: Some("empty".into()),
            account: Some("a".into()),
            user: Some("u".into()),
            host: Some("h".into()),
            port: Some(8080),
            protocol: Some("http".into()),
            authenticator: Some("SNOWFLAKE_JWT".into()),
            private_key_file: Some("/k.p8".into()),
            private_key_raw: Some(Secret::new("pem")),
            private_key_passphrase: None,
            token: Some(Secret::new("t")),
            token_file_path: Some("/t".into()),
            workload_identity_provider: Some("aws".into()),
            secondary_roles: Some("all".into()),
            database: Some("d".into()),
            schema: Some("s".into()),
            role: Some("r".into()),
            warehouse: Some("w".into()),
            ..Default::default()
        }
    );
}

#[test]
fn connector_sign_in_keys_resolve_from_flags_file_and_env() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\npassword = \"file_pw\"\npasscode_in_password = true\n\
         oauth_client_id = \"file_id\"\noauth_disable_pkce = \"TRUE\"\n\
         client_session_keep_alive = true\nclient_session_keep_alive_heartbeat_frequency = 900\n\
         server_session_keep_alive = 0\n",
    )]);
    let env = env(&[
        ("SNOWFLAKE_OAUTH_CLIENT_SECRET", "env_secret"),
        ("SNOWFLAKE_OAUTH_ENABLE_REFRESH_TOKENS", "false"),
        ("SNOWFLAKE_CONNECTIONS_DEV_OAUTH_SCOPE", "session:role:R"),
        ("SNOWFLAKE_PASSWORD", "ignored: the file has one"),
    ]);
    let conn = resolve_connection(&src, &named("dev"), &env).unwrap();
    assert_eq!(conn.password, Some(Secret::new("file_pw")));
    assert_eq!(conn.passcode_in_password, Some(true));
    assert_eq!(conn.oauth_client_id.as_deref(), Some("file_id"));
    assert_eq!(conn.oauth_client_secret, Some(Secret::new("env_secret")));
    assert_eq!(conn.oauth_scope.as_deref(), Some("session:role:R"));
    assert_eq!(conn.oauth_disable_pkce, Some(true));
    assert_eq!(conn.oauth_enable_refresh_tokens, Some(false));
    assert_eq!(conn.client_session_keep_alive, Some(true));
    assert_eq!(
        conn.client_session_keep_alive_heartbeat_frequency,
        Some(900)
    );
    assert_eq!(conn.server_session_keep_alive, Some(false));
    assert_eq!(conn.client_store_temporary_credential, None);

    let options = ConnectionOptions {
        password: Some(Secret::new("flag_pw")),
        mfa_passcode: Some(Some(Secret::new("123456"))),
        protocol: Some("http".into()),
        oauth_client_id: Some("i".into()),
        oauth_client_secret: Some(Secret::new("s")),
        oauth_authorization_url: Some("https://a".into()),
        oauth_token_request_url: Some("https://t".into()),
        oauth_redirect_uri: Some("http://127.0.0.1:8001".into()),
        oauth_scope: Some("sc".into()),
        oauth_disable_pkce: true,
        oauth_enable_refresh_tokens: true,
        oauth_enable_single_use_refresh_tokens: true,
        client_store_temporary_credential: true,
        server_session_keep_alive: true,
        ..named("dev")
    };
    let conn = resolve_connection(&src, &options, &env).unwrap();
    assert_eq!(conn.password, Some(Secret::new("flag_pw")));
    assert_eq!(conn.passcode, Some(Secret::new("123456")));
    assert_eq!(conn.protocol.as_deref(), Some("http"));
    assert_eq!(conn.oauth_client_id.as_deref(), Some("i"));
    assert_eq!(conn.oauth_client_secret, Some(Secret::new("s")));
    assert_eq!(conn.oauth_authorization_url.as_deref(), Some("https://a"));
    assert_eq!(conn.oauth_token_request_url.as_deref(), Some("https://t"));
    assert_eq!(
        conn.oauth_redirect_uri.as_deref(),
        Some("http://127.0.0.1:8001")
    );
    assert_eq!(conn.oauth_scope.as_deref(), Some("sc"));
    assert_eq!(conn.oauth_enable_refresh_tokens, Some(true));
    assert_eq!(conn.oauth_enable_single_use_refresh_tokens, Some(true));
    assert_eq!(conn.client_store_temporary_credential, Some(true));
    assert_eq!(conn.server_session_keep_alive, Some(true));

    // `--mfa-passcode` with no value leaves the passcode to the prompt.
    let options = ConnectionOptions {
        mfa_passcode: Some(None),
        ..named("dev")
    };
    assert_eq!(
        resolve_connection(&src, &options, &env).unwrap().passcode,
        None
    );

    let env = self::env(&[("SNOWFLAKE_PASSWORD", "env_pw")]);
    let src = source(&[("config.toml", "[connections.dev]\n")]);
    assert_eq!(
        resolve_connection(&src, &named("dev"), &env)
            .unwrap()
            .password,
        Some(Secret::new("env_pw"))
    );
}

#[test]
fn bad_booleans_and_seconds_name_the_key_not_the_value() {
    for (toml, key) in [
        ("oauth_disable_pkce = \"maybe\"", "oauth_disable_pkce"),
        (
            "server_session_keep_alive = 1.5",
            "server_session_keep_alive",
        ),
        (
            "client_session_keep_alive_heartbeat_frequency = \"soon\"",
            "client_session_keep_alive_heartbeat_frequency",
        ),
    ] {
        let src = source(&[("config.toml", &format!("[connections.dev]\n{toml}\n"))]);
        let err = resolve_connection(&src, &named("dev"), &env(&[])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains(key), "{}", err.message());
        assert!(!err.message().contains("maybe") && !err.message().contains("soon"));
    }
}

#[test]
fn sign_in_keys_follow_the_same_precedence() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\ntoken = \"file\"\nworkload_identity_provider = \"GCP\"\nsecondary_roles = \"ALL\"\n",
    )]);
    // The connection's variable beats the file; the generic one only fills what is unset.
    let env = env(&[
        ("SNOWFLAKE_CONNECTIONS_DEV_TOKEN", "conn-env"),
        ("SNOWFLAKE_TOKEN", "generic"),
        ("SNOWFLAKE_TOKEN_FILE_PATH", "/generic"),
        ("SNOWFLAKE_SECONDARY_ROLES", "NONE"),
    ]);
    let conn = resolve_connection(&src, &named("dev"), &env).unwrap();
    assert_eq!(conn.token, Some(Secret::new("conn-env")));
    assert_eq!(conn.token_file_path, Some("/generic".into()));
    assert_eq!(conn.workload_identity_provider.as_deref(), Some("GCP"));
    assert_eq!(conn.secondary_roles.as_deref(), Some("ALL"));
    // Flags beat everything.
    let options = ConnectionOptions {
        connection: Some("dev".into()),
        token: Some(Secret::new("flag")),
        workload_identity_provider: Some("AWS".into()),
        secondary_roles: Some("NONE".into()),
        ..Default::default()
    };
    let conn = resolve_connection(&src, &options, &env).unwrap();
    assert_eq!(conn.token, Some(Secret::new("flag")));
    assert_eq!(conn.workload_identity_provider.as_deref(), Some("AWS"));
    assert_eq!(conn.secondary_roles.as_deref(), Some("NONE"));
}

#[test]
fn the_provider_flag_must_be_spelled_as_snow_lists_it() {
    let src = source(&[("config.toml", "[connections.dev]\n")]);
    for value in ["oidc", "k8s"] {
        let options = ConnectionOptions {
            connection: Some("dev".into()),
            workload_identity_provider: Some(value.into()),
            ..Default::default()
        };
        let err = resolve_connection(&src, &options, &env(&[])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(
            err.message(),
            format!(
                "Invalid workload identity provider '{value}'. Valid values are: AWS, AZURE, GCP, OIDC"
            )
        );
    }
}

#[test]
fn empty_value_in_the_file_blocks_the_generic_env_but_empty_generic_env_is_ignored() {
    let src = source(&[("config.toml", "[connections.dev]\nrole = \"\"\n")]);
    let env = env(&[("SNOWFLAKE_ROLE", "generic"), ("SNOWFLAKE_WAREHOUSE", "")]);
    let conn = resolve_connection(&src, &named("dev"), &env).unwrap();
    assert_eq!(conn.role.as_deref(), Some(""));
    assert_eq!(conn.warehouse, None);
}

#[test]
fn connection_env_with_lower_case_name_and_new_keys() {
    let src = source(&[("config.toml", "[connections.my_dev]\nuser = \"u\"\n")]);
    let env = env(&[
        ("SNOWFLAKE_CONNECTIONS_MY_DEV_WAREHOUSE", "conn_env_wh"),
        ("SNOWFLAKE_CONNECTIONS_OTHER_ROLE", "other"),
        ("SNOWFLAKE_WAREHOUSE", "generic"),
    ]);
    let conn = resolve_connection(&src, &named("my_dev"), &env).unwrap();
    assert_eq!(conn.warehouse.as_deref(), Some("conn_env_wh"));
    assert_eq!(conn.role, None);
}

#[test]
fn default_connection_is_used_without_dash_c() {
    let src = source(&[(
        "config.toml",
        "[connections.default]\nuser = \"d\"\n[connections.other]\nuser = \"o\"\n",
    )]);
    let conn = resolve_connection(&src, &ConnectionOptions::default(), &env(&[])).unwrap();
    assert_eq!(conn.name.as_deref(), Some("default"));
    assert_eq!(conn.user.as_deref(), Some("d"));

    let e = env(&[("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "other")]);
    let conn = resolve_connection(&src, &ConnectionOptions::default(), &e).unwrap();
    assert_eq!(conn.user.as_deref(), Some("o"));
}

#[test]
fn default_connection_name_from_config_toml() {
    let src = source(&[(
        "config.toml",
        "default_connection_name = \"other\"\n[connections.other]\nuser = \"o\"\n",
    )]);
    let conn = resolve_connection(&src, &ConnectionOptions::default(), &env(&[])).unwrap();
    assert_eq!(conn.name.as_deref(), Some("other"));
}

#[test]
fn missing_default_connection_error() {
    let src = source(&[("config.toml", "default_connection_name = \"prod\"\n")]);
    let err = resolve_connection(&src, &ConnectionOptions::default(), &env(&[])).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert_eq!(
        err.message(),
        "Couldn't find connection for default connection `prod`. Specify connection name or configure default connection."
    );
}

#[test]
fn missing_named_connection_error() {
    let err = resolve_connection(&source(&[("config.toml", DEV)]), &named("nope"), &env(&[]))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert_eq!(err.exit_code(), 1);
    assert_eq!(err.message(), "Connection nope is not configured");
}

#[test]
fn env_only_connection_is_not_configured() {
    let e = env(&[
        ("SNOWFLAKE_CONNECTIONS_ENVONLY_ACCOUNT", "a"),
        ("SNOWFLAKE_CONNECTIONS_ENVONLY_USER", "u"),
    ]);
    let err = resolve_connection(&source(&[]), &named("envonly"), &e).unwrap_err();
    assert_eq!(err.message(), "Connection envonly is not configured");
}

#[test]
fn connections_toml_replaces_config_toml_connections() {
    let src = source(&[
        ("config.toml", DEV),
        ("connections.toml", "[prod]\nuser = \"prod_user\"\n"),
    ]);
    let err = resolve_connection(&src, &named("dev"), &env(&[])).unwrap_err();
    assert_eq!(err.message(), "Connection dev is not configured");
    let conn = resolve_connection(&src, &named("prod"), &env(&[])).unwrap();
    assert_eq!(conn.user.as_deref(), Some("prod_user"));
}

#[test]
fn temporary_connection_uses_flags_then_generic_env_only() {
    let src = source(&[(
        "config.toml",
        "[connections.default]\nuser = \"file\"\nrole = \"file\"\n",
    )]);
    let options = ConnectionOptions {
        temporary_connection: true,
        user: Some("flag".into()),
        ..Default::default()
    };
    let e = env(&[
        ("SNOWFLAKE_USER", "generic_user"),
        ("SNOWFLAKE_ACCOUNT", "generic_account"),
        ("SNOWFLAKE_CONNECTIONS_DEFAULT_ROLE", "ignored"),
    ]);
    let conn = resolve_connection(&src, &options, &e).unwrap();
    assert_eq!(
        conn,
        ConnectionConfig {
            name: None,
            user: Some("flag".into()),
            account: Some("generic_account".into()),
            ..Default::default()
        }
    );
}

#[test]
fn connection_with_temporary_connection_is_a_usage_error() {
    let options = ConnectionOptions {
        temporary_connection: true,
        ..named("dev")
    };
    let err = resolve_connection(&source(&[]), &options, &env(&[])).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Usage);
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn key_aliases() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nprivate_key_path = \"/p.p8\"\nprivate_key_file_pwd = \"pw\"\n",
    )]);
    let conn = resolve_connection(&src, &named("dev"), &env(&[])).unwrap();
    assert_eq!(conn.private_key_file.as_deref(), Some(Path::new("/p.p8")));
    assert_eq!(conn.private_key_passphrase, Some(Secret::new("pw")));
}

#[test]
fn private_key_path_wins_over_private_key_file_as_in_snow() {
    // snow keeps private_key_path among the "other" settings, applied after the known ones.
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nprivate_key_path = \"/path.p8\"\n",
    )]);
    let e = env(&[("SNOWFLAKE_CONNECTIONS_DEV_PRIVATE_KEY_FILE", "/file.p8")]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(
        conn.private_key_file.as_deref(),
        Some(Path::new("/path.p8"))
    );
}

#[test]
fn generic_private_key_file_wins_over_generic_private_key_path() {
    let src = source(&[("config.toml", "[connections.dev]\n")]);
    let e = env(&[
        ("SNOWFLAKE_PRIVATE_KEY_PATH", "/path.p8"),
        ("SNOWFLAKE_PRIVATE_KEY_FILE", "/file.p8"),
    ]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(
        conn.private_key_file.as_deref(),
        Some(Path::new("/file.p8"))
    );
}

#[test]
fn private_key_passphrase_env_replaces_every_layer() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nprivate_key_passphrase = \"file\"\n",
    )]);
    let e = env(&[
        (
            "SNOWFLAKE_CONNECTIONS_DEV_PRIVATE_KEY_PASSPHRASE",
            "conn_env",
        ),
        ("PRIVATE_KEY_PASSPHRASE", "env"),
    ]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(conn.private_key_passphrase, Some(Secret::new("env")));

    let e = env(&[(
        "SNOWFLAKE_CONNECTIONS_DEV_PRIVATE_KEY_PASSPHRASE",
        "conn_env",
    )]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(conn.private_key_passphrase, Some(Secret::new("conn_env")));

    let e = env(&[("PRIVATE_KEY_PASSPHRASE", "")]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(conn.private_key_passphrase, Some(Secret::new("")));
}

#[test]
fn port_from_toml_integer_and_env_string() {
    let src = source(&[("config.toml", "[connections.dev]\nport = 443\n")]);
    let conn = resolve_connection(&src, &named("dev"), &env(&[])).unwrap();
    assert_eq!(conn.port, Some(443));
    let e = env(&[("SNOWFLAKE_CONNECTIONS_DEV_PORT", "8443")]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(conn.port, Some(8443));
}

#[test]
fn invalid_port_names_the_source_but_not_the_value() {
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
    let cases: [Case; 4] = [
        ("port = 70000", &[], "key 'port' in the config file"),
        (
            "port = \"abc-marker\"",
            &[],
            "key 'port' in the config file",
        ),
        ("port = true", &[], "key 'port' in the config file"),
        ("", &[("SNOWFLAKE_PORT", "xyz-marker")], "SNOWFLAKE_PORT"),
    ];
    for (toml, pairs, origin) in cases {
        let src = source(&[("config.toml", &format!("[connections.dev]\n{toml}\n"))]);
        let err = resolve_connection(&src, &named("dev"), &env(pairs)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains(origin), "{}", err.message());
        assert!(
            err.message().contains("connection 'dev'"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("marker"), "{}", err.message());
        assert!(!err.message().contains("70000"), "{}", err.message());
    }
}

#[test]
fn non_string_value_is_an_error_without_the_value() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nrole = [\"SECRET-MARKER\"]\n",
    )]);
    let err = resolve_connection(&src, &named("dev"), &env(&[])).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert!(err.message().contains("key 'role'"), "{}", err.message());
    assert!(!err.message().contains("SECRET-MARKER"));
}

#[test]
fn integer_values_are_accepted_as_text() {
    let src = source(&[("config.toml", "[connections.dev]\naccount = 12345\n")]);
    let conn = resolve_connection(&src, &named("dev"), &env(&[])).unwrap();
    assert_eq!(conn.account.as_deref(), Some("12345"));
}

#[test]
fn unsupported_keys_are_ignored() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nuser = \"u\"\npassword = \"p\"\nregion = \"r\"\nweird = 1\n",
    )]);
    let e = env(&[("SNOWFLAKE_CONNECTIONS_DEV_MASTER_TOKEN", "t")]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(
        conn,
        ConnectionConfig {
            name: Some("dev".into()),
            user: Some("u".into()),
            password: Some(Secret::new("p")),
            ..Default::default()
        }
    );
}

#[test]
fn private_key_file_tilde_is_expanded() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nprivate_key_file = \"~/keys/k.p8\"\n",
    )]);
    let e = env(&[("HOME", "/home/test"), ("USERPROFILE", "/home/test")]);
    let conn = resolve_connection(&src, &named("dev"), &e).unwrap();
    assert_eq!(
        conn.private_key_file,
        Some(Path::new("/home/test").join("keys/k.p8"))
    );

    let options = ConnectionOptions {
        private_key_file: Some("~/flag.p8".into()),
        ..named("dev")
    };
    let conn = resolve_connection(&src, &options, &e).unwrap();
    assert_eq!(
        conn.private_key_file,
        Some(Path::new("/home/test").join("flag.p8"))
    );
}

#[test]
fn non_table_connection_is_an_error() {
    let src = source(&[("config.toml", "[connections]\ndev = \"oops\"\n")]);
    let err = resolve_connection(&src, &named("dev"), &env(&[])).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert!(err.message().contains("not a TOML table"));
    assert!(!err.message().contains("oops"));
}

#[test]
fn debug_of_the_resolved_connection_masks_secrets() {
    let src = source(&[(
        "config.toml",
        "[connections.dev]\nprivate_key_raw = \"PEM-MARKER\"\nprivate_key_passphrase = \"PASS-MARKER\"\n",
    )]);
    let conn = resolve_connection(&src, &named("dev"), &env(&[])).unwrap();
    let debug = format!("{conn:?}");
    assert!(!debug.contains("PEM-MARKER"));
    assert!(!debug.contains("PASS-MARKER"));
}
