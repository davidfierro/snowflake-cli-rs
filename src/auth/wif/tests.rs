use super::jwt::make;
use super::*;
use crate::auth::Authenticator;
use httpmock::MockServer;
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;

/// Every metadata service and STS on `server`.
pub(crate) fn endpoints(server: &MockServer) -> Endpoints {
    let base = server.base_url();
    Endpoints {
        gcp_service_account: format!("{base}/computeMetadata/v1/instance/service-accounts/default"),
        azure_imds_token: format!("{base}/metadata/identity/oauth2/token"),
        azure_authority: format!("{base}/"),
        aws_imds: base.clone(),
        aws_container: base.clone(),
        aws_sts: Some(base),
    }
}

pub(crate) fn attester<'a>(env: &'a Env, server: &MockServer) -> Attester<'a> {
    Attester::new(env, endpoints(server))
}

fn t1000() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1000)
}

fn oidc_token(exp: u64) -> String {
    make(&json!({"iss": "https://issuer", "sub": "workload", "exp": exp}))
}

#[test]
fn providers_parse_case_insensitively() {
    assert_eq!(Provider::parse("aws").unwrap(), Provider::Aws);
    assert_eq!(Provider::parse("Azure").unwrap(), Provider::Azure);
    assert_eq!(Provider::parse("GCP").unwrap(), Provider::Gcp);
    assert_eq!(Provider::parse("oidc").unwrap(), Provider::Oidc);
    let err = Provider::parse("k8s").unwrap_err();
    assert_eq!(err.code, INVALID_WIF_SETTINGS);
    assert_eq!(
        err.message,
        "Unknown workload_identity_provider: 'k8s'. Expected one of: AWS, AZURE, GCP, OIDC"
    );
    assert_eq!(
        err.clone().into_generate_error().message(),
        "251017: 251017: Unknown workload_identity_provider: 'k8s'. Expected one of: AWS, AZURE, GCP, OIDC"
    );
    assert!(
        err.into_connect_error()
            .message()
            .starts_with("Could not connect to Snowflake. Reason: 251017: Unknown")
    );
}

#[test]
fn oidc_attestation_is_the_token_once_it_reads_as_a_jwt() {
    let env = Env::default();
    let a = Attester::new(&env, Endpoints::default());
    let token = Secret::new(oidc_token(5));
    let attestation = a
        .attest(Provider::Oidc, Some(&token), AwsToken::OutboundJwt)
        .unwrap();
    assert_eq!(attestation.credential.expose(), token.expose());
    let err = a
        .attest(Provider::Oidc, None, AwsToken::OutboundJwt)
        .unwrap_err();
    assert_eq!(err.code, WIF_CREDENTIALS_NOT_FOUND);
    assert_eq!(
        err.message,
        "token must be provided if workload_identity_provider=OIDC"
    );
    let err = a
        .attest(
            Provider::Oidc,
            Some(&Secret::new("SECRET")),
            AwsToken::OutboundJwt,
        )
        .unwrap_err();
    assert_eq!(err.message, "Invalid JWT token: Not enough segments");
}

#[test]
fn gcp_identity_token_from_the_metadata_server() {
    let server = MockServer::start();
    let token = oidc_token(5);
    let metadata = server.mock(|when, then| {
        when.method("GET")
            .path("/computeMetadata/v1/instance/service-accounts/default/identity")
            .query_param("audience", "snowflakecomputing.com")
            .header("metadata-flavor", "Google");
        then.status(200).body(&token);
    });
    let env = Env::default();
    let attestation = attester(&env, &server)
        .attest(Provider::Gcp, None, AwsToken::OutboundJwt)
        .unwrap();
    assert_eq!(attestation.provider, Provider::Gcp);
    assert_eq!(attestation.credential.expose(), token);
    metadata.assert();
}

#[test]
fn gcp_failures_say_where_to_run() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.any_request();
        then.status(404).body("SECRET-BODY");
    });
    let env = Env::default();
    let err = attester(&env, &server).gcp_attestation().unwrap_err();
    assert_eq!(err.code, WIF_CREDENTIALS_NOT_FOUND);
    assert_eq!(
        err.message,
        "Error fetching GCP identity token: HTTP 404. Ensure the application is running on GCP."
    );
    let mut down = endpoints(&server);
    down.gcp_service_account = "http://127.0.0.1:1".into();
    let err = Attester::new(&env, down).gcp_attestation().unwrap_err();
    assert!(
        err.message
            .starts_with("Error fetching GCP identity token: ")
    );
}

#[test]
fn azure_imds_token_with_an_optional_client_id() {
    let server = MockServer::start();
    let token = oidc_token(5);
    let imds = server.mock(|when, then| {
        when.method("GET")
            .path("/metadata/identity/oauth2/token")
            .query_param("api-version", "2018-02-01")
            .query_param("resource", "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad")
            .query_param("client_id", "mi-client")
            .header("metadata", "true");
        then.status(200).json_body(json!({"access_token": token}));
    });
    let env = Env::from_pairs([("MANAGED_IDENTITY_CLIENT_ID", "mi-client")]);
    let attestation = attester(&env, &server)
        .attest(Provider::Azure, None, AwsToken::OutboundJwt)
        .unwrap();
    assert_eq!(attestation.credential.expose(), token);
    imds.assert();
}

#[test]
fn azure_functions_identity_endpoint() {
    let server = MockServer::start();
    let token = oidc_token(5);
    let functions = server.mock(|when, then| {
        when.method("GET")
            .path("/msi/token")
            .query_param("api-version", "2019-08-01")
            .query_param("resource", "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad")
            .header("x-identity-header", "ID-HEADER");
        then.status(200).json_body(json!({"access_token": token}));
    });
    let endpoint = format!("{}/msi/token", server.base_url());
    let env = Env::from_pairs([
        ("IDENTITY_ENDPOINT", endpoint.as_str()),
        ("IDENTITY_HEADER", "ID-HEADER"),
    ]);
    let a = attester(&env, &server);
    assert_eq!(a.azure_attestation().unwrap().expose(), token);
    functions.assert();

    let env = Env::from_pairs([("IDENTITY_ENDPOINT", endpoint.as_str())]);
    let err = attester(&env, &server).azure_attestation().unwrap_err();
    assert_eq!(
        err.message,
        "Managed identity is not enabled on this Azure function."
    );
}

#[test]
fn azure_aks_exchanges_the_federated_token() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("azure-token");
    std::fs::write(&file, "fed.token.jwt\n").unwrap();
    let server = MockServer::start();
    let token = oidc_token(5);
    let entra = server.mock(|when, then| {
        when.method("POST")
            .path("/tenant-1/oauth2/v2.0/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .form_urlencoded_tuple("client_assertion", "fed.token.jwt")
            .form_urlencoded_tuple(
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            )
            .form_urlencoded_tuple("client_id", "app-1")
            .form_urlencoded_tuple("grant_type", "client_credentials")
            .form_urlencoded_tuple(
                "scope",
                "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad/.default",
            );
        then.status(200).json_body(json!({"access_token": token}));
    });
    let path = file.to_str().unwrap();
    let env = Env::from_pairs([
        ("AZURE_CLIENT_ID", "app-1"),
        ("AZURE_TENANT_ID", "tenant-1"),
        ("AZURE_FEDERATED_TOKEN_FILE", path),
    ]);
    assert_eq!(
        attester(&env, &server)
            .azure_attestation()
            .unwrap()
            .expose(),
        token
    );
    entra.assert();

    // AZURE_AUTHORITY_HOST wins over the default authority.
    let env = Env::from_pairs([
        ("AZURE_CLIENT_ID", "app-1"),
        ("AZURE_TENANT_ID", "tenant-1"),
        ("AZURE_FEDERATED_TOKEN_FILE", path),
        ("AZURE_AUTHORITY_HOST", &server.base_url()),
    ]);
    let mut nowhere = endpoints(&server);
    nowhere.azure_authority = "http://127.0.0.1:1/".into();
    assert!(Attester::new(&env, nowhere).azure_attestation().is_ok());
}

#[test]
fn azure_failures_never_echo_a_body() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/metadata/identity/oauth2/token");
        then.status(400).body("SECRET-BODY");
    });
    server.mock(|when, then| {
        when.path("/t/oauth2/v2.0/token");
        then.status(200)
            .json_body(json!({"token_type": "SECRET-BODY"}));
    });
    let env = Env::default();
    let err = attester(&env, &server).azure_attestation().unwrap_err();
    assert_eq!(
        err.message,
        "Error fetching Azure metadata: HTTP 400. Ensure the application is running on Azure."
    );

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("t");
    std::fs::write(&file, "fed").unwrap();
    let env = Env::from_pairs([
        ("AZURE_CLIENT_ID", "c"),
        ("AZURE_TENANT_ID", "t"),
        ("AZURE_FEDERATED_TOKEN_FILE", file.to_str().unwrap()),
    ]);
    let err = attester(&env, &server).azure_attestation().unwrap_err();
    assert!(err.message.starts_with(
        "Error fetching Azure MI token via WorkloadIdentityCredential: no access_token in the response."
    ));
    assert!(!err.message.contains("SECRET-BODY"));

    let ok_without_token = MockServer::start();
    ok_without_token.mock(|when, then| {
        when.any_request();
        then.status(200).json_body(json!({}));
    });
    let env = Env::default();
    let err = attester(&env, &ok_without_token)
        .azure_attestation()
        .unwrap_err();
    assert_eq!(
        err.message,
        "No access token found in Azure metadata service response."
    );

    let mut down = endpoints(&server);
    down.azure_imds_token = "http://127.0.0.1:1".into();
    assert!(Attester::new(&env, down).azure_attestation().is_err());

    // A missing token file is not AKS: IMDS is used.
    let env = Env::from_pairs([
        ("AZURE_CLIENT_ID", "c"),
        ("AZURE_TENANT_ID", "t"),
        ("AZURE_FEDERATED_TOKEN_FILE", "/nonexistent"),
    ]);
    let err = attester(&env, &server).azure_attestation().unwrap_err();
    assert!(err.message.starts_with("Error fetching Azure metadata"));
}

#[test]
fn github_actions_token_is_picked_up_when_none_is_usable() {
    let server = MockServer::start();
    let fresh = oidc_token(5000);
    let github = server.mock(|when, then| {
        when.method("GET")
            .path("/idtoken")
            .query_param("api-version", "2.0")
            .query_param("audience", "custom.aud")
            .header("authorization", "bearer GH-REQUEST");
        then.status(200).json_body(json!({"value": fresh}));
    });
    let url = format!("{}/idtoken?api-version=2.0", server.base_url());
    let env = Env::from_pairs([
        ("GITHUB_ACTIONS", "true"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GH-REQUEST"),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", url.as_str()),
        ("SNOWFLAKE_AUDIENCE", "custom.aud"),
    ]);
    let a = attester(&env, &server).with_clock(t1000);
    // No token: GitHub's. An expired one (or one expiring within 60 s): GitHub's.
    for token in [None, Some(oidc_token(1000)), Some(oidc_token(1060))] {
        let conn = ConnectionConfig {
            token: token.map(Secret::new),
            ..Default::default()
        };
        assert_eq!(a.ambient_oidc_token(&conn).unwrap().expose(), fresh);
    }
    // A usable token, an opaque one, or a token file: left alone.
    for conn in [
        ConnectionConfig {
            token: Some(Secret::new(oidc_token(2000))),
            ..Default::default()
        },
        ConnectionConfig {
            token: Some(Secret::new("opaque")),
            ..Default::default()
        },
        ConnectionConfig {
            token_file_path: Some("/f".into()),
            ..Default::default()
        },
    ] {
        assert!(a.ambient_oidc_token(&conn).is_none());
    }
    assert_eq!(github.calls(), 3);
}

#[test]
fn github_detection_failures_are_only_logged() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/denied");
        then.status(403);
    });
    server.mock(|when, then| {
        when.path("/garbage");
        then.status(200).body("{}");
    });
    let denied = format!("{}/denied", server.base_url());
    let garbage = format!("{}/garbage", server.base_url());
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (vec![], "not running in GitHub Actions"),
        (
            vec![("GITHUB_ACTIONS", "true")],
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable was unset",
        ),
        (
            vec![
                ("GITHUB_ACTIONS", "true"),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x"),
            ],
            "ACTIONS_ID_TOKEN_REQUEST_URL environment variable was unset",
        ),
        (
            vec![
                ("GITHUB_ACTIONS", "true"),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x"),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", denied.as_str()),
            ],
            "GitHub: OIDC token request failed (code=403)",
        ),
        (
            vec![
                ("GITHUB_ACTIONS", "true"),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x"),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", garbage.as_str()),
            ],
            "GitHub: malformed OIDC token response",
        ),
    ];
    for (pairs, why) in cases {
        let env = Env::from_pairs(pairs);
        let a = attester(&env, &server);
        assert!(a.github_token().unwrap_err().ends_with(why), "{why}");
        assert!(a.ambient_oidc_token(&ConnectionConfig::default()).is_none());
    }
    let env = Env::from_pairs([
        ("GITHUB_ACTIONS", "true"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x"),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "not json either"),
    ]);
    assert!(attester(&env, &server).github_token().is_err());
    server.mock(|when, then| {
        when.path("/text");
        then.status(200).body("not json");
    });
    let text = format!("{}/text", server.base_url());
    let env = Env::from_pairs([
        ("GITHUB_ACTIONS", "true"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x"),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", text.as_str()),
    ]);
    assert!(
        attester(&env, &server)
            .github_token()
            .unwrap_err()
            .ends_with("malformed OIDC token response")
    );
}

#[test]
fn host_allowlist_is_the_connector_s() {
    let env = Env::default();
    for host in [
        "acct.snowflakecomputing.com",
        "ACCT.SnowflakeComputing.com.",
        "acct.snowflakecomputing.com:443",
        "snowflakecomputing.cn",
        "a.b.snowflakecomputing.mil",
    ] {
        assert!(verify_host(host, &env).is_ok(), "{host}");
    }
    for host in [
        "127.0.0.1",
        "evil-snowflakecomputing.com",
        "snowflakecomputing.com.evil.io",
        "",
    ] {
        let err = verify_host(host, &env).unwrap_err();
        assert_eq!(err.code, WIF_UNTRUSTED_HOST, "{host}");
        assert_eq!(
            err.message,
            format!(
                "WORKLOAD_IDENTITY requires a recognized Snowflake host (*.snowflakecomputing.com, .cn or .mil). Got: '{host}'."
            )
        );
    }
    // URL delimiters would make the requested host differ from the checked one.
    for delimiter in ["/", "#", "?", "@", "\\", " ", "%2F"] {
        let host = format!("attacker.example{delimiter}.snowflakecomputing.com");
        let err = verify_host(&host, &env).unwrap_err();
        assert_eq!(err.code, WIF_UNTRUSTED_HOST, "{host}");
    }
    for host in [
        "acct.snowflakecomputing.com:",
        "acct.snowflakecomputing.com:44x",
        "a..snowflakecomputing.com",
        ".snowflakecomputing.com",
    ] {
        assert!(verify_host(host, &env).is_err(), "{host}");
    }
    let env = Env::from_pairs([(EXTRA_SUFFIXES_VAR, " corp.internal , ,127.0.0.1")]);
    assert!(verify_host("sf.corp.internal", &env).is_ok());
    assert!(verify_host("127.0.0.1", &env).is_ok());
    assert!(verify_host("corp.internal.evil", &env).is_err());
}

fn wif_conn(provider: Option<&str>, token: Option<&str>) -> ConnectionConfig {
    ConnectionConfig {
        authenticator: Some("WORKLOAD_IDENTITY".into()),
        workload_identity_provider: provider.map(str::to_string),
        token: token.map(Secret::new),
        ..Default::default()
    }
}

#[test]
fn sign_in_sends_wif_provider_and_attestation() {
    let env = Env::default();
    let a = Attester::new(&env, Endpoints::default()).with_clock(t1000);
    let token = oidc_token(5000);
    let auth = authenticator(
        &wif_conn(Some("oidc"), Some(&token)),
        "acct.snowflakecomputing.com",
        &a,
    )
    .unwrap();
    let header = auth.authorization().unwrap();
    assert_eq!(header.token.expose(), format!("WIF.OIDC.{token}"));
    assert_eq!(header.token_type, "WORKLOAD_IDENTITY_FEDERATION");

    // The token file wins over the token.
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("t");
    std::fs::write(&file, format!("{token}\n")).unwrap();
    let mut conn = wif_conn(Some("OIDC"), Some("stale"));
    conn.token_file_path = Some(file);
    let header = authenticator(&conn, "acct.snowflakecomputing.com", &a)
        .unwrap()
        .authorization()
        .unwrap();
    assert_eq!(header.token.expose(), format!("WIF.OIDC.{token}"));
}

#[test]
fn sign_in_errors_match_the_connector() {
    let env = Env::default();
    let a = Attester::new(&env, Endpoints::default());
    let host = "acct.snowflakecomputing.com";
    let message = |conn: &ConnectionConfig, host: &str| {
        authenticator(conn, host, &a)
            .unwrap_err()
            .message()
            .to_string()
    };
    assert_eq!(
        message(&wif_conn(None, None), host),
        "Could not connect to Snowflake. Reason: 251017: workload_identity_provider must be set to one of AWS,AZURE,GCP,OIDC when authenticator is WORKLOAD_IDENTITY."
    );
    assert_eq!(
        message(&wif_conn(Some(""), None), host),
        message(&wif_conn(None, None), host)
    );
    assert!(
        message(&wif_conn(Some("x"), None), host)
            .contains("Unknown workload_identity_provider: 'x'")
    );
    assert_eq!(
        message(&wif_conn(Some("OIDC"), None), host),
        "Could not connect to Snowflake. Reason: 251018: token must be provided if workload_identity_provider=OIDC"
    );
    // The host is checked before any credential is fetched.
    let token = oidc_token(5000);
    assert!(
        message(&wif_conn(Some("GCP"), Some(&token)), "127.0.0.1")
            .contains("251021: WORKLOAD_IDENTITY requires a recognized Snowflake host")
    );
    // `host` and `account` with URL delimiters, through the host the client would request.
    for delimiter in ["/", "#", "?", "@", "\\"] {
        let mut conn = wif_conn(Some("OIDC"), Some(&token));
        conn.host = Some(format!(
            "attacker.example{delimiter}.snowflakecomputing.com"
        ));
        let host = crate::sql::client::host(&conn).unwrap();
        assert!(message(&conn, &host).contains("251021"), "{host}");
        let mut conn = wif_conn(Some("OIDC"), Some(&token));
        conn.account = Some(format!("attacker.example{delimiter}x"));
        let host = crate::sql::client::host(&conn).unwrap();
        assert!(message(&conn, &host).contains("251021"), "{host}");
    }
    let mut conn = wif_conn(Some("OIDC"), None);
    conn.token_file_path = Some("/nonexistent/token".into());
    assert!(message(&conn, host).contains("Couldn't read the token file /nonexistent/token"));
}
