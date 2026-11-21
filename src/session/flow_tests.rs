//! Every sign-in flow of ADR 0005 Decision 4 against a mocked Snowflake (and IdP) that checks the
//! request shapes the connector sends: `Session::login` with fake prompt, browser and cache.

use super::*;
use crate::session::cache::{TokenKey, TokenType};
use httpmock::{HttpMockRequest, HttpMockResponse, Method::GET, Method::POST, MockServer};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// PKCE S256: `base64url(sha256(verifier))`.
fn pkce(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

const LOGIN: &str = "/session/v1/login-request";
const AUTHENTICATOR_REQUEST: &str = "/session/authenticator-request";
const QUERY: &str = "/queries/v1/query-request";
const PASSWORD: &str = "PW-SECRET-MARKER";

fn conn(server: &MockServer, authenticator: &str) -> ConnectionConfig {
    ConnectionConfig {
        account: Some("testacct".into()),
        user: Some("tester".into()),
        host: Some(server.host()),
        port: Some(server.port()),
        protocol: Some("http".into()),
        authenticator: Some(authenticator.into()),
        password: Some(Secret::new(PASSWORD)),
        ..Default::default()
    }
}

/// The `data` of a JSON request body.
fn data(req: &HttpMockRequest) -> Value {
    let body: Value = serde_json::from_str(&req.body_string()).unwrap_or_default();
    body["data"].clone()
}

/// A response body captured from the sandbox by `scripts/capture-connector-fixtures.py`.
fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/connector")
        .join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The captured successful `login-request` answer, with this session token.
fn ok_login(token: &str) -> Value {
    let mut body = fixture("login-request-success");
    body["data"]["token"] = token.into();
    body["data"]["masterToken"] = "master".into();
    body
}

#[derive(Default)]
struct FakePrompt {
    answers: Mutex<Vec<String>>,
    said: Mutex<Vec<String>>,
}

impl FakePrompt {
    fn answering(answer: &str) -> Self {
        Self {
            answers: Mutex::new(vec![answer.to_string()]),
            ..Self::default()
        }
    }
}

impl Prompt for FakePrompt {
    fn prompt(&self, _label: &str, _hidden: bool) -> Result<String> {
        self.answers
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Aborted, "no answer"))
    }
    fn say(&self, line: &str) {
        self.said.lock().unwrap().push(line.to_string());
    }
}

/// A browser that is not there.
struct NoBrowser;
impl BrowserOpener for NoBrowser {
    fn open(&self, _url: &str) -> bool {
        false
    }
}

/// A browser that plays the IdP: `act` gets the URL and does what the IdP's redirect would.
struct FakeBrowser<F: Fn(String) + Send + Sync + Clone + 'static>(F);
impl<F: Fn(String) + Send + Sync + Clone + 'static> BrowserOpener for FakeBrowser<F> {
    fn open(&self, url: &str) -> bool {
        let act = self.0.clone();
        let url = url.to_string();
        std::thread::spawn(move || act(url));
        true
    }
}

#[derive(Default)]
struct MemoryCache(Mutex<HashMap<String, String>>);
impl CredentialCache for MemoryCache {
    fn retrieve(&self, key: &TokenKey) -> Option<Secret> {
        self.0
            .lock()
            .unwrap()
            .get(&key.hash()?)
            .map(|t| Secret::new(t.as_str()))
    }
    fn store(&self, key: &TokenKey, token: &Secret) {
        if let Some(hash) = key.hash() {
            self.0
                .lock()
                .unwrap()
                .insert(hash, token.expose().to_string());
        }
    }
    fn remove(&self, key: &TokenKey) {
        if let Some(hash) = key.hash() {
            self.0.lock().unwrap().remove(&hash);
        }
    }
}

impl MemoryCache {
    fn get(&self, key: &TokenKey) -> Option<String> {
        self.retrieve(key).map(|s| s.expose().to_string())
    }
}

fn login_with(
    conn: &ConnectionConfig,
    options: SessionOptions,
    prompt: &dyn Prompt,
    browser: &dyn BrowserOpener,
    cache: &dyn CredentialCache,
) -> Result<Session> {
    // A browser that never calls back must not hold a test for two minutes.
    let options = SessionOptions {
        browser_timeout: options.browser_timeout.min(Duration::from_secs(10)),
        ..options
    };
    let io = Interaction {
        credential: None,
        prompt,
        browser,
        cache,
        clock: SystemTime::now,
    };
    Session::login(conn, options, &io)
}

fn login(conn: &ConnectionConfig) -> Result<Session> {
    login_with(
        conn,
        SessionOptions::default(),
        &FakePrompt::default(),
        &NoBrowser,
        &NoCache,
    )
}

/// GET `http://127.0.0.1:<port><target>` with `headers`, and an optional body (POST).
fn call(port: u16, method: &str, target: &str, headers: &[(&str, &str)], body: &str) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut raw = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for (n, v) in headers {
        raw.push_str(&format!("{n}: {v}\r\n"));
    }
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(raw.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
}

fn assert_no_secret(err: &Error) {
    let text = format!("{err} {err:?}");
    assert!(!text.contains(PASSWORD), "{text}");
}

// ------------------------------------------------------------------ SNOWFLAKE (password)

#[test]
fn password_sign_in_sends_the_password_and_runs_queries() {
    let server = MockServer::start();
    let login_mock = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .header("accept", "application/json")
            .is_true(|req| {
                let d = data(req);
                d["PASSWORD"] == PASSWORD
                    && d["LOGIN_NAME"] == "tester"
                    && d["ACCOUNT_NAME"] == "testacct"
                    && d.get("AUTHENTICATOR").is_none()
                    && d.get("EXT_AUTHN_DUO_METHOD").is_none()
                    && d["SESSION_PARAMETERS"]["PYTHON_CONNECTOR_QUERY_RESULT_FORMAT"] == "json"
            });
        then.status(200).json_body(ok_login("tok"));
    });
    let query = server.mock(|when, then| {
        when.method(POST)
            .path(QUERY)
            .header("authorization", "Snowflake Token=\"tok\"");
        then.status(200).json_body(fixture("query-request-select"));
    });
    let close = server.mock(|when, then| {
        when.method(POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(fixture("close"));
    });
    let session = login(&conn(&server, "SNOWFLAKE")).unwrap();
    let rows = session
        .query("SELECT 1")
        .unwrap()
        .into_rows(&session)
        .unwrap()
        .into_result()
        .unwrap();
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(
        rows.columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        ["N", "S", "B"]
    );
    session.close().unwrap();
    login_mock.assert();
    query.assert();
    close.assert();
}

#[test]
fn a_rejected_password_reads_like_snow_and_hides_the_password() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(json!({
            "success": false, "code": "390100",
            "message": "Incorrect username or password was specified.",
        }));
    });
    let err = login(&conn(&server, "snowflake")).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::Connection);
    assert_eq!(
        err.message(),
        format!(
            "Could not connect to Snowflake. Reason: 390100 (28000): Failed to connect to DB: {}:{}. Incorrect username or password was specified.",
            server.host(),
            server.port()
        )
    );
    assert_no_secret(&err);
}

#[test]
fn an_mfa_passcode_goes_with_the_password() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["EXT_AUTHN_DUO_METHOD"] == "passcode" && d["PASSCODE"] == "123456"
        });
        then.status(200).json_body(ok_login("tok"));
    });
    let mut c = conn(&server, "SNOWFLAKE");
    c.passcode = Some(Secret::new("123456"));
    login(&c).unwrap();
    mock.assert();
}

#[test]
fn a_duo_push_is_waited_for_then_the_tokens_are_collected() {
    let server = MockServer::start();
    let first = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .body_excludes("inFlightCtx")
            .is_true(|req| data(req)["PASSWORD"] == PASSWORD);
        then.status(200).json_body(json!({"success": true, "data": {
            "nextAction": "EXT_AUTHN_DUO_ALL", "inFlightCtx": "ctx-1",
        }}));
    });
    let push = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let body: Value = serde_json::from_str(&req.body_string()).unwrap_or_default();
            body["inFlightCtx"] == "ctx-1"
                && body["data"]["EXT_AUTHN_DUO_METHOD"] == "push"
                && body["data"]["PASSWORD"] == PASSWORD
        });
        then.status(200).json_body(json!({"success": true, "data": {
            "nextAction": "EXT_AUTHN_SUCCESS", "inFlightCtx": "ctx-2",
        }}));
    });
    let collect = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let body: Value = serde_json::from_str(&req.body_string()).unwrap_or_default();
            body["inFlightCtx"] == "ctx-2" && body["data"].get("PASSWORD").is_none()
        });
        then.status(200).json_body(ok_login("tok"));
    });
    login(&conn(&server, "SNOWFLAKE")).unwrap();
    first.assert();
    push.assert();
    collect.assert();
}

#[test]
fn a_denied_duo_push_fails_with_the_connector_text() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN).body_excludes("inFlightCtx");
        then.status(200).json_body(json!({"success": true, "data": {
            "nextAction": "EXT_AUTHN_DUO_PUSH_N_PASSCODE", "inFlightCtx": "c",
        }}));
    });
    server.mock(|when, then| {
        when.method(POST).path(LOGIN).body_includes("inFlightCtx");
        then.status(200)
            .json_body(json!({"success": false, "message": "Push denied.", "data": {}}));
    });
    let err = login(&conn(&server, "SNOWFLAKE")).err().unwrap();
    assert!(
        err.message()
            .contains("Failed to connect to DB. MFA authentication failed:"),
        "{}",
        err.message()
    );
    assert!(err.message().ends_with("Push denied."));
}

// ------------------------------------------------------------- USERNAME_PASSWORD_MFA

#[test]
fn username_password_mfa_caches_the_mfa_token_and_drops_it_on_failure() {
    let server = MockServer::start();
    let cache = MemoryCache::default();
    let c = conn(&server, "USERNAME_PASSWORD_MFA");
    let key = TokenKey::sign_in("tester", &server.host(), TokenType::MfaToken);
    let mut first = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["PASSWORD"] == PASSWORD
                && d.get("TOKEN").is_none()
                && d.get("AUTHENTICATOR").is_none()
                && d["SESSION_PARAMETERS"]["CLIENT_REQUEST_MFA_TOKEN"] == true
        });
        then.status(200).json_body(json!({"success": true, "data": {
            "token": "tok", "masterToken": "m", "mfaToken": "MFA-1",
        }}));
    });
    let prompt = FakePrompt::default();
    login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &cache).unwrap();
    first.assert();
    assert_eq!(cache.get(&key).as_deref(), Some("MFA-1"));
    first.delete();

    let second = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["TOKEN"] == "MFA-1");
        then.status(200).json_body(ok_login("tok"));
    });
    login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &cache).unwrap();
    second.assert();
    assert_eq!(
        cache.get(&key).as_deref(),
        Some("MFA-1"),
        "kept: no new token"
    );

    let mut second = second;
    second.delete();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(
            json!({"success": false, "code": "394508", "message": "MFA token expired."}),
        );
    });
    let err = login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &cache)
        .err()
        .unwrap();
    assert!(err.message().contains("394508 (08001)"));
    assert_eq!(cache.get(&key), None, "dropped after a rejection");
}

// ------------------------------------------------------------------- EXTERNALBROWSER

/// `authenticator-request` answering with an SSO URL that names the callback port.
fn sso(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(POST)
            .path(AUTHENTICATOR_REQUEST)
            .is_true(|req| {
                let d = data(req);
                d["AUTHENTICATOR"] == "EXTERNALBROWSER" && d["LOGIN_NAME"] == "tester"
            });
        then.respond_with(|req: &HttpMockRequest| {
            let port = data(req)["BROWSER_MODE_REDIRECT_PORT"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(
                    json!({"success": true, "data": {
                        "ssoUrl": format!("https://idp.example/sso?port={port}"),
                        "proofKey": "PROOF",
                    }})
                    .to_string(),
                )
                .build()
        });
    })
}

fn browser_login<'a>(server: &'a MockServer, token: &str) -> httpmock::Mock<'a> {
    let token = token.to_string();
    server.mock(move |when, then| {
        when.method(POST).path(LOGIN).is_true(move |req| {
            let d = data(req);
            d["AUTHENTICATOR"] == "EXTERNALBROWSER"
                && d["TOKEN"] == token.as_str()
                && d["PROOF_KEY"] == "PROOF"
        });
        then.status(200).json_body(json!({"success": true, "data": {
            "token": "tok", "masterToken": "m", "idToken": "ID-1",
        }}));
    })
}

fn port_of(url: &str) -> u16 {
    callback::query_param(url, "port").unwrap().parse().unwrap()
}

#[test]
fn external_browser_gets_the_saml_token_on_the_callback_and_caches_the_id_token() {
    let server = MockServer::start();
    let sso = sso(&server);
    let login_mock = browser_login(&server, "SAML-1");
    let cache = MemoryCache::default();
    let mut c = conn(&server, "externalbrowser");
    c.password = None;
    c.client_store_temporary_credential = Some(true);
    let prompt = FakePrompt::default();
    let browser = FakeBrowser(|url: String| {
        // An unrelated request first: ignored.
        call(port_of(&url), "GET", "/favicon.ico", &[], "");
        call(port_of(&url), "GET", "/?token=SAML-1", &[], "");
    });
    login_with(&c, SessionOptions::default(), &prompt, &browser, &cache).unwrap();
    sso.assert();
    login_mock.assert();
    let key = TokenKey::sign_in("tester", &server.host(), TokenType::IdToken);
    assert_eq!(cache.get(&key).as_deref(), Some("ID-1"));
    let said = prompt.said.lock().unwrap().join("\n");
    assert!(
        said.contains("Going to open: https://idp.example/sso?port="),
        "{said}"
    );

    // Next time the cached ID token signs in, without a browser.
    let id = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["AUTHENTICATOR"] == "ID_TOKEN"
                && d["TOKEN"] == "ID-1"
                && d["SESSION_PARAMETERS"]["CLIENT_STORE_TEMPORARY_CREDENTIAL"] == true
        });
        then.status(200).json_body(ok_login("tok"));
    });
    login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &cache).unwrap();
    id.assert();
}

#[test]
fn an_expired_id_token_falls_back_to_the_browser() {
    let server = MockServer::start();
    let cache = MemoryCache::default();
    let key = TokenKey::sign_in("tester", &server.host(), TokenType::IdToken);
    cache.store(&key, &Secret::new("OLD-ID"));
    let rejected = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["AUTHENTICATOR"] == "ID_TOKEN");
        then.status(200)
            .json_body(json!({"success": false, "code": "390195", "message": "ID token expired."}));
    });
    let sso = sso(&server);
    let login_mock = browser_login(&server, "SAML-2");
    let mut c = conn(&server, "EXTERNALBROWSER");
    c.client_store_temporary_credential = Some(true);
    let browser = FakeBrowser(|url: String| call(port_of(&url), "GET", "/?token=SAML-2", &[], ""));
    login_with(
        &c,
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &cache,
    )
    .unwrap();
    rejected.assert();
    sso.assert();
    login_mock.assert();
    assert_eq!(cache.get(&key).as_deref(), Some("ID-1"), "replaced");
}

#[test]
fn the_browser_may_post_the_token_from_snowflakes_origin_only() {
    let server = MockServer::start();
    sso(&server);
    let login_mock = browser_login(&server, "SAML-3");
    let cache = MemoryCache::default();
    let mut c = conn(&server, "EXTERNALBROWSER");
    c.client_store_temporary_credential = Some(true);
    let origin = format!("http://{}:{}", server.host(), server.port());
    let browser = FakeBrowser(move |url: String| {
        let port = port_of(&url);
        // A page elsewhere cannot hand over a token.
        call(
            port,
            "POST",
            "/",
            &[("Origin", "https://evil.example")],
            r#"{"token":"EVIL"}"#,
        );
        call(
            port,
            "OPTIONS",
            "/",
            &[
                ("Origin", "https://evil.example"),
                ("Access-Control-Request-Method", "POST"),
            ],
            "",
        );
        call(
            port,
            "OPTIONS",
            "/",
            &[
                ("Origin", &origin),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "Content-Type"),
            ],
            "",
        );
        call(
            port,
            "POST",
            "/",
            &[("Origin", &origin), ("Content-Type", "application/json")],
            r#"{"token":"SAML-3","consent":false}"#,
        );
    });
    login_with(
        &c,
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &cache,
    )
    .unwrap();
    login_mock.assert();
    let key = TokenKey::sign_in("tester", &server.host(), TokenType::IdToken);
    assert_eq!(cache.get(&key), None, "the user refused caching");
}

#[test]
fn without_a_browser_the_redirected_url_is_pasted() {
    let server = MockServer::start();
    sso(&server);
    let login_mock = browser_login(&server, "SAML-4");
    let mut c = conn(&server, "EXTERNALBROWSER");
    c.client_store_temporary_credential = Some(false);
    let prompt = FakePrompt::answering("http://localhost:1/?token=SAML-4");
    login_with(
        &c,
        SessionOptions::default(),
        &prompt,
        &NoBrowser,
        &MemoryCache::default(),
    )
    .unwrap();
    login_mock.assert();
    let said = prompt.said.lock().unwrap().join("\n");
    assert!(said.contains("We were unable to open a browser window for you"));

    let prompt = FakePrompt::answering("http://localhost:1/?nothing");
    let err = login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &NoCache)
        .err()
        .unwrap();
    assert!(
        err.message().contains("250008 (08001)"),
        "{}",
        err.message()
    );
    assert!(err.message().ends_with("SSO URL contained no token"));
}

#[test]
fn the_browser_wait_times_out_and_bad_sso_urls_are_refused() {
    let server = MockServer::start();
    sso(&server);
    let c = conn(&server, "EXTERNALBROWSER");
    let options = SessionOptions {
        browser_timeout: Duration::from_millis(200),
        ..SessionOptions::default()
    };
    let browser = FakeBrowser(|_url: String| {});
    let err = login_with(&c, options, &FakePrompt::default(), &browser, &NoCache)
        .err()
        .unwrap();
    assert!(
        err.message().contains("Timed out after 0 second(s)"),
        "{}",
        err.message()
    );

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(AUTHENTICATOR_REQUEST);
        then.status(200).json_body(
            json!({"success": true, "data": {"ssoUrl": "javascript:alert(1)", "proofKey": "p"}}),
        );
    });
    let err = login(&conn(&server, "EXTERNALBROWSER")).err().unwrap();
    assert!(
        err.message()
            .contains("The SSO URL provided javascript:alert(1) is invalid")
    );

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(AUTHENTICATOR_REQUEST);
        then.status(200)
            .json_body(json!({"success": false, "code": "390190", "message": "SAML not set up."}));
    });
    let err = login(&conn(&server, "EXTERNALBROWSER")).err().unwrap();
    assert!(
        err.message().ends_with(&format!(
            "390190 (08001): Failed to connect to DB: {}:{}, SAML not set up.",
            server.host(),
            server.port()
        )),
        "{}",
        err.message()
    );
}

// ----------------------------------------------------------------------------- Okta

fn okta_conn(server: &MockServer) -> (ConnectionConfig, SessionOptions) {
    let c = conn(server, "https://org.okta.com");
    let options = SessionOptions {
        idp_override: Some(server.base_url()),
        ..SessionOptions::default()
    };
    (c, options)
}

fn okta_authenticator<'a>(server: &'a MockServer, token_url: &str) -> httpmock::Mock<'a> {
    let token_url = token_url.to_string();
    server.mock(move |when, then| {
        when.method(POST)
            .path(AUTHENTICATOR_REQUEST)
            .is_true(|req| data(req)["AUTHENTICATOR"] == "https://org.okta.com");
        then.status(200).json_body(json!({"success": true, "data": {
            "tokenUrl": token_url, "ssoUrl": "https://org.okta.com/app/snowflake/sso/saml",
        }}));
    })
}

#[test]
fn okta_trades_the_password_for_a_saml_response() {
    let server = MockServer::start();
    let (c, options) = okta_conn(&server);
    okta_authenticator(&server, "https://org.okta.com/api/v1/authn");
    let authn = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/authn")
            .json_body(json!({"username": "tester", "password": PASSWORD}));
        then.status(200).json_body(json!({"sessionToken": "OTT"}));
    });
    let html = format!(
        r#"<html><form method="post" action="http&#x3a;&#x2f;&#x2f;{}&#x3a;{}&#x2f;fed&#x2f;login"><input name="SAMLResponse" value="x"/></form></html>"#,
        server.host(),
        server.port()
    );
    let sso_html = html.clone();
    let sso = server.mock(move |when, then| {
        when.method(GET)
            .path("/app/snowflake/sso/saml")
            .query_param("RelayState", "/some/deep/link")
            .query_param("onetimetoken", "OTT");
        then.status(200).body(sso_html);
    });
    let login_mock = server.mock(move |when, then| {
        when.method(POST).path(LOGIN).is_true(move |req| {
            let d = data(req);
            d["RAW_SAML_RESPONSE"] == html.as_str() && d.get("AUTHENTICATOR").is_none()
        });
        then.status(200).json_body(ok_login("tok"));
    });
    login_with(&c, options, &FakePrompt::default(), &NoBrowser, &NoCache).unwrap();
    authn.assert();
    sso.assert();
    login_mock.assert();
}

#[test]
fn okta_refuses_a_foreign_idp_and_a_foreign_post_back() {
    let server = MockServer::start();
    let (c, options) = okta_conn(&server);
    let mut phishing = okta_authenticator(&server, "https://evil.example/api/v1/authn");
    let err = login_with(
        &c,
        options.clone(),
        &FakePrompt::default(),
        &NoBrowser,
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(
        err.message().contains("250006 (08001): The specified authenticator is not supported: https://org.okta.com, token_url: https://evil.example/api/v1/authn"),
        "{}",
        err.message()
    );
    phishing.delete();

    okta_authenticator(&server, "https://org.okta.com/api/v1/authn");
    let mut authn = server.mock(|when, then| {
        when.method(POST).path("/api/v1/authn");
        then.status(401).json_body(json!({"errorCode": "E0000004"}));
    });
    let err = login_with(
        &c,
        options.clone(),
        &FakePrompt::default(),
        &NoBrowser,
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(
        err.message()
            .contains("The authentication failed for tester by https://org.okta.com/api/v1/authn.")
    );
    assert_no_secret(&err);
    authn.delete();

    server.mock(|when, then| {
        when.method(POST).path("/api/v1/authn");
        then.status(200).json_body(json!({"cookieToken": "OTT"}));
    });
    server.mock(|when, then| {
        when.method(GET).path("/app/snowflake/sso/saml");
        then.status(200)
            .body(r#"<form action="https://evil.example/fed/login"></form>"#);
    });
    let err = login_with(&c, options, &FakePrompt::default(), &NoBrowser, &NoCache)
        .err()
        .unwrap();
    assert!(
        err.message().contains("250007 (08001): The specified authenticator and destination URL in the SAML assertion do not match"),
        "{}",
        err.message()
    );
}

// --------------------------------------------------------------- OAuth authorization code

fn oauth_conn(server: &MockServer) -> ConnectionConfig {
    let mut c = conn(server, "OAUTH_AUTHORIZATION_CODE");
    c.password = None;
    c.role = Some("ANALYST".into());
    c.oauth_authorization_url = Some("http://{host}:{port}/oauth/authorize".into());
    c.oauth_token_request_url = Some("http://{host}:{port}/oauth/token-request".into());
    c
}

/// The IdP's browser side: follows the authorization URL to the redirect URI with `code`,
/// echoing `state` (or `bad_state`), and records the PKCE challenge.
fn idp_browser(
    challenge: Arc<Mutex<Option<String>>>,
    bad_state: Option<&'static str>,
) -> impl Fn(String) + Send + Sync + Clone + 'static {
    move |url: String| {
        let redirect = callback::query_param(&url, "redirect_uri").unwrap();
        let state = callback::query_param(&url, "state").unwrap();
        assert_eq!(
            callback::query_param(&url, "response_type").as_deref(),
            Some("code")
        );
        assert_eq!(
            callback::query_param(&url, "client_id").as_deref(),
            Some("LOCAL_APPLICATION")
        );
        // `offline_access` joins when refresh tokens are on (the IdP is not a Snowflake host).
        assert!(
            callback::query_param(&url, "scope")
                .is_some_and(|s| s.starts_with("session:role:ANALYST"))
        );
        *challenge.lock().unwrap() = callback::query_param(&url, "code_challenge");
        let port: u16 = redirect.rsplit(':').next().unwrap().parse().unwrap();
        let state = bad_state.map(str::to_string).unwrap_or(state);
        call(
            port,
            "GET",
            &format!("/?code=CODE-1&state={state}"),
            &[],
            "",
        );
    }
}

fn form(req: &HttpMockRequest, name: &str) -> Option<String> {
    callback::form_param(&req.body_string(), name)
}

#[test]
fn authorization_code_with_pkce_then_the_cached_and_refreshed_tokens() {
    let server = MockServer::start();
    let challenge = Arc::new(Mutex::new(None::<String>));
    let seen = challenge.clone();
    let code_grant = server.mock(move |when, then| {
        when.method(POST)
            .path("/oauth/token-request")
            .header(
                "authorization",
                "Basic TE9DQUxfQVBQTElDQVRJT046TE9DQUxfQVBQTElDQVRJT04=",
            )
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .is_true(move |req| {
                let verifier = form(req, "code_verifier").unwrap_or_default();
                let expected = seen.lock().unwrap().clone();
                form(req, "grant_type").as_deref() == Some("authorization_code")
                    && form(req, "code").as_deref() == Some("CODE-1")
                    && form(req, "redirect_uri").is_some_and(|r| r.starts_with("http://127.0.0.1:"))
                    && form(req, "enable_single_use_refresh_tokens").as_deref() == Some("true")
                    && expected == Some(pkce(&verifier))
            });
        then.status(200)
            .json_body(json!({"access_token": "AT-1", "refresh_token": "RT-1"}));
    });
    let login_1 = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["AUTHENTICATOR"] == "OAUTH"
                && d["TOKEN"] == "AT-1"
                && d["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_authorization_code"
        });
        then.status(200).json_body(ok_login("tok"));
    });
    let cache = MemoryCache::default();
    let mut c = oauth_conn(&server);
    c.client_store_temporary_credential = Some(true);
    c.oauth_enable_refresh_tokens = Some(true);
    c.oauth_enable_single_use_refresh_tokens = Some(true);
    let browser = FakeBrowser(idp_browser(challenge, None));
    login_with(
        &c,
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &cache,
    )
    .unwrap();
    code_grant.assert();
    login_1.assert();
    let host = server.host();
    let access = TokenKey::oauth(&host, "tester", TokenType::OAuthAccessToken);
    let refresh = TokenKey::oauth(&host, "tester", TokenType::OAuthRefreshToken);
    assert_eq!(cache.get(&access).as_deref(), Some("AT-1"));
    assert_eq!(cache.get(&refresh).as_deref(), Some("RT-1"));

    // The cached access token has expired: the refresh token gets a new one, no browser.
    let mut login_1 = login_1;
    login_1.delete();
    let expired = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["TOKEN"] == "AT-1");
        then.status(200).json_body(
            json!({"success": false, "code": "390318", "message": "OAuth access token expired."}),
        );
    });
    let refresh_grant = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token-request")
            .is_true(|req| {
                form(req, "grant_type").as_deref() == Some("refresh_token")
                    && form(req, "refresh_token").as_deref() == Some("RT-1")
            });
        then.status(200).json_body(json!({"access_token": "AT-2"}));
    });
    let login_2 = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["TOKEN"] == "AT-2");
        then.status(200).json_body(ok_login("tok"));
    });
    login_with(
        &c,
        SessionOptions::default(),
        &FakePrompt::default(),
        &NoBrowser,
        &cache,
    )
    .unwrap();
    expired.assert();
    refresh_grant.assert();
    login_2.assert();
    assert_eq!(cache.get(&access).as_deref(), Some("AT-2"));
    assert_eq!(
        cache.get(&refresh).as_deref(),
        Some("RT-1"),
        "kept: none returned"
    );
}

/// Stray requests (`/`, `/favicon.ico`) reach the callback port before the real redirect, whose
/// query is `redirect_query` with `{state}` replaced by the flow's state.
fn browser_with_strays(
    redirect_query: &'static str,
) -> impl Fn(String) + Send + Sync + Clone + 'static {
    move |url: String| {
        let redirect = callback::query_param(&url, "redirect_uri").unwrap();
        let state = callback::query_param(&url, "state").unwrap();
        let port: u16 = redirect.rsplit(':').next().unwrap().parse().unwrap();
        call(port, "GET", "/", &[], "");
        call(port, "GET", "/favicon.ico", &[], "");
        call(
            port,
            "GET",
            &format!("/?{}", redirect_query.replace("{state}", &state)),
            &[],
            "",
        );
    }
}

#[test]
fn stray_requests_before_the_redirect_do_not_break_the_authorization_code_sign_in() {
    let server = MockServer::start();
    let code_grant = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token-request")
            .is_true(|req| form(req, "code").as_deref() == Some("CODE-1"));
        then.status(200).json_body(json!({"access_token": "AT-1"}));
    });
    let login = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["TOKEN"] == "AT-1");
        then.status(200).json_body(ok_login("tok"));
    });
    let browser = FakeBrowser(browser_with_strays("code=CODE-1&state={state}"));
    login_with(
        &oauth_conn(&server),
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &NoCache,
    )
    .unwrap();
    code_grant.assert();
    login.assert();
}

#[test]
fn an_idp_error_after_stray_requests_still_fails_the_sign_in() {
    let server = MockServer::start();
    let browser = FakeBrowser(browser_with_strays(
        "error=access_denied&error_description=Denied",
    ));
    let err = login_with(
        &oauth_conn(&server),
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(
        err.message()
            .contains("Oauth callback returned an access_denied error: Denied"),
        "{}",
        err.message()
    );
}

#[test]
fn a_rejected_oauth_token_twice_fails_with_snows_hint() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token-request");
        then.status(200).json_body(json!({"access_token": "AT"}));
    });
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(
            json!({"success": false, "code": "390303", "message": "Invalid OAuth access token."}),
        );
    });
    let challenge = Arc::new(Mutex::new(None));
    let browser = FakeBrowser(idp_browser(challenge, None));
    let err = login_with(
        &oauth_conn(&server),
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(err.message().contains("390303 (08001)"));
    assert!(
        err.message()
            .contains("\nSilent OAuth refresh is disabled."),
        "{}",
        err.message()
    );
}

#[test]
fn a_changed_state_or_an_idp_error_stops_the_flow() {
    let server = MockServer::start();
    let challenge = Arc::new(Mutex::new(None));
    let browser = FakeBrowser(idp_browser(challenge, Some("forged")));
    let err = login_with(
        &oauth_conn(&server),
        SessionOptions::default(),
        &FakePrompt::default(),
        &browser,
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(err.message().contains("251014 (08001)"));
    assert!(
        err.message()
            .ends_with("State changed during OAuth process.")
    );

    // No browser: the pasted URL carries the IdP's error.
    let mut c = oauth_conn(&server);
    c.oauth_disable_pkce = Some(true);
    let prompt =
        FakePrompt::answering("http://127.0.0.1:1/?error=access_denied&error_description=Denied");
    let err = login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &NoCache)
        .err()
        .unwrap();
    assert!(
        err.message()
            .contains("Oauth callback returned an access_denied error: Denied")
    );
    let said = prompt.said.lock().unwrap().join("\n");
    assert!(!said.contains("code_challenge"), "PKCE is off: {said}");
    assert!(said.contains("response_type=code"));

    let prompt = FakePrompt::answering("http://127.0.0.1:1/?nothing=1");
    let err = login_with(&c, SessionOptions::default(), &prompt, &NoBrowser, &NoCache)
        .err()
        .unwrap();
    assert!(err.message().ends_with("OAuth URL contained no code"));

    let options = SessionOptions {
        browser_timeout: Duration::from_millis(100),
        ..SessionOptions::default()
    };
    let err = login_with(
        &c,
        options,
        &FakePrompt::default(),
        &FakeBrowser(|_u: String| {}),
        &NoCache,
    )
    .err()
    .unwrap();
    assert!(
        err.message().contains("251016 (08001)"),
        "{}",
        err.message()
    );
}

// ------------------------------------------------------------- OAuth client credentials

#[test]
fn client_credentials_get_a_token_with_basic_auth() {
    let server = MockServer::start();
    let grant = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token-request")
            .header("authorization", "Basic aWQ6U0VDUkVULU1BUktFUg==")
            .body("grant_type=client_credentials&scope=session%3Arole%3AANALYST");
        then.status(200).json_body(json!({"access_token": "AT-CC"}));
    });
    let login_mock = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["AUTHENTICATOR"] == "OAUTH"
                && d["TOKEN"] == "AT-CC"
                && d["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_client_credentials"
        });
        then.status(200).json_body(ok_login("tok"));
    });
    let mut c = oauth_conn(&server);
    c.authenticator = Some("OAUTH_CLIENT_CREDENTIALS".into());
    c.oauth_client_id = Some("id".into());
    c.oauth_client_secret = Some(Secret::new("SECRET-MARKER"));
    login(&c).unwrap();
    grant.assert();
    login_mock.assert();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token-request");
        then.status(400).json_body(
            json!({"error": "invalid_client", "error_description": "SECRET-MARKER bad"}),
        );
    });
    let mut c2 = oauth_conn(&server);
    c2.authenticator = Some("OAUTH_CLIENT_CREDENTIALS".into());
    c2.oauth_client_id = Some("id".into());
    c2.oauth_client_secret = Some(Secret::new("SECRET-MARKER"));
    let err = login(&c2).err().unwrap();
    assert!(err.message().contains("250006 (08001)"));
    assert!(
        err.message()
            .ends_with("Idp authentication could have failed.")
    );
    assert!(!format!("{err:?}").contains("SECRET-MARKER"));
}

// ------------------------------------------------------------------ keep-alive, close

#[test]
fn the_heartbeat_runs_while_open_and_server_keep_alive_skips_the_close() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(json!({"success": true, "data": {
            "token": "tok", "masterToken": "m", "masterValidityInSeconds": 16,
        }}));
    });
    let heartbeat = server.mock(|when, then| {
        when.method(POST)
            .path("/session/heartbeat")
            .header("authorization", "Snowflake Token=\"tok\"");
        then.status(200).json_body(json!({"success": true}));
    });
    let close = server.mock(|when, then| {
        when.method(POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(json!({"success": true}));
    });
    let mut c = conn(&server, "SNOWFLAKE");
    c.client_session_keep_alive = Some(true);
    c.client_session_keep_alive_heartbeat_frequency = Some(1);
    c.server_session_keep_alive = Some(true);
    let env = crate::env::Env::from_pairs(Vec::<(String, String)>::new());
    let options = SessionOptions::default().with_connection(&c, &env);
    let session = login_with(&c, options, &FakePrompt::default(), &NoBrowser, &NoCache).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while heartbeat.calls() < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(heartbeat.calls() >= 1, "no heartbeat");
    session.close().unwrap();
    close.assert_calls(0);
    let after = heartbeat.calls();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(heartbeat.calls(), after, "stopped at close");
}

#[test]
fn bearer_oauth_rejections_carry_snows_hint() {
    struct Token;
    impl Authenticator for Token {
        fn authorization(&self) -> Result<crate::auth::AuthHeader> {
            Ok(crate::auth::AuthHeader {
                token: Secret::new("raw"),
                token_type: crate::auth::token::OAUTH,
            })
        }
    }
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["AUTHENTICATOR"] == "OAUTH");
        then.status(200).json_body(
            json!({"success": false, "code": "390318", "message": "OAuth access token expired."}),
        );
    });
    let io = Interaction {
        credential: Some(&Token),
        prompt: &FakePrompt::default(),
        browser: &NoBrowser,
        cache: &NoCache,
        clock: SystemTime::now,
    };
    let err = Session::login(&conn(&server, "OAUTH"), SessionOptions::default(), &io)
        .err()
        .unwrap();
    assert!(
        err.message()
            .contains("\nSnowflake CLI cannot renew a raw OAuth token")
    );
}

#[test]
fn an_expired_session_token_is_renewed_with_the_master_token() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(ok_login("tok"));
    });
    let expired = server.mock(|when, then| {
        when.method(POST)
            .path(QUERY)
            .header("authorization", "Snowflake Token=\"tok\"");
        then.status(200).json_body(
            json!({"success": false, "code": "390112", "message": "Your session has expired."}),
        );
    });
    let mut renewed = fixture("token-request");
    renewed["data"]["sessionToken"] = "tok2".into();
    renewed["data"]["masterToken"] = "master2".into();
    let renew = server.mock(move |when, then| {
        when.method(POST)
            .path("/session/token-request")
            .header("authorization", "Snowflake Token=\"master\"")
            .json_body(json!({"oldSessionToken": "tok", "requestType": "RENEW"}));
        then.status(200).json_body(renewed);
    });
    let replay = server.mock(|when, then| {
        when.method(POST)
            .path(QUERY)
            .header("authorization", "Snowflake Token=\"tok2\"");
        then.status(200).json_body(fixture("query-request-select"));
    });
    let session = login(&conn(&server, "SNOWFLAKE")).unwrap();
    session.query("SELECT 1").unwrap();
    expired.assert();
    renew.assert();
    replay.assert();
}
