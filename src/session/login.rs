//! `login-request`: body, URL, response and error text (ADR 0005, Decisions 1 and 4).

use super::{APPLICATION, SessionOptions, Target, malformed, parse, status_error};
use crate::codec::form_encode_plus;
use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;

/// The connector's `ER_FAILED_TO_CONNECT_TO_DB`.
pub(super) const FAILED_TO_CONNECT: u32 = 250001;
/// SQL states of a failed sign-in (`C/sqlstate.py`).
pub(super) const NOT_ESTABLISHED: &str = "08001";
const AUTHORIZATION_FAILURE: &str = "28000";
/// Codes the connector reports as `28000` (`C/network.py`, `CREDENTIAL_REJECTION_GS_CODES`).
const CREDENTIAL_REJECTION: [&str; 9] = [
    "390100", "390144", "394300", "394301", "394302", "394303", "394304", "394305", "394306",
];
/// `nextAction` values asking for a Duo push (`C/auth/_auth.py`).
const DUO_PUSH: [&str; 2] = ["EXT_AUTHN_DUO_ALL", "EXT_AUTHN_DUO_PUSH_N_PASSCODE"];
const DUO_SUCCESS: &str = "EXT_AUTHN_SUCCESS";

/// What a flow adds to the `data` of `login-request`.
#[derive(Default)]
pub(super) struct LoginFields {
    /// `AUTHENTICATOR`, `TOKEN`, `PASSWORD`, `PROOF_KEY`, `RAW_SAML_RESPONSE`, …: credentials, so
    /// all are [`Secret`]s.
    pub fields: Vec<(&'static str, Secret)>,
    /// Added to `CLIENT_ENVIRONMENT` (`OAUTH_TYPE`).
    pub client_environment: Vec<(&'static str, &'static str)>,
    /// Added to `SESSION_PARAMETERS` (`CLIENT_STORE_TEMPORARY_CREDENTIAL`, …).
    pub session_parameters: Vec<(&'static str, serde_json::Value)>,
}

impl LoginFields {
    pub fn with(mut self, name: &'static str, value: impl Into<Secret>) -> Self {
        self.fields.push((name, value.into()));
        self
    }
}

/// `/session/v1/login-request?request_id=…[&databaseName&schemaName&warehouse&roleName]`.
pub(super) fn path(conn: &ConnectionConfig, request_id: &str) -> String {
    let mut path = format!("/session/v1/login-request?request_id={request_id}");
    for (key, value) in [
        ("databaseName", &conn.database),
        ("schemaName", &conn.schema),
        ("warehouse", &conn.warehouse),
        ("roleName", &conn.role),
    ] {
        if let Some(value) = value {
            path.push_str(&format!("&{key}={}", form_encode_plus(value)));
        }
    }
    path
}

/// The connector's `base_auth_data`: what every sign-in request starts from, also the body of
/// `authenticator-request`.
pub(super) fn base_data(conn: &ConnectionConfig) -> Result<serde_json::Value> {
    let account = conn
        .account
        .as_deref()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "The connection has no account. Set `account`.",
            )
        })?;
    let user = conn.user.as_deref().filter(|u| !u.is_empty());
    Ok(serde_json::json!({
        "CLIENT_APP_ID": "snowflake-cli-rs",
        "CLIENT_APP_VERSION": env!("CARGO_PKG_VERSION"),
        "ACCOUNT_NAME": account_name(account),
        "LOGIN_NAME": user,
        "CLIENT_ENVIRONMENT": {
            "APPLICATION": APPLICATION,
            "OS": std::env::consts::OS,
            "OS_VERSION": std::env::consts::ARCH,
        },
    }))
}

/// The request body. It holds the credential, so it is a [`Secret`].
pub(super) fn body(
    conn: &ConnectionConfig,
    options: &SessionOptions,
    fields: &LoginFields,
) -> Result<Secret> {
    let mut data = base_data(conn)?;
    // JSON results, so there is no Arrow decoder (ADR 0005, S2).
    let mut parameters = serde_json::json!({ "PYTHON_CONNECTOR_QUERY_RESULT_FORMAT": "json" });
    if options.client_session_keep_alive {
        parameters["CLIENT_SESSION_KEEP_ALIVE"] = true.into();
    }
    if let Some(seconds) = options.heartbeat_frequency {
        parameters["CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY"] = seconds.into();
    }
    for (name, value) in &fields.session_parameters {
        parameters[*name] = value.clone();
    }
    data["SESSION_PARAMETERS"] = parameters;
    for (name, value) in &fields.client_environment {
        data["CLIENT_ENVIRONMENT"][*name] = (*value).into();
    }
    for (name, value) in &fields.fields {
        data[*name] = value.expose().into();
    }
    // The connector's first request: the passcode travels with whatever the flow sends.
    if conn.passcode_in_password == Some(true) {
        data["EXT_AUTHN_DUO_METHOD"] = "passcode".into();
    } else if let Some(passcode) = conn.passcode.as_ref().filter(|p| !p.expose().is_empty()) {
        data["EXT_AUTHN_DUO_METHOD"] = "passcode".into();
        data["PASSCODE"] = passcode.expose().into();
    }
    if let Some(roles) = options.secondary_roles {
        data["SECONDARY_ROLES"] = roles.into();
    }
    Ok(Secret::new(serde_json::json!({ "data": data }).to_string()))
}

/// The resent body that waits for the Duo push: the same request with `inFlightCtx` and
/// `EXT_AUTHN_DUO_METHOD=push`.
pub(super) fn push_body(first: &Secret, in_flight: &serde_json::Value) -> Result<Secret> {
    let mut value: serde_json::Value = parse(first.expose())?;
    value["inFlightCtx"] = in_flight.clone();
    value["data"]["EXT_AUTHN_DUO_METHOD"] = "push".into();
    Ok(Secret::new(value.to_string()))
}

/// The request that collects the tokens after an approved push: the base data (no credential)
/// with `inFlightCtx`. `SESSION_PARAMETERS` stay, so results are JSON on this session too.
pub(super) fn after_push_body(first: &Secret, in_flight: &serde_json::Value) -> Result<Secret> {
    let sent: serde_json::Value = parse(first.expose())?;
    let mut data = serde_json::Map::new();
    for key in [
        "CLIENT_APP_ID",
        "CLIENT_APP_VERSION",
        "ACCOUNT_NAME",
        "LOGIN_NAME",
        "CLIENT_ENVIRONMENT",
        "SESSION_PARAMETERS",
    ] {
        data.insert(key.into(), sent["data"][key].clone());
    }
    Ok(Secret::new(
        serde_json::json!({ "data": data, "inFlightCtx": in_flight }).to_string(),
    ))
}

/// The connector's `parse_account`: the region part goes, and so does the external id of a
/// `.global` account.
pub(crate) fn account_name(account: &str) -> &str {
    let mut parts = account.split('.');
    let first = parts.next().unwrap_or(account);
    match parts.next() {
        Some("global") => first.rfind('-').map_or(first, |i| &first[..i]),
        Some(_) => first,
        None => account,
    }
}

/// What the client keeps from a successful sign-in.
pub(super) struct LoginData {
    pub token: Secret,
    pub master_token: Secret,
    pub master_validity: Option<u64>,
    pub id_token: Option<Secret>,
    pub mfa_token: Option<Secret>,
    pub parameters: serde_json::Value,
    /// `sessionInfo`: the database, schema, warehouse and role the session starts with.
    pub session_info: serde_json::Value,
    pub session_id: Option<String>,
}

/// A `login-request` answer.
pub(super) enum Reply {
    Success(LoginData),
    /// A Duo push is pending: resend with this `inFlightCtx`.
    Push(serde_json::Value),
    Failure {
        code: String,
        message: String,
    },
}

pub(super) fn parse_reply(status: u16, body: &str) -> Result<Reply> {
    if status != 200 {
        return Err(status_error(status, body));
    }
    let value: serde_json::Value = parse(body)?;
    let data = &value["data"];
    if let Some(action) = data["nextAction"].as_str()
        && DUO_PUSH.contains(&action)
    {
        return Ok(Reply::Push(data["inFlightCtx"].clone()));
    }
    if value["success"] != true {
        return Ok(Reply::Failure {
            code: code_text(&value["code"]),
            message: message_text(&value),
        });
    }
    success(data).map(Reply::Success)
}

/// After the push request.
pub(super) enum PushOutcome {
    /// The push was approved: collect the tokens with this `inFlightCtx`.
    Collect(serde_json::Value),
    Done(Reply),
}

/// The answer to the push request: `EXT_AUTHN_SUCCESS` means "collect the tokens now"; tokens
/// right away are a success; anything else failed.
pub(super) fn parse_push_reply(status: u16, body: &str, target: &Target) -> Result<PushOutcome> {
    if status != 200 {
        return Err(status_error(status, body));
    }
    let value: serde_json::Value = parse(body)?;
    let data = &value["data"];
    if data["nextAction"] == DUO_SUCCESS {
        return Ok(PushOutcome::Collect(data["inFlightCtx"].clone()));
    }
    if data["token"].is_string() {
        return parse_reply(status, body).map(PushOutcome::Done);
    }
    Err(super::connect_error(
        FAILED_TO_CONNECT,
        Some(NOT_ESTABLISHED),
        &format!(
            "Failed to connect to DB. MFA authentication failed: {}. {}",
            target.host_port(),
            message_text(&value)
        ),
    ))
}

fn success(data: &serde_json::Value) -> Result<LoginData> {
    let token = data["token"]
        .as_str()
        .ok_or_else(|| malformed("no session token"))?;
    let secret = |name: &str| data[name].as_str().map(Secret::new);
    Ok(LoginData {
        token: Secret::new(token),
        master_token: secret("masterToken").unwrap_or_else(|| Secret::new("")),
        master_validity: data["masterValidityInSeconds"].as_u64(),
        id_token: secret("idToken"),
        mfa_token: secret("mfaToken"),
        parameters: data["parameters"].clone(),
        session_info: data["sessionInfo"].clone(),
        session_id: match &data["sessionId"] {
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        },
    })
}

fn code_text(code: &serde_json::Value) -> String {
    match code {
        serde_json::Value::String(c) => c.clone(),
        serde_json::Value::Number(c) => c.to_string(),
        _ => FAILED_TO_CONNECT.to_string(),
    }
}

fn message_text(value: &serde_json::Value) -> String {
    value["message"]
        .as_str()
        .unwrap_or("no error message")
        .to_string()
}

/// A rejected sign-in, as `snow` shows it:
/// `Could not connect to Snowflake. Reason: 390100 (28000): Failed to connect to DB: <host>:<port>. <message>`.
pub(super) fn failure(target: &Target, code: &str, message: &str) -> Error {
    let state = if CREDENTIAL_REJECTION.contains(&code) {
        AUTHORIZATION_FAILURE
    } else {
        NOT_ESTABLISHED
    };
    let errno = code.parse::<u32>().unwrap_or(FAILED_TO_CONNECT);
    super::connect_error(
        errno,
        Some(state),
        &format!("Failed to connect to DB: {}. {message}", target.host_port()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> ConnectionConfig {
        ConnectionConfig {
            account: Some("myorg-acct.eu-west-1".into()),
            user: Some("me".into()),
            database: Some("My DB".into()),
            role: Some("R".into()),
            ..Default::default()
        }
    }

    fn target() -> Target {
        Target {
            protocol: "https".into(),
            host: "h.example".into(),
            port: 443,
        }
    }

    fn data(body: &Secret) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_str(body.expose()).unwrap();
        value["data"].clone()
    }

    #[test]
    fn account_name_drops_region_and_external_id() {
        assert_eq!(account_name("abc"), "abc");
        assert_eq!(account_name("abc.us-east-1"), "abc");
        assert_eq!(account_name("org-acct-ext.global"), "org-acct");
        assert_eq!(account_name("noext.global"), "noext");
    }

    #[test]
    fn the_path_carries_the_context() {
        assert_eq!(
            path(&conn(), "id"),
            "/session/v1/login-request?request_id=id&databaseName=My+DB&roleName=R"
        );
    }

    #[test]
    fn the_body_has_the_connector_fields() {
        let options = SessionOptions {
            secondary_roles: Some("ALL"),
            client_session_keep_alive: true,
            heartbeat_frequency: Some(900),
            ..SessionOptions::default()
        };
        let fields = LoginFields {
            client_environment: vec![("OAUTH_TYPE", "oauth_client_credentials")],
            session_parameters: vec![("CLIENT_REQUEST_MFA_TOKEN", true.into())],
            ..LoginFields::default()
        }
        .with("AUTHENTICATOR", "SNOWFLAKE_JWT")
        .with("TOKEN", "tok");
        let data = data(&body(&conn(), &options, &fields).unwrap());
        assert_eq!(data["ACCOUNT_NAME"], "myorg-acct");
        assert_eq!(data["LOGIN_NAME"], "me");
        assert_eq!(data["AUTHENTICATOR"], "SNOWFLAKE_JWT");
        assert_eq!(data["TOKEN"], "tok");
        assert_eq!(data["SECONDARY_ROLES"], "ALL");
        assert_eq!(data["CLIENT_ENVIRONMENT"]["APPLICATION"], "SNOWFLAKE_CLI");
        assert_eq!(
            data["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"],
            "oauth_client_credentials"
        );
        let params = &data["SESSION_PARAMETERS"];
        assert_eq!(params["PYTHON_CONNECTOR_QUERY_RESULT_FORMAT"], "json");
        assert_eq!(params["CLIENT_SESSION_KEEP_ALIVE"], true);
        assert_eq!(params["CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY"], 900);
        assert_eq!(params["CLIENT_REQUEST_MFA_TOKEN"], true);
        assert!(data.get("EXT_AUTHN_DUO_METHOD").is_none());

        let mut c = conn();
        c.user = None;
        assert_eq!(
            data_of(&c)["LOGIN_NAME"],
            serde_json::Value::Null,
            "OAuth flows may sign in without a user"
        );
        c.account = None;
        assert!(body(&c, &SessionOptions::default(), &LoginFields::default()).is_err());
    }

    fn data_of(c: &ConnectionConfig) -> serde_json::Value {
        data(&body(c, &SessionOptions::default(), &LoginFields::default()).unwrap())
    }

    #[test]
    fn a_passcode_rides_on_the_first_request() {
        let mut c = conn();
        c.passcode = Some(Secret::new("123456"));
        let d = data_of(&c);
        assert_eq!(d["EXT_AUTHN_DUO_METHOD"], "passcode");
        assert_eq!(d["PASSCODE"], "123456");
        c.passcode_in_password = Some(true);
        let d = data_of(&c);
        assert_eq!(d["EXT_AUTHN_DUO_METHOD"], "passcode");
        assert!(d.get("PASSCODE").is_none());
        c.passcode = Some(Secret::new(""));
        c.passcode_in_password = Some(false);
        assert!(data_of(&c).get("EXT_AUTHN_DUO_METHOD").is_none());
    }

    #[test]
    fn push_bodies_follow_the_connector() {
        let first = body(
            &conn(),
            &SessionOptions::default(),
            &LoginFields::default().with("PASSWORD", "pw"),
        )
        .unwrap();
        let ctx = serde_json::json!("ctx-1");
        let push: serde_json::Value =
            serde_json::from_str(push_body(&first, &ctx).unwrap().expose()).unwrap();
        assert_eq!(push["inFlightCtx"], "ctx-1");
        assert_eq!(push["data"]["EXT_AUTHN_DUO_METHOD"], "push");
        assert_eq!(push["data"]["PASSWORD"], "pw");
        let after: serde_json::Value =
            serde_json::from_str(after_push_body(&first, &ctx).unwrap().expose()).unwrap();
        assert_eq!(after["inFlightCtx"], "ctx-1");
        assert!(after["data"].get("PASSWORD").is_none(), "no credential");
        assert_eq!(after["data"]["LOGIN_NAME"], "me");
        assert_eq!(
            after["data"]["SESSION_PARAMETERS"]["PYTHON_CONNECTOR_QUERY_RESULT_FORMAT"],
            "json"
        );
    }

    #[test]
    fn replies_map_to_tokens_pushes_or_failures() {
        let Reply::Success(ok) = parse_reply(
            200,
            r#"{"success":true,"data":{"token":"t","masterToken":"m","masterValidityInSeconds":14400,"idToken":"i","mfaToken":"f","parameters":[]}}"#,
        )
        .unwrap() else {
            panic!("not a success")
        };
        assert_eq!(ok.token.expose(), "t");
        assert_eq!(ok.master_token.expose(), "m");
        assert_eq!(ok.master_validity, Some(14400));
        assert_eq!(ok.id_token.unwrap().expose(), "i");
        assert_eq!(ok.mfa_token.unwrap().expose(), "f");
        let Reply::Push(ctx) = parse_reply(
            200,
            r#"{"success":true,"data":{"nextAction":"EXT_AUTHN_DUO_ALL","inFlightCtx":"c"}}"#,
        )
        .unwrap() else {
            panic!("not a push")
        };
        assert_eq!(ctx, "c");
        let Reply::Failure { code, message } = parse_reply(
            200,
            r#"{"success":false,"code":"390100","message":"Incorrect username or password was specified."}"#,
        )
        .unwrap() else {
            panic!("not a failure")
        };
        assert_eq!(
            (code.as_str(), message.as_str()),
            ("390100", "Incorrect username or password was specified.")
        );
        let Reply::Failure { code, message } =
            parse_reply(200, r#"{"success":false,"code":1}"#).unwrap()
        else {
            panic!("not a failure")
        };
        assert_eq!((code.as_str(), message.as_str()), ("1", "no error message"));
        let Reply::Failure { code, .. } = parse_reply(200, r#"{"success":false}"#).unwrap() else {
            panic!("not a failure")
        };
        assert_eq!(code, "250001");
        assert!(parse_reply(200, r#"{"success":true,"data":{}}"#).is_err());
        assert_eq!(
            parse_reply(403, "{}").err().unwrap().kind(),
            ErrorKind::Connection
        );
    }

    #[test]
    fn push_replies() {
        let t = target();
        let PushOutcome::Collect(ctx) = parse_push_reply(
            200,
            r#"{"data":{"nextAction":"EXT_AUTHN_SUCCESS","inFlightCtx":"c2"}}"#,
            &t,
        )
        .unwrap() else {
            panic!("not approved")
        };
        assert_eq!(ctx, "c2");
        assert!(matches!(
            parse_push_reply(200, r#"{"success":true,"data":{"token":"t"}}"#, &t).unwrap(),
            PushOutcome::Done(Reply::Success(_))
        ));
        let err = parse_push_reply(
            200,
            r#"{"success":false,"message":"Timeout","data":{}}"#,
            &t,
        )
        .err()
        .unwrap();
        assert_eq!(err.kind(), ErrorKind::Connection);
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 250001 (08001): Failed to connect to DB. MFA authentication failed: h.example:443. Timeout"
        );
        assert!(parse_push_reply(500, "", &t).is_err());
    }

    #[test]
    fn failures_read_like_snow() {
        let err = failure(
            &target(),
            "390100",
            "Incorrect username or password was specified.",
        );
        assert_eq!(err.kind(), ErrorKind::Connection);
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 390100 (28000): Failed to connect to DB: h.example:443. Incorrect username or password was specified."
        );
        let err = failure(&target(), "390195", "id token expired");
        assert!(err.message().contains("390195 (08001)"));
        let err = failure(&target(), "x", "m");
        assert!(err.message().contains("250001 (08001)"));
    }
}
