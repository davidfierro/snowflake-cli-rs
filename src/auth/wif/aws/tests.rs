use super::super::tests::{attester, endpoints};
use super::*;
use crate::auth::wif::Endpoints;
use crate::env::Env;
use httpmock::MockServer;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;

/// 2026-11-21T12:34:56Z, the time of the botocore vectors below.
fn fixed() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_795_264_496)
}

const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn creds(token: Option<&str>) -> Credentials {
    Credentials {
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: Secret::new(SECRET_KEY),
        session_token: token.map(Secret::new),
    }
}

/// What botocore 1.x `SigV4Auth` produced for the same inputs (scripted with a frozen clock).
#[test]
fn signatures_match_botocore() {
    let get_caller = |token| {
        sign(
            &creds(token),
            "eu-west-1",
            "POST",
            "sts.eu-west-1.amazonaws.com",
            "/",
            CALLER_IDENTITY_QUERY,
            &[("X-Snowflake-Audience", SNOWFLAKE_AUDIENCE)],
            "",
            fixed(),
        )
    };
    let signed = get_caller(None);
    assert_eq!(signed.amz_date, "20261121T123456Z");
    assert_eq!(
        signed.authorization.expose(),
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261121/eu-west-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date;x-snowflake-audience, \
         Signature=312ae07b26a74fcb7578c5d8488d603105001620163ca8124da485cfbcc6d779"
    );
    assert!(
        get_caller(Some("SESSIONTOKEN"))
            .authorization
            .expose()
            .ends_with(
                "SignedHeaders=host;x-amz-date;x-amz-security-token;x-snowflake-audience, \
                 Signature=402b2c533a333b97a8ab2142f252560de2c87b0ff77d2dcd67a0ff88e6b81816"
            )
    );
    let form = sign(
        &creds(Some("SESSIONTOKEN")),
        "eu-west-1",
        "POST",
        "sts.eu-west-1.amazonaws.com",
        "/",
        "",
        &[("Content-Type", FORM)],
        "Action=GetWebIdentityToken&Version=2011-06-15&Audience.member.1=snowflakecomputing.com&SigningAlgorithm=ES384",
        fixed(),
    );
    assert!(form.authorization.expose().ends_with(
        "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, \
         Signature=25333981d5fcdc07bb31b09daa3c9cd83514917fe4fb379e6fe45c72e7f94563"
    ));
}

/// The connector's attestation for the same request, byte for byte (botocore + `json.dumps`).
#[test]
fn presigned_request_matches_the_connector() {
    let env = Env::from_pairs([
        ("AWS_REGION", "eu-west-1"),
        ("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
    ]);
    let credential = Attester::new(&env, Endpoints::default())
        .with_clock(fixed)
        .aws_attestation(AwsToken::PresignedRequest)
        .unwrap();
    assert_eq!(
        credential.expose(),
        "eyJ1cmwiOiAiaHR0cHM6Ly9zdHMuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUiLCAibWV0aG9kIjogIlBPU1QiLCAiaGVhZGVycyI6IHsiSG9zdCI6ICJzdHMuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb20iLCAiWC1Tbm93Zmxha2UtQXVkaWVuY2UiOiAic25vd2ZsYWtlY29tcHV0aW5nLmNvbSIsICJYLUFtei1EYXRlIjogIjIwMjYxMTIxVDEyMzQ1NloiLCAiQXV0aG9yaXphdGlvbiI6ICJBV1M0LUhNQUMtU0hBMjU2IENyZWRlbnRpYWw9QUtJREVYQU1QTEUvMjAyNjExMjEvZXUtd2VzdC0xL3N0cy9hd3M0X3JlcXVlc3QsIFNpZ25lZEhlYWRlcnM9aG9zdDt4LWFtei1kYXRlO3gtc25vd2ZsYWtlLWF1ZGllbmNlLCBTaWduYXR1cmU9MzEyYWUwN2IyNmE3NGZjYjc1NzhjNWQ4NDg4ZDYwMzEwNTAwMTYyMDE2M2NhODEyNGRhNDg1Y2ZiY2M2ZDc3OSJ9fQ=="
    );

    let env = Env::from_pairs([
        ("AWS_DEFAULT_REGION", "eu-west-1"),
        ("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
        ("AWS_SESSION_TOKEN", "SESSIONTOKEN"),
    ]);
    let credential = Attester::new(&env, Endpoints::default())
        .with_clock(fixed)
        .aws_attestation(AwsToken::PresignedRequest)
        .unwrap();
    assert_eq!(
        credential.expose(),
        "eyJ1cmwiOiAiaHR0cHM6Ly9zdHMuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUiLCAibWV0aG9kIjogIlBPU1QiLCAiaGVhZGVycyI6IHsiSG9zdCI6ICJzdHMuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb20iLCAiWC1Tbm93Zmxha2UtQXVkaWVuY2UiOiAic25vd2ZsYWtlY29tcHV0aW5nLmNvbSIsICJYLUFtei1EYXRlIjogIjIwMjYxMTIxVDEyMzQ1NloiLCAiWC1BbXotU2VjdXJpdHktVG9rZW4iOiAiU0VTU0lPTlRPS0VOIiwgIkF1dGhvcml6YXRpb24iOiAiQVdTNC1ITUFDLVNIQTI1NiBDcmVkZW50aWFsPUFLSURFWEFNUExFLzIwMjYxMTIxL2V1LXdlc3QtMS9zdHMvYXdzNF9yZXF1ZXN0LCBTaWduZWRIZWFkZXJzPWhvc3Q7eC1hbXotZGF0ZTt4LWFtei1zZWN1cml0eS10b2tlbjt4LXNub3dmbGFrZS1hdWRpZW5jZSwgU2lnbmF0dXJlPTQwMmIyYzUzM2EzMzNiOTdhOGFiMjE0MmYyNTI1NjBkZTJjODdiMGZmNzdkMmRjZDY3YTBmZjg4ZTZiODE4MTYifX0="
    );
}

#[test]
fn china_regions_use_the_cn_endpoint() {
    let env = Env::default();
    let a = Attester::new(&env, Endpoints::default());
    assert_eq!(
        a.sts_base("cn-north-1"),
        "https://sts.cn-north-1.amazonaws.com.cn"
    );
    assert_eq!(
        a.sts_base("us-east-1"),
        "https://sts.us-east-1.amazonaws.com"
    );
}

#[test]
fn outbound_token_comes_from_sts_get_web_identity_token() {
    let server = MockServer::start();
    let sts = server.mock(|when, then| {
        when.method("POST")
            .path("/")
            .header("content-type", FORM)
            .header("x-amz-date", "20261121T123456Z")
            .header("x-amz-security-token", "SESSIONTOKEN")
            .header_matches(
                "authorization",
                r"^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261121/eu-west-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$",
            )
            .body(
                "Action=GetWebIdentityToken&Version=2011-06-15&Audience.member.1=snowflakecomputing.com&SigningAlgorithm=ES384",
            );
        then.status(200).body(
            "<GetWebIdentityTokenResponse><GetWebIdentityTokenResult><WebIdentityToken>aws.jwt.token</WebIdentityToken></GetWebIdentityTokenResult></GetWebIdentityTokenResponse>",
        );
    });
    let env = Env::from_pairs([
        ("AWS_REGION", "eu-west-1"),
        ("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
        ("AWS_SESSION_TOKEN", "SESSIONTOKEN"),
    ]);
    let a = attester(&env, &server).with_clock(fixed);
    let token = a.aws_attestation(AwsToken::OutboundJwt).unwrap();
    assert_eq!(token.expose(), "aws.jwt.token");
    sts.assert();
}

#[test]
fn outbound_token_errors_carry_the_sts_error_only() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path("/");
        then.status(403).body(
            "<ErrorResponse><Error><Code>AccessDenied</Code><Message>not allowed &amp; denied</Message></Error></ErrorResponse>",
        );
    });
    let env = Env::from_pairs([
        ("AWS_REGION", "eu-west-1"),
        ("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
    ]);
    let err = attester(&env, &server)
        .aws_attestation(AwsToken::OutboundJwt)
        .unwrap_err();
    assert_eq!(err.code, WIF_CREDENTIALS_NOT_FOUND);
    assert_eq!(
        err.message,
        "An error occurred (AccessDenied) when calling the GetWebIdentityToken operation: not allowed & denied"
    );
    assert!(!err.message.contains(SECRET_KEY));

    let empty = MockServer::start();
    empty.mock(|when, then| {
        when.method("POST");
        then.status(200).body("<Nothing/>");
    });
    let err = attester(&env, &empty)
        .aws_attestation(AwsToken::OutboundJwt)
        .unwrap_err();
    assert_eq!(err.message, "STS returned no WebIdentityToken.");

    let mut down = endpoints(&empty);
    down.aws_sts = Some("http://127.0.0.1:1".into());
    let err = Attester::new(&env, down)
        .aws_attestation(AwsToken::OutboundJwt)
        .unwrap_err();
    assert!(
        err.message
            .starts_with("Error fetching the AWS web identity token: ")
    );
}

#[test]
fn no_region_or_no_credentials_fail_like_the_connector() {
    let server = MockServer::start();
    let env = Env::from_pairs([("AWS_EC2_METADATA_DISABLED", "true")]);
    let err = attester(&env, &server)
        .aws_attestation(AwsToken::PresignedRequest)
        .unwrap_err();
    assert_eq!(
        err.message,
        "No AWS region was found. Ensure the application is running on AWS."
    );
    let home = TempDir::new().unwrap();
    let env = Env::from_pairs([
        ("AWS_REGION", "eu-west-1"),
        ("AWS_EC2_METADATA_DISABLED", "TRUE"),
        ("HOME", home.path().to_str().unwrap()),
    ]);
    let err = attester(&env, &server)
        .aws_attestation(AwsToken::PresignedRequest)
        .unwrap_err();
    assert_eq!(err.code, WIF_CREDENTIALS_NOT_FOUND);
    assert_eq!(
        err.message,
        "No AWS credentials were found. Ensure the application is running on AWS with an IAM role attached."
    );
}

#[test]
fn ec2_instance_metadata_gives_region_and_credentials() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method("PUT")
            .path("/latest/api/token")
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600");
        then.status(200).body("IMDS-TOKEN");
    });
    server.mock(|when, then| {
        when.method("GET")
            .path("/latest/meta-data/placement/availability-zone/")
            .header("x-aws-ec2-metadata-token", "IMDS-TOKEN");
        then.status(200).body("eu-west-1b");
    });
    server.mock(|when, then| {
        when.method("GET")
            .path("/latest/meta-data/iam/security-credentials/")
            .header("x-aws-ec2-metadata-token", "IMDS-TOKEN");
        then.status(200).body("my-role\n");
    });
    server.mock(|when, then| {
        when.method("GET")
            .path("/latest/meta-data/iam/security-credentials/my-role");
        then.status(200).json_body(serde_json::json!({
            "AccessKeyId": "ASIAEC2", "SecretAccessKey": "EC2-SECRET", "Token": "EC2-TOKEN"
        }));
    });
    let home = TempDir::new().unwrap();
    let env = Env::from_pairs([("HOME", home.path().to_str().unwrap())]);
    let a = attester(&env, &server).with_clock(fixed);
    let credential = a.aws_attestation(AwsToken::PresignedRequest).unwrap();
    let json = String::from_utf8(STANDARD.decode(credential.expose()).unwrap()).unwrap();
    assert!(json.contains(&format!(
        "\"url\": \"{}/?Action=GetCallerIdentity&Version=2011-06-15\"",
        server.base_url()
    )));
    assert!(json.contains("\"X-Amz-Security-Token\": \"EC2-TOKEN\""));
    assert!(json.contains("Credential=ASIAEC2/20261121/eu-west-1/sts/aws4_request"));
    assert!(token.calls() >= 2);

    // The endpoint variable wins over the default.
    let other = MockServer::start();
    let env = Env::from_pairs([
        ("HOME", home.path().to_str().unwrap()),
        ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.base_url()),
    ]);
    let mut nowhere = endpoints(&other);
    nowhere.aws_imds = "http://127.0.0.1:1".into();
    assert!(Attester::new(&env, nowhere).imds_region().is_some());
}

#[test]
fn ec2_metadata_failures_mean_no_credentials() {
    let server = MockServer::start();
    let env = Env::default();
    // No token endpoint at all.
    assert!(attester(&env, &server).imds_credentials().is_none());
    server.mock(|when, then| {
        when.method("PUT").path("/latest/api/token");
        then.status(200).body("T");
    });
    // No role, then an empty role name.
    assert!(attester(&env, &server).imds_credentials().is_none());
    server.mock(|when, then| {
        when.path("/latest/meta-data/iam/security-credentials/");
        then.status(200).body("\n");
    });
    assert!(attester(&env, &server).imds_credentials().is_none());
    server.mock(|when, then| {
        when.path("/latest/meta-data/placement/availability-zone/");
        then.status(200).body("1");
    });
    assert!(attester(&env, &server).imds_region().is_none());
}

#[test]
fn environment_credentials_come_first() {
    let env = Env::from_pairs([
        ("AWS_ACCESS_KEY_ID", "AKIDENV"),
        ("AWS_SECRET_ACCESS_KEY", "S"),
        ("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent"),
        ("AWS_ROLE_ARN", "arn:aws:iam::1:role/r"),
    ]);
    let c = Attester::new(&env, Endpoints::default())
        .aws_credentials("eu-west-1")
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id, "AKIDENV");
    assert!(c.session_token.is_none());
}

#[test]
fn web_identity_assumes_the_role() {
    let dir = TempDir::new().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "k8s.sa.token\n").unwrap();
    let server = MockServer::start();
    let sts = server.mock(|when, then| {
        when.method("POST")
            .path("/")
            .header("content-type", FORM)
            .body("Action=AssumeRoleWithWebIdentity&RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fr&RoleSessionName=sess&Version=2011-06-15&WebIdentityToken=k8s.sa.token");
        then.status(200).body(
            "<AssumeRoleWithWebIdentityResponse><Credentials><AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>WEB-SECRET</SecretAccessKey><SessionToken>WEB-TOKEN</SessionToken></Credentials></AssumeRoleWithWebIdentityResponse>",
        );
    });
    let env = Env::from_pairs([
        ("AWS_WEB_IDENTITY_TOKEN_FILE", token_file.to_str().unwrap()),
        ("AWS_ROLE_ARN", "arn:aws:iam::1:role/r"),
        ("AWS_ROLE_SESSION_NAME", "sess"),
    ]);
    let c = attester(&env, &server)
        .aws_credentials("eu-west-1")
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id, "ASIAWEB");
    assert_eq!(c.session_token.unwrap().expose(), "WEB-TOKEN");
    sts.assert();
}

#[test]
fn web_identity_failures_name_the_role_not_the_token() {
    let dir = TempDir::new().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "SECRET-TOKEN").unwrap();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST");
        then.status(400).body(
            "<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>bad</Message></Error></ErrorResponse>",
        );
    });
    let env = Env::from_pairs([
        ("AWS_WEB_IDENTITY_TOKEN_FILE", token_file.to_str().unwrap()),
        ("AWS_ROLE_ARN", "arn:r"),
    ]);
    let err = attester(&env, &server)
        .aws_credentials("eu-west-1")
        .unwrap_err();
    assert_eq!(
        err.message,
        "Error assuming arn:r: An error occurred (InvalidIdentityToken) when calling the AssumeRoleWithWebIdentity operation: bad"
    );
    assert!(!err.message.contains("SECRET-TOKEN"));

    let ok_empty = MockServer::start();
    ok_empty.mock(|when, then| {
        when.method("POST");
        then.status(200).body("<x/>");
    });
    let err = attester(&env, &ok_empty)
        .aws_credentials("eu-west-1")
        .unwrap_err();
    assert!(err.message.ends_with("STS returned no credentials"));

    let env = Env::from_pairs([
        ("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token"),
        ("AWS_ROLE_ARN", "arn:r"),
    ]);
    let err = attester(&env, &server)
        .aws_credentials("eu-west-1")
        .unwrap_err();
    assert!(err.message.contains("cannot read /nonexistent/token"));

    let mut down = endpoints(&server);
    down.aws_sts = Some("http://127.0.0.1:1".into());
    let env = Env::from_pairs([
        ("AWS_WEB_IDENTITY_TOKEN_FILE", token_file.to_str().unwrap()),
        ("AWS_ROLE_ARN", "arn:r"),
    ]);
    assert!(Attester::new(&env, down).aws_credentials("x").is_err());
}

#[test]
fn shared_credentials_file_profiles() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("credentials");
    std::fs::write(
        &file,
        "# comment\n[default]\naws_access_key_id = AKIDDEFAULT\naws_secret_access_key = D\n\n\
         [work]\n; comment\nAWS_ACCESS_KEY_ID=AKIDWORK\naws_secret_access_key=W\naws_session_token=WT\n[empty]\naws_access_key_id=\n",
    )
    .unwrap();
    let path = file.to_str().unwrap();
    let get = |pairs: Vec<(&str, &str)>| {
        let env = Env::from_pairs(pairs);
        Attester::new(&env, Endpoints::default()).shared_file_credentials()
    };
    let c = get(vec![("AWS_SHARED_CREDENTIALS_FILE", path)]).unwrap();
    assert_eq!(c.access_key_id, "AKIDDEFAULT");
    let c = get(vec![
        ("AWS_SHARED_CREDENTIALS_FILE", path),
        ("AWS_PROFILE", "work"),
    ])
    .unwrap();
    assert_eq!(c.access_key_id, "AKIDWORK");
    assert_eq!(c.session_token.unwrap().expose(), "WT");
    let c = get(vec![
        ("AWS_SHARED_CREDENTIALS_FILE", path),
        ("AWS_DEFAULT_PROFILE", "work"),
    ]);
    assert!(c.is_some());
    assert!(
        get(vec![
            ("AWS_SHARED_CREDENTIALS_FILE", path),
            ("AWS_PROFILE", "empty")
        ])
        .is_none()
    );
    // ~/.aws/credentials by default.
    std::fs::create_dir(dir.path().join(".aws")).unwrap();
    std::fs::copy(&file, dir.path().join(".aws/credentials")).unwrap();
    assert!(get(vec![("HOME", dir.path().to_str().unwrap())]).is_some());
    assert!(get(vec![]).is_none());
}

#[test]
fn container_credentials_relative_and_full_uri() {
    let server = MockServer::start();
    let relative = server.mock(|when, then| {
        when.method("GET").path("/v2/credentials/abc");
        then.status(200).json_body(serde_json::json!({
            "AccessKeyId": "ASIAECS", "SecretAccessKey": "ECS-SECRET", "Token": "ECS-TOKEN"
        }));
    });
    let env = Env::from_pairs([(
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "/v2/credentials/abc",
    )]);
    let c = attester(&env, &server)
        .container_credentials()
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id, "ASIAECS");
    relative.assert();

    let dir = TempDir::new().unwrap();
    let auth_file = dir.path().join("auth");
    std::fs::write(&auth_file, "POD-AUTH\n").unwrap();
    let full = server.mock(|when, then| {
        when.method("GET")
            .path("/pod")
            .header("authorization", "POD-AUTH");
        then.status(200).json_body(serde_json::json!({
            "AccessKeyId": "ASIAPOD", "SecretAccessKey": "POD-SECRET"
        }));
    });
    let url = format!("{}/pod", server.base_url());
    let env = Env::from_pairs([
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", url.as_str()),
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            auth_file.to_str().unwrap(),
        ),
    ]);
    let c = attester(&env, &server)
        .container_credentials()
        .unwrap()
        .unwrap();
    assert_eq!(c.access_key_id, "ASIAPOD");
    assert!(c.session_token.is_none());
    full.assert();

    let env = Env::from_pairs([
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", url.as_str()),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "POD-AUTH"),
    ]);
    assert!(
        attester(&env, &server)
            .container_credentials()
            .unwrap()
            .is_some()
    );
}

#[test]
fn container_credential_failures() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/bad");
        then.status(500);
    });
    server.mock(|when, then| {
        when.path("/garbage");
        then.status(200).body("not json");
    });
    let run = |pairs: Vec<(&str, &str)>| {
        let env = Env::from_pairs(pairs);
        attester(&env, &server).container_credentials()
    };
    let err = run(vec![("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/bad")]).unwrap_err();
    assert!(err.message.ends_with("HTTP 500"));
    let err = run(vec![("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/garbage")]).unwrap_err();
    assert!(err.message.ends_with("malformed response"));
    let err = run(vec![(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "http://evil.example.com/creds",
    )])
    .unwrap_err();
    assert!(err.message.contains("evil.example.com"));
    let err = run(vec![
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/x"),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/nonexistent"),
    ])
    .unwrap_err();
    assert!(err.message.contains("cannot read /nonexistent"));
    let mut down = endpoints(&server);
    down.aws_container = "http://127.0.0.1:1".into();
    let env = Env::from_pairs([("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/x")]);
    assert!(Attester::new(&env, down).container_credentials().is_err());
    assert!(run(vec![]).unwrap().is_none());
}

#[test]
fn container_hosts_botocore_allows() {
    for url in [
        "https://anything.example.com/x",
        "http://127.0.0.1:8080/x",
        "http://localhost/x",
        "http://169.254.170.2/v2",
        "http://169.254.170.23/v1/credentials",
        "http://[fd00:ec2::23]/v1",
        "http://[::1]:80/x",
    ] {
        assert!(container_url_allowed(url), "{url}");
    }
    for url in [
        "http://example.com/x",
        "ftp://127.0.0.1/x",
        "http://[fe80::1]/x",
    ] {
        assert!(!container_url_allowed(url), "{url}");
    }
}

#[test]
fn xml_and_ini_helpers() {
    assert_eq!(
        xml_text("<a><B> x &lt;&gt;&quot;&apos;&amp; </B></a>", "B").as_deref(),
        Some("x <>\"'&")
    );
    assert_eq!(xml_text("<B>unterminated", "B"), None);
    assert_eq!(authority("https://h:1/p"), "h:1");
    assert_eq!(authority("h"), "h");
    assert!(ini_section("[a]\nk=v\n", "b").is_empty());
}
