//! AWS: the workload's IAM credentials (the parts of botocore's chain a workload uses), then either
//! the signed `GetCallerIdentity` request the connector sends by default, or the STS
//! `GetWebIdentityToken` JWT ("outbound token") the SQL API documents.

use super::{Attester, Reply, SNOWFLAKE_AUDIENCE, WIF_CREDENTIALS_NOT_FOUND, WifError};
use crate::codec::{hex, hmac_sha256, percent_encode};
use crate::secret::Secret;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// Which AWS credential to attest with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsToken {
    /// Base64 JSON of a SigV4-signed STS `GetCallerIdentity` request (the connector's default).
    PresignedRequest,
    /// The JWT of STS `GetWebIdentityToken` (audience `snowflakecomputing.com`, ES384).
    OutboundJwt,
}

const CALLER_IDENTITY_QUERY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";
/// Plain-HTTP container credential hosts botocore accepts.
const CONTAINER_HTTP_HOSTS: [&str; 4] = [
    "169.254.170.2",
    "169.254.170.23",
    "[fd00:ec2::23]",
    "localhost",
];

/// IAM credentials. Only the access key id may be logged.
#[derive(Debug, Clone)]
pub(crate) struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub session_token: Option<Secret>,
}

fn not_found(message: impl Into<String>) -> WifError {
    WifError::new(WIF_CREDENTIALS_NOT_FOUND, message)
}

impl Attester<'_> {
    pub(super) fn aws_attestation(&self, kind: AwsToken) -> Result<Secret, WifError> {
        let region = self.aws_region()?;
        let credentials = self.aws_credentials(&region)?.ok_or_else(|| {
            not_found(
                "No AWS credentials were found. Ensure the application is running on AWS with an IAM role attached.",
            )
        })?;
        let base = self.sts_base(&region);
        let host = authority(&base).to_string();
        let now = (self.now)();
        match kind {
            AwsToken::PresignedRequest => {
                let headers = [("X-Snowflake-Audience", SNOWFLAKE_AUDIENCE)];
                let signed = sign(
                    &credentials,
                    &region,
                    "POST",
                    &host,
                    "/",
                    CALLER_IDENTITY_QUERY,
                    &headers,
                    "",
                    now,
                );
                let url = format!("{base}/?{CALLER_IDENTITY_QUERY}");
                Ok(Secret::new(STANDARD.encode(presigned_json(
                    &url,
                    &host,
                    &signed,
                    credentials.session_token.as_ref(),
                ))))
            }
            AwsToken::OutboundJwt => {
                let body = format!(
                    "Action=GetWebIdentityToken&Version=2011-06-15&Audience.member.1={}&SigningAlgorithm=ES384",
                    percent_encode(SNOWFLAKE_AUDIENCE, b"")
                );
                let reply = self
                    .signed_post(&credentials, &region, &base, &body, now)
                    .map_err(|why| {
                        not_found(format!(
                            "Error fetching the AWS web identity token: {why}. Ensure outbound identity federation is enabled for the AWS account."
                        ))
                    })?;
                if reply.status != 200 {
                    return Err(not_found(sts_error(&reply, "GetWebIdentityToken")));
                }
                xml_text(&reply.body, "WebIdentityToken")
                    .map(Secret::new)
                    .ok_or_else(|| not_found("STS returned no WebIdentityToken."))
            }
        }
    }

    /// `AWS_REGION`, `AWS_DEFAULT_REGION`, then the EC2 metadata service.
    fn aws_region(&self) -> Result<String, WifError> {
        let region = match self
            .env
            .get_non_empty("AWS_REGION")
            .or_else(|| self.env.get_non_empty("AWS_DEFAULT_REGION"))
        {
            Some(region) => Some(region.to_string()),
            None => self.imds_region(),
        };
        region.ok_or_else(|| {
            not_found("No AWS region was found. Ensure the application is running on AWS.")
        })
    }

    fn sts_base(&self, region: &str) -> String {
        match &self.endpoints.aws_sts {
            Some(base) => base.trim_end_matches('/').to_string(),
            None if region.starts_with("cn-") => format!("https://sts.{region}.amazonaws.com.cn"),
            None => format!("https://sts.{region}.amazonaws.com"),
        }
    }

    /// botocore's chain, minus SSO and credential processes: environment, web identity (EKS
    /// IRSA), the shared credentials file, container credentials (ECS, EKS Pod Identity), EC2.
    fn aws_credentials(&self, region: &str) -> Result<Option<Credentials>, WifError> {
        if let (Some(id), Some(secret)) = (
            self.env.get_non_empty("AWS_ACCESS_KEY_ID"),
            self.env.get_non_empty("AWS_SECRET_ACCESS_KEY"),
        ) {
            log::debug!("AWS credentials from the environment");
            return Ok(Some(Credentials {
                access_key_id: id.to_string(),
                secret_access_key: Secret::new(secret),
                session_token: self.env.get_non_empty("AWS_SESSION_TOKEN").map(Secret::new),
            }));
        }
        if let Some(credentials) = self.web_identity_credentials(region)? {
            return Ok(Some(credentials));
        }
        if let Some(credentials) = self.shared_file_credentials() {
            return Ok(Some(credentials));
        }
        if let Some(credentials) = self.container_credentials()? {
            return Ok(Some(credentials));
        }
        Ok(self.imds_credentials())
    }

    /// `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`: STS `AssumeRoleWithWebIdentity`.
    fn web_identity_credentials(&self, region: &str) -> Result<Option<Credentials>, WifError> {
        let (Some(token_file), Some(role_arn)) = (
            self.env.get_non_empty("AWS_WEB_IDENTITY_TOKEN_FILE"),
            self.env.get_non_empty("AWS_ROLE_ARN"),
        ) else {
            return Ok(None);
        };
        log::debug!("AWS credentials from AssumeRoleWithWebIdentity");
        let failed = |why: String| not_found(format!("Error assuming {role_arn}: {why}"));
        let token = std::fs::read_to_string(token_file)
            .map(|t| Secret::new(t.trim()))
            .map_err(|e| failed(format!("cannot read {token_file}: {e}")))?;
        let session = self.env.get_non_empty("AWS_ROLE_SESSION_NAME").map_or_else(
            || format!("snowflake-cli-rs-{}", self.now_secs()),
            str::to_string,
        );
        let body = Secret::new(format!(
            "Action=AssumeRoleWithWebIdentity&RoleArn={}&RoleSessionName={}&Version=2011-06-15&WebIdentityToken={}",
            percent_encode(role_arn, b""),
            percent_encode(&session, b""),
            percent_encode(token.expose(), b"")
        ));
        let url = format!("{}/", self.sts_base(region));
        let reply = self
            .send(
                &self.remote,
                "POST",
                &url,
                &[("Content-Type", FORM)],
                body.expose(),
            )
            .map_err(failed)?;
        if reply.status != 200 {
            return Err(failed(sts_error(&reply, "AssumeRoleWithWebIdentity")));
        }
        let field = |name| xml_text(&reply.body, name);
        match (field("AccessKeyId"), field("SecretAccessKey")) {
            (Some(id), Some(secret)) => Ok(Some(Credentials {
                access_key_id: id,
                secret_access_key: Secret::new(secret),
                session_token: field("SessionToken").map(Secret::new),
            })),
            _ => Err(failed("STS returned no credentials".into())),
        }
    }

    /// Static keys of `AWS_PROFILE` (else `default`) in `~/.aws/credentials`.
    fn shared_file_credentials(&self) -> Option<Credentials> {
        let path = match self.env.get_non_empty("AWS_SHARED_CREDENTIALS_FILE") {
            Some(path) => std::path::PathBuf::from(path),
            None => std::path::PathBuf::from(self.env.get_non_empty("HOME")?)
                .join(".aws")
                .join("credentials"),
        };
        let text = std::fs::read_to_string(path).ok()?;
        let profile = self
            .env
            .get_non_empty("AWS_PROFILE")
            .or_else(|| self.env.get_non_empty("AWS_DEFAULT_PROFILE"))
            .unwrap_or("default");
        let values = ini_section(&text, profile);
        let get = |key: &str| {
            values
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
        };
        let id = get("aws_access_key_id")?;
        let secret = get("aws_secret_access_key")?;
        log::debug!("AWS credentials from the shared credentials file, profile {profile}");
        Some(Credentials {
            access_key_id: id,
            secret_access_key: Secret::new(secret),
            session_token: get("aws_session_token").map(Secret::new),
        })
    }

    /// `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `…_FULL_URI`, with the optional authorization
    /// token (`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` / `…_TOKEN`).
    fn container_credentials(&self) -> Result<Option<Credentials>, WifError> {
        let url = if let Some(relative) = self
            .env
            .get_non_empty("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        {
            format!("{}{relative}", self.endpoints.aws_container)
        } else if let Some(full) = self.env.get_non_empty("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            if !container_url_allowed(full) {
                return Err(not_found(format!(
                    "Unsupported host in AWS_CONTAINER_CREDENTIALS_FULL_URI: {}. Use https, or http to a loopback or ECS/EKS address.",
                    authority(full)
                )));
            }
            full.to_string()
        } else {
            return Ok(None);
        };
        log::debug!("AWS credentials from the container credentials endpoint");
        let failed =
            |why: String| not_found(format!("Error fetching AWS container credentials: {why}"));
        let token = match self
            .env
            .get_non_empty("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        {
            Some(file) => Some(
                std::fs::read_to_string(file)
                    .map(|t| Secret::new(t.trim()))
                    .map_err(|e| failed(format!("cannot read {file}: {e}")))?,
            ),
            None => self
                .env
                .get_non_empty("AWS_CONTAINER_AUTHORIZATION_TOKEN")
                .map(Secret::new),
        };
        let headers: Vec<(&str, &str)> = token
            .as_ref()
            .map(|t| ("Authorization", t.expose()))
            .into_iter()
            .collect();
        let reply = self.get(&self.local, &url, &headers).map_err(failed)?;
        if reply.status != 200 {
            return Err(failed(format!("HTTP {}", reply.status)));
        }
        json_credentials(&reply)
            .map(Some)
            .ok_or_else(|| failed("malformed response".into()))
    }

    fn imds_base(&self) -> Option<String> {
        if self
            .env
            .get("AWS_EC2_METADATA_DISABLED")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            return None;
        }
        Some(
            self.env
                .get_non_empty("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                .unwrap_or(&self.endpoints.aws_imds)
                .trim_end_matches('/')
                .to_string(),
        )
    }

    /// An IMDSv2 session token.
    fn imds_token(&self, base: &str) -> Option<Secret> {
        let reply = self
            .send(
                &self.local,
                "PUT",
                &format!("{base}/latest/api/token"),
                &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
                "",
            )
            .ok()?;
        (reply.status == 200).then(|| Secret::new(reply.body))
    }

    fn imds_get(&self, base: &str, token: &Secret, path: &str) -> Option<String> {
        let reply = self
            .get(
                &self.local,
                &format!("{base}{path}"),
                &[("X-aws-ec2-metadata-token", token.expose())],
            )
            .ok()?;
        (reply.status == 200).then_some(reply.body)
    }

    /// The region of the instance: its availability zone without the final letter.
    fn imds_region(&self) -> Option<String> {
        let base = self.imds_base()?;
        let token = self.imds_token(&base)?;
        let zone = self.imds_get(
            &base,
            &token,
            "/latest/meta-data/placement/availability-zone/",
        )?;
        let zone = zone.trim();
        let region = zone.strip_suffix(|c: char| c.is_ascii_alphabetic())?;
        (!region.is_empty()).then(|| region.to_string())
    }

    fn imds_credentials(&self) -> Option<Credentials> {
        let base = self.imds_base()?;
        let token = self.imds_token(&base)?;
        const ROLES: &str = "/latest/meta-data/iam/security-credentials/";
        let roles = self.imds_get(&base, &token, ROLES)?;
        let role = roles.lines().next()?.trim().to_string();
        if role.is_empty() {
            return None;
        }
        log::debug!("AWS credentials from the EC2 instance role {role}");
        let body = self.imds_get(&base, &token, &format!("{ROLES}{role}"))?;
        json_credentials(&Reply { status: 200, body })
    }

    /// A SigV4-signed form POST to STS.
    fn signed_post(
        &self,
        credentials: &Credentials,
        region: &str,
        base: &str,
        body: &str,
        now: SystemTime,
    ) -> Result<Reply, String> {
        let host = authority(base).to_string();
        let signed = sign(
            credentials,
            region,
            "POST",
            &host,
            "/",
            "",
            &[("Content-Type", FORM)],
            body,
            now,
        );
        let mut headers = vec![
            ("Content-Type", FORM),
            ("X-Amz-Date", signed.amz_date.as_str()),
            ("Authorization", signed.authorization.expose()),
        ];
        if let Some(token) = &credentials.session_token {
            headers.push(("X-Amz-Security-Token", token.expose()));
        }
        self.send(&self.remote, "POST", &format!("{base}/"), &headers, body)
    }
}

/// `AccessKeyId`, `SecretAccessKey`, `Token` of a container or IMDS reply.
fn json_credentials(reply: &Reply) -> Option<Credentials> {
    let value: serde_json::Value = serde_json::from_str(&reply.body).ok()?;
    let text = |name: &str| value.get(name)?.as_str().map(str::to_string);
    Some(Credentials {
        access_key_id: text("AccessKeyId")?,
        secret_access_key: Secret::new(text("SecretAccessKey")?),
        session_token: text("Token").map(Secret::new),
    })
}

/// botocore's error text from an STS error reply (code and message are not secrets).
fn sts_error(reply: &Reply, operation: &str) -> String {
    let code = xml_text(&reply.body, "Code").unwrap_or_else(|| format!("HTTP {}", reply.status));
    let message = xml_text(&reply.body, "Message").unwrap_or_default();
    format!("An error occurred ({code}) when calling the {operation} operation: {message}")
}

fn container_url_allowed(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = match authority(rest) {
        a if a.starts_with('[') => a.split_inclusive(']').next().unwrap_or(a),
        a => a.split(':').next().unwrap_or_default(),
    };
    CONTAINER_HTTP_HOSTS.contains(&host) || host.starts_with("127.") || host == "[::1]"
}

/// `host[:port]` of a URL (or of a bare authority).
fn authority(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or_default()
}

/// The text of the first `<tag>…</tag>`, XML entities decoded.
fn xml_text(body: &str, tag: &str) -> Option<String> {
    let start = body.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + body[start..].find(&format!("</{tag}>"))?;
    Some(
        body[start..end]
            .trim()
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// `key = value` pairs of `[section]` in an INI file.
fn ini_section(text: &str, section: &str) -> Vec<(String, String)> {
    let mut inside = false;
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = name.trim() == section;
            continue;
        }
        if inside && let Some((key, value)) = line.split_once('=') {
            values.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    values
}

/// The headers SigV4 adds.
pub(crate) struct Signed {
    pub amz_date: String,
    pub authorization: Secret,
}

/// AWS Signature Version 4 for STS (botocore's `SigV4Auth`): signs `host`, `headers`,
/// `x-amz-date` and, with a session token, `x-amz-security-token`. `query` is already
/// canonical (sorted, encoded).
#[allow(clippy::too_many_arguments)] // the parts of one HTTP request; a struct would only rename them
pub(crate) fn sign(
    credentials: &Credentials,
    region: &str,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &str,
    now: SystemTime,
) -> Signed {
    let timestamp = jiff::Timestamp::try_from(now).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let mut canonical: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| {
            (
                n.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    canonical.push(("host".into(), host.to_string()));
    canonical.push(("x-amz-date".into(), amz_date.clone()));
    if let Some(token) = &credentials.session_token {
        canonical.push(("x-amz-security-token".into(), token.expose().to_string()));
    }
    canonical.sort();
    let signed_headers = canonical
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let header_block: String = canonical
        .iter()
        .map(|(n, v)| format!("{n}:{v}\n"))
        .collect();
    let request = format!(
        "{method}\n{path}\n{query}\n{header_block}\n{signed_headers}\n{}",
        hex(&Sha256::digest(payload.as_bytes()))
    );
    let scope = format!("{date}/{region}/sts/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(request.as_bytes()))
    );
    let secret = Secret::new(format!("AWS4{}", credentials.secret_access_key.expose()));
    let key = hmac_sha256(secret.expose().as_bytes(), date);
    let key = hmac_sha256(&key, region);
    let key = hmac_sha256(&key, "sts");
    let key = hmac_sha256(&key, "aws4_request");
    let signature = hex(&hmac_sha256(&key, &to_sign));
    Signed {
        authorization: Secret::new(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credentials.access_key_id
        )),
        amz_date,
    }
}

/// `json.dumps` of the connector's assertion dict (Python's default separators).
fn presigned_json(url: &str, host: &str, signed: &Signed, token: Option<&Secret>) -> String {
    let s = |v: &str| serde_json::Value::from(v).to_string();
    let mut headers = vec![
        ("Host", host.to_string()),
        ("X-Snowflake-Audience", SNOWFLAKE_AUDIENCE.to_string()),
        ("X-Amz-Date", signed.amz_date.clone()),
    ];
    if let Some(token) = token {
        headers.push(("X-Amz-Security-Token", token.expose().to_string()));
    }
    headers.push(("Authorization", signed.authorization.expose().to_string()));
    let headers = headers
        .iter()
        .map(|(n, v)| format!("{}: {}", s(n), s(v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"url\": {}, \"method\": \"POST\", \"headers\": {{{headers}}}}}",
        s(url)
    )
}

#[cfg(test)]
mod tests;
