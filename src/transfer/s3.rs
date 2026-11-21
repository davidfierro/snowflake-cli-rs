//! Amazon S3 stages (connector `s3_storage_client.py`): our own SigV4 signer with the temporary
//! session credentials, virtual-host URLs, multipart uploads and ranged downloads.

use super::crypto::Metadata;
use super::storage::{
    Body, Credentials, Download, Header, Http, Multipart, Request, RequestBody, Response, Storage,
    Upload, copy_body, http_error, part_size, read_text, split_location,
};
use crate::codec::{hex, hmac_sha256, percent_encode};
use crate::error::{Error, ErrorKind, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::time::SystemTime;

const META: &str = "x-amz-meta-";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const MAX_REDIRECTS: usize = 5;
const MIB: u64 = 1 << 20;

pub(crate) struct S3<'a> {
    http: &'a Http,
    creds: &'a Credentials<'a>,
    /// `https://<bucket>.<host>`, or the test override.
    endpoint: String,
    prefix: String,
    region: Mutex<String>,
    clock: fn() -> SystemTime,
}

impl<'a> S3<'a> {
    pub(crate) fn new(
        stage: &serde_json::Value,
        http: &'a Http,
        creds: &'a Credentials<'a>,
        endpoint_override: Option<&str>,
        clock: fn() -> SystemTime,
    ) -> Self {
        let (bucket, prefix) = split_location(stage["location"].as_str().unwrap_or_default());
        let region = stage["region"].as_str().unwrap_or_default().to_string();
        let flag = |key: &str| stage[key].as_bool().unwrap_or(false);
        let endpoint = match (endpoint_override, stage["endPoint"].as_str()) {
            (Some(base), _) => base.trim_end_matches('/').to_string(),
            _ if region.starts_with("cn-") => {
                format!("https://{bucket}.s3.{region}.amazonaws.com.cn")
            }
            (None, Some(end_point)) if !end_point.is_empty() => {
                format!("https://{bucket}.{end_point}")
            }
            _ if flag("useS3RegionalUrl") || flag("useRegionalUrl") => {
                format!("https://{bucket}.s3.{region}.amazonaws.com")
            }
            // Internal stages live in `sfc-` buckets, for which the connector never asks for
            // the transfer-acceleration endpoint either.
            _ => format!("https://{bucket}.s3.amazonaws.com"),
        };
        Self {
            http,
            creds,
            endpoint,
            prefix,
            region: Mutex::new(region),
            clock,
        }
    }

    fn url(&self, name: &str) -> String {
        format!(
            "{}/{}",
            self.endpoint,
            percent_encode(
                &format!("{}{}", self.prefix, name.trim_start_matches('/')),
                b"/",
            )
        )
    }

    fn region(&self) -> String {
        self.region
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A signed request, following up to five redirects.
    #[allow(clippy::too_many_arguments)] // mirrors the connector's request parameters
    fn send(
        &self,
        method: &'static str,
        url: String,
        query: &[(&str, &str)],
        amz: &[(String, String)],
        headers: &[(&str, &str)],
        body: RequestBody,
        unsigned_payload: bool,
    ) -> Result<Response> {
        let mut url = url;
        for _ in 0..MAX_REDIRECTS {
            let target = with_query(&url, query);
            let body_ref = &body;
            let build = || -> Result<(Request, u64)> {
                let (key_id, generation) = self.creds.get("AWS_KEY_ID");
                let (secret, _) = self.creds.get("AWS_SECRET_KEY");
                let (token, _) = self.creds.get("AWS_TOKEN");
                let (Some(key_id), Some(secret)) = (key_id, secret) else {
                    return Err(Error::new(
                        ErrorKind::Communication,
                        "The stage credentials have no AWS key.",
                    ));
                };
                let mut signed: BTreeMap<String, String> = amz
                    .iter()
                    .map(|(k, v)| (k.to_lowercase(), v.clone()))
                    .collect();
                // Credentials without a session token sign no token header at all.
                if let Some(token) = token.filter(|t| !t.expose().is_empty()) {
                    signed.insert("x-amz-security-token".into(), token.expose().to_string());
                }
                signed.insert("host".into(), authority(&url).to_string());
                let payload_hash = if unsigned_payload {
                    UNSIGNED_PAYLOAD.to_string()
                } else {
                    match body_ref {
                        RequestBody::Bytes(b) => hex(&Sha256::digest(b)),
                        _ => hex(&Sha256::digest(b"")),
                    }
                };
                signed.insert("x-amz-content-sha256".into(), payload_hash.clone());
                let amzdate = amz_date((self.clock)());
                signed.insert("x-amz-date".into(), amzdate.clone());
                let authorization = sign(&SigningInput {
                    method,
                    path: path_of(&url),
                    query,
                    headers: &signed,
                    payload_hash: &payload_hash,
                    region: &self.region(),
                    service: "s3",
                    key_id: key_id.expose(),
                    secret: secret.expose(),
                    amzdate: &amzdate,
                });
                let mut all: Vec<(String, String)> = headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                all.extend(signed.into_iter().filter(|(k, _)| k != "host"));
                all.push(("Authorization".into(), authorization));
                let body = match body_ref {
                    RequestBody::None => RequestBody::None,
                    RequestBody::Bytes(b) => RequestBody::Bytes(b.clone()),
                    RequestBody::File(f) => RequestBody::File(f.clone()),
                };
                Ok((
                    Request {
                        method,
                        url: target.clone(),
                        headers: all,
                        body,
                    },
                    generation,
                ))
            };
            let expired = |status: u16, text: &str| {
                status == 400 && text.contains("<Code>ExpiredToken</Code>")
            };
            let response = self.http.send(&build, &expired, &|g| self.creds.renew(g))?;
            let status = response.status().as_u16();
            if !matches!(status, 301 | 302 | 307 | 308) {
                return Ok(response);
            }
            url = self.redirect(&response, method)?;
        }
        Err(redirect_error(format!(
            "Too many S3 redirects (max {MAX_REDIRECTS})"
        )))
    }

    /// `_handle_s3_redirect`: the new URL; the bucket region becomes the signing region.
    fn redirect(&self, response: &Response, method: &str) -> Result<String> {
        let status = response.status().as_u16();
        if matches!(status, 301 | 302) && !matches!(method, "GET" | "HEAD") {
            return Err(redirect_error(format!(
                "S3 returned {status} for {method} request. Expected 307/308 for method-preserving redirect."
            )));
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let location = header("Location").ok_or_else(|| {
            redirect_error(format!("S3 returned {status} without Location header"))
        })?;
        let region = header("x-amz-bucket-region").ok_or_else(|| {
            redirect_error(format!(
                "S3 returned {status} without x-amz-bucket-region header"
            ))
        })?;
        *self
            .region
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = region;
        // Drop the query: it is rebuilt from the signed query parts.
        Ok(location.split('?').next().unwrap_or(&location).to_string())
    }

    fn metadata(upload: &Upload<'_>) -> Vec<(String, String)> {
        let mut meta = vec![(format!("{META}sfc-digest"), upload.digest.to_string())];
        if let Some(enc) = upload.encryption {
            meta.push((format!("{META}x-amz-iv"), enc.iv.clone()));
            meta.push((format!("{META}x-amz-key"), enc.key.clone()));
            meta.push((format!("{META}x-amz-matdesc"), enc.matdesc.clone()));
        }
        meta
    }

    fn check(response: Response, method: &str, url: &str) -> Result<Response> {
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(response)
        } else {
            Err(http_error(method, url, status))
        }
    }
}

fn redirect_error(message: String) -> Error {
    super::files::connector_error(253003, message)
}

impl Storage for S3<'_> {
    fn chunk_size(&self, size: u64) -> Option<u64> {
        Some(part_size(size, 8 * MIB, 10_000, 5 * MIB))
    }

    fn head(&self, name: &str, _presigned_url: Option<&str>) -> Result<Option<Header>> {
        let url = self.url(name);
        let response = self.send("HEAD", url.clone(), &[], &[], &[], RequestBody::None, false)?;
        match response.status().as_u16() {
            404 => Ok(None),
            200 => {
                let get = |key: &str| {
                    response
                        .headers()
                        .get(key)
                        .and_then(|v| v.to_str().ok())
                        .map(String::from)
                };
                let encryption = get(&format!("{META}x-amz-key")).map(|key| Metadata {
                    key,
                    iv: get(&format!("{META}x-amz-iv")).unwrap_or_default(),
                    matdesc: get(&format!("{META}x-amz-matdesc")).unwrap_or_default(),
                });
                Ok(Some(Header {
                    size: get("Content-Length").and_then(|v| v.parse().ok()),
                    encryption,
                }))
            }
            status => Err(http_error("HEAD", &url, status)),
        }
    }

    fn put(&self, upload: &Upload<'_>, body: &Body) -> Result<()> {
        let url = self.url(upload.name);
        let response = self.send(
            "PUT",
            url.clone(),
            &[],
            &Self::metadata(upload),
            &[("Content-Type", "application/octet-stream")],
            RequestBody::File(body.clone()),
            true,
        )?;
        Self::check(response, "PUT", &url).map(drop)
    }

    fn begin_multipart(&self, upload: &Upload<'_>, _parts: usize) -> Result<Multipart> {
        let url = self.url(upload.name);
        let response = self.send(
            "POST",
            url.clone(),
            &[("uploads", "")],
            &Self::metadata(upload),
            &[("Content-Type", "application/octet-stream")],
            RequestBody::None,
            false,
        )?;
        let mut response = Self::check(response, "POST", &url)?;
        let text = read_text(&mut response);
        let upload_id = tag(&text, "UploadId").ok_or_else(|| {
            Error::new(ErrorKind::Communication, "S3 did not return an upload id.")
        })?;
        Ok(Multipart {
            upload_id,
            block_ids: Vec::new(),
        })
    }

    fn put_part(
        &self,
        upload: &Upload<'_>,
        multipart: &Multipart,
        index: usize,
        body: &Body,
    ) -> Result<String> {
        let url = self.url(upload.name);
        let part = (index + 1).to_string();
        let response = self.send(
            "PUT",
            url.clone(),
            &[("partNumber", &part), ("uploadId", &multipart.upload_id)],
            &[],
            &[],
            RequestBody::File(body.clone()),
            true,
        )?;
        let response = Self::check(response, "PUT", &url)?;
        Ok(response
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string())
    }

    fn complete_multipart(
        &self,
        upload: &Upload<'_>,
        multipart: &Multipart,
        etags: &[String],
    ) -> Result<()> {
        let url = self.url(upload.name);
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (i, etag) in etags.iter().enumerate() {
            xml.push_str(&format!(
                "<Part><ETag>{}</ETag><PartNumber>{}</PartNumber></Part>",
                xml_escape(etag),
                i + 1
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let response = self.send(
            "POST",
            url.clone(),
            &[("uploadId", &multipart.upload_id)],
            &[],
            &[],
            RequestBody::Bytes(xml.into_bytes()),
            false,
        )?;
        Self::check(response, "POST", &url).map(drop)
    }

    fn abort_multipart(&self, upload: &Upload<'_>, multipart: &Multipart) {
        let url = self.url(upload.name);
        let _ = self.send(
            "DELETE",
            url,
            &[("uploadId", &multipart.upload_id)],
            &[],
            &[],
            RequestBody::None,
            false,
        );
    }

    fn get(
        &self,
        download: &Download<'_>,
        range: Option<(u64, Option<u64>)>,
        out: &mut dyn Write,
    ) -> Result<Option<Metadata>> {
        let url = self.url(download.name);
        let range_header = range.map(|(first, last)| match last {
            Some(last) => format!("bytes={first}-{last}"),
            None => format!("bytes={first}-"),
        });
        let headers: Vec<(&str, &str)> = range_header
            .as_deref()
            .map(|r| vec![("Range", r)])
            .unwrap_or_default();
        let response = self.send(
            "GET",
            url.clone(),
            &[],
            &[],
            &headers,
            RequestBody::None,
            false,
        )?;
        let mut response = Self::check(response, "GET", &url)?;
        copy_body(&mut response, out)?;
        Ok(None)
    }
}

/// The text of the first `<name>…</name>` element.
fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].to_string())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `url` with `k=v` pairs (an empty value: just `k`), as `_construct_query_string`.
fn with_query(url: &str, query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return url.to_string();
    }
    let parts: Vec<String> = query
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                percent_encode(k, b"")
            } else {
                format!("{}={}", percent_encode(k, b""), percent_encode(v, b""))
            }
        })
        .collect();
    format!("{url}?{}", parts.join("&"))
}

/// `host[:port]` of a URL.
fn authority(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

/// The path of a URL, `/` when empty.
fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let path = rest.find('/').map_or("", |i| &rest[i..]);
    let path = path.split('?').next().unwrap_or(path);
    if path.is_empty() { "/" } else { path }
}

/// `YYYYMMDDTHHMMSSZ` in UTC.
fn amz_date(now: SystemTime) -> String {
    let ts = jiff::Timestamp::try_from(now).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    ts.strftime("%Y%m%dT%H%M%SZ").to_string()
}

struct SigningInput<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a [(&'a str, &'a str)],
    /// Lower-case names; every one is signed.
    headers: &'a BTreeMap<String, String>,
    payload_hash: &'a str,
    region: &'a str,
    service: &'a str,
    key_id: &'a str,
    secret: &'a str,
    amzdate: &'a str,
}

/// Canonical query string: encoded names and values, sorted by encoded name, then value.
fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (percent_encode(k, b""), percent_encode(v, b"")))
        .collect();
    pairs.sort();
    let parts: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join("&")
}

/// The `Authorization` value of AWS Signature Version 4.
fn sign(input: &SigningInput<'_>) -> String {
    let query = canonical_query(input.query);
    let canonical_headers: String = input
        .headers
        .iter()
        .map(|(k, v)| {
            let value = v.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("{}:{value}\n", k.trim())
        })
        .collect();
    let signed_headers = input.headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical = [
        input.method,
        input.path,
        &query,
        &canonical_headers,
        &signed_headers,
        input.payload_hash,
    ]
    .join("\n");
    let date = &input.amzdate[..8];
    let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        input.amzdate,
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{}", input.secret).as_bytes(), date);
    let k_region = hmac_sha256(&k_date, input.region);
    let k_service = hmac_sha256(&k_region, input.service);
    let k_signing = hmac_sha256(&k_service, "aws4_request");
    let signature = hex(&hmac_sha256(&k_signing, &to_sign));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        input.key_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS Signature Version 4 test suite, `get-vanilla`.
    #[test]
    fn sigv4_known_answer() {
        let headers: BTreeMap<String, String> = [
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ]
        .into();
        let auth = sign(&SigningInput {
            method: "GET",
            path: "/",
            query: &[],
            headers: &headers,
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            region: "us-east-1",
            service: "service",
            key_id: "AKIDEXAMPLE",
            secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amzdate: "20150830T123600Z",
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// AWS test suite, `get-vanilla-query-order-key-case`: query parts are sorted.
    #[test]
    fn sigv4_sorts_query_parts() {
        let headers: BTreeMap<String, String> = [
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ]
        .into();
        let auth = sign(&SigningInput {
            method: "GET",
            path: "/",
            query: &[("Param2", "value2"), ("Param1", "value1")],
            headers: &headers,
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            region: "us-east-1",
            service: "service",
            key_id: "AKIDEXAMPLE",
            secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amzdate: "20150830T123600Z",
        });
        assert!(
            auth.ends_with(
                "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
            ),
            "{auth}"
        );
    }

    /// AWS test suite canonical queries: `get-vanilla-query-unreserved`, `get-vanilla-utf8-query`,
    /// `get-vanilla-query-order-value`, plus the reserved characters `+`, `/`, `=` and space.
    #[test]
    fn canonical_query_follows_the_aws_spec() {
        let unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
        assert_eq!(
            canonical_query(&[(unreserved, unreserved)]),
            format!("{unreserved}={unreserved}")
        );
        assert_eq!(canonical_query(&[("\u{1234}", "bar")]), "%E1%88%B4=bar");
        assert_eq!(
            canonical_query(&[("Param1", "value2"), ("Param1", "value1")]),
            "Param1=value1&Param1=value2"
        );
        assert_eq!(
            canonical_query(&[("prefix", "a+b/c=d e"), ("a b", "")]),
            "a%20b=&prefix=a%2Bb%2Fc%3Dd%20e"
        );
        assert_eq!(
            with_query("u", &[("prefix", "a+b/c=d")]),
            "u?prefix=a%2Bb%2Fc%3Dd"
        );
    }

    #[test]
    fn url_helpers() {
        assert_eq!(with_query("u", &[("uploads", "")]), "u?uploads");
        assert_eq!(
            with_query("u", &[("partNumber", "1"), ("uploadId", "x")]),
            "u?partNumber=1&uploadId=x"
        );
        assert_eq!(with_query("u", &[]), "u");
        assert_eq!(
            authority("https://b.s3.amazonaws.com/p/q"),
            "b.s3.amazonaws.com"
        );
        assert_eq!(authority("http://127.0.0.1:9/x"), "127.0.0.1:9");
        assert_eq!(path_of("https://h/a%20b/c?x=1"), "/a%20b/c");
        assert_eq!(path_of("https://h"), "/");
        assert_eq!(
            tag("<a><UploadId>id-1</UploadId></a>", "UploadId").as_deref(),
            Some("id-1")
        );
        assert_eq!(tag("<a/>", "UploadId"), None);
        assert_eq!(xml_escape("\"e&<>\""), "&quot;e&amp;&lt;&gt;&quot;");
        assert_eq!(
            amz_date(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_440_938_160)),
            "20150830T123600Z"
        );
    }

    #[test]
    fn endpoints_follow_the_stage_info() {
        let http = Http::new(super::super::storage::backoff);
        let requery = |_: &str| Ok(serde_json::Value::Null);
        let creds = Credentials::new(&serde_json::json!({}), "PUT", &requery);
        let endpoint = |stage: serde_json::Value| {
            S3::new(&stage, &http, &creds, None, SystemTime::now).endpoint
        };
        assert_eq!(
            endpoint(serde_json::json!({"location": "sfc-b/p", "region": "eu-west-3"})),
            "https://sfc-b.s3.amazonaws.com"
        );
        assert_eq!(
            endpoint(
                serde_json::json!({"location": "b/p", "region": "eu-west-3", "useS3RegionalUrl": true})
            ),
            "https://b.s3.eu-west-3.amazonaws.com"
        );
        assert_eq!(
            endpoint(serde_json::json!({"location": "b", "region": "cn-north-1"})),
            "https://b.s3.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            endpoint(
                serde_json::json!({"location": "b", "region": "x", "endPoint": "s3-fips.us-east-1.amazonaws.com"})
            ),
            "https://b.s3-fips.us-east-1.amazonaws.com"
        );
        let s3 = S3::new(
            &serde_json::json!({"location": "b/stage/dir", "region": "r"}),
            &http,
            &creds,
            Some("http://127.0.0.1:1/"),
            SystemTime::now,
        );
        assert_eq!(s3.url("/a b.csv"), "http://127.0.0.1:1/stage/dir/a%20b.csv");
    }
}
