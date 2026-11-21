//! Google Cloud Storage stages (connector `gcs_storage_client.py`): an access token or a presigned
//! URL per file; files are never split.

use super::azure::{encryption_data, parse_encryption_data};
use super::crypto::Metadata;
use super::storage::{
    Body, Credentials, Download, Header, Http, Multipart, Request, RequestBody, Response, Storage,
    Upload, copy_body, http_error, split_location,
};
use crate::codec::percent_encode;
use crate::error::{Error, ErrorKind, Result};
use std::io::Write;
use std::sync::Mutex;

const DIGEST: &str = "x-goog-meta-sfc-digest";
const MATDESC: &str = "x-goog-meta-matdesc";
const ENCRYPTION: &str = "x-goog-meta-encryptiondata";

pub(crate) struct Gcs<'a> {
    http: &'a Http,
    creds: &'a Credentials<'a>,
    /// Endpoint with the bucket (path style) or without it (virtual host).
    base: String,
    prefix: String,
}

impl<'a> Gcs<'a> {
    pub(crate) fn new(
        stage: &serde_json::Value,
        http: &'a Http,
        creds: &'a Credentials<'a>,
        endpoint_override: Option<&str>,
    ) -> Self {
        let (bucket, prefix) = split_location(stage["location"].as_str().unwrap_or_default());
        let region = stage["region"].as_str().unwrap_or_default().to_lowercase();
        let virtual_url = stage["useVirtualUrl"].as_bool().unwrap_or(false);
        let regional =
            region == "me-central2" || stage["useRegionalUrl"].as_bool().unwrap_or(false);
        let base = match (endpoint_override, stage["endPoint"].as_str()) {
            (Some(base), _) => format!("{}/{bucket}", base.trim_end_matches('/')),
            (None, Some(end_point)) if !end_point.is_empty() => {
                let end_point = end_point.trim_end_matches('/');
                let end_point = if end_point.starts_with("https://") {
                    end_point.to_string()
                } else {
                    format!("https://{end_point}")
                };
                if virtual_url {
                    end_point
                } else {
                    format!("{end_point}/{bucket}")
                }
            }
            _ if virtual_url => format!("https://{bucket}.storage.googleapis.com"),
            _ if regional => format!("https://storage.{region}.rep.googleapis.com/{bucket}"),
            _ => format!("https://storage.googleapis.com/{bucket}"),
        };
        Self {
            http,
            creds,
            base,
            prefix,
        }
    }

    fn url(&self, name: &str) -> String {
        format!(
            "{}/{}",
            self.base,
            percent_encode(
                &format!("{}{}", self.prefix, name.trim_start_matches('/')),
                b"/",
            )
        )
    }

    fn token(&self) -> (Option<String>, u64) {
        let (token, generation) = self.creds.get("GCS_ACCESS_TOKEN");
        (
            token
                .map(|t| t.expose().to_string())
                .filter(|t| !t.is_empty()),
            generation,
        )
    }

    /// `PUT` without an access token: the statement again, for this one file, gives a
    /// presigned URL (`_update_presigned_url`).
    fn presigned_put_url(&self, name: &str) -> Result<String> {
        let statement = self.creds.statement();
        let Some(local) = local_path(statement) else {
            return Err(no_presigned_url());
        };
        let data = self.creds.requery(&statement.replace(&local, name))?;
        data["stageInfo"]["presignedUrl"]
            .as_str()
            .map(String::from)
            .ok_or_else(no_presigned_url)
    }

    fn send(
        &self,
        method: &'static str,
        url: &Mutex<String>,
        presigned: bool,
        headers: Vec<(String, String)>,
        body: &RequestBody,
        refresh: Option<&dyn Fn() -> Result<String>>,
    ) -> Result<Response> {
        let build = || -> Result<(Request, u64)> {
            let mut all = headers.clone();
            let (token, generation) = self.token();
            if let (Some(token), false) = (token, presigned) {
                all.push(("Authorization".into(), format!("Bearer {token}")));
            }
            let body = match body {
                RequestBody::None => RequestBody::None,
                RequestBody::Bytes(b) => RequestBody::Bytes(b.clone()),
                RequestBody::File(f) => RequestBody::File(f.clone()),
            };
            let url = url
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            Ok((
                Request {
                    method,
                    url,
                    headers: all,
                    body,
                },
                generation,
            ))
        };
        let has_token = self.token().0.is_some();
        // An expired presigned URL answers 400; it is refreshed once.
        let refreshed = std::sync::atomic::AtomicBool::new(false);
        let expired = |status: u16, _: &str| {
            if has_token && !presigned {
                status == 401
            } else {
                status == 400
                    && refresh.is_some()
                    && !refreshed.swap(true, std::sync::atomic::Ordering::SeqCst)
            }
        };
        let renew = |generation: u64| -> Result<()> {
            match refresh {
                Some(refresh) if presigned => {
                    let fresh = refresh()?;
                    *url.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
                    Ok(())
                }
                _ => self.creds.renew(generation),
            }
        };
        let response = self.http.send(&build, &expired, &renew)?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) || (method == "HEAD" && status == 404) {
            Ok(response)
        } else {
            let shown = url
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            Err(http_error(method, &shown, status))
        }
    }
}

fn no_presigned_url() -> Error {
    Error::new(
        ErrorKind::Communication,
        "Snowflake did not return a presigned URL for the upload.",
    )
}

/// The local path of a `PUT` statement (`_get_local_file_path_from_put_command`).
fn local_path(statement: &str) -> Option<String> {
    const FILE: &str = "file://";
    let begin = statement.find(FILE)?;
    let quoted = begin > 0 && statement.as_bytes()[begin - 1] == b'\'';
    let start = begin + FILE.len();
    let rest = &statement[start..];
    let path = if quoted {
        &rest[..rest.find('\'')?]
    } else {
        let end = [' ', '\n', ';']
            .iter()
            .filter_map(|d| rest.find(*d))
            .min()
            .unwrap_or(rest.len());
        &rest[..end]
    };
    (!path.is_empty()).then(|| path.to_string())
}

fn header(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

impl Storage for Gcs<'_> {
    fn chunk_size(&self, _size: u64) -> Option<u64> {
        None
    }

    fn head(&self, name: &str, presigned_url: Option<&str>) -> Result<Option<Header>> {
        if presigned_url.is_some() || self.token().0.is_none() {
            // With a presigned URL there is no way to ask; the connector assumes "not found".
            return Ok(None);
        }
        let url = Mutex::new(self.url(name));
        let response = self.send("HEAD", &url, false, Vec::new(), &RequestBody::None, None)?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let encryption = header(&response, ENCRYPTION)
            .and_then(|data| parse_encryption_data(&data, header(&response, MATDESC).as_deref()));
        Ok(Some(Header {
            size: header(&response, "content-length").and_then(|v| v.parse().ok()),
            encryption,
        }))
    }

    fn put(&self, upload: &Upload<'_>, body: &Body) -> Result<()> {
        let content_encoding = match upload.compression {
            Some(name) if name != "GZIP" => name.to_lowercase(),
            _ => String::new(),
        };
        let mut headers = vec![
            ("Content-Encoding".to_string(), content_encoding),
            (DIGEST.to_string(), upload.digest.to_string()),
        ];
        if let Some(enc) = upload.encryption {
            headers.push((ENCRYPTION.into(), encryption_data(enc, "AES_CBC_256")));
            headers.push((MATDESC.into(), enc.matdesc.clone()));
        }
        let body = RequestBody::File(body.clone());
        if self.token().0.is_some() {
            let url = Mutex::new(self.url(upload.name));
            return self
                .send("PUT", &url, false, headers, &body, None)
                .map(drop);
        }
        let first = match upload.presigned_url {
            Some(url) => url.to_string(),
            None => self.presigned_put_url(upload.name)?,
        };
        let url = Mutex::new(first);
        let refresh = || self.presigned_put_url(upload.name);
        self.send("PUT", &url, true, headers, &body, Some(&refresh))
            .map(drop)
    }

    fn put_part(
        &self,
        upload: &Upload<'_>,
        _: &Multipart,
        _: usize,
        body: &Body,
    ) -> Result<String> {
        self.put(upload, body).map(|()| String::new())
    }

    fn get(
        &self,
        download: &Download<'_>,
        _range: Option<(u64, Option<u64>)>,
        out: &mut dyn Write,
    ) -> Result<Option<Metadata>> {
        let (url, presigned) = match download.presigned_url {
            Some(url) => (url.to_string(), true),
            None => (self.url(download.name), false),
        };
        let url = Mutex::new(url);
        let mut response =
            self.send("GET", &url, presigned, Vec::new(), &RequestBody::None, None)?;
        let encryption = header(&response, ENCRYPTION)
            .and_then(|data| parse_encryption_data(&data, header(&response, MATDESC).as_deref()));
        copy_body(&mut response, out)?;
        Ok(encryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_paths_of_put_statements() {
        assert_eq!(
            local_path("PUT file:///a/b.csv @s").as_deref(),
            Some("/a/b.csv")
        );
        assert_eq!(
            local_path("PUT 'file:///a b.csv' @s").as_deref(),
            Some("/a b.csv")
        );
        assert_eq!(local_path("PUT file:///x.csv;").as_deref(), Some("/x.csv"));
        assert_eq!(local_path("PUT file:///end").as_deref(), Some("/end"));
        assert_eq!(local_path("PUT 'file://' @s"), None);
        assert_eq!(local_path("PUT x @s"), None);
    }

    #[test]
    fn urls() {
        let http = Http::new(super::super::storage::backoff);
        let requery = |_: &str| Ok(serde_json::Value::Null);
        let creds = Credentials::new(&serde_json::json!({}), "PUT", &requery);
        let url = |stage: serde_json::Value| Gcs::new(&stage, &http, &creds, None).url("f.gz");
        assert_eq!(
            url(serde_json::json!({"location": "b/p"})),
            "https://storage.googleapis.com/b/p/f.gz"
        );
        assert_eq!(
            url(serde_json::json!({"location": "b/p", "useVirtualUrl": true})),
            "https://b.storage.googleapis.com/p/f.gz"
        );
        assert_eq!(
            url(serde_json::json!({"location": "b", "region": "ME-CENTRAL2"})),
            "https://storage.me-central2.rep.googleapis.com/b/f.gz"
        );
        assert_eq!(
            url(serde_json::json!({"location": "b", "endPoint": "example.com/"})),
            "https://example.com/b/f.gz"
        );
        assert_eq!(
            url(
                serde_json::json!({"location": "b", "endPoint": "https://e.com", "useVirtualUrl": true})
            ),
            "https://e.com/f.gz"
        );
    }
}
