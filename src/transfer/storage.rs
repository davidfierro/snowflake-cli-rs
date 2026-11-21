//! What the storage clients share: the interface, request retries, temporary credentials and
//! their renewal (connector `storage_client.py`).

use super::crypto::Metadata;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Attempts per request (`max_retry`).
const MAX_ATTEMPTS: u32 = 5;
/// Statuses retried with backoff (`TRANSIENT_HTTP_ERR`).
const TRANSIENT: [u16; 6] = [408, 429, 500, 502, 503, 504];

/// What a HEAD tells about a remote file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Header {
    pub size: Option<u64>,
    pub encryption: Option<Metadata>,
}

/// One file to upload, as the storage client sees it.
pub(crate) struct Upload<'a> {
    /// Target name inside the stage location.
    pub name: &'a str,
    pub digest: &'a str,
    pub encryption: Option<&'a Metadata>,
    /// Base64 MD5 of the uploaded bytes (Azure block lists only).
    pub md5: Option<&'a str>,
    /// Name of the target compression (GCS `Content-Encoding`), if any.
    pub compression: Option<&'static str>,
    /// Presigned URL (GCS without an access token).
    pub presigned_url: Option<&'a str>,
}

/// One file to download.
pub(crate) struct Download<'a> {
    /// Name inside the stage location.
    pub name: &'a str,
    pub presigned_url: Option<&'a str>,
}

/// A byte range of a local file, read anew for every attempt.
#[derive(Debug, Clone)]
pub(crate) struct Body {
    pub path: PathBuf,
    pub offset: u64,
    pub len: u64,
}

impl Body {
    pub(crate) fn open(&self) -> Result<std::io::Take<std::fs::File>> {
        let mut file = std::fs::File::open(&self.path).map_err(file_error)?;
        file.seek(SeekFrom::Start(self.offset))
            .map_err(file_error)?;
        Ok(file.take(self.len))
    }
}

pub(crate) fn file_error(e: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Client,
        "Could not read or write a transferred file.",
    )
    .with_source(e)
}

/// A started multipart upload: the S3 upload id or the Azure block ids.
#[derive(Debug, Clone, Default)]
pub(crate) struct Multipart {
    pub upload_id: String,
    pub block_ids: Vec<String>,
}

/// One cloud (or the local file system).
pub(crate) trait Storage: Sync {
    /// The part size for a file of `size` bytes, or `None` when files are never split (GCS).
    fn chunk_size(&self, size: u64) -> Option<u64>;
    /// `None` when the file does not exist.
    fn head(&self, name: &str, presigned_url: Option<&str>) -> Result<Option<Header>>;
    fn put(&self, upload: &Upload<'_>, body: &Body) -> Result<()>;
    fn begin_multipart(&self, _upload: &Upload<'_>, _parts: usize) -> Result<Multipart> {
        Ok(Multipart::default())
    }
    /// Returns the part's ETag (S3), or an empty string.
    fn put_part(
        &self,
        upload: &Upload<'_>,
        multipart: &Multipart,
        index: usize,
        body: &Body,
    ) -> Result<String>;
    fn complete_multipart(
        &self,
        _upload: &Upload<'_>,
        _multipart: &Multipart,
        _etags: &[String],
    ) -> Result<()> {
        Ok(())
    }
    fn abort_multipart(&self, _upload: &Upload<'_>, _multipart: &Multipart) {}
    /// Writes the object (or `range`: first byte, last byte inclusive or to the end) to `out`.
    /// Returns encryption metadata found in the response headers (GCS).
    fn get(
        &self,
        download: &Download<'_>,
        range: Option<(u64, Option<u64>)>,
        out: &mut dyn Write,
    ) -> Result<Option<Metadata>>;
}

/// Re-runs the statement for fresh credentials or a presigned URL; returns the answer's `data`.
pub(crate) type Requery<'a> = &'a (dyn Fn(&str) -> Result<serde_json::Value> + Sync);

/// The temporary stage credentials, shared by every worker and renewed once per expiry.
pub(crate) struct Credentials<'a> {
    state: Mutex<(BTreeMap<String, Secret>, u64)>,
    statement: String,
    requery: Requery<'a>,
}

impl<'a> Credentials<'a> {
    pub(crate) fn new(creds: &serde_json::Value, statement: &str, requery: Requery<'a>) -> Self {
        Self {
            state: Mutex::new((secrets(creds), 0)),
            statement: statement.to_string(),
            requery,
        }
    }

    /// One credential (e.g. `AWS_KEY_ID`) and the generation it belongs to.
    pub(crate) fn get(&self, key: &str) -> (Option<Secret>, u64) {
        let state = lock(&self.state);
        (state.0.get(key).cloned(), state.1)
    }

    /// Renews the credentials unless another worker already did since `generation`.
    pub(crate) fn renew(&self, generation: u64) -> Result<()> {
        let mut state = lock(&self.state);
        if state.1 != generation {
            return Ok(());
        }
        log::debug!("renewing expired stage credentials");
        let data = (self.requery)(&self.statement)?;
        state.0 = secrets(&data["stageInfo"]["creds"]);
        state.1 += 1;
        Ok(())
    }

    pub(crate) fn requery(&self, statement: &str) -> Result<serde_json::Value> {
        (self.requery)(statement)
    }

    pub(crate) fn statement(&self) -> &str {
        &self.statement
    }
}

fn secrets(creds: &serde_json::Value) -> BTreeMap<String, Secret> {
    creds
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), Secret::new(v))))
                .collect()
        })
        .unwrap_or_default()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One HTTP request, rebuilt for every attempt (fresh credentials, signature and body).
pub(crate) struct Request {
    pub method: &'static str,
    pub url: String,
    /// Header values may hold credentials; they are never logged.
    pub headers: Vec<(String, String)>,
    pub body: RequestBody,
}

pub(crate) enum RequestBody {
    None,
    Bytes(Vec<u8>),
    File(Body),
}

/// A response with its body not read yet.
pub(crate) type Response = ureq::http::Response<ureq::Body>;

/// The storage HTTP client: no redirects followed (S3 handles them), no status as error.
pub(crate) struct Http {
    agent: ureq::Agent,
    /// Backoff before attempt `n` (n ≥ 1): `min(2^(n-1), 16)` s; zero in tests.
    sleep: fn(u32) -> Duration,
}

pub(crate) fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.saturating_sub(1).min(4)).min(16))
}

impl Http {
    pub(crate) fn new(sleep: fn(u32) -> Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_recv_body(Some(Duration::from_secs(600)))
            .timeout_recv_response(Some(Duration::from_secs(600)))
            .user_agent(concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent();
        Self { agent, sleep }
    }

    /// Sends `build()`, retrying transient statuses and transport errors; `expired` says when an
    /// error answer means the credentials expired, then `renew` runs and the request is retried.
    /// Other answers, errors included, are returned for the caller to judge.
    pub(crate) fn send(
        &self,
        build: &dyn Fn() -> Result<(Request, u64)>,
        expired: &dyn Fn(u16, &str) -> bool,
        renew: &dyn Fn(u64) -> Result<()>,
    ) -> Result<Response> {
        let mut last = None;
        let mut target = (String::new(), String::new());
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep((self.sleep)(attempt));
            }
            let (request, generation) = build()?;
            let shown = shown_url(&request.url);
            log::debug!("{} {shown}", request.method);
            target = (request.method.to_string(), shown.to_string());
            match self.send_once(&request) {
                Ok(response) if TRANSIENT.contains(&response.status().as_u16()) => {
                    log::debug!("{} {shown}: HTTP {}", request.method, response.status());
                    last = Some(format!("HTTP {}", response.status().as_u16()));
                }
                // "Not found" is an answer for the caller (a HEAD of a new file).
                Ok(mut response)
                    if response.status().as_u16() >= 400 && response.status().as_u16() != 404 =>
                {
                    let status = response.status().as_u16();
                    let text = read_text(&mut response);
                    if expired(status, &text) {
                        renew(generation)?;
                        last = Some("expired credentials".into());
                        continue;
                    }
                    return Err(http_error(request.method, &request.url, status));
                }
                Ok(response) => return Ok(response),
                Err(e) => {
                    let what = describe(&e);
                    log::debug!("{} {shown}: {what}", request.method);
                    last = Some(what.to_string());
                }
            }
        }
        let detail = last.unwrap_or_default();
        Err(Error::new(
            ErrorKind::Communication,
            format!(
                "{} with url {} failed for exceeding maximum retries ({detail}).",
                target.0, target.1
            ),
        ))
    }

    fn send_once(&self, request: &Request) -> std::result::Result<Response, ureq::Error> {
        let mut builder = ureq::http::Request::builder()
            .method(request.method)
            .uri(&request.url);
        for (key, value) in &request.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let invalid = |e: ureq::http::Error| ureq::Error::Http(e);
        match &request.body {
            RequestBody::None => self.agent.run(builder.body(()).map_err(invalid)?),
            RequestBody::Bytes(bytes) => self
                .agent
                .run(builder.body(bytes.as_slice()).map_err(invalid)?),
            RequestBody::File(body) => {
                let mut reader = body
                    .open()
                    .map_err(|e| ureq::Error::Io(std::io::Error::other(e)))?;
                let builder = builder.header("Content-Length", body.len.to_string());
                self.agent.run(
                    builder
                        .body(ureq::SendBody::from_reader(&mut reader))
                        .map_err(invalid)?,
                )
            }
        }
    }
}

/// What went wrong, without the error's own text (a malformed-URI error would repeat the URL,
/// signature included).
fn describe(e: &ureq::Error) -> &'static str {
    match e {
        ureq::Error::Timeout(_) => "timed out",
        ureq::Error::Io(_) => "connection failed",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::ConnectionFailed => "connection failed",
        _ => "request failed",
    }
}

/// Reads a (small) error body as text.
pub(crate) fn read_text(response: &mut Response) -> String {
    response
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_string()
        .unwrap_or_default()
}

/// Copies a response body to `out`.
pub(crate) fn copy_body(response: &mut Response, out: &mut dyn Write) -> Result<u64> {
    let mut reader = response.body_mut().as_reader();
    std::io::copy(&mut reader, out).map_err(|e| {
        Error::new(
            ErrorKind::Communication,
            "The connection to the storage failed while reading a file.",
        )
        .with_source(e)
    })
}

/// The URL without its query string (SAS tokens, presigned signatures) for messages and logs.
pub(crate) fn shown_url(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

pub(crate) fn http_error(method: &str, url: &str, status: u16) -> Error {
    Error::new(
        ErrorKind::Communication,
        format!("{method} with url {} failed: HTTP {status}", shown_url(url)),
    )
}

/// `<bucket>/<path>` of a stage location; the path ends with `/` unless empty.
pub(crate) fn split_location(location: &str) -> (String, String) {
    match location.split_once('/') {
        Some((bucket, path)) if !path.is_empty() && !path.ends_with('/') => {
            (bucket.to_string(), format!("{path}/"))
        }
        Some((bucket, path)) => (bucket.to_string(), path.to_string()),
        None => (location.to_string(), String::new()),
    }
}

/// `_chunk_size_calculator`: the default part size unless the file needs more than `max_parts`.
pub(crate) fn part_size(size: u64, default: u64, max_parts: u64, min: u64) -> u64 {
    if size.div_ceil(default) > max_parts {
        size.div_ceil(max_parts).max(min)
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_locations() {
        assert_eq!(
            crate::codec::percent_encode("a b/c+d~é", b"/"),
            "a%20b/c%2Bd~%C3%A9"
        );
        assert_eq!(
            split_location("bucket/p/q"),
            ("bucket".into(), "p/q/".into())
        );
        assert_eq!(split_location("bucket/p/"), ("bucket".into(), "p/".into()));
        assert_eq!(split_location("bucket/"), ("bucket".into(), String::new()));
        assert_eq!(split_location("bucket"), ("bucket".into(), String::new()));
        assert_eq!(shown_url("https://h/p?sig=x"), "https://h/p");
    }

    #[test]
    fn part_sizes_scale_past_the_part_limit() {
        let mib = 1 << 20;
        assert_eq!(part_size(100 * mib, 8 * mib, 10_000, 5 * mib), 8 * mib);
        let huge = 100_000 * mib;
        assert_eq!(
            part_size(huge, 8 * mib, 10_000, 5 * mib),
            huge.div_ceil(10_000)
        );
    }

    #[test]
    fn transport_errors_are_described_without_their_text() {
        assert_eq!(describe(&ureq::Error::HostNotFound), "host not found");
        assert_eq!(
            describe(&ureq::Error::ConnectionFailed),
            "connection failed"
        );
        assert_eq!(
            describe(&ureq::Error::Timeout(ureq::Timeout::Global)),
            "timed out"
        );
        assert_eq!(
            describe(&ureq::Error::BadUri("https://h/p?sig=secret".into())),
            "request failed"
        );
    }

    #[test]
    fn backoff_doubles_up_to_16_s() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(5), Duration::from_secs(16));
        assert_eq!(backoff(9), Duration::from_secs(16));
    }

    #[test]
    fn credentials_renew_once_per_generation() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let requery = |sql: &str| {
            assert_eq!(sql, "PUT x");
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({"stageInfo": {"creds": {"K": "new"}}}))
        };
        let creds = Credentials::new(&serde_json::json!({"K": "old", "N": 1}), "PUT x", &requery);
        let (value, generation) = creds.get("K");
        assert_eq!(value.unwrap().expose(), "old");
        assert!(creds.get("N").0.is_none());
        creds.renew(generation).unwrap();
        creds.renew(generation).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (value, generation) = creds.get("K");
        assert_eq!((value.unwrap().expose(), generation), ("new", 1));
        assert_eq!(creds.statement(), "PUT x");
        assert!(creds.requery("PUT x").is_ok());
    }
}
