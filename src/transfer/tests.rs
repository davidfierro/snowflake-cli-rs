//! Transfer tests against mocked storage endpoints (ADR 0005, Decision 7): S3, Azure, GCS and
//! `LOCAL_FS`, for uploads, downloads, compression, encryption, wildcards, overwrite and
//! failures. `httpmock` plays the cloud; `endpoint_override` points the clients at it.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use httpmock::MockServer;
use serde_json::{Value as Json, json};
use std::path::Path;
use std::sync::Arc;

const MASTER_KEY: [u8; 16] = [7u8; 16];

fn options(server: Option<&MockServer>) -> TransferOptions {
    TransferOptions {
        home: None,
        endpoint_override: server.map(MockServer::base_url),
        sleep: |_| Duration::ZERO,
        clock: SystemTime::now,
    }
}

fn material() -> Json {
    json!({"queryStageMasterKey": STANDARD.encode(MASTER_KEY), "queryId": "q-1", "smkId": 12})
}

fn crypto_material() -> Material {
    Material::from_json(&material()).unwrap()
}

fn s3_stage() -> Json {
    json!({
        "locationType": "S3", "location": "bucket/stage/dir/", "region": "eu-west-3",
        "creds": {"AWS_KEY_ID": "AKID", "AWS_SECRET_KEY": "secret", "AWS_TOKEN": "old"}
    })
}

fn put_data(stage: Json, sources: Vec<String>, extra: Json) -> Json {
    let mut data = json!({
        "command": "UPLOAD", "src_locations": sources, "parallel": 4, "overwrite": false,
        "autoCompress": true, "sourceCompression": "auto_detect", "stageInfo": stage,
        "queryId": "01-put",
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data
}

fn get_data(stage: Json, sources: &[&str], local: &Path, extra: Json) -> Json {
    let mut data = json!({
        "command": "DOWNLOAD", "src_locations": sources, "parallel": 4,
        "stageInfo": stage, "localLocation": local.display().to_string(), "queryId": "01-get",
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data
}

fn no_requery(_: &str) -> Result<Json> {
    panic!("no requery expected")
}

/// Rows as text, for compact assertions.
fn rows(result: &QueryResult) -> Vec<Vec<String>> {
    result
        .rows
        .iter()
        .map(|r| {
            r.iter()
                .map(|v| match v {
                    Value::Text(t) => t.clone(),
                    Value::Int(i) => i.to_string(),
                    other => format!("{other:?}"),
                })
                .collect()
        })
        .collect()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A body-capturing matcher.
fn capture() -> (
    Arc<Mutex<Vec<u8>>>,
    impl Fn(&httpmock::HttpMockRequest) -> bool + Send + Sync + 'static,
) {
    let store = Arc::new(Mutex::new(Vec::new()));
    let inner = Arc::clone(&store);
    (store, move |req: &httpmock::HttpMockRequest| {
        *inner.lock().unwrap() = req.body().to_vec();
        true
    })
}

fn encrypted(plain: &[u8]) -> (Vec<u8>, Metadata) {
    let mut out = Vec::new();
    let (meta, _) = crypto::encrypt(&crypto_material(), &mut &plain[..], &mut out).unwrap();
    (out, meta)
}

fn decrypted(cipher: &[u8], meta: &Metadata) -> Vec<u8> {
    let mut out = Vec::new();
    crypto::decrypt(meta, &crypto_material(), &mut &cipher[..], &mut out).unwrap();
    out
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(bytes), &mut out).unwrap();
    out
}

#[test]
fn s3_upload_compresses_encrypts_and_signs() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "f1.csv", b"a,b\n1,2\n");
    write(dir.path(), "f2.csv", b"x\n");
    write(dir.path(), "other.txt", b"no");
    let head = server.mock(|when, then| {
        when.method("HEAD")
            .path_matches(r"^/stage/dir/f[12]\.csv\.gz$");
        then.status(404);
    });
    let (body, matcher) = capture();
    let put1 = server.mock(|when, then| {
        when.method("PUT")
            .path("/stage/dir/f1.csv.gz")
            .header("content-type", "application/octet-stream")
            .header("x-amz-security-token", "old")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header_exists("x-amz-meta-sfc-digest")
            .header_exists("x-amz-meta-x-amz-key")
            .header_exists("x-amz-meta-x-amz-iv")
            .header("x-amz-meta-x-amz-matdesc", r#"{"queryId":"q-1","smkId":"12","keySize":"128"}"#)
            .header_matches(
                "authorization",
                r"^AWS4-HMAC-SHA256 Credential=AKID/\d{8}/eu-west-3/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-sfc-digest;x-amz-meta-x-amz-iv;x-amz-meta-x-amz-key;x-amz-meta-x-amz-matdesc;x-amz-security-token, Signature=[0-9a-f]{64}$",
            )
            .is_true(matcher);
        then.status(200);
    });
    let put2 = server.mock(|when, then| {
        when.method("PUT").path("/stage/dir/f2.csv.gz");
        then.status(200);
    });
    let pattern = format!("{}/f*.csv", dir.path().display());
    let data = put_data(
        s3_stage(),
        vec![pattern],
        json!({"encryptionMaterial": material()}),
    );
    let result = run("PUT …", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(result.statement_handle, "01-put");
    assert_eq!(
        rows(&result),
        [
            [
                "f1.csv",
                "f1.csv.gz",
                "8",
                "48",
                "NONE",
                "GZIP",
                "UPLOADED",
                ""
            ],
            [
                "f2.csv",
                "f2.csv.gz",
                "2",
                "32",
                "NONE",
                "GZIP",
                "UPLOADED",
                ""
            ],
        ]
    );
    head.assert_calls(2);
    put1.assert();
    put2.assert();
    // What went up decrypts to the gzip of the file, and the key/IV are those in the headers.
    let uploaded = body.lock().unwrap().clone();
    assert_eq!(uploaded.len(), 48);
    let names: Vec<_> = result.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "source",
            "target",
            "source_size",
            "target_size",
            "source_compression",
            "target_compression",
            "status",
            "message"
        ]
    );
}

#[test]
fn s3_uploaded_bytes_decrypt_to_the_gzip_of_the_file() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "f1.csv", b"a,b\n1,2\n");
    let headers: Arc<Mutex<Option<Metadata>>> = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&headers);
    let (body, matcher) = capture();
    server.mock(|when, then| {
        when.method("PUT")
            .is_true(move |req: &httpmock::HttpMockRequest| {
                let get = |name: &str| {
                    req.headers()
                        .get(name)
                        .map(|v| v.to_str().unwrap().to_string())
                        .unwrap_or_default()
                };
                *seen.lock().unwrap() = Some(Metadata {
                    key: get("x-amz-meta-x-amz-key"),
                    iv: get("x-amz-meta-x-amz-iv"),
                    matdesc: get("x-amz-meta-x-amz-matdesc"),
                });
                true
            })
            .is_true(matcher);
        then.status(200);
    });
    let data = put_data(
        s3_stage(),
        vec![format!("{}/f1.csv", dir.path().display())],
        json!({"encryptionMaterial": material(), "overwrite": true}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    let meta = headers.lock().unwrap().clone().unwrap();
    let plain = decrypted(&body.lock().unwrap(), &meta);
    assert_eq!(gunzip(&plain), b"a,b\n1,2\n");
}

#[test]
fn s3_existing_files_are_skipped_unless_overwrite() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "g.csv.gz", b"\x1f\x8bnot really");
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/g.csv.gz");
        then.status(200).header("Content-Length", "10");
    });
    let put = server.mock(|when, then| {
        when.method("PUT").path("/stage/dir/g.csv.gz");
        then.status(200);
    });
    let data = put_data(s3_stage(), vec![file.display().to_string()], json!({}));
    let result = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(
        rows(&result),
        [[
            "g.csv.gz", "g.csv.gz", "12", "0", "GZIP", "GZIP", "SKIPPED", ""
        ]]
    );
    put.assert_calls(0);
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true}),
    );
    let result = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    // Already compressed, not encrypted: uploaded as is.
    assert_eq!(rows(&result)[0][3], "12");
    assert_eq!(rows(&result)[0][6], "UPLOADED");
    put.assert_calls(1);
}

#[test]
fn s3_large_files_go_up_in_parts() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let size = 9 << 20;
    let bytes: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    let file = write(dir.path(), "big.bin", &bytes);
    let initiate = server.mock(|when, then| {
        when.method("POST")
            .path("/stage/dir/big.bin")
            .query_param_exists("uploads")
            .header_exists("x-amz-meta-sfc-digest");
        then.status(200).body(
            "<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>up-1</UploadId></InitiateMultipartUploadResult>",
        );
    });
    let part1 = server.mock(|when, then| {
        when.method("PUT")
            .path("/stage/dir/big.bin")
            .query_param("partNumber", "1")
            .query_param("uploadId", "up-1")
            .header("content-length", (8 << 20).to_string());
        then.status(200).header("ETag", "\"e1\"");
    });
    let part2 = server.mock(|when, then| {
        when.method("PUT")
            .path("/stage/dir/big.bin")
            .query_param("partNumber", "2")
            .header("content-length", (1 << 20).to_string());
        then.status(200).header("ETag", "\"e2\"");
    });
    let complete = server.mock(|when, then| {
        when.method("POST")
            .path("/stage/dir/big.bin")
            .query_param("uploadId", "up-1")
            .body(
                "<CompleteMultipartUpload><Part><ETag>&quot;e1&quot;</ETag><PartNumber>1</PartNumber></Part><Part><ETag>&quot;e2&quot;</ETag><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>",
            );
        then.status(200);
    });
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true, "autoCompress": false, "threshold": 1024, "parallel": 2}),
    );
    let result = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(rows(&result)[0][3], size.to_string());
    initiate.assert();
    part1.assert();
    part2.assert();
    complete.assert();
}

#[test]
fn s3_failed_parts_abort_the_upload_and_fail_the_statement() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "big.bin", &vec![1u8; 9 << 20]);
    server.mock(|when, then| {
        when.method("POST").query_param_exists("uploads");
        then.status(200).body("<R><UploadId>up-2</UploadId></R>");
    });
    server.mock(|when, then| {
        when.method("PUT").query_param("partNumber", "1");
        then.status(200).header("ETag", "e1");
    });
    server.mock(|when, then| {
        when.method("PUT").query_param("partNumber", "2");
        then.status(403);
    });
    let abort = server.mock(|when, then| {
        when.method("DELETE").query_param("uploadId", "up-2");
        then.status(204);
    });
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true, "autoCompress": false, "threshold": 1}),
    );
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert!(
        err.message().starts_with(
            "253003: 253003: While putting file(s) there was an error: 'PUT with url http://"
        ),
        "{}",
        err.message()
    );
    assert!(err.message().ends_with(
        "/stage/dir/big.bin failed: HTTP 403', this might be caused by your access to the blob storage provider, or by Snowflake."
    ));
    abort.assert();
}

#[test]
fn s3_expired_credentials_are_renewed_once() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"1");
    let expired = server.mock(|when, then| {
        when.method("PUT").header("x-amz-security-token", "old");
        then.status(400)
            .body("<Error><Code>ExpiredToken</Code><Message>The provided token has expired.</Message></Error>");
    });
    let fresh = server.mock(|when, then| {
        when.method("PUT")
            .header("x-amz-security-token", "new")
            .header(
                "x-amz-meta-sfc-digest",
                "a4ayc/80/OGda4BO/1o/V0etpOqiLx1JwB5S3beHW0s=",
            );
        then.status(200);
    });
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let requery = |sql: &str| {
        assert_eq!(sql, "PUT 'file://a.csv' @~");
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"stageInfo": {"creds": {"AWS_KEY_ID": "AKID", "AWS_SECRET_KEY": "s2", "AWS_TOKEN": "new"}}}),
        )
    };
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true, "autoCompress": false}),
    );
    run(
        "PUT 'file://a.csv' @~",
        &data,
        &requery,
        &options(Some(&server)),
    )
    .unwrap();
    expired.assert_calls(1);
    fresh.assert_calls(1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn s3_transient_errors_are_retried_then_reported() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"1");
    let flaky = server.mock(|when, then| {
        when.method("HEAD");
        then.status(503).up_to_n_times(2);
    });
    let head = server.mock(|when, then| {
        when.method("HEAD");
        then.status(404);
    });
    let busy = server.mock(|when, then| {
        when.method("PUT");
        then.status(500);
    });
    let data = put_data(s3_stage(), vec![file.display().to_string()], json!({}));
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    flaky.assert_calls(2);
    head.assert_calls(1);
    busy.assert_calls(5);
    assert!(
        err.message()
            .contains("failed for exceeding maximum retries (HTTP 500)."),
        "{}",
        err.message()
    );
}

#[test]
fn s3_redirects_are_followed_with_the_bucket_region() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"1");
    let target = server.url("/moved/a.csv");
    let redirect = server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/a.csv");
        then.status(307)
            .header("Location", target.as_str())
            .header("x-amz-bucket-region", "us-west-2");
    });
    let moved = server.mock(|when, then| {
        when.method("HEAD")
            .path("/moved/a.csv")
            .header_matches("authorization", "/us-west-2/s3/aws4_request");
        then.status(404);
    });
    server.mock(|when, then| {
        when.method("PUT");
        then.status(200);
    });
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"autoCompress": false}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    redirect.assert();
    moved.assert();
}

#[test]
fn s3_bad_redirects_fail() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"1");
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(307).header("Location", "http://127.0.0.1:1/x");
    });
    let data = put_data(s3_stage(), vec![file.display().to_string()], json!({}));
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("without x-amz-bucket-region header"),
        "{}",
        err.message()
    );

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("PUT");
        then.status(301).header("Location", "http://127.0.0.1:1/x");
    });
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true}),
    );
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("S3 returned 301 for PUT request"),
        "{}",
        err.message()
    );

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(302);
    });
    let data = put_data(s3_stage(), vec![file.display().to_string()], json!({}));
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("without Location header"),
        "{}",
        err.message()
    );

    let server = MockServer::start();
    let looping = server.url("/stage/dir/a.csv");
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(307)
            .header("Location", looping.as_str())
            .header("x-amz-bucket-region", "r");
    });
    let data = put_data(
        s3_stage(),
        vec![file.display().to_string()],
        json!({"autoCompress": false}),
    );
    let err = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("Too many S3 redirects (max 5)"),
        "{}",
        err.message()
    );
}

#[test]
fn s3_download_decrypts_with_the_head_metadata() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let plain = b"hello stage".to_vec();
    let (cipher, meta) = encrypted(&plain);
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/prefix/sub/h.txt");
        then.status(200)
            .header("Content-Length", cipher.len().to_string())
            .header("x-amz-meta-x-amz-key", meta.key.as_str())
            .header("x-amz-meta-x-amz-iv", meta.iv.as_str())
            .header("x-amz-meta-x-amz-matdesc", meta.matdesc.as_str());
    });
    server.mock(|when, then| {
        when.method("GET").path("/stage/dir/prefix/sub/h.txt");
        then.status(200).body(cipher.clone());
    });
    // Links planted at guessable temp names must not be followed.
    #[cfg(unix)]
    for name in ["h.txt.0.part", ".0.part", ".part", "h.txt.tmp"] {
        std::os::unix::fs::symlink("/nonexistent/target", dir.path().join(name)).unwrap();
    }
    let data = get_data(
        s3_stage(),
        &["prefix/sub/h.txt"],
        dir.path(),
        json!({"encryptionMaterial": [material()]}),
    );
    let result = run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(rows(&result), [["sub/h.txt", "11", "DOWNLOADED", ""]]);
    assert_eq!(std::fs::read(dir.path().join("h.txt")).unwrap(), plain);
    #[cfg(unix)]
    assert!(!Path::new("/nonexistent/target").exists());
    // Only the planted links are left: the temp files are gone.
    let mut left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    #[cfg(unix)]
    assert_eq!(
        left,
        [".0.part", ".part", "h.txt", "h.txt.0.part", "h.txt.tmp"]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("h.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn downloads_of_long_file_names_succeed() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let name = format!("{}.txt", "n".repeat(246));
    assert_eq!(name.len(), 250);
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(200).header("Content-Length", "5");
    });
    server.mock(|when, then| {
        when.method("GET");
        then.status(200).body("hello");
    });
    let data = get_data(
        s3_stage(),
        &[&format!("prefix/{name}")],
        dir.path(),
        json!({}),
    );
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(std::fs::read(dir.path().join(&name)).unwrap(), b"hello");
}

#[test]
fn encrypted_downloads_of_long_file_names_succeed() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let name = format!("{}.txt", "n".repeat(246));
    let (cipher, meta) = encrypted(b"hello stage");
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(200)
            .header("Content-Length", cipher.len().to_string())
            .header("x-amz-meta-x-amz-key", meta.key.as_str())
            .header("x-amz-meta-x-amz-iv", meta.iv.as_str())
            .header("x-amz-meta-x-amz-matdesc", meta.matdesc.as_str());
    });
    server.mock(|when, then| {
        when.method("GET");
        then.status(200).body(cipher.clone());
    });
    let data = get_data(
        s3_stage(),
        &[&format!("prefix/{name}")],
        dir.path(),
        json!({"encryptionMaterial": [material()]}),
    );
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join(&name)).unwrap(),
        b"hello stage"
    );
}

#[test]
fn s3_large_downloads_use_ranges() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let size: usize = (8 << 20) + 5;
    let first = vec![1u8; 8 << 20];
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(200).header("Content-Length", size.to_string());
    });
    let part1 = server.mock(|when, then| {
        when.method("GET")
            .header("range", format!("bytes=0-{}", (8 << 20) - 1));
        then.status(206).body(first.clone());
    });
    let part2 = server.mock(|when, then| {
        when.method("GET")
            .header("range", format!("bytes={}-{}", 8 << 20, size - 1));
        then.status(206).body(vec![2u8; 5]);
    });
    let data = get_data(
        s3_stage(),
        &["p/big.bin"],
        dir.path(),
        json!({"threshold": 1024}),
    );
    let result = run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(rows(&result)[0][1], size.to_string());
    part1.assert();
    part2.assert();
    let written = std::fs::read(dir.path().join("big.bin")).unwrap();
    assert_eq!(&written[size - 6..], &[1, 2, 2, 2, 2, 2]);
}

#[test]
fn download_failures() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    // The size the storage announced is not what came: an error, no file left behind.
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/p/short.txt");
        then.status(200).header("Content-Length", "100");
    });
    server.mock(|when, then| {
        when.method("GET").path("/stage/dir/p/short.txt");
        then.status(200).body("tiny");
    });
    let data = get_data(s3_stage(), &["p/short.txt"], dir.path(), json!({}));
    let err = run("GET", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(err.message().starts_with("253002: 253002: While getting file(s) there was an error: 'The downloaded file does not have the size"), "{}", err.message());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    // Encrypted stage, but the file has no metadata.
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/p/plain.txt");
        then.status(200).header("Content-Length", "4");
    });
    server.mock(|when, then| {
        when.method("GET").path("/stage/dir/p/plain.txt");
        then.status(200).body("abcd");
    });
    let data = get_data(
        s3_stage(),
        &["p/plain.txt"],
        dir.path(),
        json!({"encryptionMaterial": [material()]}),
    );
    let err = run("GET", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("has no encryption metadata"),
        "{}",
        err.message()
    );
    // Ciphertext that does not decrypt.
    let (_, meta) = encrypted(b"x");
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/p/bad.txt");
        then.status(200)
            .header("Content-Length", "16")
            .header("x-amz-meta-x-amz-key", meta.key.as_str())
            .header("x-amz-meta-x-amz-iv", meta.iv.as_str());
    });
    server.mock(|when, then| {
        when.method("GET").path("/stage/dir/p/bad.txt");
        then.status(200).body(vec![0u8; 16]);
    });
    let data = get_data(
        s3_stage(),
        &["p/bad.txt"],
        dir.path(),
        json!({"encryptionMaterial": [material()]}),
    );
    let err = run("GET", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("Could not decrypt"),
        "{}",
        err.message()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    // A HEAD that fails.
    server.mock(|when, then| {
        when.method("HEAD").path("/stage/dir/p/denied.txt");
        then.status(403);
    });
    let data = get_data(s3_stage(), &["p/denied.txt"], dir.path(), json!({}));
    let err = run("GET", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(err.message().contains("HEAD with url"), "{}", err.message());
}

#[test]
fn get_plans_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let local = |extra: Json, sources: &[&str], path: &Path| {
        let data = get_data(s3_stage(), sources, path, extra);
        run("GET", &data, &no_requery, &options(None)).unwrap_err()
    };
    let err = local(json!({}), &["p/a"], &dir.path().join("missing"));
    assert_eq!(
        err.message(),
        format!(
            "253005: 253005: The local path is not a directory: {}",
            dir.path().join("missing").display()
        )
    );
    let err = local(json!({}), &[], dir.path());
    assert_eq!(
        err.message(),
        "253006: 253006: While getting file(s) there was an error: the file does not exist."
    );
    let err = local(
        json!({"encryptionMaterial": [material()]}),
        &["p/a", "p/b"],
        dir.path(),
    );
    assert!(
        err.message().contains("files=2, encmat=1"),
        "{}",
        err.message()
    );
    for unsafe_name in ["p/..", "p/x/.", "p/"] {
        let err = local(json!({}), &[unsafe_name], dir.path());
        assert_eq!(err.kind(), ErrorKind::Client, "{unsafe_name}");
        assert!(
            err.message().contains("not a plain file name"),
            "{}",
            err.message()
        );
    }
}

#[test]
fn put_plans_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let fail = |data: Json| run("PUT", &data, &no_requery, &options(None)).unwrap_err();
    let missing = format!("{}/none*.csv", dir.path().display());
    let err = fail(put_data(s3_stage(), vec![missing.clone()], json!({})));
    assert_eq!(
        err.message(),
        format!("253006: 253006: File doesn't exist: ['{missing}']")
    );
    let err = fail(put_data(
        s3_stage(),
        vec![dir.path().display().to_string()],
        json!({}),
    ));
    assert_eq!(
        err.message(),
        format!(
            "253006: 253006: Not a file but a directory: {}",
            dir.path().display()
        )
    );
    let xz = write(dir.path(), "a.xz", b"x");
    let err = fail(put_data(
        s3_stage(),
        vec![xz.display().to_string()],
        json!({}),
    ));
    assert!(
        err.message()
            .starts_with("253007: 253007: Feature is not supported: CompressionType(name='XZ'")
    );
    let err = fail(put_data(s3_stage(), vec![], json!({"command": "NOPE"})));
    assert_eq!(
        err.message(),
        "253004: 253004: Failed to parse server's response"
    );
    let err = fail(json!({"command": "UPLOAD", "src_locations": "x"}));
    assert_eq!(
        err.message(),
        "253004: 253004: Failed to parse the location"
    );
    let mut bad_stage = s3_stage();
    bad_stage["locationType"] = "FTP".into();
    let err = fail(put_data(bad_stage, vec![], json!({})));
    assert_eq!(
        err.message(),
        "253001: 253001: Destination location type is not valid: FTP"
    );
    let err = fail(put_data(
        s3_stage(),
        vec![xz.display().to_string()],
        json!({"sourceCompression": "lzma"}),
    ));
    assert!(err.message().contains("name='LZMA'"));
}

#[test]
fn source_compression_and_auto_compress_decide_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    let stage_json =
        json!({"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}});
    let file = write(dir.path(), "data.csv", b"1,2\n");
    let gz = write(dir.path(), "data2.csv.gz", &[0x1f, 0x8b, 0, 0]);
    let run_put = |extra: Json, path: &Path| {
        let data = put_data(stage_json.clone(), vec![path.display().to_string()], extra);
        rows(&run("PUT", &data, &no_requery, &options(None)).unwrap())
    };
    assert_eq!(
        run_put(json!({"autoCompress": false}), &file)[0][1..6],
        ["data.csv", "4", "4", "NONE", "NONE"]
    );
    assert_eq!(
        run_put(
            json!({"sourceCompression": "gzip", "overwrite": true}),
            &file
        )[0][1..6],
        ["data.csv", "4", "4", "GZIP", "GZIP"]
    );
    assert_eq!(
        run_put(json!({"sourceCompression": "none"}), &gz)[0][1..6],
        ["data2.csv.gz.gz", "4", "39", "NONE", "GZIP"]
    );
    assert_eq!(
        run_put(json!({}), &gz)[0][1..6],
        ["data2.csv.gz", "4", "4", "GZIP", "GZIP"]
    );
}

#[test]
fn local_fs_round_trip_encrypts_uploads_and_copies_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    let stage_json =
        json!({"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}});
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    write(&src, "a.csv", b"a,b\n1,2\n");
    write(&src, "b.csv", b"x\n");
    let data = put_data(
        stage_json.clone(),
        vec![format!("{}/*.csv", src.display())],
        json!({"encryptionMaterial": material()}),
    );
    let result = run("PUT", &data, &no_requery, &options(None)).unwrap();
    // As the connector: encrypted on the way up, with the sizes `snow` shows.
    assert_eq!(rows(&result)[0][..4], ["a.csv", "a.csv.gz", "8", "48"]);
    assert_eq!(std::fs::metadata(stage.join("a.csv.gz")).unwrap().len(), 48);
    // Second run: both exist, both skipped.
    let result = run("PUT", &data, &no_requery, &options(None)).unwrap();
    assert!(rows(&result).iter().all(|r| r[6] == "SKIPPED"));
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let data = get_data(
        stage_json,
        &["a.csv.gz", "b.csv.gz"],
        &out,
        json!({"encryptionMaterial": [material(), material()]}),
    );
    let result = run("GET", &data, &no_requery, &options(None)).unwrap();
    assert_eq!(
        rows(&result),
        [
            ["a.csv.gz", "48", "DOWNLOADED", ""],
            ["b.csv.gz", "32", "DOWNLOADED", ""]
        ]
    );
    let names: Vec<_> = result.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["file", "size", "status", "message"]);
    // The connector copies a LOCAL_FS download as is (no metadata to decrypt with): the file
    // is exactly what the stage holds, never a half-decrypted mix.
    assert_eq!(
        std::fs::read(out.join("a.csv.gz")).unwrap(),
        std::fs::read(stage.join("a.csv.gz")).unwrap()
    );
}

#[test]
fn local_fs_get_refuses_names_outside_the_stage() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    std::fs::create_dir(&stage).unwrap();
    write(dir.path(), "secret", b"top");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let stage_json =
        json!({"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}});
    let data = get_data(stage_json, &["x/../../secret"], &out, json!({}));
    let err = run("GET", &data, &no_requery, &options(None)).unwrap_err();
    assert!(
        err.message().contains("outside the stage directory"),
        "{}",
        err.message()
    );
    assert!(!out.join("secret").exists());
}

#[test]
fn a_failed_file_does_not_abort_finished_single_part_uploads() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let ok = write(dir.path(), "a.bin", b"fine");
    let bad = write(dir.path(), "b.bin", b"bad");
    server.mock(|when, then| {
        when.method("PUT").path_includes("a.bin");
        then.status(200);
    });
    server.mock(|when, then| {
        when.method("PUT").path_includes("b.bin");
        then.status(403);
    });
    let abort = server.mock(|when, then| {
        when.method("DELETE");
        then.status(204);
    });
    let data = put_data(
        s3_stage(),
        vec![ok.display().to_string(), bad.display().to_string()],
        json!({"overwrite": true, "autoCompress": false, "parallel": 1}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert_eq!(abort.calls(), 0);
}

#[test]
fn s3_requests_without_a_session_token_sign_no_token_header() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "f.bin", b"x");
    let put = server.mock(|when, then| {
        when.method("PUT")
            .header_missing("x-amz-security-token")
            .is_true(|req| {
                !req.headers().iter().any(|(k, v)| {
                    k.as_str().eq_ignore_ascii_case("authorization")
                        && String::from_utf8_lossy(v.as_bytes()).contains("x-amz-security-token")
                })
            });
        then.status(200);
    });
    let mut stage = s3_stage();
    stage["creds"] = json!({"AWS_KEY_ID": "AKID", "AWS_SECRET_KEY": "secret"});
    let data = put_data(
        stage,
        vec![file.display().to_string()],
        json!({"overwrite": true, "autoCompress": false}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    put.assert();
}

#[test]
fn get_warns_about_same_basename_files_like_the_connector() {
    let files = |names: &[&str]| -> Vec<GetFile> {
        names
            .iter()
            .map(|n| GetFile {
                source: (*n).to_string(),
                shown: (*n).to_string(),
                path: PathBuf::from("/out").join(n.rsplit('/').next().unwrap()),
                material: None,
                presigned_url: None,
            })
            .collect()
    };
    assert_eq!(
        duplicate_basenames(&files(&["a/f", "b/f", "c/g", "d/f"])),
        ["f"]
    );
    assert!(duplicate_basenames(&files(&["a/f", "b/g"])).is_empty());
    // End to end: both are downloaded, the last written wins, as in the connector.
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    std::fs::create_dir_all(stage.join("a")).unwrap();
    std::fs::create_dir_all(stage.join("b")).unwrap();
    write(&stage.join("a"), "f", b"1");
    write(&stage.join("b"), "f", b"2");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let stage_json =
        json!({"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}});
    let data = get_data(stage_json, &["a/f", "b/f"], &out, json!({}));
    let result = run("GET", &data, &no_requery, &options(None)).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert!(out.join("f").exists());
}

#[test]
fn many_small_files_with_parallel_one() {
    let dir = tempfile::tempdir().unwrap();
    let stage = dir.path().join("stage");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for i in 0..25 {
        write(&src, &format!("f{i:02}.txt"), format!("{i}").as_bytes());
    }
    let data = put_data(
        json!({"locationType": "local_fs", "location": stage.display().to_string()}),
        vec![format!("{}/*.txt", src.display())],
        json!({"parallel": 1}),
    );
    let result = run("PUT", &data, &no_requery, &options(None)).unwrap();
    assert_eq!(result.rows.len(), 25);
    assert_eq!(rows(&result)[0][0], "f00.txt");
    assert_eq!(rows(&result)[24][0], "f24.txt");
}

fn azure_stage() -> Json {
    json!({
        "locationType": "AZURE", "location": "container/stage/", "storageAccount": "acct",
        "endPoint": "blob.core.windows.net", "creds": {"AZURE_SAS_TOKEN": "?sv=1&sig=old"}
    })
}

#[test]
fn azure_upload_with_sas_and_metadata() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"a\n");
    let head = server.mock(|when, then| {
        when.method("HEAD")
            .path("/container/stage/a.csv.gz")
            .query_param("sig", "old");
        then.status(404);
    });
    let put = server.mock(|when, then| {
        when.method("PUT")
            .path("/container/stage/a.csv.gz")
            .query_param("sv", "1")
            .header("x-ms-blob-type", "BlockBlob")
            .header("content-encoding", "utf-8")
            .header_exists("x-ms-meta-sfcdigest")
            .header_matches(
                "x-ms-meta-encryptiondata",
                r#""EncryptionAlgorithm": "AES_CBC_128""#,
            )
            .header(
                "x-ms-meta-matdesc",
                r#"{"queryId":"q-1","smkId":"12","keySize":"128"}"#,
            );
        then.status(201);
    });
    let data = put_data(
        azure_stage(),
        vec![file.display().to_string()],
        json!({"encryptionMaterial": material()}),
    );
    let result = run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(rows(&result)[0][6], "UPLOADED");
    head.assert();
    put.assert();
}

#[test]
fn azure_block_lists_and_expired_sas() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "big.bin", &vec![3u8; 9 << 20]);
    let expired = server.mock(|when, then| {
        when.method("PUT").query_param("comp", "block").query_param("sig", "old");
        then.status(403).body("<Error><Code>AuthenticationFailed</Code><Message>Server failed to authenticate the request.</Message></Error>");
    });
    let blocks = server.mock(|when, then| {
        when.method("PUT")
            .query_param("comp", "block")
            .query_param("sig", "new")
            .query_param_matches("blockid", "^[0-9a-f]{20}$");
        then.status(201);
    });
    let list = server.mock(|when, then| {
        when.method("PUT")
            .query_param("comp", "blocklist")
            .header_exists("x-ms-blob-content-md5")
            .header("x-ms-blob-content-encoding", "utf-8")
            .body_matches("^<BlockList><Latest>[0-9a-f]{20}</Latest><Latest>[0-9a-f]{20}</Latest></BlockList>$");
        then.status(201);
    });
    let requery =
        |_: &str| Ok(json!({"stageInfo": {"creds": {"AZURE_SAS_TOKEN": "sv=1&sig=new"}}}));
    let data = put_data(
        azure_stage(),
        vec![file.display().to_string()],
        json!({"overwrite": true, "autoCompress": false, "threshold": 1, "parallel": 1}),
    );
    run("PUT", &data, &requery, &options(Some(&server))).unwrap();
    expired.assert_calls(1);
    blocks.assert_calls(2);
    list.assert();
}

#[test]
fn azure_download_reads_encryption_data() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let (cipher, meta) = encrypted(b"azure!");
    let data_header = azure::encryption_data(&meta, "AES_CBC_128");
    server.mock(|when, then| {
        when.method("HEAD").path("/container/stage/s/f.txt");
        then.status(200)
            .header("Content-Length", cipher.len().to_string())
            .header("x-ms-meta-encryptiondata", data_header.as_str())
            .header("x-ms-meta-matdesc", meta.matdesc.as_str());
    });
    server.mock(|when, then| {
        when.method("GET").path("/container/stage/s/f.txt");
        then.status(200).body(cipher.clone());
    });
    let data = get_data(
        azure_stage(),
        &["s/f.txt"],
        dir.path(),
        json!({"encryptionMaterial": [material()]}),
    );
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    assert_eq!(std::fs::read(dir.path().join("f.txt")).unwrap(), b"azure!");
    // A failing GET.
    server.mock(|when, then| {
        when.method("HEAD").path("/container/stage/s/g.txt");
        then.status(200).header("Content-Length", "1");
    });
    server.mock(|when, then| {
        when.method("GET").path("/container/stage/s/g.txt");
        then.status(404);
    });
    let data = get_data(azure_stage(), &["s/g.txt"], dir.path(), json!({}));
    let err = run("GET", &data, &no_requery, &options(Some(&server))).unwrap_err();
    assert!(err.message().contains("GET with url"), "{}", err.message());
    // The SAS token never reaches a message.
    assert!(
        !err.message().contains("sig=") && !err.message().contains("sv="),
        "{}",
        err.message()
    );
}

#[test]
fn azure_large_downloads_use_ranges() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let size: usize = (8 << 20) + 1;
    server.mock(|when, then| {
        when.method("HEAD");
        then.status(200).header("Content-Length", size.to_string());
    });
    let first = server.mock(|when, then| {
        when.method("GET")
            .header("range", format!("bytes=0-{}", (8 << 20) - 1));
        then.status(206).body(vec![0u8; 8 << 20]);
    });
    server.mock(|when, then| {
        when.method("GET")
            .header("range", format!("bytes={}-{}", 8 << 20, 8 << 20));
        then.status(206).body("z");
    });
    let data = get_data(
        azure_stage(),
        &["s/b.bin"],
        dir.path(),
        json!({"threshold": 1}),
    );
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    first.assert();
}

fn gcs_stage(token: Option<&str>) -> Json {
    json!({
        "locationType": "GCS", "location": "bucket/stage", "region": "US-CENTRAL1",
        "creds": token.map_or(json!({}), |t| json!({"GCS_ACCESS_TOKEN": t}))
    })
}

#[test]
fn gcs_upload_with_an_access_token() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"a\n");
    let deflate = write(dir.path(), "b.deflate", b"zz");
    let head = server.mock(|when, then| {
        when.method("HEAD")
            .path("/bucket/stage/a.csv.gz")
            .header("authorization", "Bearer tok");
        then.status(404);
    });
    let put = server.mock(|when, then| {
        when.method("PUT")
            .path("/bucket/stage/a.csv.gz")
            .header("authorization", "Bearer tok")
            .header_exists("x-goog-meta-sfc-digest")
            .header_matches(
                "x-goog-meta-encryptiondata",
                r#""EncryptionAlgorithm": "AES_CBC_256""#,
            )
            .header_exists("x-goog-meta-matdesc");
        then.status(200);
    });
    let data = put_data(
        gcs_stage(Some("tok")),
        vec![file.display().to_string()],
        json!({"encryptionMaterial": material()}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    head.assert();
    put.assert();
    // A given compression other than gzip becomes the Content-Encoding.
    let put = server.mock(|when, then| {
        when.method("PUT")
            .path("/bucket/stage/b.deflate")
            .header("content-encoding", "deflate");
        then.status(200);
    });
    let data = put_data(
        gcs_stage(Some("tok")),
        vec![deflate.display().to_string()],
        json!({"sourceCompression": "deflate", "overwrite": true}),
    );
    run("PUT", &data, &no_requery, &options(Some(&server))).unwrap();
    put.assert();
}

#[test]
fn gcs_expired_tokens_are_renewed() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"a\n");
    let old = server.mock(|when, then| {
        when.method("PUT").header("authorization", "Bearer old");
        then.status(401);
    });
    let new = server.mock(|when, then| {
        when.method("PUT").header("authorization", "Bearer new");
        then.status(200);
    });
    let requery = |_: &str| Ok(json!({"stageInfo": {"creds": {"GCS_ACCESS_TOKEN": "new"}}}));
    let data = put_data(
        gcs_stage(Some("old")),
        vec![file.display().to_string()],
        json!({"overwrite": true}),
    );
    run("PUT", &data, &requery, &options(Some(&server))).unwrap();
    old.assert_calls(1);
    new.assert_calls(1);
}

#[test]
fn gcs_upload_without_a_token_asks_for_a_presigned_url_per_file() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "a.csv", b"a\n");
    let expired = server.mock(|when, then| {
        when.method("PUT").path("/signed/1");
        then.status(400);
    });
    let put = server.mock(|when, then| {
        when.method("PUT")
            .path("/signed/2")
            .header_missing("authorization");
        then.status(200);
    });
    let statement = format!("PUT file://{} @~/x", file.display());
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let url1 = server.url("/signed/1");
    let url2 = server.url("/signed/2");
    let requery = |sql: &str| {
        assert_eq!(sql, "PUT file://a.csv.gz @~/x");
        let n = calls.fetch_add(1, Ordering::SeqCst);
        let url = if n == 0 { &url1 } else { &url2 };
        Ok(json!({"stageInfo": {"presignedUrl": url}}))
    };
    let data = put_data(gcs_stage(None), vec![file.display().to_string()], json!({}));
    let result = run(&statement, &data, &requery, &options(Some(&server))).unwrap();
    assert_eq!(rows(&result)[0][6], "UPLOADED");
    expired.assert_calls(1);
    put.assert_calls(1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // No local path in the statement: no presigned URL.
    let err = run("PUT x", &data, &requery, &options(Some(&server))).unwrap_err();
    assert!(
        err.message().contains("did not return a presigned URL"),
        "{}",
        err.message()
    );
}

#[test]
fn gcs_download_with_presigned_urls_and_with_a_token() {
    let server = MockServer::start();
    let dir = tempfile::tempdir().unwrap();
    let (cipher, meta) = encrypted(b"from gcs");
    let enc = azure::encryption_data(&meta, "AES_CBC_256");
    let signed = server.mock(|when, then| {
        when.method("GET")
            .path("/signed/f.txt")
            .header_missing("authorization");
        then.status(200)
            .header("x-goog-meta-encryptiondata", enc.as_str())
            .header("x-goog-meta-matdesc", meta.matdesc.as_str())
            .body(cipher.clone());
    });
    let data = get_data(
        gcs_stage(None),
        &["s/f.txt"],
        dir.path(),
        json!({"encryptionMaterial": [material()], "presignedUrls": [server.url("/signed/f.txt")]}),
    );
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    signed.assert();
    assert_eq!(
        std::fs::read(dir.path().join("f.txt")).unwrap(),
        b"from gcs"
    );
    let head = server.mock(|when, then| {
        when.method("HEAD")
            .path("/bucket/stage/s/g.txt")
            .header("authorization", "Bearer tok");
        then.status(200)
            .header("content-length", "3")
            .header("x-goog-meta-encryptiondata", "null");
    });
    server.mock(|when, then| {
        when.method("GET")
            .path("/bucket/stage/s/g.txt")
            .header("authorization", "Bearer tok");
        then.status(200).body("abc");
    });
    let data = get_data(gcs_stage(Some("tok")), &["s/g.txt"], dir.path(), json!({}));
    run("GET", &data, &no_requery, &options(Some(&server))).unwrap();
    head.assert();
    assert_eq!(std::fs::read(dir.path().join("g.txt")).unwrap(), b"abc");
}

#[test]
fn execute_requeries_through_the_session() {
    // Covered end to end by the CLI tests (tests/it/put_get.rs); here only the options.
    let options = TransferOptions::new(Some(PathBuf::from("/h")));
    assert_eq!(options.home.as_deref(), Some(Path::new("/h")));
    assert!(options.endpoint_override.is_none());
    assert_eq!(py_list(&["a'b".into(), "c".into()]), r#"["a'b", 'c']"#);
}

#[test]
fn upload_for_borrows_the_file_and_the_prepared_upload() {
    let file = PutFile {
        name: "a.csv".into(),
        path: PathBuf::from("a.csv"),
        size: 3,
        target: "a.csv.gz".into(),
        source_compression: None,
        target_compression: Some(&files::GZIP),
        compress: true,
    };
    let meta = Metadata {
        key: "k".into(),
        iv: "i".into(),
        matdesc: "m".into(),
    };
    let ready = ReadyUpload {
        data: PathBuf::from("a.csv.gz"),
        size: 3,
        digest: "d".into(),
        encryption: Some(meta.clone()),
        md5: Some("md5".into()),
        part_size: 3,
        multipart: None,
        temporary: Vec::new(),
    };
    let upload = upload_for(&file, &ready);
    assert_eq!(upload.name, "a.csv.gz");
    assert_eq!(upload.digest, "d");
    assert_eq!(upload.encryption, Some(&meta));
    assert_eq!(upload.md5, Some("md5"));
    assert_eq!(upload.compression, Some(files::GZIP.name));
    assert_eq!(upload.presigned_url, None);
}
