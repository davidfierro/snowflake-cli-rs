//! `PUT`/`GET` file transfer (ADR 0005, Decision 5), built on the answer a `PUT`/`GET`
//! statement gets from `query-request`: the client compresses, encrypts and moves the files
//! itself, straight to or from the stage's cloud storage. `sql` uses it today; `stage copy` will
//! build its statement and call the same [`execute`].
//!
//! Files stream through temporary files and fixed-size buffers, so memory stays bounded whatever
//! their size: at most `2 × workers` parts are queued, and each part is read from disk when it
//! is sent.

mod azure;
mod crypto;
mod files;
mod gcs;
mod local;
mod s3;
mod storage;

use crate::error::{Error, ErrorKind, Result};
use crate::session::{Session, TransferCommand};
use crate::sql::{Column, QueryResult, SfType, Value};
use crypto::{Material, Metadata};
use files::{Compression, ER_FILE_NOT_EXISTS, connector_error};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime};
use storage::{Body, Credentials, Download, Header, Http, Multipart, Storage, Upload};

const ER_INVALID_STAGE_FS: u32 = 253001;
const ER_FAILED_TO_DOWNLOAD_FROM_STAGE: u32 = 253002;
const ER_FAILED_TO_UPLOAD_TO_STAGE: u32 = 253003;
const ER_INVALID_STAGE_LOCATION: u32 = 253004;
const ER_LOCAL_PATH_NOT_DIRECTORY: u32 = 253005;
const ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL: u32 = 253008;
/// `multipart_threshold` when the answer has no `threshold`.
const DEFAULT_THRESHOLD: u64 = 64 << 20;
/// Part size of downloads (`S3_DEFAULT_CHUNK_SIZE`, `AZURE_CHUNK_SIZE`).
const DOWNLOAD_PART: u64 = 8 << 20;

/// How a transfer runs.
#[derive(Debug, Clone)]
pub struct TransferOptions {
    /// The home directory, for `~` in local paths.
    pub home: Option<PathBuf>,
    /// Base URL of every storage request instead of the one `stageInfo` names (tests only).
    pub(crate) endpoint_override: Option<String>,
    /// Backoff before retry `n` (tests: none).
    pub(crate) sleep: fn(u32) -> Duration,
    pub(crate) clock: fn() -> SystemTime,
}

impl TransferOptions {
    pub fn new(home: Option<PathBuf>) -> Self {
        Self {
            home,
            endpoint_override: None,
            sleep: storage::backoff,
            clock: SystemTime::now,
        }
    }
}

/// Executes the transfer a `PUT`/`GET` `query-request` answer describes; returns `snow`'s rows.
pub fn execute(
    session: &Session,
    statement: &str,
    data: &serde_json::Value,
    options: &TransferOptions,
) -> Result<QueryResult> {
    let requery = |sql: &str| session.query(sql).map(|r| r.data);
    run(statement, data, &requery, options)
}

/// A `ResultStatus` of the connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Uploaded,
    Skipped,
    Downloaded,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Uploaded => "UPLOADED",
            Status::Skipped => "SKIPPED",
            Status::Downloaded => "DOWNLOADED",
        }
    }
}

/// One file of a `PUT`.
struct PutFile {
    /// Source base name.
    name: String,
    path: PathBuf,
    size: u64,
    target: String,
    source_compression: Option<&'static Compression>,
    target_compression: Option<&'static Compression>,
    compress: bool,
}

/// One file of a `GET`.
struct GetFile {
    /// Name inside the stage location.
    source: String,
    /// What the row shows: the source without its first path segment.
    shown: String,
    /// Where it is written: the base name, inside the local directory.
    path: PathBuf,
    material: Option<Material>,
    presigned_url: Option<String>,
}

/// The parts of `data` every transfer reads.
struct Plan<'a> {
    command: TransferCommand,
    sources: Vec<String>,
    parallel: usize,
    threshold: u64,
    stage_type: String,
    stage: &'a serde_json::Value,
}

fn plan(data: &serde_json::Value) -> Result<Plan<'_>> {
    let command = match data["command"].as_str() {
        Some("UPLOAD") => TransferCommand::Upload,
        Some("DOWNLOAD") => TransferCommand::Download,
        _ => {
            return Err(connector_error(
                ER_INVALID_STAGE_LOCATION,
                "Failed to parse server's response",
            ));
        }
    };
    let Some(sources) = data["src_locations"].as_array() else {
        return Err(connector_error(
            ER_INVALID_STAGE_LOCATION,
            "Failed to parse the location",
        ));
    };
    let stage = &data["stageInfo"];
    let stage_type = stage["locationType"]
        .as_str()
        .unwrap_or_default()
        .to_uppercase();
    if !matches!(stage_type.as_str(), "LOCAL_FS" | "S3" | "AZURE" | "GCS") {
        return Err(connector_error(
            ER_INVALID_STAGE_FS,
            format!("Destination location type is not valid: {stage_type}"),
        ));
    }
    Ok(Plan {
        command,
        sources: sources
            .iter()
            .map(|s| s.as_str().unwrap_or_default().to_string())
            .collect(),
        parallel: data["parallel"]
            .as_u64()
            .and_then(|p| usize::try_from(p).ok())
            .unwrap_or(1)
            .max(1),
        threshold: data["threshold"].as_u64().unwrap_or(DEFAULT_THRESHOLD),
        stage_type,
        stage,
    })
}

/// [`execute`] without a session: `requery` runs a statement again (fresh credentials, a GCS
/// presigned URL) and returns its `data`.
pub(crate) fn run(
    statement: &str,
    data: &serde_json::Value,
    requery: storage::Requery<'_>,
    options: &TransferOptions,
) -> Result<QueryResult> {
    let plan = plan(data)?;
    let handle = data["queryId"].as_str().unwrap_or_default().to_string();
    let http = Http::new(options.sleep);
    let creds = Credentials::new(&plan.stage["creds"], statement, requery);
    match plan.command {
        TransferCommand::Upload => {
            let files = put_files(&plan, data, options)?;
            let material = data["encryptionMaterial"]
                .as_object()
                .and_then(|_| Material::from_json(&data["encryptionMaterial"]));
            let storage = storage_for(&plan, &http, &creds, options)?;
            let outcomes = upload(&plan, &files, material.as_ref(), storage.as_ref(), data)?;
            Ok(put_result(handle, &files, &outcomes))
        }
        TransferCommand::Download => {
            let files = get_files(&plan, data, options)?;
            let storage = storage_for(&plan, &http, &creds, options)?;
            let sizes = download(&plan, &files, storage.as_ref())?;
            Ok(get_result(handle, &files, &sizes))
        }
    }
}

fn storage_for<'a>(
    plan: &Plan<'_>,
    http: &'a Http,
    creds: &'a Credentials<'a>,
    options: &'a TransferOptions,
) -> Result<Box<dyn Storage + 'a>> {
    let endpoint = options.endpoint_override.as_deref();
    Ok(match plan.stage_type.as_str() {
        "S3" => Box::new(s3::S3::new(
            plan.stage,
            http,
            creds,
            endpoint,
            options.clock,
        )),
        "AZURE" => Box::new(azure::Azure::new(plan.stage, http, creds, endpoint)),
        "GCS" => Box::new(gcs::Gcs::new(plan.stage, http, creds, endpoint)),
        _ => Box::new(local::LocalFs::new(
            plan.stage["location"].as_str().unwrap_or_default(),
            options.home.as_deref(),
        )?),
    })
}

/// Python's `repr()` of a list of strings.
fn py_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| crate::script::py_repr(s)).collect();
    format!("[{}]", quoted.join(", "))
}

/// The local files of a `PUT`, checked and with their compression decided
/// (`_init_file_metadata`, `_process_file_compression_type`).
fn put_files(
    plan: &Plan<'_>,
    data: &serde_json::Value,
    options: &TransferOptions,
) -> Result<Vec<PutFile>> {
    let paths = files::expand(&plan.sources, options.home.as_deref());
    if paths.is_empty() {
        return Err(connector_error(
            ER_FILE_NOT_EXISTS,
            format!("File doesn't exist: {}", py_list(&plan.sources)),
        ));
    }
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let meta = std::fs::metadata(&path).map_err(|_| {
            connector_error(
                ER_FILE_NOT_EXISTS,
                format!("File doesn't exist: {}", path.display()),
            )
        })?;
        if meta.is_dir() {
            return Err(connector_error(
                ER_FILE_NOT_EXISTS,
                format!("Not a file but a directory: {}", path.display()),
            ));
        }
        out.push((path, meta.len()));
    }
    let auto_compress = data["autoCompress"].as_bool().unwrap_or(true);
    let mode = files::source_compression(data["sourceCompression"].as_str().unwrap_or(""))?;
    out.into_iter()
        .map(|(path, size)| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let detected = files::detect(&path, &mode)?;
            let (target, target_compression, compress) = match detected {
                Some(found) => (name.clone(), Some(found), false),
                None if auto_compress => (
                    format!("{name}{}", files::GZIP.extension),
                    Some(&files::GZIP),
                    true,
                ),
                None => (name.clone(), None, false),
            };
            Ok(PutFile {
                name,
                path,
                size,
                target,
                source_compression: detected,
                target_compression,
                compress,
            })
        })
        .collect()
}

/// The stage files of a `GET` and where each goes (`_parse_command`, `_init_file_metadata`).
fn get_files(
    plan: &Plan<'_>,
    data: &serde_json::Value,
    options: &TransferOptions,
) -> Result<Vec<GetFile>> {
    let materials: Vec<Option<Material>> = data["encryptionMaterial"]
        .as_array()
        .map(|list| list.iter().map(Material::from_json).collect())
        .unwrap_or_default();
    let present = materials.iter().filter(|m| m.is_some()).count();
    if present != 0 && materials.len() != plan.sources.len() {
        return Err(Error::new(
            ErrorKind::Sql,
            format!(
                "{ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL}: {ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL}: \
                 The number of downloading files doesn't match the encryption materials: \
                 files={}, encmat={present}",
                plan.sources.len()
            ),
        ));
    }
    let local = data["localLocation"].as_str().unwrap_or_default();
    let local = crate::config::expand_user_with(local, options.home.as_deref());
    if !local.is_dir() {
        return Err(connector_error(
            ER_LOCAL_PATH_NOT_DIRECTORY,
            format!("The local path is not a directory: {}", local.display()),
        ));
    }
    let urls = data["presignedUrls"].as_array();
    // The connector encrypts a LOCAL_FS `PUT` but copies a LOCAL_FS `GET` as is: the stage keeps
    // no encryption metadata, so the file could not be decrypted anyway (golden `put_get` tests).
    let decrypt = plan.stage_type != "LOCAL_FS";
    let mut out: Vec<GetFile> = Vec::new();
    for (i, source) in plan.sources.iter().enumerate() {
        if source.is_empty() {
            continue;
        }
        let shown = source.split_once('/').map_or(source.as_str(), |(_, r)| r);
        let base = shown.rsplit('/').next().unwrap_or(shown);
        if base.is_empty() || base == "." || base == ".." || base.contains(['\\', '\0']) {
            return Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Refusing to download '{}': it is not a plain file name.",
                    crate::render::sanitize::sanitize_for_terminal(source)
                ),
            ));
        }
        out.push(GetFile {
            source: source.clone(),
            shown: shown.to_string(),
            path: local.join(base),
            material: materials.get(i).cloned().flatten().filter(|_| decrypt),
            presigned_url: urls
                .and_then(|u| u.get(i))
                .and_then(|u| u.as_str())
                .map(String::from),
        });
    }
    let duplicates = duplicate_basenames(&out);
    if !duplicates.is_empty() {
        // The connector only warns, and the last file written wins.
        eprintln!(
            "Downloading multiple files with the same name could cause failures. \
             File names with multiple entries: {}",
            py_list(&duplicates)
        );
    }
    if out.is_empty() {
        return Err(connector_error(
            ER_FILE_NOT_EXISTS,
            "While getting file(s) there was an error: the file does not exist.",
        ));
    }
    Ok(out)
}

/// Base names that more than one `GET` file maps to, in first-seen order.
fn duplicate_basenames(files: &[GetFile]) -> Vec<String> {
    let mut seen: Vec<(String, usize)> = Vec::new();
    for file in files {
        let base = file
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match seen.iter_mut().find(|(name, _)| *name == base) {
            Some((_, count)) => *count += 1,
            None => seen.push((base, 1)),
        }
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, _)| name)
        .collect()
}

/// A private temporary directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("snow-rs-transfer-{}", uuid::Uuid::new_v4()));
        #[cfg_attr(not(unix), allow(unused_mut))]
        // `mut` is needed only by the unix-only mode call below
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&path).map_err(storage::file_error)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The work of one file: prepared once, then sent in parts by the network workers.
struct Prepared<P> {
    value: P,
    parts: usize,
}

type PrepareFn<'a, P> = dyn Fn(usize) -> Result<Option<Prepared<P>>> + Sync + 'a;
type PartFn<'a, P> = dyn Fn(usize, &P, usize) -> Result<String> + Sync + 'a;
type FinishFn<'a, P> = dyn Fn(usize, &P, Vec<String>) -> Result<()> + Sync + 'a;
type AbortFn<'a, P> = dyn Fn(usize, &P) + Sync + 'a;

/// Runs `prepare` for every file on a few threads, the parts of the prepared files on
/// `workers` threads, and `finish` once all parts of a file are done (ADR 0005, Decision 5:
/// at most `2 × workers` parts queued). The first error cancels the rest.
fn pipeline<P: Send + Sync>(
    files: usize,
    workers: usize,
    prepare: &PrepareFn<'_, P>,
    part: &PartFn<'_, P>,
    finish: &FinishFn<'_, P>,
    abort: &AbortFn<'_, P>,
) -> Result<()> {
    struct Slot<P> {
        file: usize,
        value: P,
        remaining: AtomicUsize,
        results: Mutex<Vec<String>>,
        failed: AtomicBool,
    }
    let failure: Mutex<Option<Error>> = Mutex::new(None);
    let cancel = AtomicBool::new(false);
    let next = AtomicUsize::new(0);
    let fail = |e: Error| {
        let mut slot = failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(e);
        }
        cancel.store(true, Ordering::SeqCst);
    };
    let preparers = files
        .min(std::thread::available_parallelism().map_or(4, |n| n.get()))
        .max(1);
    let (sender, receiver) = mpsc::sync_channel::<(Arc<Slot<P>>, usize)>(2 * workers);
    let receiver = Mutex::new(receiver);
    let complete = |slot: &Slot<P>| {
        if slot.failed.load(Ordering::SeqCst) || cancel.load(Ordering::SeqCst) {
            abort(slot.file, &slot.value);
            return;
        }
        let results = std::mem::take(
            &mut *slot
                .results
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if let Err(e) = finish(slot.file, &slot.value, results) {
            fail(e);
        }
    };
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let job = receiver
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok((slot, index)) = job else { return };
                    if !cancel.load(Ordering::SeqCst) {
                        match part(slot.file, &slot.value, index) {
                            Ok(result) => {
                                slot.results
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)[index] =
                                    result;
                            }
                            Err(e) => {
                                slot.failed.store(true, Ordering::SeqCst);
                                fail(e);
                            }
                        }
                    }
                    if slot.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                        complete(&slot);
                    }
                }
            });
        }
        for _ in 0..preparers {
            let sender = sender.clone();
            let (next, cancel, fail) = (&next, &cancel, &fail);
            scope.spawn(move || {
                loop {
                    let file = next.fetch_add(1, Ordering::SeqCst);
                    if file >= files || cancel.load(Ordering::SeqCst) {
                        return;
                    }
                    let prepared = match prepare(file) {
                        Ok(Some(prepared)) => prepared,
                        Ok(None) => continue,
                        Err(e) => {
                            fail(e);
                            return;
                        }
                    };
                    let parts = prepared.parts.max(1);
                    let slot = Arc::new(Slot {
                        file,
                        value: prepared.value,
                        remaining: AtomicUsize::new(parts),
                        results: Mutex::new(vec![String::new(); parts]),
                        failed: AtomicBool::new(false),
                    });
                    for index in 0..parts {
                        if sender.send((Arc::clone(&slot), index)).is_err() {
                            return;
                        }
                    }
                }
            });
        }
        drop(sender);
    });
    match failure
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A `PUT` file ready to send.
struct ReadyUpload {
    data: PathBuf,
    size: u64,
    digest: String,
    encryption: Option<Metadata>,
    md5: Option<String>,
    part_size: u64,
    /// Set when `begin_multipart` opened a multipart/block upload.
    multipart: Option<Multipart>,
    /// Temporary files of this file, removed once it is sent.
    temporary: Vec<PathBuf>,
}

/// The storage client's view of `file`, borrowed from the prepared upload.
fn upload_for<'a>(file: &'a PutFile, ready: &'a ReadyUpload) -> Upload<'a> {
    Upload {
        name: &file.target,
        digest: &ready.digest,
        encryption: ready.encryption.as_ref(),
        md5: ready.md5.as_deref(),
        compression: file.target_compression.map(|c| c.name),
        presigned_url: None,
    }
}

/// What each `PUT` file ended as: status and target size.
type Outcomes = Vec<Mutex<Option<(Status, u64)>>>;

fn upload(
    plan: &Plan<'_>,
    files: &[PutFile],
    material: Option<&Material>,
    storage: &dyn Storage,
    data: &serde_json::Value,
) -> Result<Outcomes> {
    let overwrite = data["overwrite"].as_bool().unwrap_or(false);
    let temp = TempDir::new()?;
    let outcomes: Outcomes = files.iter().map(|_| Mutex::new(None)).collect();
    let set = |i: usize, outcome: (Status, u64)| {
        *outcomes[i]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
    };
    let prepare = |i: usize| -> Result<Option<Prepared<ReadyUpload>>> {
        let file = &files[i];
        if !overwrite && storage.head(&file.target, None)?.is_some() {
            set(i, (Status::Skipped, 0));
            return Ok(None);
        }
        let mut temporary = Vec::new();
        let mut data_path = file.path.clone();
        if file.compress {
            let gz = temp.0.join(format!("{i}.gz"));
            files::gzip(&file.path, &gz, &file.name)?;
            temporary.push(gz.clone());
            data_path = gz;
        }
        let (digest, mut size) = files::digest(&data_path)?;
        let mut encryption = None;
        if let Some(material) = material {
            let encrypted = temp.0.join(format!("{i}.enc"));
            let mut input = std::fs::File::open(&data_path).map_err(storage::file_error)?;
            let mut output = std::io::BufWriter::new(files::create_private(&encrypted)?);
            let (meta, written) = crypto::encrypt(material, &mut input, &mut output)?;
            std::io::Write::flush(&mut output).map_err(storage::file_error)?;
            temporary.push(encrypted.clone());
            data_path = encrypted;
            size = written;
            encryption = Some(meta);
        }
        let part_size = storage.chunk_size(size).filter(|_| size >= plan.threshold);
        let parts = part_size.map_or(1, |p| usize::try_from(size.div_ceil(p)).unwrap_or(1).max(1));
        let md5 = if parts > 1 && plan.stage_type == "AZURE" {
            Some(files::md5(&data_path)?)
        } else {
            None
        };
        let mut ready = ReadyUpload {
            data: data_path,
            size,
            digest,
            encryption,
            md5,
            part_size: part_size.unwrap_or(size),
            multipart: None,
            temporary,
        };
        if parts > 1 {
            let started = storage.begin_multipart(&upload_for(file, &ready), parts)?;
            // A storage without multipart uploads (GCS, local) returns an empty one.
            ready.multipart =
                Some(started).filter(|m| !(m.upload_id.is_empty() && m.block_ids.is_empty()));
        }
        Ok(Some(Prepared {
            value: ready,
            parts,
        }))
    };
    let part = |i: usize, ready: &ReadyUpload, index: usize| -> Result<String> {
        let upload = upload_for(&files[i], ready);
        match &ready.multipart {
            None => {
                let body = Body {
                    path: ready.data.clone(),
                    offset: 0,
                    len: ready.size,
                };
                storage.put(&upload, &body).map(|()| String::new())
            }
            Some(multipart) => {
                let offset = index as u64 * ready.part_size;
                let body = Body {
                    path: ready.data.clone(),
                    offset,
                    len: ready.part_size.min(ready.size - offset),
                };
                storage.put_part(&upload, multipart, index, &body)
            }
        }
    };
    let finish = |i: usize, ready: &ReadyUpload, etags: Vec<String>| -> Result<()> {
        if let Some(multipart) = &ready.multipart {
            storage.complete_multipart(&upload_for(&files[i], ready), multipart, &etags)?;
        }
        for path in &ready.temporary {
            let _ = std::fs::remove_file(path);
        }
        set(i, (Status::Uploaded, ready.size));
        Ok(())
    };
    let abort = |i: usize, ready: &ReadyUpload| {
        // Single-part uploads have nothing to abort (S3 would get an empty `uploadId`).
        if let Some(multipart) = &ready.multipart {
            storage.abort_multipart(&upload_for(&files[i], ready), multipart);
        }
    };
    pipeline(files.len(), plan.parallel, &prepare, &part, &finish, &abort)
        .map_err(|e| transfer_error(ER_FAILED_TO_UPLOAD_TO_STAGE, "putting", e))?;
    Ok(outcomes)
}

/// `While putting file(s) there was an error: '<cause>', …`: a failure while moving the files.
fn transfer_error(code: u32, verb: &str, cause: Error) -> Error {
    if cause.kind() == ErrorKind::Sql {
        // Already a connector error (e.g. renewing the credentials failed in SQL).
        return cause;
    }
    connector_error(
        code,
        format!(
            "While {verb} file(s) there was an error: '{}', this might be caused by your access \
             to the blob storage provider, or by Snowflake.",
            cause.message()
        ),
    )
}

/// A `GET` file being written.
struct ReadyDownload {
    part_path: PathBuf,
    size: Option<u64>,
    header_encryption: Option<Metadata>,
    response_encryption: Mutex<Option<Metadata>>,
    /// Bytes received over all parts.
    received: std::sync::atomic::AtomicU64,
}

/// Counts what goes through it.
struct Counting<W> {
    inner: W,
    count: u64,
}

impl<W: std::io::Write> std::io::Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn temp_error(e: std::io::Error) -> Error {
    Error::new(ErrorKind::Client, "Could not create a temporary file.").with_source(e)
}

fn download(plan: &Plan<'_>, files: &[GetFile], storage: &dyn Storage) -> Result<Vec<u64>> {
    let sizes: Vec<Mutex<u64>> = files.iter().map(|_| Mutex::new(0)).collect();
    let chunked = storage.chunk_size(0).is_some();
    let prepare = |i: usize| -> Result<Option<Prepared<ReadyDownload>>> {
        let file = &files[i];
        let header: Option<Header> = storage.head(&file.source, file.presigned_url.as_deref())?;
        let size = header.as_ref().and_then(|h| h.size);
        let parts = match size {
            Some(size) if chunked && size > plan.threshold => {
                usize::try_from(size.div_ceil(DOWNLOAD_PART)).unwrap_or(1)
            }
            _ => 1,
        };
        // A short hidden name, whatever the stage file's name (a name near the limit must still
        // work), unique per file (two stage files with the same base name, `a/f` and `b/f`,
        // must not share it; the connector's does, and one of them fails), created exclusively
        // and owner-only: never written through a link or into an old file.
        let (created, part_path) =
            crate::fsutil::create_temp(crate::fsutil::parent_dir(&file.path), ".part")
                .map_err(temp_error)?;
        if let Some(size) = size {
            created.set_len(size).map_err(storage::file_error)?;
        }
        Ok(Some(Prepared {
            value: ReadyDownload {
                part_path,
                size,
                header_encryption: header.and_then(|h| h.encryption),
                response_encryption: Mutex::new(None),
                received: std::sync::atomic::AtomicU64::new(0),
            },
            parts,
        }))
    };
    let part = |i: usize, ready: &ReadyDownload, index: usize| -> Result<String> {
        let file = &files[i];
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .open(&ready.part_path)
            .map_err(storage::file_error)?;
        let range = match ready.size {
            Some(size) if size > plan.threshold && chunked => {
                let first = index as u64 * DOWNLOAD_PART;
                let last = (first + DOWNLOAD_PART).min(size) - 1;
                out.seek(SeekFrom::Start(first))
                    .map_err(storage::file_error)?;
                Some((first, Some(last)))
            }
            _ => None,
        };
        let mut writer = Counting {
            inner: std::io::BufWriter::new(out),
            count: 0,
        };
        let found = storage.get(
            &Download {
                name: &file.source,
                presigned_url: file.presigned_url.as_deref(),
            },
            range,
            &mut writer,
        )?;
        std::io::Write::flush(&mut writer).map_err(storage::file_error)?;
        ready.received.fetch_add(writer.count, Ordering::SeqCst);
        if found.is_some() {
            *ready
                .response_encryption
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = found;
        }
        Ok(String::new())
    };
    let finish_download = |i: usize, ready: &ReadyDownload, _: Vec<String>| -> Result<()> {
        let file = &files[i];
        let written = ready.received.load(Ordering::SeqCst);
        if ready.size.is_some_and(|size| size != written) {
            return Err(Error::new(
                ErrorKind::Communication,
                "The downloaded file does not have the size the storage reported.",
            ));
        }
        match &file.material {
            Some(material) => {
                let response = ready
                    .response_encryption
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let metadata = response
                    .or_else(|| ready.header_encryption.clone())
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::Communication,
                            "The stage file has no encryption metadata.",
                        )
                    })?;
                let (decrypted_file, decrypted) =
                    crate::fsutil::create_temp(crate::fsutil::parent_dir(&file.path), ".tmp")
                        .map_err(temp_error)?;
                let result = (|| -> Result<()> {
                    let mut input =
                        std::fs::File::open(&ready.part_path).map_err(storage::file_error)?;
                    let mut output = std::io::BufWriter::new(decrypted_file);
                    crypto::decrypt(&metadata, material, &mut input, &mut output)?;
                    std::io::Write::flush(&mut output).map_err(storage::file_error)?;
                    std::fs::rename(&decrypted, &file.path).map_err(storage::file_error)
                })();
                let _ = std::fs::remove_file(&ready.part_path);
                if result.is_err() {
                    let _ = std::fs::remove_file(&decrypted);
                }
                result?;
            }
            None => {
                std::fs::rename(&ready.part_path, &file.path).map_err(storage::file_error)?;
            }
        }
        let size = std::fs::metadata(&file.path)
            .map_err(storage::file_error)?
            .len();
        *sizes[i]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = size;
        Ok(())
    };
    let finish = |i: usize, ready: &ReadyDownload, parts: Vec<String>| -> Result<()> {
        let result = finish_download(i, ready, parts);
        if result.is_err() {
            let _ = std::fs::remove_file(&ready.part_path);
        }
        result
    };
    let abort = |_: usize, ready: &ReadyDownload| {
        let _ = std::fs::remove_file(&ready.part_path);
    };
    pipeline(files.len(), plan.parallel, &prepare, &part, &finish, &abort)
        .map_err(|e| transfer_error(ER_FAILED_TO_DOWNLOAD_FROM_STAGE, "getting", e))?;
    Ok(sizes
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .collect())
}

fn text_column(name: &str) -> Column {
    Column {
        name: name.to_string(),
        sf_type: SfType::Text,
        nullable: false,
    }
}

fn fixed_column(name: &str) -> Column {
    Column {
        name: name.to_string(),
        sf_type: SfType::Fixed {
            precision: 0,
            scale: 0,
        },
        nullable: false,
    }
}

/// The `PUT` rows, sorted as the connector sorts them.
fn put_result(handle: String, files: &[PutFile], outcomes: &Outcomes) -> QueryResult {
    let compression = |c: Option<&Compression>| c.map_or("NONE", |c| c.name).to_string();
    let mut rows: Vec<(String, String, i128, i128, String, String, &'static str)> = files
        .iter()
        .zip(outcomes)
        .map(|(file, outcome)| {
            let (status, size) = outcome
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unwrap_or((Status::Skipped, 0));
            (
                file.name.clone(),
                file.target.clone(),
                i128::from(file.size),
                i128::from(size),
                compression(file.source_compression),
                compression(file.target_compression),
                status.name(),
            )
        })
        .collect();
    rows.sort();
    QueryResult {
        statement_handle: handle,
        columns: vec![
            text_column("source"),
            text_column("target"),
            fixed_column("source_size"),
            fixed_column("target_size"),
            text_column("source_compression"),
            text_column("target_compression"),
            text_column("status"),
            text_column("message"),
        ],
        rows: rows
            .into_iter()
            .map(|(source, target, ssize, tsize, scomp, tcomp, status)| {
                vec![
                    Value::Text(source),
                    Value::Text(target),
                    Value::Int(ssize),
                    Value::Int(tsize),
                    Value::Text(scomp),
                    Value::Text(tcomp),
                    Value::Text(status.to_string()),
                    Value::Text(String::new()),
                ]
            })
            .collect(),
    }
}

/// The `GET` rows, sorted.
fn get_result(handle: String, files: &[GetFile], sizes: &[u64]) -> QueryResult {
    let mut rows: Vec<(String, i128)> = files
        .iter()
        .zip(sizes)
        .map(|(file, size)| (file.shown.clone(), i128::from(*size)))
        .collect();
    rows.sort();
    QueryResult {
        statement_handle: handle,
        columns: vec![
            text_column("file"),
            fixed_column("size"),
            text_column("status"),
            text_column("message"),
        ],
        rows: rows
            .into_iter()
            .map(|(file, size)| {
                vec![
                    Value::Text(file),
                    Value::Int(size),
                    Value::Text(Status::Downloaded.name().to_string()),
                    Value::Text(String::new()),
                ]
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
