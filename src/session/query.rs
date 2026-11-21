//! `query-request`: one statement, polling, and its rows (inline `rowset` + chunks).

use super::{Session, lock, malformed, parse, status_error};
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use crate::sql::result::{Column, SfType, uniquify_column_names};
use crate::sql::stream::{Pages, RowStream, Rows};
use std::collections::VecDeque;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const QUERY_PATH: &str = "/queries/v1/query-request";
/// Server codes: the statement is still running; poll `getResultUrl`.
const RUNNING: [&str; 2] = ["333333", "333334"];
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How often a waiting statement checks for Ctrl-C.
const INTERRUPT_CHECK: Duration = Duration::from_millis(50);

/// The `data` of a successful answer.
pub struct SessionResponse {
    pub query_id: String,
    pub data: serde_json::Value,
}

/// What a `PUT`/`GET` answer asks the client to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCommand {
    Upload,
    Download,
}

impl SessionResponse {
    /// `UPLOAD`/`DOWNLOAD` when the statement was a `PUT`/`GET`.
    pub fn transfer_command(&self) -> Option<TransferCommand> {
        match self.data["command"].as_str() {
            Some("UPLOAD") => Some(TransferCommand::Upload),
            Some("DOWNLOAD") => Some(TransferCommand::Download),
            _ => None,
        }
    }

    /// The rows: the inline `rowset`, then the chunks, downloaded ahead on worker threads (at most
    /// `partition_concurrency` outstanding, so memory stays bounded).
    pub fn into_rows(mut self, session: &Session) -> Result<RowStream> {
        // Moved out of the response, not cloned: `rowset` can be large.
        let row_type = match self.data["rowtype"].take() {
            serde_json::Value::Array(row_type) => row_type,
            _ => Vec::new(),
        };
        let names: Vec<String> = row_type
            .iter()
            .map(|r| r["name"].as_str().unwrap_or_default().to_string())
            .collect();
        let columns: Vec<Column> = uniquify_column_names(&names)
            .into_iter()
            .zip(&row_type)
            .map(|(name, r)| Column {
                name,
                sf_type: SfType::from_row_type(
                    r["type"].as_str().unwrap_or_default(),
                    r["precision"].as_i64(),
                    r["scale"].as_i64(),
                ),
                nullable: r["nullable"].as_bool().unwrap_or(false),
            })
            .collect();
        let rows: Rows = match self.data["rowset"].take() {
            serde_json::Value::Null => Vec::new(),
            rowset => {
                serde_json::from_value(rowset).map_err(|e| malformed("rowset").with_source(e))?
            }
        };
        let ltz_zone = if columns
            .iter()
            .any(|c| matches!(c.sf_type, SfType::TimestampLtz { .. }))
        {
            let name = session.time_zone().unwrap_or_else(|| "UTC".into());
            Some(jiff::tz::TimeZone::get(&name).map_err(|e| {
                Error::new(
                    ErrorKind::Client,
                    format!("Unknown session time zone '{name}'."),
                )
                .with_source(e)
            })?)
        } else {
            None
        };
        let urls = self.data["chunks"]
            .as_array()
            .map(|c| {
                c.iter()
                    .filter_map(|c| c["url"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let pages: Pages = Box::new(Chunks::new(
            session.agent().clone(),
            chunk_headers(&self.data),
            urls,
            session.options().partition_concurrency,
        ));
        Ok(RowStream::from_pages(
            self.query_id,
            columns,
            rows,
            pages,
            ltz_zone,
            session.options().decimal_precision,
        ))
    }
}

/// `chunkHeaders`, else the SSE-C headers from `qrmk` (`result_batch.py`).
fn chunk_headers(data: &serde_json::Value) -> Vec<(String, Secret)> {
    if let Some(headers) = data["chunkHeaders"].as_object() {
        return headers
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), Secret::new(v))))
            .collect();
    }
    match data["qrmk"].as_str() {
        Some(qrmk) => vec![
            (
                "x-amz-server-side-encryption-customer-algorithm".into(),
                Secret::new("AES256"),
            ),
            (
                "x-amz-server-side-encryption-customer-key".into(),
                Secret::new(qrmk),
            ),
        ],
        None => Vec::new(),
    }
}

type Headers = Vec<(String, Secret)>;

/// One chunk request; the worker answers on `reply` with the parsed rows.
struct ChunkJob {
    index: usize,
    reply: mpsc::SyncSender<Result<Rows>>,
}

/// The result chunks, in order. Up to `limit` chunks download ahead on worker threads, as the
/// SQL API partitions do (`PartitionRows`); the workers start on the first read.
struct Chunks {
    agent: ureq::Agent,
    headers: Arc<Headers>,
    urls: Arc<Vec<String>>,
    limit: usize,
    /// Replies of the requested chunks that were not yielded yet, in order.
    pending: VecDeque<mpsc::Receiver<Result<Rows>>>,
    next_to_dispatch: usize,
    jobs: Option<mpsc::Sender<ChunkJob>>,
    cancel: Arc<AtomicBool>,
    done: bool,
}

impl Chunks {
    fn new(agent: ureq::Agent, headers: Headers, urls: Vec<String>, limit: usize) -> Self {
        Self {
            agent,
            headers: Arc::new(headers),
            urls: Arc::new(urls),
            limit: limit.max(1),
            pending: VecDeque::new(),
            next_to_dispatch: 0,
            jobs: None,
            cancel: Arc::new(AtomicBool::new(false)),
            done: false,
        }
    }

    fn spawn_workers(&mut self) {
        let (jobs, receiver) = mpsc::channel::<ChunkJob>();
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..self.limit.min(self.urls.len()) {
            let receiver = Arc::clone(&receiver);
            let (agent, headers) = (self.agent.clone(), Arc::clone(&self.headers));
            let (urls, cancel) = (Arc::clone(&self.urls), Arc::clone(&self.cancel));
            std::thread::spawn(move || {
                loop {
                    // The lock is held only while waiting for the next job.
                    let job = match receiver.lock() {
                        Ok(guard) => guard.recv(),
                        Err(_) => return,
                    };
                    let Ok(job) = job else { return };
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    log::debug!("fetching result chunk {}", job.index + 1);
                    let rows = fetch_chunk(&agent, &urls[job.index], &headers);
                    // The stream may be gone already; nothing to do then.
                    let _ = job.reply.send(rows);
                }
            });
        }
        self.jobs = Some(jobs);
    }

    /// Requests chunks in order until `limit` are outstanding.
    fn fill_window(&mut self) {
        let Some(jobs) = &self.jobs else { return };
        while self.pending.len() < self.limit && self.next_to_dispatch < self.urls.len() {
            let (reply, receiver) = mpsc::sync_channel(1);
            let job = ChunkJob {
                index: self.next_to_dispatch,
                reply,
            };
            if jobs.send(job).is_err() {
                return;
            }
            self.pending.push_back(receiver);
            self.next_to_dispatch += 1;
        }
    }

    /// Ends the iteration and lets the workers go (they are not joined).
    fn stop(&mut self) {
        self.done = true;
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs = None;
        self.pending.clear();
    }
}

impl Iterator for Chunks {
    type Item = Result<Rows>;

    fn next(&mut self) -> Option<Result<Rows>> {
        if self.done {
            return None;
        }
        if self.jobs.is_none() && !self.urls.is_empty() {
            self.spawn_workers();
        }
        self.fill_window();
        let Some(receiver) = self.pending.pop_front() else {
            self.stop();
            return None;
        };
        match receiver.recv() {
            Ok(Ok(rows)) => Some(Ok(rows)),
            Ok(Err(e)) => {
                self.stop();
                Some(Err(e))
            }
            Err(_) => {
                self.stop();
                Some(Err(malformed("a result chunk download stopped")))
            }
        }
    }
}

impl Drop for Chunks {
    fn drop(&mut self) {
        self.stop();
    }
}

fn fetch_chunk(agent: &ureq::Agent, url: &str, headers: &[(String, Secret)]) -> Result<Rows> {
    // No source: a ureq error can repeat the presigned URL.
    let failed = || {
        Error::new(
            ErrorKind::Communication,
            "Failed to download a result chunk.",
        )
    };
    let mut request = agent.get(url);
    for (key, value) in headers {
        request = request.header(key.as_str(), value.expose());
    }
    let mut response = request.call().map_err(|_| failed())?;
    let status = response.status().as_u16();
    // The buffer starts with the `[` that `parse_chunk` needs, so the body is not copied again.
    let mut buffer = vec![b'['];
    response
        .body_mut()
        .with_config()
        .limit(u64::MAX)
        .reader()
        .read_to_end(&mut buffer)
        .map_err(|_| failed())?;
    if status != 200 {
        return Err(Error::new(
            ErrorKind::Communication,
            format!("Result chunk download returned HTTP {status}."),
        ));
    }
    parse_chunk(buffer)
}

/// A chunk body: rows without the enclosing `[`…`]` (ADR 0005, S6), possibly gzip. `buffer` is
/// the body behind a leading `[` placeholder; the closing `]` is added here.
fn parse_chunk(mut buffer: Vec<u8>) -> Result<Rows> {
    if buffer[1..].starts_with(&[0x1f, 0x8b]) {
        let mut text = Vec::with_capacity(buffer.len() * 4);
        text.push(b'[');
        flate2::read::MultiGzDecoder::new(&buffer[1..])
            .read_to_end(&mut text)
            .map_err(|e| malformed("result chunk").with_source(e))?;
        buffer = text;
    }
    buffer.push(b']');
    serde_json::from_slice(&buffer).map_err(|e| malformed("result chunk").with_source(e))
}

/// Runs one statement (ADR 0005, Decision 1: one `query-request` per statement). With an
/// interrupt flag set on the session, it waits on a worker thread so that Ctrl-C returns at
/// once and cancels the statement in Snowflake, as the connector's SIGINT handler does.
pub(super) fn run(session: &Session, sql: &str) -> Result<SessionResponse> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let flag = lock(&session.inner.state).interrupt.clone();
    let Some(flag) = flag else {
        return run_with_id(session, sql, &request_id);
    };
    let (tx, rx) = mpsc::channel();
    let worker = session.clone();
    let (text, id) = (sql.to_string(), request_id.clone());
    std::thread::spawn(move || {
        // The receiver is gone once the statement was interrupted.
        let _ = tx.send(run_with_id(&worker, &text, &id));
    });
    loop {
        match rx.recv_timeout(INTERRUPT_CHECK) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) if flag.load(Ordering::SeqCst) => {
                // Best effort, as the connector: the statement may have finished meanwhile.
                let _ = session.abort(sql, &request_id);
                return Err(Error::new(ErrorKind::Aborted, "Interrupted."));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::new(
                    ErrorKind::Client,
                    "The statement stopped unexpectedly.",
                ));
            }
        }
    }
}

fn run_with_id(session: &Session, sql: &str, request_id: &str) -> Result<SessionResponse> {
    let reply = post_query(session, sql, request_id, false)?;
    wait(session, reply, Some(sql))
}

/// `POST query-request` for `sql`; `async_exec` is the connector's `_no_results`.
fn post_query(
    session: &Session,
    sql: &str,
    request_id: &str,
    async_exec: bool,
) -> Result<super::Reply> {
    let body = {
        let mut state = lock(&session.inner.state);
        state.sequence += 1;
        // No `queryContextDTO`: the connector's query-context cache (a client-side merge of
        // server hints) is an optimisation the server does not require.
        let body = serde_json::json!({
            "sqlText": sql,
            "asyncExec": async_exec,
            "sequenceId": state.sequence,
            "querySubmissionTime": millis(),
        });
        body.to_string()
    };
    let path = format!("{QUERY_PATH}?requestId={request_id}");
    log::debug!("POST {QUERY_PATH}");
    session.authorized("POST", &path, Some(&body))
}

/// `cursor.execute_async`: the server answers `333334` (detached) with the query id at once;
/// any other answer is waited for as a plain statement (`network.py`, `_post_request`). The
/// connector strips the text first.
pub(super) fn submit_async(session: &Session, sql: &str) -> Result<String> {
    let sql = sql.trim_matches([' ', '\t', '\n', '\r']);
    let request_id = uuid::Uuid::new_v4().to_string();
    let reply = post_query(session, sql, &request_id, true)?;
    if reply.status == 200 && super::code_of(&reply.body).as_deref() == Some(RUNNING[1]) {
        let value: serde_json::Value = parse(&reply.body)?;
        return Ok(value["data"]["queryId"]
            .as_str()
            .unwrap_or_default()
            .to_string());
    }
    Ok(wait(session, reply, Some(sql))?.query_id)
}

/// `GET /queries/<id>/result` (`cursor.query_result`).
pub(super) fn result(session: &Session, query_id: &str) -> Result<SessionResponse> {
    log::debug!("GET /queries/<id>/result");
    let reply = session.authorized("GET", &format!("/queries/{query_id}/result"), None)?;
    wait(session, reply, None)
}

/// Polls `getResultUrl` until the statement is done. `sql` is the statement, when it is one
/// of this run (the session context follows it).
fn wait(session: &Session, mut reply: super::Reply, sql: Option<&str>) -> Result<SessionResponse> {
    let mut interval = FIRST_POLL_INTERVAL.min(session.inner.options.poll_interval_max);
    loop {
        if reply.status != 200 {
            return Err(status_error(reply.status, &reply.body));
        }
        let value: serde_json::Value = parse(&reply.body)?;
        let code = super::code_of(&reply.body);
        if code.as_deref().is_some_and(|c| RUNNING.contains(&c)) {
            let url = value["data"]["getResultUrl"]
                .as_str()
                .ok_or_else(|| malformed("no getResultUrl"))?
                .to_string();
            std::thread::sleep(interval);
            interval = (interval * 2).min(session.inner.options.poll_interval_max);
            log::debug!("statement still running");
            reply = session.authorized("GET", &url, None)?;
            continue;
        }
        if let Some(sql) = sql {
            lock(&session.inner.state)
                .context
                .update(sql, &value["data"]);
        }
        return finish(session, value, code);
    }
}

fn finish(
    session: &Session,
    mut value: serde_json::Value,
    code: Option<String>,
) -> Result<SessionResponse> {
    let data = value["data"].take();
    if value["success"] != true {
        let message = value["message"].as_str().unwrap_or("no error message");
        let code = code.unwrap_or_default();
        let id = data["queryId"].as_str().unwrap_or_default();
        let text = match data["sqlState"].as_str().filter(|s| !s.is_empty()) {
            Some(state) => format!("{code} ({state}): {id}: {message}"),
            None => format!("{code}: {id}: {message}"),
        };
        return Err(Error::new(ErrorKind::Sql, text));
    }
    session.inner.update_parameters(&data["parameters"]);
    Ok(SessionResponse {
        query_id: data["queryId"].as_str().unwrap_or_default().to_string(),
        data,
    })
}

fn millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A body behind the leading `[` placeholder, as `fetch_chunk` buffers it.
    fn framed(body: &[u8]) -> Vec<u8> {
        [b"[".as_slice(), body].concat()
    }

    fn chunk_server(count: usize) -> (httpmock::MockServer, Vec<String>) {
        let server = httpmock::MockServer::start();
        let urls = (0..count)
            .map(|i| server.url(format!("/chunks/{i}")))
            .collect();
        (server, urls)
    }

    fn mock_chunk<'a>(
        server: &'a httpmock::MockServer,
        index: usize,
        body: &str,
        status: u16,
        delay: u64,
    ) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method("GET").path(format!("/chunks/{index}"));
            then.status(status)
                .body(body)
                .delay(Duration::from_millis(delay));
        })
    }

    fn chunks(urls: Vec<String>, limit: usize) -> Chunks {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .new_agent();
        Chunks::new(agent, Vec::new(), urls, limit)
    }

    #[test]
    fn chunks_download_ahead_up_to_the_limit_and_arrive_in_order() {
        let (server, urls) = chunk_server(4);
        // The first chunk is slow, so the second one is requested before it completes.
        let mocks: Vec<_> = (0..4)
            .map(|i| {
                mock_chunk(
                    &server,
                    i,
                    &format!(r#"["{i}"]"#),
                    200,
                    if i == 0 { 300 } else { 0 },
                )
            })
            .collect();
        let mut chunks = chunks(urls, 2);
        assert_eq!(chunks.next().unwrap().unwrap()[0][0].as_deref(), Some("0"));
        // Two outstanding: chunk 1 is already requested, chunks 2 and 3 are not.
        mocks[1].assert_calls(1);
        mocks[2].assert_calls(0);
        mocks[3].assert_calls(0);
        for i in 1..4 {
            assert_eq!(
                chunks.next().unwrap().unwrap()[0][0].as_deref(),
                Some(i.to_string().as_str())
            );
        }
        assert!(chunks.next().is_none());
    }

    #[test]
    fn dropping_the_chunks_cancels_the_workers() {
        let (server, urls) = chunk_server(3);
        let mocks: Vec<_> = (0..3)
            .map(|i| mock_chunk(&server, i, r#"["x"]"#, 200, 0))
            .collect();
        let mut chunks = chunks(urls, 1);
        chunks.next().unwrap().unwrap();
        drop(chunks);
        std::thread::sleep(Duration::from_millis(300));
        mocks[0].assert_calls(1);
        // Chunk 1 was requested ahead of time; nothing after it ever is.
        assert!(mocks[1].calls() <= 1);
        mocks[2].assert_calls(0);
    }

    #[test]
    fn a_failed_download_ends_the_chunks_with_its_error() {
        let (server, urls) = chunk_server(3);
        mock_chunk(&server, 0, r#"["a"]"#, 200, 0);
        mock_chunk(&server, 1, "oops", 500, 0);
        let last = mock_chunk(&server, 2, r#"["c"]"#, 200, 0);
        let mut chunks = chunks(urls, 1);
        assert!(chunks.next().unwrap().is_ok());
        let err = chunks.next().unwrap().unwrap_err();
        assert_eq!(err.message(), "Result chunk download returned HTTP 500.");
        assert!(chunks.next().is_none());
        last.assert_calls(0);
    }

    #[test]
    fn chunks_are_rows_without_brackets_plain_or_gzip() {
        let rows = parse_chunk(framed(br#"["1","a"],[null,"b"]"#)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0], None);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(br#"["2","c"]"#).unwrap();
        let rows = parse_chunk(framed(&gz.finish().unwrap())).unwrap();
        assert_eq!(rows[0][1].as_deref(), Some("c"));
        assert!(parse_chunk(framed(b"not json")).is_err());
    }

    #[test]
    fn chunk_headers_prefer_chunk_headers_then_qrmk() {
        let data = serde_json::json!({"chunkHeaders": {"h": "v"}, "qrmk": "k"});
        let headers = chunk_headers(&data);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "h");
        let headers = chunk_headers(&serde_json::json!({"qrmk": "k"}));
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1.expose(), "k");
        assert!(chunk_headers(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn transfer_commands_are_recognised() {
        let r = |command: &str| SessionResponse {
            query_id: String::new(),
            data: serde_json::json!({ "command": command }),
        };
        assert_eq!(
            r("UPLOAD").transfer_command(),
            Some(TransferCommand::Upload)
        );
        assert_eq!(
            r("DOWNLOAD").transfer_command(),
            Some(TransferCommand::Download)
        );
        assert_eq!(r("OTHER").transfer_command(), None);
    }
}
