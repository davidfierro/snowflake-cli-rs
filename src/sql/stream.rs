//! Ordered row stream over the partitions of one statement (ADR 0002, Decisions 1, 2 and 4).
//!
//! The consumer (the iterator, on the caller's thread) dispatches partition requests in order to
//! a pool of worker threads and waits on each partition's reply in order. At most
//! `partition_concurrency` partitions after the first are outstanding: requested and not yet
//! fully yielded. Partition `k + limit` is requested only once partition `k` is finished.

use super::client::{Inner, Started, malformed};
use super::convert::convert;
use super::result::{Column, QueryResult, Value};
pub(crate) use super::wire::Rows;
use crate::error::Result;
use jiff::tz::TimeZone;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};

/// One partition request; the worker downloads and parses it, and answers on `reply` with its rows.
struct Job {
    partition: usize,
    reply: SyncSender<Result<Rows>>,
}

/// The rows of one statement, in statement order.
pub struct RowStream {
    handle: String,
    source: Source,
    columns: Vec<Column>,
    ltz_zone: Option<TimeZone>,
    decimal_precision: Option<usize>,
}

/// Where the rows come from (ADR 0005, Decision 2: a page source next to the partitions).
enum Source {
    /// Strings as the server sent them, converted on the way out.
    Raw(RawRows),
    /// Rows built by the client (the `PUT`/`GET` result).
    Values(std::vec::IntoIter<Vec<Value>>),
}

/// The pages of a session result after the inline rows: downloaded chunks, in order.
pub(crate) type Pages = Box<dyn Iterator<Item = Result<Rows>> + Send>;

/// The rows as the server returns them (strings), in order: the part shared with the time-zone
/// lookup, which needs no conversion.
pub(super) enum RawRows {
    /// SQL API partitions (ADR 0002).
    Partitions(PartitionRows),
    /// A session result: inline rows, then each page in order.
    Pages(PageRows),
}

pub(super) struct PageRows {
    width: usize,
    current: std::vec::IntoIter<Vec<Option<String>>>,
    pages: Pages,
    done: bool,
}

pub(super) struct PartitionRows {
    handle: String,
    width: usize,
    inner: Arc<Inner>,
    current: std::vec::IntoIter<Vec<Option<String>>>,
    /// Partition whose rows are in `current`.
    current_partition: usize,
    /// Replies of the outstanding partitions after `current_partition`, in order.
    pending: VecDeque<Receiver<Result<Rows>>>,
    next_to_dispatch: usize,
    partitions: usize,
    jobs: Option<Sender<Job>>,
    cancel: Arc<AtomicBool>,
    done: bool,
}

impl RowStream {
    pub(super) fn new(
        inner: Arc<Inner>,
        started: Started,
        ltz_zone: Option<TimeZone>,
        decimal_precision: Option<usize>,
    ) -> Self {
        let Started {
            handle,
            columns,
            rows,
            partitions,
        } = started;
        Self {
            source: Source::Raw(RawRows::Partitions(PartitionRows::new(
                inner,
                handle.clone(),
                columns.len(),
                rows,
                partitions,
            ))),
            handle,
            columns,
            ltz_zone,
            decimal_precision,
        }
    }

    /// A session result: the inline rows, then `pages` (downloaded chunks) in order.
    pub(crate) fn from_pages(
        handle: String,
        columns: Vec<Column>,
        rows: Rows,
        pages: Pages,
        ltz_zone: Option<TimeZone>,
        decimal_precision: Option<usize>,
    ) -> Self {
        Self {
            source: Source::Raw(RawRows::Pages(PageRows {
                width: columns.len(),
                current: rows.into_iter(),
                pages,
                done: false,
            })),
            handle,
            columns,
            ltz_zone,
            decimal_precision,
        }
    }

    /// Rows the client built itself (a `PUT`/`GET` result).
    pub fn from_result(result: QueryResult) -> Self {
        Self {
            handle: result.statement_handle,
            source: Source::Values(result.rows.into_iter()),
            columns: result.columns,
            ltz_zone: None,
            decimal_precision: None,
        }
    }

    pub fn statement_handle(&self) -> &str {
        &self.handle
    }

    /// De-duplicated as in ADR 0001 Decision 6.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Collects the remaining rows into a `QueryResult`.
    pub fn into_result(mut self) -> Result<QueryResult> {
        let rows = (&mut self).collect::<Result<Vec<_>>>()?;
        Ok(QueryResult {
            statement_handle: self.handle.clone(),
            columns: std::mem::take(&mut self.columns),
            rows,
        })
    }

    pub(super) fn into_raw(self) -> RawRows {
        match self.source {
            Source::Raw(raw) => raw,
            Source::Values(_) => RawRows::Pages(PageRows {
                width: 0,
                current: Vec::new().into_iter(),
                pages: Box::new(std::iter::empty()),
                done: true,
            }),
        }
    }
}

/// Yields `Ok(row)` (len == columns().len()) in statement order. After an `Err` it yields
/// `None`: a failed partition ends the stream.
impl Iterator for RowStream {
    type Item = Result<Vec<Value>>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = match &mut self.source {
            Source::Values(rows) => return rows.next().map(Ok),
            Source::Raw(raw) => raw,
        };
        let row = match raw.next()? {
            Ok(row) => row,
            Err(e) => return Some(Err(e)),
        };
        let converted = self
            .columns
            .iter()
            .zip(row)
            .map(|(column, raw)| {
                convert(
                    &column.sf_type,
                    raw,
                    self.ltz_zone.as_ref(),
                    self.decimal_precision,
                )
            })
            .collect::<Result<Vec<_>>>();
        if converted.is_err() {
            raw.stop();
        }
        Some(converted)
    }
}

impl RawRows {
    fn stop(&mut self) {
        match self {
            RawRows::Partitions(p) => p.stop(),
            RawRows::Pages(p) => p.done = true,
        }
    }
}

impl Iterator for RawRows {
    type Item = Result<Vec<Option<String>>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RawRows::Partitions(p) => p.next(),
            RawRows::Pages(p) => p.next(),
        }
    }
}

impl Iterator for PageRows {
    type Item = Result<Vec<Option<String>>>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            if let Some(row) = self.current.next() {
                if row.len() != self.width {
                    self.done = true;
                    return Some(Err(malformed("a row has the wrong number of values")));
                }
                return Some(Ok(row));
            }
            match self.pages.next() {
                Some(Ok(rows)) => self.current = rows.into_iter(),
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(e));
                }
                None => self.done = true,
            }
        }
        None
    }
}

impl PartitionRows {
    fn new(inner: Arc<Inner>, handle: String, width: usize, rows: Rows, partitions: usize) -> Self {
        let mut stream = Self {
            handle,
            width,
            current: rows.into_iter(),
            current_partition: 0,
            pending: VecDeque::new(),
            next_to_dispatch: 1,
            partitions,
            jobs: None,
            cancel: Arc::new(AtomicBool::new(false)),
            done: false,
            inner,
        };
        let limit = stream.inner.partition_concurrency();
        let workers = limit.min(partitions - 1);
        if workers > 0 {
            stream.jobs = Some(spawn_workers(
                workers,
                &stream.inner,
                &stream.handle,
                &stream.cancel,
            ));
            for _ in 0..workers {
                stream.dispatch();
            }
        }
        stream
    }

    /// Requests the next partition in order, if any is left.
    fn dispatch(&mut self) {
        if self.next_to_dispatch >= self.partitions {
            return;
        }
        let Some(jobs) = &self.jobs else { return };
        let (reply, receiver) = mpsc::sync_channel(1);
        let job = Job {
            partition: self.next_to_dispatch,
            reply,
        };
        // Workers only stop once `cancel` is set or the channel is closed, both by us.
        if jobs.send(job).is_ok() {
            self.pending.push_back(receiver);
            self.next_to_dispatch += 1;
        }
    }

    /// Moves to the next partition: frees a window slot, then waits for its body in order.
    fn advance(&mut self) -> Result<bool> {
        if self.current_partition + 1 >= self.partitions {
            return Ok(false);
        }
        if self.current_partition >= 1 {
            self.dispatch();
        }
        let receiver = self
            .pending
            .pop_front()
            .ok_or_else(|| malformed("a partition was never requested"))?;
        let rows = receiver
            .recv()
            .map_err(|_| malformed("a partition download stopped"))??;
        self.current = rows.into_iter();
        self.current_partition += 1;
        Ok(true)
    }

    /// Ends the stream and lets the workers go.
    fn stop(&mut self) {
        self.done = true;
        self.cancel.store(true, Ordering::Relaxed);
        self.jobs = None;
        self.pending.clear();
    }
}

impl Iterator for PartitionRows {
    type Item = Result<Vec<Option<String>>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if let Some(row) = self.current.next() {
                if row.len() != self.width {
                    self.stop();
                    return Some(Err(malformed("a row has the wrong number of values")));
                }
                return Some(Ok(row));
            }
            match self.advance() {
                Ok(true) => {}
                Ok(false) => {
                    self.stop();
                    return None;
                }
                Err(e) => {
                    self.stop();
                    return Some(Err(e));
                }
            }
        }
    }
}

impl Drop for PartitionRows {
    /// Workers exit after their current request; they are not joined (ADR 0002, Decision 1).
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_workers(
    count: usize,
    inner: &Arc<Inner>,
    handle: &str,
    cancel: &Arc<AtomicBool>,
) -> Sender<Job> {
    let (jobs, receiver) = mpsc::channel::<Job>();
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..count {
        let receiver = Arc::clone(&receiver);
        let inner = Arc::clone(inner);
        let handle = handle.to_string();
        let cancel = Arc::clone(cancel);
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
                let body = inner.fetch_partition_rows(&handle, job.partition);
                // The stream may be gone already; nothing to do then.
                let _ = job.reply.send(body);
            }
        });
    }
    jobs
}

#[cfg(test)]
mod tests {
    use super::super::client::{ClientOptions, PARSED_ON, SqlClient};
    use crate::auth::KeyPairAuthenticator;
    use crate::connection::ConnectionConfig;
    use httpmock::MockServer;
    use serde_json::json;
    use std::path::PathBuf;

    const HANDLE: &str = "parse-thread-test";

    fn client(server: &MockServer) -> SqlClient {
        let conn = ConnectionConfig {
            account: Some("testacct".into()),
            user: Some("tester".into()),
            host: Some(server.host()),
            port: Some(server.port()),
            protocol: Some("http".into()),
            private_key_file: Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/keys/unencrypted.p8"),
            ),
            ..Default::default()
        };
        let auth = KeyPairAuthenticator::from_connection(&conn).unwrap();
        SqlClient::new(&conn, Box::new(auth), ClientOptions::default()).unwrap()
    }

    #[test]
    fn partitions_are_parsed_by_the_workers_not_the_consumer() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method("POST").path("/api/v2/statements");
            then.status(200).json_body(json!({
                "resultSetMetaData": {
                    "numRows": 3, "format": "jsonv2",
                    "partitionInfo": [{"rowCount": 1}, {"rowCount": 1}, {"rowCount": 1}],
                    "rowType": [{"name": "N", "type": "text", "nullable": true}],
                },
                "data": [["a"]],
                "code": "090001", "sqlState": "00000", "statementHandle": HANDLE,
                "message": "ok",
            }));
        });
        for (partition, value) in [(1, "b"), (2, "c")] {
            server.mock(|when, then| {
                when.method("GET")
                    .path(format!("/api/v2/statements/{HANDLE}"))
                    .query_param("partition", partition.to_string());
                then.status(200).json_body(json!({ "data": [[value]] }));
            });
        }
        let rows = client(&server).execute("SELECT N").unwrap().rows;
        assert_eq!(rows.len(), 3);
        let parsed: Vec<_> = PARSED_ON
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _)| handle == HANDLE)
            .map(|(_, thread)| *thread)
            .collect();
        assert_eq!(parsed.len(), 2, "both partitions are parsed");
        assert!(!parsed.contains(&std::thread::current().id()));
    }
}
