//! Parallel partition download and the ordered row stream (ADR 0002, Decision 6), against a
//! small threaded HTTP server that can delay, fail or cut each partition and counts the partition
//! requests in flight (httpmock can do neither of the last two).

use crate::common;

use serde_json::json;
use snowflake_cli_rs::connection::ConnectionConfig;
use snowflake_cli_rs::error::ErrorKind;
use snowflake_cli_rs::output::format::OutputFormat;
use snowflake_cli_rs::render::render_stream;
use snowflake_cli_rs::report::report_error;
use snowflake_cli_rs::sql::{ClientOptions, SqlClient, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Runs `sql` and prints it as `snow sql` does for one statement: the rows to `out`, any error
/// (also after output started) to `stderr` as the panel. Returns the exit code.
fn print_query(
    client: &SqlClient,
    sql: &str,
    format: OutputFormat,
    terminal_width: Option<usize>,
    out: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let outcome = client.query(sql).and_then(|mut stream| {
        let columns = stream.columns().to_vec();
        render_stream(&columns, &mut stream, format, terminal_width, out)
    });
    match outcome {
        Ok(()) => 0,
        Err(err) => {
            report_error(&err, false, stderr);
            err.exit_code()
        }
    }
}

/// What the server answers to one partition request.
enum Answer {
    Rows {
        rows: serde_json::Value,
        delay: Duration,
    },
    Status(u16),
    /// Headers announce more bytes than are sent, then the connection closes.
    Cut,
}

/// Decides the answer from the partition number and the attempt (1-based) for it.
type Partitions = Arc<dyn Fn(usize, usize) -> Answer + Send + Sync>;

struct Server {
    port: u16,
    /// Partition numbers in the order their requests arrived.
    requested: Arc<Mutex<Vec<usize>>>,
    posts: Arc<Mutex<Vec<String>>>,
    max_in_flight: Arc<AtomicUsize>,
}

/// How the statement requests (not the partitions) misbehave.
#[derive(Default)]
struct StatementFaults {
    /// Answers to the statement POST to cut before answering properly.
    cut_posts: AtomicUsize,
    /// The POST answers 202 and the result comes from polling the handle.
    async_post: bool,
    /// Answers to the poll GET to cut before answering properly.
    cut_polls: AtomicUsize,
}

struct Shared {
    statement: serde_json::Value,
    statement_faults: StatementFaults,
    /// Targets of the statement POSTs, in order.
    posts: Arc<Mutex<Vec<String>>>,
    partitions: Partitions,
    requested: Arc<Mutex<Vec<usize>>>,
    attempts: Mutex<HashMap<usize, usize>>,
    in_flight: AtomicUsize,
    max_in_flight: Arc<AtomicUsize>,
}

impl Server {
    /// `partition0` is the inline data; `count` the number of partitions.
    fn start(columns: &[&str], partition0: serde_json::Value, count: usize, p: Partitions) -> Self {
        Self::start_with(columns, partition0, count, p, StatementFaults::default())
    }

    fn start_with(
        columns: &[&str],
        partition0: serde_json::Value,
        count: usize,
        partitions: Partitions,
        statement_faults: StatementFaults,
    ) -> Self {
        let row_types = columns
            .iter()
            .map(|c| {
                let (name, ty) = c.split_once(':').unwrap();
                common::row_type(name, ty, Some(0))
            })
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requested = Arc::new(Mutex::new(Vec::new()));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared {
            statement: common::success_body(row_types, partition0, count),
            statement_faults,
            posts: Arc::clone(&posts),
            partitions,
            requested: Arc::clone(&requested),
            attempts: Mutex::new(HashMap::new()),
            in_flight: AtomicUsize::new(0),
            max_in_flight: Arc::clone(&max_in_flight),
        });
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || serve(conn.unwrap(), &shared));
            }
        });
        Self {
            port,
            requested,
            posts,
            max_in_flight,
        }
    }

    /// Targets of the statement POSTs received so far.
    fn posts(&self) -> Vec<String> {
        self.posts.lock().unwrap().clone()
    }

    fn requested(&self) -> Vec<usize> {
        self.requested.lock().unwrap().clone()
    }

    /// Partitions requested so far, sorted: concurrent requests arrive in any order.
    fn requested_sorted(&self) -> Vec<usize> {
        let mut requested = self.requested();
        requested.sort_unstable();
        requested
    }

    fn client(&self, partition_concurrency: usize) -> SqlClient {
        self.client_with(ClientOptions {
            partition_concurrency,
            ..common::fast_options()
        })
    }

    fn client_with(&self, options: ClientOptions) -> SqlClient {
        let conn = ConnectionConfig {
            account: Some("testacct".into()),
            user: Some("tester".into()),
            host: Some("127.0.0.1".into()),
            port: Some(self.port),
            protocol: Some("http".into()),
            authenticator: Some("SNOWFLAKE_JWT".into()),
            private_key_file: Some(common::key_path("unencrypted.p8")),
            ..Default::default()
        };
        common::client_with(&conn, options)
    }
}

/// Serves one keep-alive connection.
fn serve(stream: TcpStream, shared: &Shared) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let mut parts = request_line.split(' ');
        let is_post = parts.next() == Some("POST");
        let target = parts.next().unwrap().to_string();
        let partition = target
            .split_once("partition=")
            .map(|(_, n)| n.parse::<usize>().unwrap());
        let answer = match partition {
            None => {
                let faults = &shared.statement_faults;
                if is_post {
                    shared.posts.lock().unwrap().push(target.clone());
                }
                let cuts = if is_post {
                    &faults.cut_posts
                } else {
                    &faults.cut_polls
                };
                if cuts
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
                {
                    Answer::Cut
                } else {
                    let (status, body) = if is_post && faults.async_post {
                        (
                            202,
                            json!({"code": "333334", "statementHandle": common::HANDLE}),
                        )
                    } else {
                        (200, shared.statement.clone())
                    };
                    write_response(&mut stream, status, &body.to_string());
                    continue;
                }
            }
            Some(n) => {
                shared.requested.lock().unwrap().push(n);
                let attempt = {
                    let mut attempts = shared.attempts.lock().unwrap();
                    let a = attempts.entry(n).or_insert(0);
                    *a += 1;
                    *a
                };
                (shared.partitions)(n, attempt)
            }
        };
        let now = shared.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        shared.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let keep = match answer {
            Answer::Rows { rows, delay } => {
                std::thread::sleep(delay);
                shared.in_flight.fetch_sub(1, Ordering::SeqCst);
                write_response(&mut stream, 200, &json!({ "data": rows }).to_string());
                true
            }
            Answer::Status(status) => {
                shared.in_flight.fetch_sub(1, Ordering::SeqCst);
                write_response(&mut stream, status, r#"{"message": "partition failed"}"#);
                true
            }
            Answer::Cut => {
                shared.in_flight.fetch_sub(1, Ordering::SeqCst);
                let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                            Content-Length: 1000\r\n\r\n{\"data\": [[";
                let _ = stream.write_all(head.as_bytes());
                false
            }
        };
        if !keep {
            return;
        }
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nRetry-After: 0\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// Partition `n` holds the single row `[n]`.
fn row_of(n: usize, delay: Duration) -> Answer {
    Answer::Rows {
        rows: json!([[n.to_string()]]),
        delay,
    }
}

fn ints(rows: impl IntoIterator<Item = usize>) -> Vec<Vec<Value>> {
    rows.into_iter()
        .map(|n| vec![Value::Int(n as i128)])
        .collect()
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

const N: &str = "N:fixed";

#[test]
fn rows_keep_statement_order_when_partitions_finish_out_of_order() {
    // Later partitions answer first.
    let server = Server::start(
        &[N],
        json!([["0"]]),
        6,
        Arc::new(|n, _| row_of(n, Duration::from_millis(30 * (6 - n as u64)))),
    );
    let client = server.client(8);
    let rows: Vec<_> = client.query("q").unwrap().map(Result::unwrap).collect();
    assert_eq!(rows, ints(0..6));
    // All 5 are requested together, but on a loaded machine the fastest may finish before the
    // last one starts: what matters is that they overlapped, within the limit.
    let in_flight = server.max_in_flight.load(Ordering::SeqCst);
    assert!((2..=5).contains(&in_flight), "{in_flight}");
    assert_eq!(client.execute("q").unwrap().rows, rows);
}

#[test]
fn no_more_than_the_limit_is_outstanding() {
    let arrived = Arc::new(AtomicUsize::new(0));
    let server = Server::start(
        &[N],
        json!([["0"]]),
        7,
        Arc::new(move |n, _| {
            // Hold partitions 1 and 2 until both have arrived, so they overlap however loaded
            // the runner is (a fixed delay alone can let 1 finish before 2 is requested).
            if n <= 2 {
                arrived.fetch_add(1, Ordering::SeqCst);
                wait_until("partitions 1 and 2 arrived", || {
                    arrived.load(Ordering::SeqCst) >= 2
                });
            }
            row_of(n, Duration::from_millis(40))
        }),
    );
    let mut stream = server.client(2).query("q").unwrap();
    // Partitions 1 and 2 are requested at once; 3 waits until 1 has been consumed.
    wait_until("partitions 1 and 2 requested", || {
        server.requested().len() == 2
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(server.requested_sorted(), vec![1, 2]);
    assert_eq!(stream.next().unwrap().unwrap(), vec![Value::Int(0)]);
    assert_eq!(stream.next().unwrap().unwrap(), vec![Value::Int(1)]);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        server.requested_sorted(),
        vec![1, 2],
        "partition 1 is not finished yet"
    );
    assert_eq!(stream.next().unwrap().unwrap(), vec![Value::Int(2)]);
    wait_until("partition 3 requested", || server.requested().len() == 3);
    let rest: Vec<_> = stream.map(Result::unwrap).collect();
    assert_eq!(rest, ints(3..7));
    assert_eq!(server.max_in_flight.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrency_one_is_sequential() {
    let server = Server::start(
        &[N],
        json!([["0"]]),
        4,
        Arc::new(|n, _| row_of(n, Duration::from_millis(10))),
    );
    let result = server.client(1).execute("q").unwrap();
    assert_eq!(result.rows, ints(0..4));
    assert_eq!(server.requested(), vec![1, 2, 3]);
    assert_eq!(server.max_in_flight.load(Ordering::SeqCst), 1);
}

#[test]
fn single_partition_result_requests_no_partition() {
    let server = Server::start(
        &[N],
        json!([["0"], ["1"]]),
        1,
        Arc::new(|_, _| unreachable!()),
    );
    let mut stream = server.client(8).query("q").unwrap();
    assert_eq!(stream.statement_handle(), common::HANDLE);
    assert_eq!(stream.columns().len(), 1);
    assert_eq!((&mut stream).count(), 2);
    assert!(stream.next().is_none());
    assert!(server.requested().is_empty());
}

#[test]
fn a_partition_failing_once_is_retried() {
    let server = Server::start(
        &[N],
        json!([["0"]]),
        3,
        Arc::new(|n, attempt| {
            if n == 1 && attempt == 1 {
                Answer::Status(503)
            } else {
                row_of(n, Duration::ZERO)
            }
        }),
    );
    let result = server.client(8).execute("q").unwrap();
    assert_eq!(result.rows, ints(0..3));
    assert_eq!(server.requested().iter().filter(|&&n| n == 1).count(), 2);
}

#[test]
fn a_partition_body_cut_mid_read_is_retried() {
    let server = Server::start(
        &[N],
        json!([["0"]]),
        3,
        Arc::new(|n, attempt| {
            if n == 2 && attempt == 1 {
                Answer::Cut
            } else {
                row_of(n, Duration::ZERO)
            }
        }),
    );
    let result = server.client(8).execute("q").unwrap();
    assert_eq!(result.rows, ints(0..3));
    assert_eq!(server.requested().iter().filter(|&&n| n == 2).count(), 2);
}

#[test]
fn a_partition_cut_on_every_attempt_is_a_communication_error() {
    let server = Server::start(&[N], json!([["0"]]), 2, Arc::new(|_, _| Answer::Cut));
    let options = ClientOptions {
        max_retries: 1,
        ..common::fast_options()
    };
    let err = server.client_with(options).execute("q").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(server.requested(), vec![1, 1]);
}

fn statement_server(faults: StatementFaults) -> Server {
    Server::start_with(
        &[N],
        json!([["7"]]),
        1,
        Arc::new(|_, _| unreachable!()),
        faults,
    )
}

fn request_id_of(target: &str) -> &str {
    let (_, rest) = target.split_once("requestId=").unwrap();
    rest.split('&').next().unwrap()
}

#[test]
fn a_poll_body_cut_mid_read_is_retried() {
    let server = statement_server(StatementFaults {
        async_post: true,
        cut_polls: AtomicUsize::new(1),
        ..Default::default()
    });
    let result = server.client(8).execute("q").unwrap();
    assert_eq!(result.rows, ints(7..8));
    assert_eq!(server.posts().len(), 1);
}

#[test]
fn a_post_body_cut_mid_read_is_resubmitted_with_the_same_request_id() {
    let server = statement_server(StatementFaults {
        cut_posts: AtomicUsize::new(1),
        ..Default::default()
    });
    let result = server.client(8).execute("q").unwrap();
    assert_eq!(result.rows, ints(7..8));
    let posts = server.posts();
    assert_eq!(posts.len(), 2);
    assert!(!posts[0].contains("retry=true"), "{posts:?}");
    assert!(posts[1].contains("retry=true"), "{posts:?}");
    assert_eq!(request_id_of(&posts[0]), request_id_of(&posts[1]));
}

#[test]
fn a_statement_cut_on_every_attempt_is_a_communication_error() {
    for async_post in [false, true] {
        let server = statement_server(StatementFaults {
            async_post,
            cut_posts: AtomicUsize::new(if async_post { 0 } else { usize::MAX }),
            cut_polls: AtomicUsize::new(if async_post { usize::MAX } else { 0 }),
        });
        let options = ClientOptions {
            max_retries: 2,
            ..common::fast_options()
        };
        let err = server.client_with(options).execute("q").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Communication, "async={async_post}");
        assert_eq!(
            err.message(),
            "The connection to Snowflake failed while reading a response."
        );
        assert_eq!(server.posts().len(), if async_post { 1 } else { 3 });
    }
}

/// Partition 2 of 4 always fails with 500, after partitions 0 and 1 were printed.
fn failing_at_two() -> Server {
    Server::start(
        &[N, "S:text"],
        json!([["0", "a"]]),
        4,
        Arc::new(|n, _| {
            if n == 2 {
                Answer::Status(500)
            } else {
                Answer::Rows {
                    rows: json!([[n.to_string(), "b"]]),
                    delay: Duration::ZERO,
                }
            }
        }),
    )
}

#[test]
fn failure_after_output_started_keeps_partial_output_and_exits_one() {
    for (format, expected) in [
        (OutputFormat::Csv, "N,S\n0,a\n1,b\n"),
        (
            OutputFormat::Json,
            "[\n    {\n        \"N\": 0,\n        \"S\": \"a\"\n    },\n    {\n        \"N\": 1,\n        \"S\": \"b\"\n    }",
        ),
        (OutputFormat::Table, ""),
    ] {
        let server = failing_at_two();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = print_query(&server.client(8), "q", format, None, &mut out, &mut err);
        assert_eq!(code, 1, "{format:?}");
        assert_eq!(String::from_utf8(out).unwrap(), expected, "{format:?}");
        let err = String::from_utf8(err).unwrap();
        assert!(err.starts_with("╭─ Error"), "{err}");
        assert!(
            err.contains("Snowflake returned HTTP 500: partition failed"),
            "{err}"
        );
    }
}

#[test]
fn print_query_success_exits_zero() {
    let server = Server::start(
        &[N],
        json!([["0"]]),
        2,
        Arc::new(|n, _| row_of(n, Duration::ZERO)),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = print_query(
        &server.client(8),
        "q",
        OutputFormat::Csv,
        None,
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(out).unwrap(), "N\n0\n1\n");
    assert!(err.is_empty());
}

#[test]
fn the_stream_ends_after_an_error() {
    let server = failing_at_two();
    let mut stream = server.client(8).query("q").unwrap();
    assert!(stream.next().unwrap().is_ok());
    assert!(stream.next().unwrap().is_ok());
    assert_eq!(
        stream.next().unwrap().unwrap_err().kind(),
        ErrorKind::Communication
    );
    assert!(stream.next().is_none());
}

#[test]
fn bad_rows_in_a_later_partition_end_the_stream() {
    for (bad, message) in [
        (json!([["x"]]), None),
        (
            json!([["1", "2"]]),
            Some("Snowflake returned a malformed response: a row has the wrong number of values."),
        ),
        (json!({"no": "array"}), None),
    ] {
        let bad = Arc::new(bad);
        let server = Server::start(
            &[N],
            json!([["0"]]),
            3,
            Arc::new(move |n, _| {
                if n == 1 {
                    Answer::Rows {
                        rows: (*bad).clone(),
                        delay: Duration::ZERO,
                    }
                } else {
                    row_of(n, Duration::ZERO)
                }
            }),
        );
        let mut stream = server.client(8).query("q").unwrap();
        assert!(stream.next().unwrap().is_ok());
        let err = stream.next().unwrap().unwrap_err();
        if let Some(message) = message {
            assert_eq!(err.message(), message);
        }
        assert!(stream.next().is_none());
    }
}

#[test]
fn dropping_the_stream_stops_dispatching() {
    let server = Server::start(
        &[N],
        json!([["0"]]),
        8,
        Arc::new(|n, _| row_of(n, Duration::from_millis(30))),
    );
    let mut stream = server.client(2).query("q").unwrap();
    assert!(stream.next().unwrap().is_ok());
    drop(stream);
    std::thread::sleep(Duration::from_millis(200));
    // Only partitions inside the window were ever requested (2 may be skipped by the cancel).
    assert!(
        server.requested().iter().all(|&n| n <= 2),
        "{:?}",
        server.requested()
    );
}
