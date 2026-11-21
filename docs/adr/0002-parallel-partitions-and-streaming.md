# ADR 0002: Parallel partition download and streaming results

- **Status:** Accepted (implemented and merged)
- **Date:** 2026-11-20
- **Amends:** [ADR 0001](0001-stage-0-foundation.md): Decision 2 (Stream B public interface),
  Decision 5 (client behaviour), Decision 6 (renderer rules), Decision 9 (seams and mocked
  tests). Everything else in ADR 0001 still applies.

## Context

ADR 0001 Decision 5 left this open: "No connection pool, no async runtime: one blocking
`ureq::Agent`, sequential requests. Parallel partition download can come later if large results
need it." The stage-0 benchmark (stage 0, 2026-11-20, hyperfine against the
sandbox, key-pair JWT on both sides) shows that large results need it:

| Scenario | Rust (main @ `f70e016`) | snow 3.34.0 |
|---|---|---|
| `SELECT CURRENT_ROLE()` → JSON | 178 ms | 4252 ms |
| 100k rows → CSV | 1.98 s / 37 MiB | 5.41 s / 191 MiB |
| 1M rows → CSV | 8.64 s / 295 MiB | 11.29 s / 402 MiB |

`SqlClient::execute` (`src/sql/client.rs`, `run()`) fetches partitions 1..n one after another
and keeps every row of every partition in a `QueryResult` before `render()` runs, so time grows
with the partition count and memory with the row count.

This ADR targets: 1M rows → CSV and → JSON at least **2× faster** than snow (median wall time);
peak memory for CSV/JSON that does not grow with the row count; the trivial query stays
≤ 200 ms; output byte-identical for every format. Constraints: std threads and the existing
blocking `ureq` client, no async runtime, no other HTTP client, no Arrow, no new crates unless
they pass `cargo deny` (none are needed).

### Measurements (spike, 2026-11-20)

A throwaway spike (not committed) added a scoped-thread partition fetcher to `SqlClient`, reusing
its private `send()` (same agent, same authenticator, same retry path), and an `#[ignore]` test
that submits a statement once and then downloads and JSON-parses partitions 1..n with 1, 2, 3,
4, 6, 8, 12, 16 and 32 workers. Release build, one machine → sandbox. The query is synthetic
generator data, the same shape `bench/` will use:

```sql
SELECT SEQ8() AS id, UNIFORM(1, 1000000, RANDOM()) AS n, RANDSTR(20, RANDOM()) AS s,
       UNIFORM(0::FLOAT, 1::FLOAT, RANDOM()) AS f,
       DATEADD(second, SEQ4(), '2024-01-01'::TIMESTAMP_NTZ) AS ts
FROM TABLE(GENERATOR(ROWCOUNT => <n>))
```

**How Snowflake partitions a result.** Partition sizes are not uniform: partition 0 (inline in
the POST response) has ~1.2k rows and each following partition doubles (3.1k, 6.2k, 11k, 22k,
42k, 83k, 167k, 332k rows) until a cap of ~37 MiB of uncompressed JSON (~425k rows for this
shape). `resultSetMetaData.partitionInfo` gives `rowCount`, `uncompressedSize` and
`compressedSize` of every partition up front. gzip only shrinks this data 2.25× (random strings).

| Rows | Partitions | Raw JSON | Largest partition | Submit (POST until 200) |
|---|---|---|---|---|
| 100k | 7 | 8 MiB | 3.6 MiB | 1.1 s |
| 1M | 10 | 84 MiB | 28 MiB (two of them) | 3.2–3.5 s |
| 4M | 17 | 341 MiB | 37 MiB (cap) | 10.7–10.9 s |
| 10M | 31 | 856 MiB | 37 MiB (cap) | 25.8 s |

**Download time of partitions 1..n by number of workers** (wall ms, each run is one round; 1M
had 3 rounds, 4M and 10M 2):

| Workers | 100k | 1M | 4M | 10M |
|---|---|---|---|---|
| 1 (today) | 1501 | 6181 / 6498 / 6723 | 19390 / 22392 | — |
| 2 | 827 | 3554 / 3128 / 3798 | 11897 / 11057 | — |
| 3 | — | — | — | 21863 / 20882 |
| 4 | 630 | 2309 / 3792 / 2322 | 6907 / 6477 | 16553 / 15569 |
| 6 | — | — | — | 11661 / 11215 |
| **8** | **427** | **1679 / 1983 / 2257** | **4426 / 5409** | **9535 / 9234** |
| 12 | — | — | — | 8206 / 7889 |
| 16 | 408 | 2813 / 2645 / 3538 | 4104 / 4077 | — |
| 32 | 438 | 2333 / 2869 / 2507 | 4084 / 4538 | — |

Reading: one connection moves ~13 MiB/s, so throughput grows almost linearly with workers up to
8; past 8 the gain is small (12 workers: −14 % at 10M) or noise (16 and 32 are slower at 1M),
while each extra worker adds up to one more capped partition (~37 MiB) of buffered memory. At 1M
the floor is the two 28 MiB partitions, each on one connection (~2 s), whatever the worker
count.

## Decision 1: Concurrency model

### Options

| | Sequential (today) | std worker threads, bounded window (chosen) | Async runtime (`tokio` + `reqwest`) | Scoped threads per call |
|---|---|---|---|---|
| 1M download | 6.2–6.7 s | 1.7–2.3 s | similar to threads (network bound) | as threads |
| Binary, startup | as today | as today | larger binary, runtime start | as today |
| Streaming to the caller | no | yes: workers outlive `query()` | yes | no: `std::thread::scope` ends before `query()` returns, so it can only offer a callback API |
| Scope | — | in scope | out of scope (brief) | in scope |

### Decision

- **Workers:** `SqlClient::query` spawns `min(limit, partitions − 1)` plain `std::thread`
  workers when the result has more than one partition, and **none** for a single-partition
  result (the trivial query pays nothing). Workers share the client's `ureq::Agent` (it is
  `Clone + Send + Sync` and pools connections) and authenticator. `SqlClient` therefore holds
  its internals in an `Arc` (`Arc<dyn Authenticator>` instead of `Box`; the public constructor
  still takes a `Box<dyn Authenticator>`), so the workers do not borrow the client.
- **Window, not a free-for-all:** the consumer (the `RowStream` iterator on the caller's thread)
  dispatches partition requests to the workers over an `mpsc` channel, in partition order, and
  each request carries a one-shot reply channel (`mpsc::sync_channel(1)`). At most `limit`
  partitions are **outstanding** at any time, where outstanding means requested and not yet
  fully yielded to the caller: being downloaded, or downloaded and waiting its turn. Partition
  `k + limit` is dispatched only when the caller has finished partition `k`. This one rule gives
  both bounds the brief asks for: never more than `limit` requests in flight, and memory bounded
  by `limit` partitions regardless of the row count or of which partition finishes first.
- **Default limit: 8**, from the measurements above: the knee of the curve at every size, and a
  worst-case buffer of 8 capped partitions (~300 MiB raw JSON) only when the consumer is slower
  than the network on results of millions of rows.
- **Override:** `ClientOptions::partition_concurrency: usize` (default 8, `1` = sequential, as
  today). The environment variable **`SNOW_RS_PARTITION_CONCURRENCY`** (integer 1–64) sets it;
  any other value is a `Client` error: `SNOW_RS_PARTITION_CONCURRENCY must be an integer from 1
  to 64.` It is read through the injectable `Env` by a new
  `ClientOptions::from_env(&Env) -> Result<ClientOptions>` that the `sql` command (stage 2) uses,
  never from the process environment directly (ADR 0001 Decision 9). Not `SNOWFLAKE_*`: that
  prefix is snow's connection-override namespace (ADR 0001 Decision 3). No CLI flag: snow has
  none, and the `sql` command does not exist yet.
- **Same token:** every partition request takes its `Authorization` header from the shared
  authenticator, as today. `KeyPairAuthenticator` signs a fresh JWT per call (ADR 0001 Decision
  4), which is cheap and keeps the token valid during long downloads; no new auth path.
- **Connections:** the agent is built with `max_idle_connections_per_host(limit)` (ureq's
  default is 3) so the workers reuse their TLS connections across partitions.
- **Cancellation:** dropping the stream (caller stopped early, `BrokenPipe`) sets a shared
  cancel flag and closes the request channel. Workers exit after their current request; the
  stream does not join them (a join could wait up to `request_timeout` on exit). Nothing they do
  after that reaches the output.

## Decision 2: Streaming interface and ordering

Amends ADR 0001's Stream B public interface (`src/sql/client.rs`, new `src/sql/stream.rs`):

```rust
// src/sql/client.rs
#[derive(Debug, Clone)]
pub struct ClientOptions {
    // ... ADR 0001 fields unchanged ...
    /// Partitions outstanding at once (ADR 0002), default 8; 1 = sequential.
    pub partition_concurrency: usize,
}
impl ClientOptions {
    /// Defaults, with `SNOW_RS_PARTITION_CONCURRENCY` applied (Client error if invalid).
    pub fn from_env(env: &crate::env::Env) -> Result<Self>;
}

impl SqlClient {
    /// Runs one statement. Returns once the statement has finished and partition 0 has
    /// arrived; the remaining partitions download in the background while the caller iterates.
    /// Errors before the first row (submit, SQL error, auth, session time zone) come from here.
    pub fn query(&self, sql: &str) -> Result<crate::sql::stream::RowStream>;
    /// Runs one statement and returns all rows of all partitions: `query()` collected.
    /// Kept for small results and the golden tests.
    pub fn execute(&self, sql: &str) -> Result<crate::sql::result::QueryResult>;
}

// src/sql/stream.rs
/// The rows of one statement, in statement order.
pub struct RowStream { /* columns, handle, partition 0 rows, window, workers, ltz zone */ }
impl RowStream {
    pub fn statement_handle(&self) -> &str;
    /// De-duplicated as in ADR 0001 Decision 6.
    pub fn columns(&self) -> &[crate::sql::result::Column];
    /// Collects the remaining rows into a `QueryResult`.
    pub fn into_result(self) -> Result<crate::sql::result::QueryResult>;
}
/// Yields `Ok(row)` (len == columns().len()) in statement order. After an `Err` it yields
/// `None`: a failed partition ends the stream.
impl Iterator for RowStream {
    type Item = Result<Vec<crate::sql::result::Value>>;
}
```

`sql/mod.rs` re-exports `RowStream`. `QueryResult`, `Column`, `SfType` and `Value` are unchanged.

- **Ordering guarantee:** rows come out exactly in statement order: partition 0, then 1, … n−1,
  each partition's rows in the order returned. The consumer always waits on the reply channel of
  the next partition in order; a later partition that finishes first waits in its slot (and
  counts towards the window).
- **Where work happens:** a worker downloads one partition and keeps its body as the raw JSON
  text (`String`). The consumer decodes one partition at a time when it reaches it, into owned
  rows, and converts them to `Value` lazily, one per `next()`, dropping each raw row as it goes
  (`vec::IntoIter`). Raw text is about 3× smaller than decoded `Vec<Vec<Option<String>>>` rows
  (a 28 MiB partition decodes to ~100 MiB), so the partitions waiting their turn stay compact
  and only one is ever decoded. A decoder borrowing from the text would save more but needs a
  self-referential struct; not required. Decoding 84 MiB of JSON takes a fraction of a second
  and overlaps with the downloads still running.
- **Memory bound:** `limit` raw partitions (outstanding) + one decoded partition + the renderer's
  current row: about 8 × 37 + 130 MiB in the worst case (capped partitions, consumer slower
  than the network), and about 2 × 28 + 100 MiB plus the base at 1M rows. It does not depend on the total row count. Because Snowflake grows partitions
  until the ~37 MiB cap, the bound grows with result size only up to ~4M rows (this shape) and is
  flat after that.
- **TIMESTAMP_LTZ:** when a column is LTZ, `query()` runs the `SHOW PARAMETERS LIKE 'TIMEZONE'`
  request (ADR 0001 Decision 5) before it returns, so a time-zone failure is an error before any
  output, as today.
- **Conversion and shape errors** (a row with the wrong number of values, a value that does not
  parse) become an `Err` item at the row where they occur and end the stream, like a failed
  partition (Decision 4).

## Decision 3: Renderers per format

Amends ADR 0001 Decision 6 (`src/render/mod.rs`):

```rust
/// Writes the rows of `stream` to `out` in `format` as they arrive (CSV, JSON), or after the
/// last one (TABLE, PLAIN). A BrokenPipe write error returns Ok. An `Err` row stops the output
/// where it is, flushes what was written and returns that error.
pub fn render_stream(
    columns: &[crate::sql::result::Column],
    rows: &mut dyn Iterator<Item = Result<Vec<crate::sql::result::Value>>>,
    format: crate::output::format::OutputFormat,
    terminal_width: Option<usize>,
    out: &mut dyn std::io::Write,
) -> Result<()>;
// render() and render_with_width() keep their signatures and output; they share the per-row
// writers with render_stream.
```

Columns and rows are separate parameters, not a `RowStream`, so renderer tests feed plain
iterators without HTTP.

| Format | Buffering | Byte-identical details |
|---|---|---|
| CSV | Streams: each row is written as it arrives | The header is written with the first row: an empty result still prints nothing. |
| JSON | Streams: each object is written as it arrives | `[` + newline before the first object, `,` + newline between objects, newline + `]` + newline after the last; an empty result is still `[]` + newline. |
| TABLE | Collects every row, then renders as today | Column widths need every row (snow does the same). |
| PLAIN | Collects every row, then renders as today | As TABLE. |

The caller passes a buffered `out` (`BufWriter` over a locked stdout); renderers flush at the
end and before returning an error. Output for every format stays byte-identical to today, so
every existing golden test passes unchanged; the golden check runs once through `execute()` +
`render()` and once through `query()` + `render_stream()`.

## Decision 4: Failure mid-stream

- **Retry:** each partition request goes through the client's existing `send()`, so a partition
  that answers 429/503/504 or times out is retried with ADR 0001's backoff (1 s, 2 s, 4 s or
  `Retry-After`, up to `max_retries`). One addition: an I/O error while reading the response
  **body** (connection reset after the headers arrived) is retried like a read timeout, as
  `Communication`. A long download is where a reset is most likely; DNS/TCP/TLS failures to
  connect stay unretried as in ADR 0001.
  *Amendment:* this applies to every request (POST, poll GET, partition GET), not only
  partition GETs. A retried POST keeps its `requestId` and adds `retry=true`, so Snowflake runs
  the statement once.
- **Out of retries:** the worker sends the error on that partition's reply channel. The stream
  yields every row of the partitions before it, then that `Err`, then `None`, and cancels the
  remaining workers. Errors keep the ADR 0001 kinds (`Communication` after the last retry, …).
- **Output:** CSV and JSON have already written the earlier rows; `render_stream` flushes them and
  returns the error. The JSON array is left unterminated on purpose: a half array must not look
  like a complete one. TABLE and PLAIN have written nothing yet, so only the error appears.
- **Exit:** the caller reports the error on stderr with `report_error` and exits **1** (ADR 0001
  Decision 7). Partial output with exit 0 must not happen. `BrokenPipe` from stdout is not an
  error and still exits 0, as in ADR 0001.

## Decision 5: Benchmark in the repo

- `bench/run.sh` (bash, run by hand; **not** wired into CI, which has no credentials) runs with
  `hyperfine` (median of ≥ 5 runs, 1 warm-up) against the sandbox, for this binary (release
  build) and the official snow 3.34.0 (`pip install snowflake-cli==3.34.0` in a venv, as
  `scripts/capture-goldens.sh` does):
  1. `SELECT CURRENT_ROLE()` → JSON;
  2. 100k rows → CSV and → JSON;
  3. 1M rows → CSV and → JSON;
  4. this binary only, memory scaling: 4M and 10M rows → CSV (snow takes minutes there and
     adds nothing to the comparison).

  The row scenarios use the generator query from the measurements above. Peak RSS comes from
  `/usr/bin/time -v` (`Maximum resident set size`), once per scenario. Output goes to
  `/dev/null`; the script prints a Markdown table to paste into PRs.
- Both sides use a temporary connection from the sandbox env (`SNOWFLAKE_ACCOUNT`,
  `SNOWFLAKE_USER`, `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`,
  `SNOWFLAKE_PRIVATE_KEY_B64` decoded to a 0600 temp file deleted on exit), with key-pair JWT.
  Until the `sql` command exists (stage 2), the Rust side is a small bench binary built on the
  public API (`query()` + `render_stream()`), e.g. `examples/bench_query.rs`; stage 2 switches
  the script to `snow sql -x -q … --format …`.
- `bench/README.md` says what it needs (hyperfine, Python 3, the env vars above; never their
  values) and how to run it. Results never include account identifiers or rows beyond the
  generator data.

## Decision 6: Tests (amends ADR 0001 Decision 9)

New seams: `render_stream` with a plain iterator of `Result` rows; `RowStream` over
`httpmock` partition endpoints with per-partition delays and failures; `ClientOptions::from_env`
with `Env::from_pairs`. Mocked-HTTP tests, at least:

- partitions completing out of order (later partitions answer first via delays): rows come out
  in statement order, and equal `execute()`'s;
- the in-flight bound: with `partition_concurrency = 2` and slow partitions, the mock server
  never sees more than 2 concurrent partition requests (e.g. a counter in a test-only HTTP
  handler, or `httpmock` hit counts sampled while requests are held), and partition `k + 2` is
  not requested before partition `k` is consumed;
- `partition_concurrency = 1` behaves as today (sequential);
- a partition that fails once (503) and then succeeds is retried and the output is complete;
- a partition body cut mid-read is retried;
- a partition that keeps failing after earlier partitions were rendered: CSV and JSON output
  holds exactly the rows before it, the error panel is on stderr, and the exit code is 1 (a CLI-
  or library-level test with `report_error`; there is no `sql` command yet);
- a single-partition result makes no partition request and spawns no worker;
- dropping the stream early stops dispatching (no request for partitions past the window);
- `SNOW_RS_PARTITION_CONCURRENCY`: unset → 8, `1`, `64`, and `0`, `65`, `abc` → `Client` error;
- every golden case renders identically through `render()` and `render_stream()`.

## Consequences

- Large results get faster in proportion to the partitions in flight, up to the network: at 1M
  rows the spike's download drops from 6.2–6.7 s to 1.7–2.3 s, at 10M from ~50 s (extrapolated from 4M)
  to 9.2–9.5 s.
- **Risk on the 2× target at 1M.** Wall time = submit (server execution, ~3.2–3.5 s for the
  generator query, the same for both clients) + download (floor ~2 s, set by the two 28 MiB
  partitions on one connection each) + rendering of the last partition. Estimated 5.5–6 s
  against snow's 11.3 s: about 2×, with little margin. If `bench/` falls short, the
  implementation PR reports the numbers; the levers, in order of cost, are: a cheaper CSV/JSON
  row writer (no per-field `String`s), raising the default limit, and decoding the head-of-line
  partition while its body is still arriving.
- **Memory criterion, as measured.** "1M rows ≈ 100k rows of peak RSS" cannot hold with any
  partition-level design: Snowflake's partitions double in size, so the largest single
  partition of a 1M result (28 MiB of text) is 3.5× the whole 100k result (8 MiB). What the
  design guarantees is a bound that does not depend on the row count: expected around
  170 MiB at 1M against today's 295 MiB (two large partitions plus one decoded), and
  **4M ≈ 10M** once partitions reach the cap. The implementation PR shows peak RSS for 100k, 1M, 4M and 10M; the
  flatness check is 4M vs 10M (within ~15 %), and 1M must be below today's 295 MiB.
- `SqlClient` gains threads and a shared `Arc`; `send()` must stay free of `&mut self` state so
  workers can call it concurrently (it is today).
- The `sql` stage builds on `query()` + `render_stream()`; `execute()` stays for small results.
  Multi-statement requests (stage 2) yield one `RowStream` per statement.
