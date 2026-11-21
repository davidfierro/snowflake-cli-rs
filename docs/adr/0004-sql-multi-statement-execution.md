# ADR 0004: `snow sql`: multi-statement execution over the SQL API

- **Status:** Accepted
- **Date:** 2026-11-21
- **Reference implementation:** Snowflake CLI `snow` **3.34.0** with
  `snowflake-connector-python` **4.8.1** (what `pip install snowflake-cli==3.34.0` resolves), as
  in [ADR 0001](0001-stage-0-foundation.md)
- **Amended by:** [Amendment 1](#amendment-1-multi-statement-latency):
  child results are fetched concurrently; Decisions 3 and 6 point to it
- **Builds on:** [ADR 0001](0001-stage-0-foundation.md) (transport, errors, renderers) and
  [ADR 0002](0002-parallel-partitions-and-streaming.md) (`RowStream`, `render_stream`). Nothing
  in them changes, except the additions listed under Decision 3.

## Context

Stage 2 builds `snow sql -q/-f/-i` with several statements per input, and stage 3
adds `-D`, `--enable-templating` and `--single-transaction`. Both must behave like
`snow` 3.34.0. `snow` runs each statement on one connector session, one after the other, so
`USE`, `ALTER SESSION`, session variables, temporary tables and `BEGIN/COMMIT` carry over from
one statement to the next. The SQL API v2 that this crate uses (ADR 0001 Decision 1) has no
session: each request is its own session, which only lasts as long as the request.

This ADR settles how the crate keeps `snow`'s behaviour on that API: the execution model, the
statement splitter, the output across several statements, errors, streaming, and the
constraints that stage 3 builds on.

### What `snow` 3.34.0 does (read from its source)

Files under `snowflake/cli/_plugins/sql/` and `snowflake/connector/` of the installed packages.

1. **Input.** `-q`, `-f` (repeatable) and `-i` are mutually exclusive (`-q` with `-f` is a usage
   error, exit 2). With none of them and a non-TTY stdin that is not blank, stdin is read as the
   query. With none and nothing on stdin, `snow` starts the interactive REPL.
2. **Pipeline** (`SqlManager.execute`, `statement_reader.py`), per input (the `-q` text, the
   stdin text, or **each `-f` file on its own**):
   1. `split_statements(text, remove_comments=not --retain-comments)` from
      `snowflake/connector/util_text.py`;
   2. for each piece: the LEGACY transpiler (`&{x}`, `&x` → `<% x %>`) if LEGACY is enabled,
      then the STANDARD renderer (`<% x %>`) with the `-D` variables. Templating runs **after**
      splitting, so a `;` in a variable value does not split at this step;
   3. lines starting with `!` are REPL commands (`!source`, `!load`, …); a piece ending in `;>`
      runs asynchronously;
   4. pieces that are empty or whose every line is blank or starts with `--` are dropped; if
      nothing is left: `No SQL statements found to execute.` (exit 1); any rendering error
      (undefined variable, …) aborts before anything runs;
   5. `--single-transaction` turns autocommit off on the connection and wraps the list in
      `BEGIN;` … `COMMIT;`, which are statements like any other (echoed, with a status row);
   6. each piece goes through `execute_string` → `connection.execute_stream`, which **splits it
      again** with `remove_comments=False`, strips each part, drops empty ones, and executes
      each part with `VerboseCursor`, which prints the statement text before running it.
3. **Output** (`commands.py`, `_app/printing.py`): with one statement in total the result prints
   as a single result (ADR 0001 renderers). With two or more it is `MultipleResults`: TABLE and
   PLAIN print each statement's echo followed by its result; JSON prints a list of results
   (format below); CSV prints each result followed by an empty line. The echo is a
   `cli_console.plain_message`, so `--silent` hides it and JSON/CSV never show it.
4. **Errors**: the generator stops at the first failing statement; what was printed stays; the
   error panel goes to stderr, followed in TABLE/PLAIN (not JSON/CSV) by the line
   `To send feedback about Snowflake CLI: snow feedback`; exit 1.

### What the SQL API does (docs and sandbox)

Docs: [Submitting multiple SQL statements in a single request][multi] and
[Handling responses][responses]. Sandbox checks ran on 2026-11-21 with key-pair JWT, a temporary
connection from the sandbox env, synthetic SQL only (no tables except a scratch table in the
role's own database, dropped afterwards). The probe scripts were throwaway and are not in the
repo; nothing they printed is reproduced here except error codes and response shapes.

| # | Claim | Source |
|---|---|---|
| A1 | `parameters.MULTI_STATEMENT_COUNT` = n runs n statements in one request; `0` accepts any number; omitted means 1. A different count fails before anything runs with `000008` (`0A000`) `Actual statement count X did not match the desired statement count Y.` | docs; sandbox (count 3 for 2 statements → `000008`) |
| A2 | On success the parent answers 200 with `statementHandles` (one per statement, in order) and a one-row `multiple statement execution` result; each child's result (columns, partition 0, `partitionInfo`) comes from `GET /api/v2/statements/{child}`, and its partitions as usual. | docs; sandbox |
| A3 | The parent answers only when **every** statement has finished (a request with `SYSTEM$WAIT(4)` second took 4.4 s; with `async=true` the 202 polls carry no `statementHandles` until the end). Children cannot be read while later statements run. | sandbox |
| A4 | `USE SCHEMA`, `SET v = …` / `$v`, `CREATE TEMPORARY TABLE` and `ALTER SESSION` carry over to later statements of the same request. | docs (use cases); sandbox |
| A5 | Statements before a failing one have run, later ones do not run. The parent answers 422 with code `100132`, sqlState `P0000` and a `SYSTEM$MULTISTMT` JavaScript wrapper message (`Execution of multiple statements failed on statement "<text, truncated>" (at line L, position P). <original message> in SYSTEM$MULTISTMT …`), **without** `statementHandles` and without the failing statement's code, sqlState or query id. | docs; sandbox |
| A6 | The children of a failed request are in `INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION` of the parent's session at once (no lag seen), in start order, with `QUERY_ID`, `QUERY_TEXT`, `EXECUTION_STATUS`, `ERROR_CODE`, `ERROR_MESSAGE` (no SQLSTATE column). The parent's `SESSION_ID` is in `QUERY_HISTORY_BY_USER`. `SNOWFLAKE.INFORMATION_SCHEMA` works without a current database. Queries run inside a `CALL` (e.g. an anonymous procedure) appear there too, between the user's statements; `EXECUTE IMMEDIATE '<sql>'` did not add a row. | sandbox |
| A7 | `GET` of a failed child answers **200** with its own error: for a compilation error `code`, `sqlState`, `message`, `statementHandle` (e.g. `002003`, `42S02`, the same message `snow` prints); for an execution error only `code` and `message` (e.g. `100051`, `Division by zero`, no `sqlState`). | sandbox |
| A8 | `BEGIN; INSERT …; <failing>; COMMIT` leaves no row; `BEGIN; INSERT …` with no `COMMIT` leaves no row (an open transaction is rolled back when the request ends); `ALTER SESSION SET AUTOCOMMIT = FALSE; INSERT …` leaves no row; without a transaction, `INSERT …; <failing>` keeps the row. `ALTER SESSION SET AUTOCOMMIT = FALSE` is accepted inside a multi-statement request. | sandbox |
| A9 | The server ignores empty statements in a multi-statement request (`select 1; ; select 2` counts 2). Sent alone, `;`, `/* c */ ;` and `-- c\n;` fail with `000900` (`42601`) `SQL compilation error:\nEmpty SQL statement.`, which is what `snow` prints for a stray `;`. | sandbox; `snow` run |
| A10 | `BEGIN`, `COMMIT`, `USE`, `ALTER SESSION`, `CREATE` children return one `status` text column with `Statement executed successfully.`: the row `snow` prints. | sandbox |
| A11 | After `ALTER SESSION SET TIMEZONE = 'Asia/Tokyo'` in the request, a later `SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION` in the same request returns `Asia/Tokyo`; TIMESTAMP_LTZ values still arrive as epoch seconds. | sandbox |
| A12 | A multi-statement request needs a warehouse; variable binding is not supported in it (the crate does not bind). | docs |
| A13 | A trailing comment after the last statement and a `;` on its own line after a `--` comment are accepted (`select 2 -- c\n;` is one statement). | sandbox |
| A14 | A **syntax error** in any statement rejects the whole request before anything runs: 422 with the statement's own code and sqlState (`001003`, `42000`) and `syntax error line L at position P`, where L counts lines from the start of the request text. Other compilation errors (unknown function, missing object) run the statements before them and answer A5's `100132`. Added by the `sql` build (stage 2). | sandbox |

[multi]: https://docs.snowflake.com/en/developer-guide/sql-api/submitting-multiple-statements
[responses]: https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses

### What `snow` printed on the sandbox (non-TTY)

- TABLE, `select 1 as a; select 'x;y' as b, 2 as c`: `select 1 as a;` newline, the table, then
  `select 'x;y' as b, 2 as c` newline, the table. No blank line between results; an empty result
  is `No data\n\n` as today. With one statement the echo is printed too.
- A stray `;` line in a file is sent and fails with `000900` after the earlier statements ran.
- JSON with several statements: see Decision 4; the extra spaces in `"A"  :   1` always appear,
  TTY or not (they come from how `snow` writes, not from the terminal).
- `--retain-comments`: a comment before a statement and a `-- …` after its `;` on the same line
  belong to that statement and are echoed with it.

## Decision 1: Execution model

### Options

| | A. One multi-statement request per run (chosen) | B. One request per statement, context replayed by the client | C. The drivers' session protocol (`/session/v1/login-request`, `/queries/v1/query-request`) | D. A Snowflake Scripting block around the input |
|---|---|---|---|---|
| Session context | Exact: one server session (A4) | Only what the client tracks: `USE`; no variables, `ALTER SESSION`, temp tables or transactions | Exact | Exact, but `USE` and some DDL behave differently inside blocks |
| `--single-transaction` | Exact (A8) | Impossible | Exact | Possible |
| Results per statement | Every child keeps its result (A2) | Yes | Yes | Only the block's return value |
| Errors | Failing child recovered from history (A6, A7); sqlState lost for execution errors | Exact | Exact | `SQLCODE`/`SQLSTATE` in a handler, results lost |
| Streaming | Output starts when the whole input has run (A3) | Per statement | Per statement | None |
| Cost | Fits ADR 0001/0002 as is | Small, but wrong | A second transport (login, session tokens, heartbeats, chunk download from cloud storage): reverses ADR 0001 Decision 1 | Rewrites the user's SQL |

### Decision

**A.** `snow sql` sends all statements of one run (every `-q`/`-i`/`-f` input, `-f` files in
order) in **one** SQL API request, so they share one session, as they share one connection in
`snow`. B cannot do transactions, variables or temporary tables. C is the only way to stream per
statement and to keep every error field, but it is a second transport over endpoints that
Snowflake documents only through its drivers; if a later stage needs it, it gets its own ADR.

- **Count:** `MULTI_STATEMENT_COUNT` is the exact number of statements the crate sends (never
  `0`). A1 then turns any disagreement between the crate's splitter and the server's into an
  error before anything runs, instead of results attached to the wrong statement. A `000008`
  answer becomes a `Client` error (exit 1): `The server split the SQL into a different number
  of statements than snow-rs did (<server> vs <client>). Please report this input.` (the counts
  come from the message).
- **One statement:** a run with exactly one statement sent is a plain request (no
  `MULTI_STATEMENT_COUNT`), the path that exists today: its errors already match `snow`
  byte for byte (ADR 0001 Decision 7).
- **Request text:** the statements, each exactly as echoed (Decision 2), joined with `\n`. A
  statement that the splitter did not see end with `;` (the last one of an input, possibly with
  a retained trailing comment) is followed by `\n;` in the request text only (A13), so the last
  statement of one `-f` file cannot run into the first of the next.
- **Hidden statements** are statements the crate adds to the request and never echoes, renders
  or counts as results:
  - `ALTER SESSION SET AUTOCOMMIT = FALSE` first, with `--single-transaction` (Decision 6);
  - `SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION` right after every user statement whose text
    contains `TIMEZONE` (ASCII case-insensitive), so TIMESTAMP_LTZ values of later statements
    are shown in the zone the session had at that point (A11). The zone of a child is the one
    from the closest hidden `SHOW` before it; before any, it is the zone from the separate
    `SHOW PARAMETERS LIKE 'TIMEZONE'` request ADR 0001 Decision 5 already makes, run at most
    once per run and only if an LTZ column appears.
- **Empty statements** (A9): a statement that is empty once comments are removed (`;`,
  `/* c */ ;`) is where the run fails in `snow`. The crate sends the statements before it as the
  request above (if any), renders them, then echoes the empty statement and sends it **alone**;
  the server's `000900` error is reported as any other failure (Decision 5). Nothing after it is
  sent.
- **Not supported yet** (checked before anything is sent; `Usage` error, exit 2, message
  `<what> is not supported yet.`): a `!` command line (`!source`, `!load`, …: `REPL commands
  (!source, !load, …) are`), a statement ending in `;>` (`Asynchronous statements (;>) are`),
  a `PUT`/`GET` statement, as the splitter flags it (`PUT and GET are`). *(Superseded: all three
  landed, `;>` last; see ADR 0005, Amendment 4.)*
- **Input rules** as `snow`: the flags are mutually exclusive with `snow`'s usage message;
  `-f` keeps the order given; with no flag and a non-TTY stdin that is not blank, stdin is the
  query (what `snow`'s code means to do; 3.34.0 reads it, then starts the REPL anyway, which
  stage 2 found on the sandbox); with no flag and nothing to read, `snow` would start the REPL: here it is a `Usage`
  error, `The interactive SQL session is not supported yet. Use --query, --filename or
  --stdin.` (exit 2). *(Superseded: the interactive session and its `!` commands landed in
  see ADR 0005, Amendment 3.)* No statement left after step 4: `No SQL statements found to execute.`
  (exit 1, as `snow`).

## Decision 2: Statement splitter

- **A port, not a new parser.** `src/script/split.rs` is a line-by-line port of
  `split_statements` and `_concatenate_statements` from
  `snowflake-connector-python` 4.8.1 `src/snowflake/connector/util_text.py` (Apache-2.0; the
  file header names the source and its license), with the default delimiter `;`. Its quirks are
  `snow`'s behaviour and are kept: `'` and `"` quotes with `\` and doubled-quote escapes, `$$…$$`
  blocks, `--` **and `//`** line comments, nested-unaware `/* */` comments, the `://` exception
  (URLs are not comments), a comment or blank rest of line after `;` attached to that statement,
  `;>` kept on the statement, `!` at column 0 as a command, and the `is_put_or_get` flag.

  ```rust
  // src/script/split.rs
  pub struct Piece {
      /// Text as the connector yields it (stripped; ends with `;` when terminated).
      pub text: String,
      /// The splitter saw this piece end with `;` (or `;>`).
      pub terminated: bool,
      /// `Some(true)` for PUT/GET, `None` for an empty or comment-only piece.
      pub put_or_get: Option<bool>,
      /// A `!` command line.
      pub command: bool,
  }
  pub fn split_statements(text: &str, remove_comments: bool) -> Vec<Piece>;
  ```

- **The statement list** (`src/script/mod.rs`, `pub fn compile(inputs, options) ->
  Result<Vec<Statement>>`) is built exactly as `snow` builds it (Context, step 2), per input:
  split with `remove_comments = !retain_comments` → render each piece (stage 3; identity in
  stage 2) → drop pieces that are empty or only blank/`--` lines → **split each rendered piece
  again with `remove_comments = false`**, strip, drop empty parts. The second split is what
  `execute_stream` does: it makes a `;` that templating produced split, as in `snow`. With
  `--single-transaction`, `BEGIN;` and `COMMIT;` are added around the whole list (stage 3).
- **What is sent is what is echoed.** Each final part is one `Statement`; its text is both the
  echo and the statement text in the request (Decision 1). The server splits the request again;
  the count check (A1) proves the two splits agree.
- **`--retain-comments`** only changes the first split's `remove_comments`; comments then reach
  the server as part of the statement text, as in `snow`.

## Decision 3: Client interface for a run

Additions to `src/sql/` (ADR 0002's `query()`, `execute()` and `RowStream` are unchanged; a new
`src/sql/script.rs`):

```rust
impl SqlClient {
    /// Runs `statements` as one session (Decision 1) and returns once the request has finished.
    /// `Err` only when nothing ran (auth, HTTP, count mismatch, a failure of the single-statement
    /// path before its result). A failure of statement k comes out of `ScriptRun` at k.
    pub fn run_script(&self, statements: &[String], options: &ScriptOptions) -> Result<ScriptRun>;
}

#[derive(Debug, Clone, Default)]
pub struct ScriptOptions {
    /// Adds the hidden `ALTER SESSION SET AUTOCOMMIT = FALSE` (Decision 6).
    pub autocommit_off: bool,
}

/// The results of a run, one per user statement, in order.
pub struct ScriptRun { /* client, child handles, hidden-statement map, LTZ zones, failure */ }
impl Iterator for ScriptRun {
    /// `Ok(stream)` for a statement that ran; `Err` for the failing one, then `None`.
    type Item = Result<RowStream>;
}
```

- Each `next()` sends `GET /api/v2/statements/{child}` for the next user statement (skipping
  hidden ones), builds a `RowStream` from it with ADR 0002's machinery (same partition workers,
  window and memory bound), and returns it. The previous `RowStream` has been consumed or
  dropped by then, so at most one statement's partitions are in flight. *Amended by
  Amendment 1:* the first GETs of the next children are prefetched in a bounded window; the
  partitions after a child's first page are still fetched only while that child is consumed.
- `RowStream` gets a crate-private constructor from a child's first GET, with the LTZ zone the
  run gives it (Decision 1); `Inner::start` is split so the 200 body of a POST and of a GET are
  parsed by the same code.
- A run of one statement is `query()` wrapped in a one-item `ScriptRun`, so the command has one
  path.

## Decision 4: Output across statements

`src/commands/sql.rs` drives `ScriptRun` and the renderers; `print_query` (`src/query.rs`) stays
for `bench/`'s replacement and is removed if nothing uses it. Let *n* be the number of user
statements in the run (with `--single-transaction`, `BEGIN;` and `COMMIT;` count).

- **TABLE and PLAIN, any n:** for each statement: the echo (its text, through
  `sanitize_for_terminal`, then `\n`) unless `--silent`, then the statement's result exactly as
  `render_stream` prints it today (a table, or `No data\n\n`). Nothing between statements.
- **JSON and CSV, n = 1:** today's single-result output, unchanged.
- **CSV, n ≥ 2:** for each statement, today's CSV of its result (an empty result prints nothing)
  followed by `\n`.
- **JSON, n ≥ 2:** `snow` writes each result with `json.dump(result, indent=2)` through a writer
  that applies `textwrap.indent(chunk, "  ")` to every chunk Python's encoder yields. The bytes
  that produces, which the new `render::json_multi` writer emits directly (streaming, one row at
  a time):

  ```text
  run      = "[\n" result ( ",\n" result )* "\n]\n\n"
  result   = "  []"                                       ; no rows
           | "  [\n" row ( "  ,\n" row )* "\n  ]"
  row      = "    {}"                                     ; no columns
           | "    {" member ( "  ," member )* "\n    }"
  member   = "\n    " "  " key "  : " "  " value
  ```

  `key` and `value` are encoded as today's JSON renderer encodes them (ensure_ascii, ANSI
  escapes removed, Python float repr), so a result with the row `{"A": 1, "B": "s"}` is
  `  [\n    {\n      "A"  :   1  ,\n      "B"  :   "s"\n    }\n  ]`. The grammar was checked
  against `snow`'s writer (Python `json` + `textwrap.indent`) on rows with several members,
  several rows, empty results and zero-column rows; golden tests hold the exact bytes.
- **DDL / `USE` / `BEGIN` / `COMMIT`** need no special case: the server returns the
  `status` column (A10) and it renders like any result.
- **Writes:** stdout is one `BufWriter` for the whole run, flushed after each statement's result
  in TABLE/PLAIN and before anything is written to stderr.

## Decision 5: Errors

- **Which statement failed.** Single-statement runs and the empty-statement case get the error
  from their own request. For a 422 `100132` from a multi-statement request (A5), the crate:
  1. finds the parent's session: `SELECT SESSION_ID FROM
     TABLE(SNOWFLAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_USER(END_TIME_RANGE_START =>
     DATEADD('minute', -10, CURRENT_TIMESTAMP()), RESULT_LIMIT => 10000)) WHERE QUERY_ID =
     '<parent handle>'`;
  2. lists its queries: `SELECT QUERY_ID, QUERY_TEXT, EXECUTION_STATUS FROM
     TABLE(SNOWFLAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION(SESSION_ID => <id>,
     RESULT_LIMIT => 10000)) ORDER BY START_TIME`, and drops the parent's row;
  3. matches the statements it sent (hidden ones included) to those rows **in order, by text**:
     statement k is the next row whose `QUERY_TEXT`, with comments removed, whitespace collapsed
     and a final `;` dropped, equals the statement's text normalised the same way. Rows that
     match nothing (queries run inside a `CALL`, A6) are skipped. The first matched row that is
     not `SUCCESS` is the failing statement;
  4. `GET`s that child (A7) for its error.
  Both lookups use the run's connection context (warehouse, role); the warehouse is already
  required (A12). They run only on failure.
- **What is printed.** The statements before the failing one are output as in Decision 4. Then
  the failing statement's echo (TABLE/PLAIN, not `--silent`), as `snow` echoes it before running
  it. In JSON with n ≥ 2 the output stops after the last complete result, without the `,`, the
  closing `]` or a newline (what `snow` leaves); in CSV after the last complete result's `\n`.
  Then stdout is flushed and the error panel goes to stderr (`report_error`), followed in TABLE
  and PLAIN only by `To send feedback about Snowflake CLI: snow feedback\n` (an addition to
  `report_error`'s callers for every command; `snow` prints it after every non-usage error in
  non-structured formats). Exit code 1.
- **Panel text:** `<code> (<sqlState>): <query id>: <message>`, as today's 422 path builds it,
  from the child's GET. **Deviation:** for an execution error the server does not return the
  sqlState (A7), so the panel reads `<code>: <query id>: <message>` (e.g. `100051: …: Division
  by zero` where `snow` prints `100051 (22012): …`). Compilation errors, the common case, match
  exactly. Stage 2 lists the deviation in `README.md`.
- **A request rejected before anything ran** (A14, found while building stage 2): the line
  number in the message names the failing statement (the request text puts every statement on
  its own line). The statements before it are sent as one request and rendered, then the
  failing one is sent **alone**, so its error (line counted within the statement) is the one
  `snow` prints. If it unexpectedly succeeds alone, the rest follows as another request. Without
  a line number the error is reported as it is.
- **Fallback.** If a lookup fails or nothing matches, the crate reports the parent's error with
  the wrapper removed: the text between the first `).\n` and ` in SYSTEM$MULTISTMT at ` as the
  message, `100132 (P0000)` and the parent's handle, and renders no result of that run (it
  cannot tell which children ran). Exit 1.
- **Mid-stream partition failures** inside one statement behave as ADR 0002 Decision 4, and end
  the run there.

## Decision 6: Streaming, `--single-transaction`, templating

- **Streaming.** Within a statement, ADR 0002 holds unchanged: partitions in parallel, rows
  streamed in CSV/JSON, memory bounded by `partition_concurrency` partitions, whatever the row
  count. Across statements, one statement's stream at a time, so the bound is the same as for a
  single statement. What changes is latency (A3): output starts when the **whole** run has
  finished on the server, where `snow` prints each result as its statement ends. Total time
  stays close to `snow`'s server time plus one GET per statement (~0.1 s each). If the bench
  shows that GET to matter for inputs with many small statements, the lever is to prefetch the
  next children's first GET in the background (bounded, like ADR 0002's window); it was not
  built in stage 2. *Amended by Amendment 1:* the bench showed that GET to be most of the time,
  and Amendment 1 builds the prefetch.
- **`--single-transaction` / `--no-single-transaction`** (stage 3): `BEGIN;` and `COMMIT;` are
  user statements added around the list (echoed, with their status rows, counted in n) and
  `ScriptOptions::autocommit_off` adds the hidden `ALTER SESSION SET AUTOCOMMIT = FALSE`, the
  SQL API's form of `snow`'s `autocommit(False)`. A failing statement ends the request with the
  transaction open, and Snowflake rolls it back (A8); there is no client-side `ROLLBACK`. As in
  `snow`, DDL inside the input still commits implicitly.
- **Templating** (stage 3) is `src/script/template.rs`, a pure function from a piece's text, the
  variables and the enabled syntaxes to text or an error, called by `compile` between the two
  splits (Decision 2). Rendering errors are collected for every piece and reported before
  anything is sent (`snow`'s warnings plus `SQL rendering error`, exit 1). Stage 3 takes the
  exact syntax, escaping and messages from `snow`'s `snowsql_templating.py` and
  `api/rendering/sql_templates.py` and golden tests; this ADR only fixes where it runs.
  *Extended by ADR 0006:* expressions, JINJA (rendered on each whole input before the first
  split), `--project`/`--env` and the template errors `snow` reports as unexpected exceptions.

## Decision 7: Tests and bench

- **Splitter tests** (`src/script/split.rs` unit tests) plus a table of inputs compared with the
  connector itself: `scripts/capture-split-goldens.sh` runs the pinned connector's
  `split_statements` (in the same venv as `capture-goldens.sh`) on every input in
  `tests/golden/split/cases.toml` with both `remove_comments` values and writes
  `tests/golden/split/<case>.json`; no network. Cases: quotes with `;`, `\'` and `''` escapes,
  quoted identifiers, `--`, `//`, `/* ; */`, `$$ ; $$`, URLs with `//`, a comment after `;`,
  `;>`, `!source` lines, a stray `;`, an unterminated last statement, CRLF line ends.
- **Output goldens** from the official CLI: `scripts/capture-goldens.sh` learns cases with a
  list of inputs (`queries = [...]` for one `-q`, `files = [...]` for `-f`, `stdin`), flags
  (`retain_comments`, later `variables`, `templating`, `single_transaction`) and the formats
  TABLE, PLAIN, JSON, CSV. For each it stores `snow`'s stdout, stderr (query ids and the role
  name replaced by placeholders) and exit code, plus the SQL API responses of the crate's own
  request sequence (parent, children, and for failure cases the history lookups and the failed
  child's GET), replayed by `httpmock` in `tests/golden.rs`. Synthetic SQL only; failure cases
  use a missing object and `1/0`. Stage 2 cases: `-q` with 1 and 3 statements, two `-f` files
  (one ending without `;`), `-i`, `USE SCHEMA` then a query, DDL status rows, empty results in
  each format, a compilation error in the middle (exact match) and an execution error in the
  middle (the documented deviation), a stray `;`, `--retain-comments`, `--silent`.
- **Mocked-HTTP tests** for `run_script`: hidden statements are not rendered and LTZ zones come
  from the right hidden `SHOW`; the count sent equals the statement list; `000008` → the client
  error; the history matching with `CALL` rows in between; the fallback when a lookup fails;
  a single statement takes the plain path (no `MULTI_STATEMENT_COUNT`).
- **Sandbox tests** (`tests/sandbox.rs`, `--ignored`): `USE SCHEMA INFORMATION_SCHEMA; SELECT
  CURRENT_SCHEMA()` returns `INFORMATION_SCHEMA`; stage 3 adds the `--single-transaction`
  rollback check on a scratch table in the role's own database (created and dropped by the
  test).
- **Bench** (`bench/run.sh`, ADR 0002 Decision 5): the Rust side becomes `snow sql -x -q …
  --format …` and `examples/bench_query.rs` is deleted. New scenarios, both compared with
  `snow`: `multi-small-json`, 20 statements (`USE SCHEMA INFORMATION_SCHEMA;` then 19 ×
  `SELECT <i> AS n;`) → JSON; and `multi-2x100k-csv`, two 100k-row generator queries → CSV. The
  trivial and 1M scenarios keep the ADR 0002 targets (≤ 200 ms; ≥ 2× faster than `snow`).

## Consequences

- Session context, temporary tables, variables and transactions behave as in `snow`, on the
  API the crate already uses, with no second transport.
- Results of a long script appear at its end instead of statement by statement; the final
  stdout, stderr and exit code are the same as `snow`'s.
- A failure costs two metadata queries plus one GET, only on the failure path.
- One documented deviation: no sqlState in the panel for execution errors in the middle of a
  multi-statement run.
- The count check turns any splitter disagreement into a clear error before execution, never
  into wrong output; the splitter goldens come from the connector itself.
- The splitter is a port of Apache-2.0 code and carries its notice.
- If streaming per statement or exact execution-error fields ever matter more than the cost of a
  second transport, option C gets its own ADR.

## Amendment 1: multi-statement latency

- **Status:** Proposed (Accepted when its PR is merged)
- **Date:** 2026-11-21
- **Targets:** `multi-small-json` at least 3× faster than `snow` (≤ ~1.86 s at
  `snow`'s 5.57 s), `single-transaction-json` ≤ 500 ms, no regression of `trivial-json`
  (≤ 200 ms) or `1m-json` (≥ 2×), byte-identical output, session semantics unchanged.

### Where the time goes

Measured on the sandbox on 2026-11-21 with the release build of `main` (`adbd034`), `--debug`
timestamps per request, and the session's `QUERY_HISTORY_BY_USER` aggregates (counts and
durations only). Medians of 7 runs unless noted.

`multi-small-json` (`USE SCHEMA INFORMATION_SCHEMA;` then 19 × `SELECT <i> AS n;`, 20 user
statements, one request):

| Phase | Time | Note |
|---|---|---|
| Process start, config, JWT | 3 ms | |
| POST until 200 | 1,370 ms | 1,340–1,480 ms over 7 runs |
| … of which server-side span of the `MULTI_STATEMENT` session | ~1,200 ms | 1,184–1,317 ms over 9 sessions; 21 queries; queued 0 ms |
| … of which network, TLS, admission | ~170 ms | |
| Polling | 0 ms | no 202 in any of ~80 runs (see option b) |
| 20 child GETs, one after the other | 2,316 ms | ~115 ms each (the first ~175 ms) |
| Rendering | < 5 ms | |
| **Total** | **3,724 ms** | `snow` 5,600 ms in the same session |

How the POST grows with the statement count (plain `SELECT <i>` statements, medians of 5):
1 statement (plain path) 165 ms, 2 → 363 ms, 5 → 488 ms, 10 → 778 ms, 20 → 1,370 ms: about
**270 ms fixed + 55 ms per statement**. The per-statement part is server-side: each child costs
~45 ms of compilation plus execution inside `SYSTEM$MULTISTMT`, and the wrapper adds its own
overhead. The warehouse was running (no queuing, no provisioning).

`single-transaction-json` (`SELECT 1 AS a; SELECT 2 AS b` with `--single-transaction`: the
hidden `ALTER SESSION`, `BEGIN`, two `SELECT`s, `COMMIT`; 5 statements sent, 4 user results):
POST 590 ms (server span 446–548 ms, median ~455 ms over 7 sessions) + 4 GETs 495 ms = 1,085 ms.

So the time is the child GETs (62 %) and the server's own execution (33 %); polling and the
client are nothing.

### Options

| | Saves on `multi-small-json` | Session semantics | Cost / risk |
|---|---|---|---|
| **a. Concurrent child GETs (chosen)** | ~2.0 s → 1.63 s measured | Untouched: the same one request | A bounded prefetch window in `ScriptRun`; output order is the step order |
| b. Tune polling | 0 (nothing to tune) | Untouched | None, but no gain |
| c. Independent requests when provably session-free | ~3.3 s on this scenario only (est. ~0.4 s total) | At risk | Needs SQL analysis; applies to almost no real script |
| d. Session transport (connector protocol) | ~2 s at best (est. 1.5–1.7 s total) | Exact | A second transport (ADR 0001 Decision 1 reversed); no better than a |

- **a. Concurrent child GETs.** All children are finished when the parent answers (A3), so
  their first GETs are independent reads and can run at once, as ADR 0002 runs partitions. A
  throwaway spike (prefetch every child's first GET with *W* worker threads before iterating;
  not committed) measured, medians of 7 to 9 runs:

  | Window *W* | 0 (today) | 4 | 8 | 12 | 16 | 20 |
  |---|---|---|---|---|---|---|
  | `multi-small-json` total | 3,641 ms | 1,960 ms | 1,706–1,796 ms | 1,641 ms | 1,631–1,634 ms | 1,517 ms |
  | vs `snow` (5,600 ms) | 1.5× | 2.9× | 3.1–3.3× | 3.4× | 3.4× | 3.7× |

  `single-transaction-json` with *W* = 16: 744 ms (`snow` 4,668 ms, 6.3×). The JSON output of
  every window was byte-identical to *W* = 0, and for `single-transaction-json` also to
  `snow`'s. *W* = 8 meets the 3× target with almost no margin (the POST alone varies by
  ±100 ms); 16 leaves ~0.2 s; beyond 16 the gain is small and every worker is one more TLS
  connection.
- **b. Polling.** The POST answers 200 synchronously when the request finishes within 45 s
  ([Handling responses][responses]: "If the statement takes longer than 45 seconds to execute",
  the answer is 202). No run here saw a 202, so the poll schedule (250 ms doubling to 2 s) adds
  nothing to these scenarios and at most ~2 s to scripts that run longer than 45 s (< 5 %).
  Unchanged.
- **c. Independent requests for session-free statements.** Proving that a statement does not
  depend on the session means parsing it: unqualified names resolve through `USE`, and
  `$variables`, temporary tables, `CURRENT_*()`, `LAST_QUERY_ID()`, sequences, `ALTER SESSION`
  parameters (time zone, formats, `QUOTED_IDENTIFIERS_IGNORE_CASE`, …) and open transactions
  all leak in. The only statements this crate could prove free of all of them are object-free
  literal `SELECT`s, i.e. the benchmark, not users' scripts. The brief says to keep the single
  request when in doubt. Rejected.
- **d. Session transport.** Measured with `snowflake-connector-python` 4.8.1 on one session
  (5 runs): the 20 `multi-small` statements take 1,312 ms of round trips (64 ms each), the
  same server cost as the multi-statement span; `BEGIN; SELECT; SELECT; COMMIT` with autocommit
  off takes 421 ms. Login took 2.2 s in Python (OCSP and Python overhead included); a native
  client would need at least one more round trip (estimated 0.2–0.4 s, not measured). It lands
  where option a already is for `multi-small-json` and above 500 ms for
  `single-transaction-json`. Not needed, and no separate protocol issue is warranted by these
  numbers.

### Decision

**a**, with a window of **16** first GETs.

- **Where:** `ScriptRun` (`src/sql/script.rs`). When `run_script` has its steps, it starts
  prefetching the first GET (`Inner::get_statement`) of every `Step::Child` and `Step::Zone`
  handle, in step order, on worker threads like ADR 0002's partition workers: at most **16**
  requests outstanding or finished-but-unconsumed at once; consuming a step frees a slot and
  dispatches the next handle. `next()` takes the step's prefetched reply (waiting for it if it
  has not arrived) instead of sending the GET itself; everything after the reply (`started`,
  LTZ zone, `RowStream::new`, the child's later partitions) is unchanged. A run with no child
  (the single-statement plain path) starts no worker.
- **Order:** replies are stored per step index and consumed strictly in step order, so output
  order, the hidden-statement map and the LTZ zone tracking are as today regardless of which
  reply arrives first.
- **Errors:** a prefetched GET that fails (HTTP, transport after its retries, a child error) is
  returned when its step is reached, never earlier: the statements before it are printed first,
  exactly as today. Retries, timeouts and the failure path of Decision 5 (history lookups, the
  failed child's GET) are unchanged; the children that ran before a failure are prefetched like
  any other.
- **Drop:** when `ScriptRun` is dropped or ends with an error, no further GET is dispatched;
  outstanding ones finish and are discarded (GETs have no side effects).
- **Memory:** each prefetched reply is a child's partition 0, which Snowflake keeps small
  (~1.2k rows for the bench's wide shape, ADR 0002 "How Snowflake partitions a result"), so the
  window adds at most 16 first pages to ADR 0002's bound. A child's further partitions are still
  fetched only while that child is consumed, so the large-result bound is unchanged.
- **Connections:** the agent's idle pool per host is raised to at least the window
  (`max_idle_connections_per_host(partition_concurrency.max(16))`, and the total to match), so
  the prefetch workers and then the next child's partition workers reuse TLS connections.
- **Not configurable.** A constant (`CHILD_PREFETCH_WINDOW = 16`); a knob can come when a case
  needs it.
- **Session semantics:** untouched. The statements still go out as the one request of
  Decision 1; only reads of finished results move.

### Expected results and the `single-transaction-json` target

| Scenario | Today | Expected | Target |
|---|---|---|---|
| `multi-small-json` | 3.80 s (1.5×) | ~1.63 s (3.4×) | ≤ ~1.86 s (3×) ✓ |
| `single-transaction-json` | 1.05 s | ~0.74 s (6.3×) | ≤ 500 ms ✗ |
| `trivial-json` | 163 ms | unchanged (plain path, no worker) | ≤ 200 ms ✓ |
| `1m-json` | 6.25 s (3.8×) | unchanged (single statement) | ≥ 2× ✓ |
| `multi-2x100k-csv` | 2.90 s | slightly lower (the second child's first GET overlaps the first's download) | no target |

**`single-transaction-json` ≤ 500 ms is not reachable while keeping the semantics, on either
transport.** The server alone spends ~455 ms (446–548 ms) running the 5 statements of the
request, before any network time; the POST takes ~570 ms with nothing else. On a session
transport the four statements alone take ~420 ms plus a login. Dropping the hidden
`ALTER SESSION SET AUTOCOMMIT = FALSE` (one statement, ~55 ms) would change what a failure after
an implicit DDL commit rolls back (Decision 6), so it stays. What this amendment delivers is
~0.74 s, 6.3× faster than `snow`; the recommended target is **≤ 800 ms**.

### Tests (for the build)

Mock server (`httpmock`): child replies delayed in reverse order still render in statement
order; at most 16 GETs outstanding (a 30-statement run with slow children); a failing child GET
in the middle prints the results before it, then the error, and dispatches nothing after the
window; dropping the run early stops dispatching; a hidden `SHOW PARAMETERS` reply that arrives
last still sets the zone of the statements after it; a single statement starts no prefetch.
Sandbox (`--ignored`): `USE`, `SET` / `$v`, a temporary table, `ALTER SESSION` and an explicit
`BEGIN … COMMIT` carry over across statements (Amendment 1 acceptance criteria). The existing golden
tests pass unchanged. Bench: `multi-small-json`, `single-transaction-json`, `multi-2x100k-csv`,
`trivial-json` and `1m-json` re-run with `WRITE_RESULTS=1`.

### Consequences

- `multi-small-json` meets 3× with ~0.2 s of margin; long scripts of small statements gain
  ~0.1 s per statement after the first.
- The remaining time is the server's: ~270 ms per request plus ~55 ms per statement inside
  `SYSTEM$MULTISTMT`. No client change on the SQL API can go below it.
- Up to 16 extra TLS connections per run with many statements; first pages only in memory.
- `single-transaction-json` stays above 500 ms (~0.74 s); the target needs revising, not the
  transport.
