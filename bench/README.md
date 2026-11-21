# Benchmarks

`bench/run.sh` compares this CLI with the official snow (`snowflake-cli` 3.34.0) on the
Snowflake account you provide (see [What it needs](#what-it-needs)), as [ADR 0002](../docs/adr/0002-parallel-partitions-and-streaming.md)
Decision 5 describes. It runs by hand; it is **not** part of CI, which has no credentials. Paste
the Markdown table it prints into PRs that add or change a command, an option or performance.
With `WRITE_RESULTS=1` it also writes `bench/results.json`, from which the README command matrix
is generated (see [Results file](#results-file)).

## What it measures

Ported commands (the command-path column is what the README matrix keys on):

| Scenario | Command | Compared with snow |
|---|---|---|
| `connection-list` | `connection list` (a one-connection config, no network) | yes |
| `connection-test` | `connection test -x` (signs in to the sandbox) | yes |
| `connection-test-diag` | `connection test -x --enable-diag --print-diag` (sandbox sign-in plus the connectivity probes; report written to a temp dir) | yes |
| `connection-test-password` | `connection test -x` with `SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE` and the password user of `scripts/sandbox/0005-connector-protocol.sql` (`SNOWFLAKE_TEST_PASSWORD_USER`, `SNOWFLAKE_TEST_PASSWORD`; the password only travels as `SNOWFLAKE_PASSWORD`). Skipped until those variables are set | yes |
| `connection-add` | `connection add -n … --no-interactive` (config restored before each run) | yes |
| `connection-remove` | `connection remove` (config restored before each run) | yes |
| `connection-set-default` | `connection set-default` (config restored before each run) | yes |
| `connection-generate-jwt` | `connection generate-jwt -x` (offline, with the sandbox key) | yes |
| `connection-generate-workload-identity-token` | `connection generate-workload-identity-token -x --workload-identity-provider OIDC --token …` (offline, an unsigned token) | yes |
| `root-info`, `root-structure` | the root options `--info` and `--structure` (offline) | yes |

`sql` (`snow sql -x -q … --format …`, both CLIs):

| Scenario | Query | Format | Compared with snow |
|---|---|---|---|
| `trivial-json` | `SELECT CURRENT_ROLE()` | JSON | yes |
| `100k-csv`, `100k-json` | 100k generator rows | CSV, JSON | yes |
| `1m-csv`, `1m-json` | 1M generator rows | CSV, JSON | yes |
| `4m-csv`, `10m-csv` | 4M and 10M generator rows | CSV | no (memory scaling only) |
| `multi-small-json` | 20 statements: `USE SCHEMA INFORMATION_SCHEMA;` then 19 × `SELECT <i> AS n;` | JSON | yes |
| `multi-2x100k-csv` | two 100k-row generator queries in one run | CSV | yes |
| `templated-json` | `SELECT <% n %> AS n` with `-D n=1` | JSON | yes |
| `templated-jinja-json` | `{% for i in range(3) %}SELECT {{ i }} + {{ n }} AS n;{% endfor %}` with `-D n=1 --enable-templating JINJA` | JSON | yes |
| `templated-project-json` | `SELECT <% ctx.env.n %> AS n, <% ctx.env.m %> AS m` with `--project` (a `snowflake.yml` whose `m` refers to `n`) and `--env n=2` | JSON | yes |
| `templating-none-json` | `multi-small-json`'s 20 statements with `--enable-templating NONE` | JSON | yes |
| `single-transaction-json` | `SELECT 1 AS a; SELECT 2 AS b` with `--single-transaction` | JSON | yes |
| `put-small-json` | `PUT` of 20 small CSV files (wildcard, `OVERWRITE=TRUE`) to a random user-stage prefix | JSON | yes |
| `put-100mb-json` | `PUT` of one 100 MB file of random bytes (`AUTO_COMPRESS=FALSE`: multipart upload) | JSON | yes |
| `get-small-json` | `GET` of those 20 files | JSON | yes |
| `get-100mb-json` | `GET` of the 100 MB file (ranged parts) | JSON | yes |
| `secondary-roles-json` | `SELECT CURRENT_ROLE()` with `--secondary-roles NONE` | JSON | yes |
| `source-json` | `!source` of a file holding `SELECT 1 AS a;` | JSON | yes |
| `local-only-json` | the same with `--local-only` | JSON | yes |
| `decimal-precision-json` | three NUMBER columns with `--decimal-precision 3` | JSON | yes |
| `json-ext` | 100k rows with an OBJECT and an ARRAY column | JSON_EXT | yes |
| `output-file-csv` | 100k generator rows with `-o output_file=<tmp file>` (removed before each run) | CSV | yes |
| `quiet-csv` | 100k generator rows with `-o quiet=true` | CSV | yes |

`repl-startup` (both CLIs): the interactive session's start-up. `bench/repl_pty.py` runs
`snow sql -x --no-prompt-exit-repl` on a pseudo-terminal, waits for the first prompt (after the
sign-in and `select current_version()`), types `quit` and waits for the exit. Its peak RSS is the
largest process of the run: the CLI, or the small Python driver when that is larger.

The rows are synthetic (`TABLE(GENERATOR(...))` with `SEQ8`, `UNIFORM`, `RANDSTR`, `DATEADD`): no
table is read. For each scenario it records the median wall time over `RUNS` hyperfine runs
(after 1 warm-up) and the peak RSS of one more run. Output goes to `/dev/null`.

This CLI's side is the release build of `snow-rs` (`target/release/snow-rs`).

## Results file

`WRITE_RESULTS=1 bench/run.sh <scenario>…` merges the scenarios that ran into
`bench/results.json` (committed): per scenario its name, the command it measures, the date, the
`snow` version, and the median wall time (seconds) and peak RSS (KiB) of both CLIs. Re-running a
scenario replaces its entry; the others stay. Run it for every scenario a change affects, commit
the file, then regenerate the README matrix: `UPDATE_README=1 cargo test --test command_matrix`.
A ported command needs a scenario in `bench/run.sh`; a scenario without results yet shows as "not benchmarked" in the README matrix. Contributors add the scenario, maintainers run it and commit the results.

The `sql` scenarios in the results file are `trivial-json` (the matrix's representative for
`sql`, so it comes first), `1m-json` (the ADR 0002 target), `multi-small-json`,
`multi-2x100k-csv`, `templated-json`, `templated-jinja-json`, `templated-project-json`,
`templating-none-json`, `single-transaction-json`, `decimal-precision-json`, `json-ext`,
`output-file-csv`, `quiet-csv`, `put-small-json`, `put-100mb-json`, `get-small-json` and
`get-100mb-json`. The other ones are run by
hand when partition download changes.

## What it needs

- `hyperfine` (1.x or 2.x), `python3`, `cargo`.
- Your own Snowflake account and user: the benchmarks (and the live tests under `tests/it/sandbox.rs`
  and `tests/it/connector_sign_in.rs`) read it from the environment and skip when it is not set. Use a
  throwaway account or user: they run synthetic queries and `PUT`/`GET` of synthetic files only. The
  variables:
  - `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY_B64` (base64 of an unencrypted
    PKCS#8 PEM key), required;
  - `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`, optional.

Both CLIs use a temporary connection (`-x`) built from those variables, with key-pair JWT and an
empty `SNOWFLAKE_HOME`. The key is written to a `0600` temp file that is deleted on exit. The
script never prints the key, the account or any row.

## How to run it

```sh
bench/run.sh                      # every scenario (about 10 minutes)
bench/run.sh trivial-json 1m-csv  # only these
WRITE_RESULTS=1 bench/run.sh connection-list  # also update bench/results.json
RUNS=10 bench/run.sh              # more runs per command (default 5)
SNOW_VENV=~/.venvs/snow bench/run.sh  # reuse a venv with snowflake-cli==3.34.0
NO_SNOW=1 bench/run.sh            # this CLI only
```

Without `SNOW_VENV` the script creates a throwaway venv and installs `snowflake-cli==3.34.0` in
it. `SNOW_RS_PARTITION_CONCURRENCY` (1 to 64, default 8) changes how many result partitions this
CLI downloads at once.

Network and warehouse load vary between runs, so compare numbers taken in the same session.
