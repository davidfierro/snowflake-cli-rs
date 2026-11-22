# snowflake-cli-rs

A Rust port of the [Snowflake CLI](https://github.com/snowflakedb/snowflake-cli) (`snow`): a
single, fast native binary. The binary is `snow-rs` (crate `snowflake-cli-rs`), so it can sit on
the same `PATH` as the official `snow`.

> Not affiliated with or endorsed by Snowflake Inc. "Snowflake" is a trademark of Snowflake Inc.

## Status

Early: `snow connection` and `snow sql` are ported; other commands are not yet. The
[command matrix](#command-matrix-vs-the-official-snow) below lists every command and option of the
official `snow`, which are ported, and how this CLI compares on time and memory.

## Install

Prebuilt binaries cover Linux (x86_64, aarch64), macOS (Intel, Apple Silicon) and Windows (x86_64).
Each channel installs the same `snow-rs` binary.

Installer script (from the latest [GitHub Release](https://github.com/davidfierro/snowflake-cli-rs/releases)):

```sh
# Linux and macOS
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/davidfierro/snowflake-cli-rs/releases/latest/download/snowflake-cli-rs-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/davidfierro/snowflake-cli-rs/releases/latest/download/snowflake-cli-rs-installer.ps1 | iex"
```

From PyPI, into an isolated environment:

```sh
pipx install snowflake-cli-rs
# or
uv tool install snowflake-cli-rs
```

From crates.io:

```sh
cargo binstall snowflake-cli-rs   # downloads the prebuilt binary
cargo install snowflake-cli-rs    # compiles it
```

Or build from source (the toolchain is pinned in `rust-toolchain.toml`):

```sh
git clone https://github.com/davidfierro/snowflake-cli-rs
cd snowflake-cli-rs
cargo build --release   # the binary is target/release/snow-rs
```

## Usage

`snow-rs` reads the same config files as `snow` (`~/.snowflake/config.toml`, `connections.toml`)
and the same `SNOWFLAKE_*` variables, and takes the same commands and options; only the
executable name differs.

```sh
snow-rs connection list
snow-rs connection test -c my_connection
snow-rs sql -c my_connection -q "select current_version()" --format json
snow-rs --help
```

## Known deviations from `snow` sql

`snow sql` runs over the SQL API, which has no session, so every statement of one run goes out
as one multi-statement request ([ADR 0004](docs/adr/0004-sql-multi-statement-execution.md)). A
run with a `PUT` or `GET` signs in with the connector protocol instead and runs its statements one
by one on that session, as `snow` does ([ADR 0005](docs/adr/0005-connector-protocol-transport.md)).
So does a run with an asynchronous statement (`;>`): it is submitted without waiting, its query
id is printed as `snow` prints it, and the session is left open at the end while it still runs.
The final stdout, stderr and exit code are `snow`'s, except:

- An execution error (for example `1/0`) in the middle of a run of several statements has no
  sqlState in the error panel: `100051: <query id>: Division by zero` where `snow` prints
  `100051 (22012): …`. Compilation errors match exactly.
- Output starts when the whole run has finished on the server; `snow` prints each result as its
  statement ends.
- With no `-q`, `-f` or `-i`, piped input is run as the query. `snow` 3.34.0 reads it but then
  starts its interactive session anyway.
- `!source` and `!load` inline a file or an `https://` URL, recursively, as `snow` does: paths
  are relative to the working directory, a cycle, more than 32 levels or 32 inclusions per
  input, and every other problem are reported before anything runs. `http://` is refused, as in
  `snow` 3.34.0. `--local-only` (also env `SNOWFLAKE_CLI_SQL_LOCAL_ONLY`, config
  `cli.sql_local_only`) refuses URLs. A directive must end its line (a line starting with `!` is
  one statement).
- The interactive session (`snow sql` with no `-q`, `-f`, `-i` or piped input) always runs on
  a connector session, so `USE`, `SET` and temporary objects last between inputs. Its prompt,
  `--prompt-format` (also `cli.prompt_format`), multi-line input, history (`repl_history` next
  to the config file, in the same format as `snow`'s, so both share it), `exit`/`quit`, Ctrl-D,
  `--no-prompt-exit-repl` and the `!` commands (`!set`, `!spool`, `!edit`, `!queries`,
  `!result`, `!abort`, `!rehash`) behave as in `snow`. The `!` commands also work in `-q`, `-f`
  and `-i` runs; `!queries`, `!result` and `!abort` switch such a run to a session. Ctrl-C
  cancels the running statement in Snowflake. The differences: no syntax highlighting and no
  SQL autocompletion (`!rehash` says `Autocomplete is disabled.`); tables appear once complete
  rather than row by row; only the prompt is coloured (in the 256-colour palette, or 24-bit with
  `PROMPT_TOOLKIT_COLOR_DEPTH=DEPTH_24_BIT`), not the banner or messages; and Ctrl-C during the
  sign-in ends the process instead of saying goodbye.
- The `[variables]` of the config files are template variables under `-D` only with
  `SNOWFLAKE_CLI_CONFIG_V2_ENABLED` on, as in `snow` 3.34.0 (its default config provider has no
  such section): the SnowSQL files (`$SNOWFLAKE_HOME/config`, else `/etc/snowsql.cnf`,
  `/etc/snowflake/snowsql.cnf`, `/usr/local/etc/snowsql.cnf`, `~/.snowsql.cnf`,
  `~/.snowsql/config`), merged, then the first `config.toml` found, whose `[variables]` replaces
  theirs. Only the variables follow that flag here; connections are still read as without it.
  A `config.toml` number or boolean is a string here (`7`, `True`), where `snow` keeps its type,
  which only matters in template expressions (`<% n + 1 %>`).
- `PUT`/`GET`: when a file fails to move, the error panel names our cause (`HEAD with url
  https://<host>/<path> failed: HTTP 403`) where `snow` prints a Python exception `repr()`;
  URLs never show their query string (signatures, SAS tokens). `GET` of two stage files with the
  same base name (`a/f.csv`, `b/f.csv`) prints the connector's warning and keeps the file
  written last, as the connector does. Azure and Google Cloud Storage stages are tested against
  mocked storage only.
- Templating (LEGACY, STANDARD, JINJA, `ctx`, `fn`, `--project`, `--env`) uses `minijinja` in
  place of Jinja2 ([ADR 0006](docs/adr/0006-sql-templating-engine.md)). Output and errors
  match `snow` for the cases in `tests/golden/template/`; the known differences are rarer error
  wordings, a few builtin filters and globals, `loop.*` attributes under JINJA, and the
  `snowflake.yml` entity schemas, which are not validated (ADR 0006, Deviations).
- When a variable's value contains `;`, the rendered text is split again as `snow` does and each
  part runs; `snow` then prints only the results counted before rendering, `snow-rs` prints all.
- `--single-transaction` sends `ALTER SESSION SET AUTOCOMMIT = FALSE` as a hidden statement with
  every request instead of connecting with autocommit off. Output matches `snow`, including a
  syntax error inside the transaction (checked against the official CLI).

## Command matrix vs the official `snow`

Which commands and options of the official `snow` are ported, and how this CLI compares on time
and memory. Generated, never edited by hand: from `docs/snow-surface.json` (every visible command
and option of the official snow, regenerated by `scripts/snapshot-snow-surface.sh`), the clap
definition of this CLI, and `bench/results.json` (written by `bench/run.sh`, see
[bench/README.md](bench/README.md)). CI fails when it is out of date; refresh it with
`UPDATE_README=1 cargo test --test it command_matrix`. Options are compared by name; positional
arguments are not counted.

<!-- command-matrix:start -->

**Commands ported: 8/190.** Options ported per ported command: `connection add` 5/5, `connection generate-jwt` 0/0, `connection generate-workload-identity-token` 0/0, `connection list` 1/1, `connection remove` 0/0, `connection set-default` 0/0, `connection test` 1/1, `sql` 13/13.

### `app`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `app bundle` | not ported | 0/5 |  |  |  |
| `app deploy` | not ported | 0/14 |  |  |  |
| `app events` | not ported | 0/20 |  |  |  |
| `app open` | not ported | 0/9 |  |  |  |
| `app publish` | not ported | 0/12 |  |  |  |
| `app release-channel add-accounts` | not ported | 0/5 |  |  |  |
| `app release-channel add-version` | not ported | 0/4 |  |  |  |
| `app release-channel list` | not ported | 0/4 |  |  |  |
| `app release-channel remove-accounts` | not ported | 0/5 |  |  |  |
| `app release-channel remove-version` | not ported | 0/4 |  |  |  |
| `app release-channel set-accounts` | not ported | 0/3 |  |  |  |
| `app release-directive add-accounts` | not ported | 0/6 |  |  |  |
| `app release-directive list` | not ported | 0/6 |  |  |  |
| `app release-directive remove-accounts` | not ported | 0/6 |  |  |  |
| `app release-directive set` | not ported | 0/7 |  |  |  |
| `app release-directive unset` | not ported | 0/5 |  |  |  |
| `app run` | not ported | 0/10 |  |  |  |
| `app setup` | not ported | 0/3 |  |  |  |
| `app teardown` | not ported | 0/9 |  |  |  |
| `app validate` | not ported | 0/6 |  |  |  |
| `app version create` | not ported | 0/10 |  |  |  |
| `app version drop` | not ported | 0/6 |  |  |  |
| `app version list` | not ported | 0/4 |  |  |  |

### `auth`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `auth oidc read-token` | not ported | 0/1 |  |  |  |

### `bundle`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `bundle alter` | not ported | 0/2 |  |  |  |
| `bundle cancel` | not ported | 0/0 |  |  |  |
| `bundle create` | not ported | 0/5 |  |  |  |
| `bundle delete` | not ported | 0/1 |  |  |  |
| `bundle execute` | not ported | 0/3 |  |  |  |
| `bundle history` | not ported | 0/12 |  |  |  |
| `bundle list` | not ported | 0/3 |  |  |  |
| `bundle status` | not ported | 0/0 |  |  |  |

### `connection`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `connection add` | ported | 5/5 |  | 600× faster (3 ms vs 1.55 s) | 12× less (13 MiB vs 147 MiB) |
| `connection generate-jwt` | ported | 0/0 |  | 1541× faster (3 ms vs 4.74 s) | 13× less (13 MiB vs 165 MiB) |
| `connection generate-workload-identity-token` | ported | 0/0 |  | 3192× faster (1 ms vs 2.00 s) | 12× less (13 MiB vs 148 MiB) |
| `connection list` | ported | 1/1 |  | 1129× faster (1 ms vs 1.56 s) | 11× less (13 MiB vs 146 MiB) |
| `connection remove` | ported | 0/0 |  | 674× faster (2 ms vs 1.55 s) | 12× less (13 MiB vs 147 MiB) |
| `connection set-default` | ported | 0/0 |  | 611× faster (3 ms vs 1.54 s) | 11× less (13 MiB vs 146 MiB) |
| `connection test` | ported | 1/1 |  | 23× faster (188 ms vs 4.42 s) | 13× less (12 MiB vs 164 MiB) |

### `cortex`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `cortex complete` | not ported | 0/3 |  |  |  |
| `cortex extract-answer` | not ported | 0/1 |  |  |  |
| `cortex sentiment` | not ported | 0/1 |  |  |  |
| `cortex summarize` | not ported | 0/1 |  |  |  |
| `cortex translate` | not ported | 0/3 |  |  |  |

### `custom-image`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `custom-image validate` | not ported | 0/1 |  |  |  |

### `dbt`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `dbt copy` | not ported | 0/5 |  |  |  |
| `dbt deploy` | not ported | 0/16 |  |  |  |
| `dbt describe` | not ported | 0/0 |  |  |  |
| `dbt drop` | not ported | 0/1 |  |  |  |
| `dbt execute build` | not ported | 0/0 |  |  |  |
| `dbt execute check` | not ported | 0/0 |  |  |  |
| `dbt execute clean` | not ported | 0/0 |  |  |  |
| `dbt execute clone` | not ported | 0/0 |  |  |  |
| `dbt execute compile` | not ported | 0/0 |  |  |  |
| `dbt execute debug` | not ported | 0/0 |  |  |  |
| `dbt execute deps` | not ported | 0/0 |  |  |  |
| `dbt execute deps_compile` | not ported | 0/0 |  |  |  |
| `dbt execute docs` | not ported | 0/0 |  |  |  |
| `dbt execute list` | not ported | 0/0 |  |  |  |
| `dbt execute ls` | not ported | 0/0 |  |  |  |
| `dbt execute parse` | not ported | 0/0 |  |  |  |
| `dbt execute retry` | not ported | 0/0 |  |  |  |
| `dbt execute run` | not ported | 0/0 |  |  |  |
| `dbt execute run-operation` | not ported | 0/0 |  |  |  |
| `dbt execute seed` | not ported | 0/0 |  |  |  |
| `dbt execute show` | not ported | 0/0 |  |  |  |
| `dbt execute snapshot` | not ported | 0/0 |  |  |  |
| `dbt execute source` | not ported | 0/0 |  |  |  |
| `dbt execute test` | not ported | 0/0 |  |  |  |
| `dbt list` | not ported | 0/3 |  |  |  |

### `dcm`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `dcm create` | not ported | 0/3 |  |  |  |
| `dcm deploy` | not ported | 0/6 |  |  |  |
| `dcm describe` | not ported | 0/2 |  |  |  |
| `dcm drop` | not ported | 0/3 |  |  |  |
| `dcm drop-deployment` | not ported | 0/4 |  |  |  |
| `dcm list` | not ported | 0/5 |  |  |  |
| `dcm list-deployments` | not ported | 0/2 |  |  |  |
| `dcm plan` | not ported | 0/6 |  |  |  |
| `dcm purge` | not ported | 0/6 |  |  |  |

### `feature`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `feature apply` | not ported | 0/4 |  |  |  |
| `feature describe` | not ported | 0/2 |  |  |  |
| `feature ingest` | not ported | 0/3 |  |  |  |
| `feature init` | not ported | 0/3 |  |  |  |
| `feature list` | not ported | 0/2 |  |  |  |
| `feature online-service create` | not ported | 0/4 |  |  |  |
| `feature online-service drop` | not ported | 0/4 |  |  |  |
| `feature online-service status` | not ported | 0/2 |  |  |  |
| `feature plan` | not ported | 0/5 |  |  |  |
| `feature query` | not ported | 0/3 |  |  |  |
| `feature sync` | not ported | 0/5 |  |  |  |

### `feedback`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `feedback` | not ported | 0/5 |  |  |  |

### `git`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `git copy` | not ported | 0/1 |  |  |  |
| `git describe` | not ported | 0/0 |  |  |  |
| `git drop` | not ported | 0/1 |  |  |  |
| `git execute` | not ported | 0/2 |  |  |  |
| `git fetch` | not ported | 0/0 |  |  |  |
| `git list` | not ported | 0/3 |  |  |  |
| `git list-branches` | not ported | 0/1 |  |  |  |
| `git list-files` | not ported | 0/1 |  |  |  |
| `git list-tags` | not ported | 0/1 |  |  |  |
| `git setup` | not ported | 0/0 |  |  |  |

### `helpers`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `helpers check-snowsql-env-vars` | not ported | 0/0 |  |  |  |
| `helpers check-version` | not ported | 0/1 |  |  |  |
| `helpers clean-installer-path` | not ported | 0/1 |  |  |  |
| `helpers detect-encoding` | not ported | 0/0 |  |  |  |
| `helpers generate-project-schema` | not ported | 0/2 |  |  |  |
| `helpers import-snowsql-connections` | not ported | 0/2 |  |  |  |
| `helpers v1-to-v2` | not ported | 0/2 |  |  |  |

### `init`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `init` | not ported | 0/4 |  |  |  |

### `logs`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `logs` | not ported | 0/6 |  |  |  |

### `notebook`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `notebook create` | not ported | 0/1 |  |  |  |
| `notebook deploy` | not ported | 0/4 |  |  |  |
| `notebook execute` | not ported | 0/0 |  |  |  |
| `notebook get-url` | not ported | 0/0 |  |  |  |
| `notebook open` | not ported | 0/0 |  |  |  |

### `object`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `object create` | not ported | 0/3 |  |  |  |
| `object describe` | not ported | 0/0 |  |  |  |
| `object drop` | not ported | 0/1 |  |  |  |
| `object list` | not ported | 0/3 |  |  |  |

### `snowpark`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `snowpark build` | not ported | 0/6 |  |  |  |
| `snowpark deploy` | not ported | 0/5 |  |  |  |
| `snowpark describe` | not ported | 0/0 |  |  |  |
| `snowpark drop` | not ported | 0/1 |  |  |  |
| `snowpark execute` | not ported | 0/0 |  |  |  |
| `snowpark list` | not ported | 0/3 |  |  |  |
| `snowpark package create` | not ported | 0/4 |  |  |  |
| `snowpark package lookup` | not ported | 0/0 |  |  |  |
| `snowpark package upload` | not ported | 0/3 |  |  |  |

### `spcs`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `spcs compute-pool create` | not ported | 0/10 |  |  |  |
| `spcs compute-pool deploy` | not ported | 0/3 |  |  |  |
| `spcs compute-pool describe` | not ported | 0/0 |  |  |  |
| `spcs compute-pool drop` | not ported | 0/1 |  |  |  |
| `spcs compute-pool list` | not ported | 0/2 |  |  |  |
| `spcs compute-pool resume` | not ported | 0/0 |  |  |  |
| `spcs compute-pool set` | not ported | 0/6 |  |  |  |
| `spcs compute-pool status` | not ported | 0/0 |  |  |  |
| `spcs compute-pool stop-all` | not ported | 0/0 |  |  |  |
| `spcs compute-pool suspend` | not ported | 0/0 |  |  |  |
| `spcs compute-pool unset` | not ported | 0/3 |  |  |  |
| `spcs image-registry login` | not ported | 0/1 |  |  |  |
| `spcs image-registry token` | not ported | 0/0 |  |  |  |
| `spcs image-registry url` | not ported | 0/1 |  |  |  |
| `spcs image-repository create` | not ported | 0/2 |  |  |  |
| `spcs image-repository deploy` | not ported | 0/3 |  |  |  |
| `spcs image-repository drop` | not ported | 0/1 |  |  |  |
| `spcs image-repository list` | not ported | 0/3 |  |  |  |
| `spcs image-repository list-images` | not ported | 0/1 |  |  |  |
| `spcs image-repository list-tags` | not ported | 0/1 |  |  |  |
| `spcs image-repository url` | not ported | 0/0 |  |  |  |
| `spcs service create` | not ported | 0/10 |  |  |  |
| `spcs service deploy` | not ported | 0/3 |  |  |  |
| `spcs service describe` | not ported | 0/0 |  |  |  |
| `spcs service drop` | not ported | 0/2 |  |  |  |
| `spcs service events` | not ported | 0/7 |  |  |  |
| `spcs service execute-job` | not ported | 0/7 |  |  |  |
| `spcs service list` | not ported | 0/3 |  |  |  |
| `spcs service list-containers` | not ported | 0/0 |  |  |  |
| `spcs service list-endpoints` | not ported | 0/0 |  |  |  |
| `spcs service list-instances` | not ported | 0/0 |  |  |  |
| `spcs service list-roles` | not ported | 0/0 |  |  |  |
| `spcs service logs` | not ported | 0/6 |  |  |  |
| `spcs service metrics` | not ported | 0/5 |  |  |  |
| `spcs service remote-build` | not ported | 0/10 |  |  |  |
| `spcs service remote-build-history` | not ported | 0/2 |  |  |  |
| `spcs service remote-build-status` | not ported | 0/1 |  |  |  |
| `spcs service resume` | not ported | 0/0 |  |  |  |
| `spcs service set` | not ported | 0/7 |  |  |  |
| `spcs service status` | not ported | 0/0 |  |  |  |
| `spcs service suspend` | not ported | 0/0 |  |  |  |
| `spcs service unset` | not ported | 0/6 |  |  |  |
| `spcs service upgrade` | not ported | 0/1 |  |  |  |

### `sql`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `sql` | ported | 13/13 |  | 27× faster (157 ms vs 4.18 s) | 13× less (13 MiB vs 164 MiB) |

### `stage`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `stage copy` | not ported | 0/5 |  |  |  |
| `stage create` | not ported | 0/2 |  |  |  |
| `stage describe` | not ported | 0/0 |  |  |  |
| `stage drop` | not ported | 0/1 |  |  |  |
| `stage execute` | not ported | 0/2 |  |  |  |
| `stage list` | not ported | 0/3 |  |  |  |
| `stage list-files` | not ported | 0/1 |  |  |  |
| `stage remove` | not ported | 0/0 |  |  |  |

### `streamlit`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `streamlit deploy` | not ported | 0/6 |  |  |  |
| `streamlit describe` | not ported | 0/0 |  |  |  |
| `streamlit drop` | not ported | 0/1 |  |  |  |
| `streamlit execute` | not ported | 0/0 |  |  |  |
| `streamlit get-url` | not ported | 0/1 |  |  |  |
| `streamlit list` | not ported | 0/3 |  |  |  |
| `streamlit logs` | not ported | 0/4 |  |  |  |
| `streamlit share` | not ported | 0/4 |  |  |  |
| `streamlit status` | not ported | 0/0 |  |  |  |

### `upgrade`

| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |
|---|---|---|---|---|---|
| `upgrade` | not ported | 0/2 |  |  |  |

### Authenticators

The `authenticator` values of a connection. "mock-tested only": covered by tests against a mocked server, not yet run against Snowflake. The temporary credential cache (ID, MFA and OAuth tokens) is the connector's file cache on every OS, where `snow` uses the keychain on macOS and Windows (ADR 0005, Decision 3).

| Authenticator | Status |
|---|---|
| `SNOWFLAKE_JWT` | ported |
| `OAUTH` | ported, mock-tested only |
| `PROGRAMMATIC_ACCESS_TOKEN` | ported, mock-tested only |
| `WORKLOAD_IDENTITY` | ported, mock-tested only |
| `SNOWFLAKE (password)` | ported, mock-tested only |
| `SNOWFLAKE with an MFA passcode or Duo push` | ported, mock-tested only |
| `USERNAME_PASSWORD_MFA` | ported, mock-tested only |
| `EXTERNALBROWSER` | ported, mock-tested only |
| `OAUTH_AUTHORIZATION_CODE` | ported, mock-tested only |
| `OAUTH_CLIENT_CREDENTIALS` | ported, mock-tested only |
| `https://<okta_account>.okta.com` | ported, mock-tested only |

### `sql` statements that need a session

The SQL API cannot run them, so a run that has one signs in with the connector protocol and runs every statement on that session (ADR 0005).

| Statement | Status |
|---|---|
| PUT / GET, stage on AWS S3 | ported |
| PUT / GET, stage on Azure | ported, mock-tested only |
| PUT / GET, stage on Google Cloud Storage | ported, mock-tested only |

### Global options

Output, logging and connection options that most commands share, plus the root options. Their status covers the ported commands that take them in snow: `partial (k/n)` means k of n accept the option, and names the ones that do not.

| Option | Status |
|---|---|
| `--account` | ported |
| `--authenticator` | ported |
| `--client-store-temporary-credential` | ported |
| `--config-file` | ported |
| `--connection` | ported |
| `--database` | ported |
| `--debug` | ported |
| `--decimal-precision` | ported |
| `--diag-allowlist-path` | ported |
| `--diag-log-path` | ported |
| `--enable-diag` | ported |
| `--enhanced-exit-codes` | ported |
| `--format` | ported |
| `--host` | ported |
| `--info` | ported |
| `--install-completion` | ported |
| `--mfa-passcode` | ported |
| `--no-auto-upgrade` | ported |
| `--oauth-authorization-url` | ported |
| `--oauth-client-id` | ported |
| `--oauth-client-secret` | ported |
| `--oauth-disable-pkce` | ported |
| `--oauth-enable-refresh-tokens` | ported |
| `--oauth-enable-single-use-refresh-tokens` | ported |
| `--oauth-redirect-uri` | ported |
| `--oauth-scope` | ported |
| `--oauth-token-request-url` | ported |
| `--password` | ported |
| `--port` | ported |
| `--private-key-file` | ported |
| `--protocol` | ported |
| `--role` | ported |
| `--schema` | ported |
| `--secondary-roles` | ported |
| `--server-session-keep-alive` | ported |
| `--show-completion` | ported |
| `--silent` | ported |
| `--structure` | ported |
| `--temporary-connection` | ported |
| `--token` | ported |
| `--token-file-path` | ported |
| `--user` | ported |
| `--verbose` | ported |
| `--version` | ported |
| `--warehouse` | ported |
| `--workload-identity-provider` | ported |

### Benchmark scenarios

| Scenario | Command | snow-rs median | snow median | snow-rs peak RSS | snow peak RSS |
|---|---|---|---|---|---|
| `connection-list` | `connection list` | 1 ms | 1.56 s | 13 MiB | 146 MiB |
| `connection-test` | `connection test` | 188 ms | 4.42 s | 12 MiB | 164 MiB |
| `connection-add` | `connection add` | 3 ms | 1.55 s | 13 MiB | 147 MiB |
| `connection-remove` | `connection remove` | 2 ms | 1.55 s | 13 MiB | 147 MiB |
| `connection-set-default` | `connection set-default` | 3 ms | 1.54 s | 13 MiB | 146 MiB |
| `connection-generate-jwt` | `connection generate-jwt` | 3 ms | 4.74 s | 13 MiB | 165 MiB |
| `trivial-json` | `sql` | 157 ms | 4.18 s | 13 MiB | 164 MiB |
| `1m-json` | `sql` | 6.44 s | 22.93 s | 205 MiB | 413 MiB |
| `multi-small-json` | `sql` | 1.34 s | 5.44 s | 20 MiB | 166 MiB |
| `multi-2x100k-csv` | `sql` | 2.55 s | 7.05 s | 39 MiB | 200 MiB |
| `templated-json` | `sql` | 160 ms | 4.32 s | 13 MiB | 164 MiB |
| `single-transaction-json` | `sql` | 649 ms | 4.55 s | 13 MiB | 166 MiB |
| `connection-test-diag` | `connection test` | 3.22 s | 10.15 s | 13 MiB | 168 MiB |
| `root-info` | `--info` | 2 ms | 1.23 s | 12 MiB | 127 MiB |
| `root-structure` | `--structure` | 1 ms | 1.69 s | 12 MiB | 152 MiB |
| `decimal-precision-json` | `sql` | 173 ms | 4.17 s | 12 MiB | 165 MiB |
| `source-json` | `sql` | 165 ms | 4.23 s | 12 MiB | 164 MiB |
| `local-only-json` | `sql` | 168 ms | 4.24 s | 12 MiB | 164 MiB |
| `json-ext` | `sql` | 1.71 s | 11.97 s | 31 MiB | 193 MiB |
| `output-file-csv` | `sql` | 1.21 s | 7.10 s | 33 MiB | 195 MiB |
| `quiet-csv` | `sql` | 1.24 s | 7.10 s | 32 MiB | 189 MiB |
| `connection-generate-workload-identity-token` | `connection generate-workload-identity-token` | 1 ms | 2.00 s | 13 MiB | 148 MiB |
| `secondary-roles-json` | `sql` | 526 ms | 4.23 s | 13 MiB | 164 MiB |
| `templated-jinja-json` | `sql` | 571 ms | 4.36 s | 13 MiB | 163 MiB |
| `templated-project-json` | `sql` | 163 ms | 4.51 s | 13 MiB | 164 MiB |
| `templating-none-json` | `sql` | 1.70 s | 6.61 s | 18 MiB | 164 MiB |
| `put-small-json` | `sql` | 774 ms | 4.73 s | 16 MiB | 184 MiB |
| `put-100mb-json` | `sql` | 1.84 s | 5.82 s | 13 MiB | 262 MiB |
| `get-small-json` | `sql` | 1.03 s | 4.95 s | 19 MiB | 190 MiB |
| `get-100mb-json` | `sql` | 3.40 s | 7.27 s | 16 MiB | 306 MiB |
| `repl-startup` | `sql` | 393 ms | 5.44 s | 13 MiB | 166 MiB |

Commands and options: snow 3.34.0. Benchmarks: 2026-11-21 against snow 3.34.0.
<!-- command-matrix:end -->

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Architecture decisions (transport, module boundaries,
crates, testing) are in [docs/adr](docs/adr/README.md). Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md); report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for the credit to the official Snowflake CLI, whose
help texts and output formats this port reproduces.
