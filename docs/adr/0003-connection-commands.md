# ADR 0003: `snow connection` commands: config writer, crates and deviations from snow

- **Status:** Accepted (on merge)
- **Date:** 2026-11-20
- **Reference implementation:** Snowflake CLI `snow` **3.34.0**, as in [ADR 0001](0001-stage-0-foundation.md)

## Context

Stage 1 adds the first command group, `snow connection add|list|remove|set-default|test|generate-jwt`.
It is the first code that writes config files, so it needs a TOML-preserving editor, a terminal
prompt and a decision on each place where the brief and snow 3.34.0 disagree.

## Decision

### Crates

| Crate | Why | Alternatives |
|---|---|---|
| `toml_edit` | Edits `config.toml` / `connections.toml` keeping comments, key order and formatting. The `toml` crate (already used for reading) rewrites the whole file. | Hand-written line editor: fragile with quoting, dotted keys and inline tables. |
| `rpassword` | Reads the `add` password and the key passphrase without echo. | `termios` by hand: platform-specific code to maintain. |

Both pass `cargo deny` (advisories, bans, licenses, sources) with the existing configuration.

### Config writer (`config::writer`)

- Target file as snow: `connections.toml` if it exists, else `config.toml`. `default_connection_name`
  always goes in `config.toml`.
- Atomic: a temp file in the target's directory, then a rename. New files are 0600, an existing file
  keeps its mode. A symlinked file is edited in place.
- Each write goes to a unique, unpredictable temp name (`.<name>.<random>.tmp`), created
  exclusively with mode 0600, and the temp file is removed if the write fails. A leftover from a
  crash never blocks later writes.
- `remove` of the default connection removes the entry and `default_connection_name` in one write
  when both are in `config.toml`; with a `connections.toml` they are two files, so two writes (the
  default first, as snow does). Like snow, the default is the env-aware one
  (`SNOWFLAKE_DEFAULT_CONNECTION_NAME` wins over the file), checked against snow 3.34.0.
- Ctrl-D at a prompt prints `Aborted.` on stderr and exits 1, like snow (`typer.Abort`). On a
  hidden prompt (password, passphrase) `rpassword` returns an empty answer for Ctrl-D, so there it
  cannot be told from Enter.
- A new `config.toml` starts with snow's defaults (`[cli]`, `[cli.logs]`), as snow writes it.
- Unlike snow (tomlkit rewrites the file), an edit leaves every byte outside the edited entry
  untouched: `account="q"` stays `account="q"`. A comment paragraph separated from a removed entry
  by a blank line goes to the next entry; a comment directly above it goes with it.
- Reading still goes through `ConfigSource::load`, so the permission checks (error for default
  files readable by others, warning for `--config-file`) are the stage 0 ones.

### Where this port deliberately differs from snow 3.34.0

| Case | snow 3.34.0 | This port | Why |
|---|---|---|---|
| `add` without a connection name and no prompting | Writes a connection named `None`, exit 0 | Usage error, exit 2 | The brief requires it; `None` is a bug nobody relies on. |
| `list --all` | Legacy config provider ignores the flag; env-only connections show only with `SNOWFLAKE_CLI_CONFIG_V2_ENABLED=1` | Always includes `SNOWFLAKE_CONNECTIONS_<NAME>_*`-only connections | The brief requires it; it is what snow prints with the V2 provider. |
| `generate-jwt` | Ignores generic `SNOWFLAKE_USER` / `_ACCOUNT` / `_PRIVATE_KEY_FILE` variables | Uses the same resolution as `test` (they apply) | Same command family, one resolution; more lenient only. |
| First run without `config.toml` | Every command, even `list`, creates a default `config.toml` | Only commands that write create it | Read-only commands should not write. |
| Invalid `--port` | click panel `Invalid value for '-P' / '--port': 'abc' is not a valid integer.` | clap's message, exit 2 in both | Argument-parser text is not part of the contract. |
| Passphrase prompt of `generate-jwt` | Prompts when the key is encrypted | Same, only on a terminal; without one, the stage 0 error asks for `PRIVATE_KEY_PASSPHRASE` | The brief: never prompt without a terminal. |
| Spaces in the `add` password prompt | Trims every prompted answer, the password too | The password is stored exactly as typed (the key passphrase prompt likewise) | A secret with leading or trailing spaces would silently change. Other answers are trimmed as snow does. |
| `test` | `USE ROLE/DATABASE/SCHEMA/WAREHOUSE` in one session | One `SELECT 1` carrying role, database, schema and warehouse | The SQL API has no session (ADR 0001, Decision 1); the server rejects unknown objects. |

Output of `list` and `test` (all four formats), `add`, `remove` and `set-default` messages and
their error panels are byte-identical to snow's: goldens in `tests/golden/connection/` (captured by
`scripts/capture-connection-goldens.sh`) and `test` against the sandbox.

### Output and warnings

`output::result::CommandResult` (`Message`, `Object`, `Collection`) mirrors snow's
`MessageResult`, `ObjectResult` and `CollectionResult`. Warnings snow prints through its console
(the plain-password warning, "Reading connections from …") go to **stdout**, ahead of the result,
and are muted for JSON/CSV (the password warning is not muted, as in snow).

## Consequences

- Passwords given to `add` are stored in plain text, as in snow. `ConnectionArgs` holds the
  password as a `Secret`, so `Debug` output and logs never show it.
- `connection test --enable-diag/--print-diag` and `generate-workload-identity-token` are not
  implemented; clap rejects them with exit 2.
- Terminal width for TABLE folding comes from `COLUMNS` (no platform dependency); without it,
  columns take their natural width.
