# Contributing

Thank you for helping. This file is the single source of the development rules, for people and for
coding agents (`CLAUDE.md` imports it). CI enforces them.

## Licence

The project is licensed under [Apache-2.0](LICENSE). There is no CLA and no DCO: as the licence says
(section 5), a contribution you submit is under Apache-2.0 unless you state otherwise.

## Build and test

```sh
cargo build --release   # target/release/snow-rs
cargo test --all-features
```

The Rust toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use. Bump it in
its own PR.

## Rules

- Every change ships with tests. Line coverage must stay **≥ 90%** (`cargo llvm-cov`). No coverage
  exclusions; if one is ever needed, justify it in the PR.
- `cargo fmt`, `cargo clippy` (default lints, no `pedantic`) and compiler warnings are all errors.
- No `#[allow(...)]` to silence a lint without a comment justifying it.
- Integration tests go in `tests/it/<name>.rs` and are declared in `tests/it/main.rs` (one test
  binary, to keep `target/` small); never add top-level files in `tests/`. Run one module with
  `cargo test --test it <name>::`.
- Architecture decisions are in [docs/adr](docs/adr/README.md); a change that contradicts one
  amends it in the same PR.

## Commands, options and the README matrix

The README command matrix is generated from `docs/snow-surface.json` (every visible command and
option of the official `snow`), the clap definition of this CLI and `bench/results.json`.

A PR that adds or changes a command or option:

1. adds or updates the scenario in `bench/run.sh`;
2. regenerates the matrix with `UPDATE_README=1 cargo test --test it command_matrix` and commits
   `README.md`.

A ported command with no scenario in `bench/run.sh` fails `cargo test`. A scenario that has no
results yet is fine: the matrix shows the command as "not benchmarked". You do not need a Snowflake
account for this. A maintainer runs the benchmark (`WRITE_RESULTS=1 bench/run.sh <scenario>…`, see
[bench/README.md](bench/README.md)) and commits `bench/results.json`.

A new `snow` version means running `scripts/snapshot-snow-surface.sh` and reviewing the snapshot
diff.

## Live tests and benchmarks: bring your own Snowflake account

The tests that talk to Snowflake (`tests/it/sandbox.rs`, `tests/it/connector_sign_in.rs`) and the
benchmarks (`bench/run.sh`) need an account you control. They skip, with a printed reason, when
their variables are unset, so a plain `cargo test` needs nothing. CI has no credentials.

Set up a throwaway user with key-pair authentication, then export `SNOWFLAKE_ACCOUNT`,
`SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY_B64` (base64 of an unencrypted PKCS#8 PEM key) and,
optionally, `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`. The password, PAT and
connector-protocol tests also read `SNOWFLAKE_TEST_PASSWORD_USER`, `SNOWFLAKE_TEST_PASSWORD` and
`SNOWFLAKE_TEST_PAT`, which `scripts/sandbox/0005-connector-protocol.sql` creates (read its header and
[ADR 0005](docs/adr/0005-connector-protocol-transport.md), Decision 8). Details of the benchmark
variables are in [bench/README.md](bench/README.md).

## Reproduce each CI job locally

| CI job | Command |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --all-targets --all-features -- -D warnings` |
| `test` | `RUSTFLAGS="-D warnings" cargo test --all-features` (CI runs it on Linux, macOS and Windows) |
| `coverage` | `cargo llvm-cov --workspace --all-features --fail-under-lines 90` (needs `cargo install cargo-llvm-cov --locked`) |
| `deny` | `cargo deny check advisories bans licenses sources` (needs `cargo install cargo-deny --locked`) |
| README matrix | `cargo test --test it command_matrix` (rewrite it with `UPDATE_README=1`; part of `cargo test`) |
| benchmarks | `WRITE_RESULTS=1 bench/run.sh <scenario>…` (by hand, your Snowflake account, not in CI) |
| snow snapshot | `scripts/snapshot-snow-surface.sh` (by hand; rewrites `docs/snow-surface.json`) |
| `ci` | Aggregate: passes only if all of the above succeeded. This is the check required on `main`. |

## Pull requests

1. Fork the repository and create a branch (any name).
2. Make small commits with clear messages.
3. Open one PR against `main`, filling in the PR template.
4. Only maintainers merge, and only after a green `ci` check.

## Conduct and security

Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as
[SECURITY.md](SECURITY.md) describes, not in a public issue.
