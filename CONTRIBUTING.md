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
| `naming` | `scripts/check-naming.sh` (its own workflow, not part of `ci`; see [Naming](#naming-branches-commits-and-pr-titles)) |

## Pull requests

1. Create a branch named as below (in a fork, any name works).
2. Make small commits, with subjects in the form below.
3. Open one PR against `main`, with a title in the same form, filling in the PR template.
4. Only maintainers merge, by squash and only after a green `ci` check.

## Naming: branches, commits and PR titles

The `naming` check validates all three on every PR, with `scripts/check-naming.sh`.

**Commit subjects and PR titles** follow
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>[(scope)][!]: <summary>
```

- `type` is one of:

  | Type | Use it for |
  |---|---|
  | `feat` | a new command, option or behaviour a user can see |
  | `fix` | a bug fix |
  | `perf` | a change that only makes something faster or lighter |
  | `refactor` | a code change with no behaviour change |
  | `docs` | documentation only (README, ADRs, comments) |
  | `test` | tests only |
  | `build` | dependencies, the toolchain, `Cargo.toml`, packaging |
  | `ci` | workflows and the checks they run |
  | `chore` | maintenance that fits none of the above |
  | `style` | formatting only |
  | `revert` | reverting an earlier commit |

- `scope` is optional: the area touched, in lowercase kebab-case (`sql`, `connection`, `put-get`).
- `!` marks a breaking change.
- `summary` says what changes, in the imperative, with no final period. The whole line is at most
  100 characters.

Examples: `feat(sql): support --retain-comments`, `fix: keep CRLF in goldens`,
`refactor(connection)!: drop the legacy config path`.

PRs are squash-merged, so the PR title becomes the commit on `main`: it is the one that stays in
the history. Merge commits in a PR branch are not checked.

**Branches** are `<type>/[<ISSUE-KEY>-]<slug>`: one of the types above, then the issue key when
the work has one, then a short lowercase kebab-case slug. Examples: `feat/retain-comments`,
`fix/DFI-174-float-str-repr`. The check skips the branch name of PRs from forks.

Check them before pushing:

```sh
scripts/check-naming.sh branch "$(git branch --show-current)"
scripts/check-naming.sh commits origin/main..HEAD
scripts/check-naming.sh title "feat(sql): support --retain-comments"
```

### Commit messages and PR titles

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
`<type>[(scope)][!]: <summary>`, for example `feat(sql): support --retain-comments` or
`fix: keep CRLF in goldens`. The PR title follows the same form, since it becomes the squash
commit. The CHANGELOG and the next version come from these messages. While we are on 0.x, a
breaking change (`!` or a `BREAKING CHANGE:` footer) bumps the minor version and anything else the
patch; from 1.0, `feat` bumps the minor and a breaking change the major. Other common types:
`docs`, `test`, `refactor`, `perf`, `ci`, `chore`. Nothing lints them; a message that doesn't
follow the form lands under "Other" in the CHANGELOG.

## Releasing

Releases are automated ([ADR 0007](docs/adr/0007-release-pipeline.md)); a maintainer only merges
the release PR.

1. On every push to `main`, `release-plz` opens or updates a PR titled `chore: release vX.Y.Z`,
   with the version bump and the new `CHANGELOG.md` section. Edit the CHANGELOG in that PR if
   needed. `ci` runs on it like on any PR.
2. Merging it publishes the crate to crates.io and pushes the `vX.Y.Z` tag.
3. The tag starts `release.yml` (dist: archives, checksums, installers and the GitHub Release)
   and `pypi.yml` (wheels and sdist to PyPI).

Both tag workflows first check that the tag's commit is on `main` and stop otherwise, so a tag
pushed by hand on an unmerged commit publishes nothing. A tag ruleset on `v*` blocks moving or
deleting a release tag. Never push release tags by hand; release-plz does.

If a job fails after the tag exists for a reason outside the code (a runner, a network or registry
outage, a missing secret), re-run the failed jobs of that workflow run. Don't move or re-push the
tag: a version already on crates.io or PyPI can't be replaced, so a fix that needs a code change
ships as the next version.

`release.yml` is generated: change `dist-workspace.toml` and run `dist generate` (check locally
with `dist plan`), never edit the file by hand. Its `main` check lives in
`.github/release-guard.yml`, which dist injects through `github-build-setup`. Locally, `dist build`,
`maturin build` and `cargo package` reproduce the three channels' builds.

## Conduct and security

Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as
[SECURITY.md](SECURITY.md) describes, not in a public issue.
