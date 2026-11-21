## What changes and why

## How it was verified

## Checklist

- [ ] Tests added or updated; coverage stays ≥ 90%.
- [ ] `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings` and `RUSTFLAGS="-D warnings" cargo test --all-features` pass locally.
- [ ] A new or changed command or option has its scenario in `bench/run.sh` and the README matrix is regenerated (`UPDATE_README=1 cargo test --test it command_matrix`).
- [ ] No secrets, account names or private data in the diff.
- [ ] One PR against `main`; I understand that only maintainers merge, after a green `ci`.
