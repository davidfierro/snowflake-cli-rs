#!/usr/bin/env bash
# Captures the golden outputs of the official snow CLI (ADR 0001, Decision 9).
#
# For every case in tests/golden/cases.toml it writes, from the Snowflake sandbox:
#   tests/golden/<case>.json, tests/golden/<case>.csv  snow's stdout (--format json|csv)
#   tests/golden/<case>.sqlapi.json                     the raw SQL API v2 responses
#
# Run by the builder, never by CI. Needs the sandbox env: SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER,
# SNOWFLAKE_ROLE, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_DATABASE, SNOWFLAKE_PRIVATE_KEY_B64.
# The key is written to a 0600 temp file, deleted on exit, and never printed.
# Cases must use synthetic literals only (no tables), so goldens hold no real data.
#
# With --sql it captures the `snow sql` cases of tests/golden/sql/cases.toml instead (ADR 0004,
# Decision 7): snow's stdout, stderr and exit code per format, plus the SQL API exchanges of this
# crate's own request sequence, recorded through a local proxy (scripts/capture_sql_goldens.py).
#
# With --put-get it captures the `PUT`/`GET` cases of scripts/capture_put_get_goldens.py into
# tests/golden/put_get/cases.json (ADR 0005, Decision 7): snow's stdout, stderr and exit code
# for synthetic files moved to and from a random prefix of the user stage, removed afterwards.
#
# With --async it captures the asynchronous statement cases (`;>`) of
# scripts/capture_async_goldens.py into tests/golden/async/cases.json: snow's stdout,
# stderr and exit code, query ids replaced by a fixed token.
#
# Usage: scripts/capture-goldens.sh [--sql | --put-get | --async] [case-name ...]
# SNOW_VENV=<dir> reuses an existing venv with snowflake-cli==3.34.0.
set -euo pipefail

SNOW_VERSION=3.34.0
repo_root=$(cd "$(dirname "$0")/.." && pwd)
sql=""
put_get=""
async=""
if [ "${1:-}" = --sql ]; then
    sql=1
    shift
elif [ "${1:-}" = --put-get ]; then
    put_get=1
    shift
elif [ "${1:-}" = --async ]; then
    async=1
    shift
fi

for var in SNOWFLAKE_ACCOUNT SNOWFLAKE_USER SNOWFLAKE_PRIVATE_KEY_B64; do
    if [ -z "${!var:-}" ]; then
        echo "error: $var is not set" >&2
        exit 1
    fi
done

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

venv=${SNOW_VENV:-$work/venv}
if [ ! -x "$venv/bin/snow" ]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet "snowflake-cli==$SNOW_VERSION"
fi
"$venv/bin/snow" --version | grep -q "$SNOW_VERSION" || {
    echo "error: $venv does not have snowflake-cli $SNOW_VERSION" >&2
    exit 1
}

key_file=$work/key.p8
(umask 077 && printenv SNOWFLAKE_PRIVATE_KEY_B64 | base64 -d > "$key_file")

# An empty SNOWFLAKE_HOME so no user config is read; -x uses SNOWFLAKE_* only.
mkdir -m 700 "$work/home"

export SNOW_BIN="$venv/bin/snow" SNOWFLAKE_HOME="$work/home" SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT
export SNOWFLAKE_PRIVATE_KEY_FILE="$key_file"
if [ -n "$async" ]; then
    "$venv/bin/python" -I "$repo_root/scripts/capture_async_goldens.py" \
        "$repo_root/tests/golden/async" "$@"
elif [ -n "$put_get" ]; then
    "$venv/bin/python" -I "$repo_root/scripts/capture_put_get_goldens.py" \
        "$repo_root/tests/golden/put_get" "$@"
elif [ -n "$sql" ]; then
    cargo build --quiet --manifest-path "$repo_root/Cargo.toml" --bin snow-rs
    "$venv/bin/python" -I "$repo_root/scripts/capture_sql_goldens.py" "$repo_root/tests/golden/sql" \
        "$repo_root/target/debug/snow-rs" "$@"
else
    "$venv/bin/python" -I "$repo_root/scripts/capture_goldens.py" "$repo_root/tests/golden" "$@"
fi
