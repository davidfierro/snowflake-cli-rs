#!/usr/bin/env bash
# Captures the statement-splitter goldens from the pinned connector (ADR 0004, Decision 7).
#
# For every case in tests/golden/split/cases.toml it runs snowflake-connector-python's
# split_statements (the version snowflake-cli 3.34.0 resolves) with remove_comments true and
# false and writes tests/golden/split/<case>.json. No network, no credentials.
#
# Usage: scripts/capture-split-goldens.sh
# SNOW_VENV=<dir> reuses an existing venv with snowflake-cli==3.34.0.
set -euo pipefail

SNOW_VERSION=3.34.0
repo_root=$(cd "$(dirname "$0")/.." && pwd)

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

venv=${SNOW_VENV:-$work/venv}
if [ ! -x "$venv/bin/snow" ]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet "snowflake-cli==$SNOW_VERSION"
fi

"$venv/bin/python" -I - "$repo_root/tests/golden/split" <<'PY'
import io, json, os, sys, tomllib
from importlib.metadata import version
from snowflake.connector.util_text import split_statements

out_dir = sys.argv[1]
with open(os.path.join(out_dir, "cases.toml"), "rb") as f:
    cases = tomllib.load(f)["case"]
for case in cases:
    record = {"connector": version("snowflake-connector-python"), "text": case["text"]}
    for remove in (True, False):
        pieces = split_statements(io.StringIO(case["text"]), remove_comments=remove)
        record["remove_comments" if remove else "keep_comments"] = [
            [text, flag] for text, flag in pieces
        ]
    with open(os.path.join(out_dir, case["name"] + ".json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("captured", case["name"], file=sys.stderr)
PY
