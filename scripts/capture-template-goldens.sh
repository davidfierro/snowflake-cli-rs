#!/usr/bin/env bash
# Captures the `snow sql` templating goldens from the official CLI (ADR 0006).
#
# For every case in tests/golden/template/cases.toml it runs snow 3.34.0's `snow sql` with
# statement execution replaced by a recorder (scripts/capture_template_goldens.py) and writes
# tests/golden/template/<case>.json. No network, no credentials.
#
# Usage: scripts/capture-template-goldens.sh [case-name ...]
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
"$venv/bin/snow" --version | grep -q "$SNOW_VERSION" || {
    echo "error: $venv does not have snowflake-cli $SNOW_VERSION" >&2
    exit 1
}

"$venv/bin/python" -I "$repo_root/scripts/capture_template_goldens.py" \
    "$repo_root/tests/golden/template" "$@"
