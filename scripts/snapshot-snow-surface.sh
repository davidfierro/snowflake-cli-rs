#!/usr/bin/env bash
# Regenerates docs/snow-surface.json from the official snow (the snapshot the README command
# matrix compares against). A snow version bump is: change SNOW_VERSION here (and in
# bench/run.sh), run this, review the diff, then `UPDATE_README=1 cargo test --test command_matrix`.
#
# Usage: scripts/snapshot-snow-surface.sh
#   SNOW_VENV=<dir>  reuse a venv that has snowflake-cli==$SNOW_VERSION
# Needs python3. It runs `snow --structure` with an empty HOME: no connection, no network.
set -euo pipefail

SNOW_VERSION=3.34.0
repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

venv=${SNOW_VENV:-$work/venv}
if [ ! -x "$venv/bin/snow" ]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet "snowflake-cli==$SNOW_VERSION"
fi
"$venv/bin/snow" --version | grep -q "$SNOW_VERSION" || {
    echo "error: $venv does not have snowflake-cli $SNOW_VERSION" >&2
    exit 1
}
python3 -I "$repo_root/scripts/snapshot_snow_surface.py" "$venv/bin/snow" "$SNOW_VERSION" \
    > "$work/snow-surface.json"
mv "$work/snow-surface.json" "$repo_root/docs/snow-surface.json"
echo "wrote docs/snow-surface.json" >&2
