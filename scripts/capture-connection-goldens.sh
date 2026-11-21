#!/usr/bin/env bash
# Captures the goldens of `snow connection` from the official snow CLI.
#
# Writes tests/golden/connection/{config.toml,list.table,list.json,list.csv,list.plain}: the
# config.toml snow writes for `add dev`, `add full` (every flag, `--default`), plus a hand-written
# `quoted` entry, and what `snow connection list` prints for it. The home path is stored as
# `{HOME}`. No network and no credentials are needed.
#
# Usage: scripts/capture-connection-goldens.sh      (SNOW_VENV=<dir> reuses a venv with snow 3.34.0)
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
venv=${SNOW_VENV:-$work/venv}
if [ ! -x "$venv/bin/snow" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q snowflake-cli==3.34.0
fi
snow=$venv/bin/snow

home=$work/home
mkdir -m 700 "$home"
cd "$home"
export SNOWFLAKE_HOME=$home
# Never inherit credentials or overrides from the caller.
for name in $(env | grep -o '^SNOWFLAKE_[A-Z_]*' || true); do
  [ "$name" = SNOWFLAKE_HOME ] || unset "$name"
done
touch key.p8 token.txt

"$snow" connection add -n dev -a acc -u me --no-interactive >/dev/null
"$snow" connection add -n full -a a2 -u u2 -p pw -r R -w W -d D -s S -h H -P 443 \
  --protocol https -R reg -A snowflake_jwt -W aws -k key.p8 -t token.txt \
  --secondary-roles ALL --server-session-keep-alive --client-store-temporary-credential \
  --default --no-interactive >/dev/null 2>&1
cat >> config.toml <<'TOML'

[connections.quoted]
account = "it's"
user = 'say "hi"'
private_key_file_pwd = "p"
role = "a,b"
TOML

out=$repo_root/tests/golden/connection
mkdir -p "$out"
sed "s#$home#{HOME}#g" config.toml > "$out/config.toml"
for format in table json csv plain; do
  "$snow" connection list --format "$format" | sed "s#$home#{HOME}#g" > "$out/list.$format"
done
echo "Wrote $out"
