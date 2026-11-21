#!/usr/bin/env bash
# Captures the `!source`/`!load` goldens from the pinned snow.
#
# For every case in tests/golden/source/cases.toml it runs snow's own statement reader
# (`query_reader`/`files_reader` and `compile_statements`, as `SqlManager.execute` calls them)
# and writes tests/golden/source/<case>.json: the statements to run and the error lines snow
# prints. The fixture directory is `<root>` in the paths. No network, no credentials.
#
# Usage: scripts/capture-source-goldens.sh
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

cd "$repo_root/tests/golden/source"
"$venv/bin/python" -I - "$PWD" <<'PY'
import json, os, sys, tomllib
from functools import partial
from snowflake.cli._plugins.sql.snowsql_templating import transpile_snowsql_templates
from snowflake.cli._plugins.sql.statement_reader import (
    compile_statements, files_reader, query_reader,
)
from snowflake.cli.api.rendering.sql_templates import snowflake_sql_jinja_render
from snowflake.cli.api.secure_path import SecurePath
from snowflake.cli.api.rendering.sql_templates import SQLTemplateSyntaxConfig

root = sys.argv[1]
with open("cases.toml", "rb") as f:
    cases = tomllib.load(f)["case"]
for case in cases:
    data = case.get("variables", {})
    operators = [
        transpile_snowsql_templates,
        partial(
            snowflake_sql_jinja_render,
            template_syntax_config=SQLTemplateSyntaxConfig(
                enable_legacy_syntax=True,
                enable_standard_syntax=True,
                enable_jinja_syntax=False,
            ),
            data=data,
        ),
    ]
    remove_comments = not case.get("retain_comments", False)
    local_only = case.get("local_only", False)
    if "file" in case:
        reader = files_reader(
            [SecurePath(case["file"])], operators, remove_comments, None, local_only
        )
    else:
        reader = query_reader(case["text"], operators, remove_comments, None, local_only)
    errors, _, compiled = compile_statements(reader)
    record = {
        "snow": "3.34.0",
        "statements": [c.statement for c in compiled],
        "errors": [e.replace(root, "<root>") for e in errors],
    }
    with open(case["name"] + ".json", "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("captured", case["name"], file=sys.stderr)
PY
