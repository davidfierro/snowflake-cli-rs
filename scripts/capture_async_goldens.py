"""Captures snow's output for the asynchronous statement goldens (`;>`).

Run through `scripts/capture-goldens.sh --async`. Every case runs `snow sql -x` with its query,
files or stdin in each format against the sandbox. Statements are synthetic literals only. Query
ids are replaced by a fixed token of the same length; tests/it/sql_async.rs replays the cases
against a mocked connector server.

Usage: capture_async_goldens.py <out-dir> [case-name ...]
"""

import json
import os
import re
import subprocess
import sys
import tempfile

FORMATS = ["TABLE", "PLAIN", "JSON", "CSV"]
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ID_TOKEN = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Keys: query (-q), files (contents, one -f each), stdin (-i), args (extra arguments).
CASES = [
    {"name": "alone", "query": "select 1 as a;>"},
    {"name": "then_sync", "query": "select 1 as a;> select 2 as b;"},
    {"name": "between_sync", "query": "select 1 as a; select 2 as b;> select 3 as c;"},
    {"name": "after_one_sync", "query": "select 1 as a; select 2 as b;>"},
    {"name": "last_of_three", "query": "select 1 as a; select 2 as b; select 3 as c;>"},
    {"name": "first_of_three", "query": "select 1 as a;> select 2 as b; select 3 as c"},
    {"name": "two_in_a_row", "query": "select 1 as a;>\nselect 2 as b ;>\nselect 3 as c;"},
    {"name": "not_checked", "query": "selec 1;> select 2 as b"},
    {"name": "files", "files": ["select 1 as a;>\nselect 2 as b;\n", "select 3 as c;>\n"]},
    {"name": "stdin", "stdin": "select 1 as a;>\nselect 2 as b;\n"},
    {"name": "single_transaction", "query": "select 1 as a;> select 2 as b",
     "args": ["--single-transaction"]},
    {"name": "retained_comment", "query": "-- lead\nselect 1 as a;>\nselect 2 as b;",
     "args": ["--retain-comments"]},
    {"name": "silent", "query": "select 1 as a;> select 2 as b; select 3 as c",
     "args": ["--silent"]},
]


def main():
    out_dir = sys.argv[1]
    only = set(sys.argv[2:])
    snow = os.environ["SNOW_BIN"]
    path = os.path.join(out_dir, "cases.json")
    existing = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            existing = {c["name"]: c for c in json.load(f)}
    results = []
    with tempfile.TemporaryDirectory() as work:
        for case in CASES:
            if only and case["name"] not in only:
                if case["name"] in existing:
                    results.append(existing[case["name"]])
                continue
            args = []
            if "query" in case:
                args += ["-q", case["query"]]
            for i, text in enumerate(case.get("files", [])):
                file = os.path.join(work, f"input{i + 1}.sql")
                with open(file, "w", encoding="utf-8") as f:
                    f.write(text)
                args += ["-f", file]
            if "stdin" in case:
                args.append("-i")
            args += case.get("args", [])
            runs = {}
            for fmt in FORMATS:
                proc = subprocess.run(
                    [snow, "sql", "-x", *args, "--format", fmt],
                    input=case.get("stdin", ""), capture_output=True, text=True,
                    env=dict(os.environ, COLUMNS="80"),
                )

                def clean(text):
                    return UUID.sub(ID_TOKEN, text.replace(work, "{WORK}"))

                runs[fmt] = {"stdout": clean(proc.stdout), "stderr": clean(proc.stderr),
                             "exit": proc.returncode}
            record = {k: v for k, v in case.items()}
            record["runs"] = runs
            results.append(record)
            print(case["name"], file=sys.stderr)
    for name in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_ROLE",
                 "SNOWFLAKE_DATABASE", "SNOWFLAKE_WAREHOUSE"):
        value = os.environ.get(name)
        if value and value.lower() in json.dumps(results).lower():
            sys.exit(f"error: {name} would be written to the goldens")
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
