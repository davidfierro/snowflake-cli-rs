"""Captures snow's output for the PUT/GET goldens (ADR 0005, Decision 7).

Run through `scripts/capture-goldens.sh --put-get`. Every case runs `snow sql -x -q <sql>` in
each of its formats against the sandbox, with synthetic files in a temporary directory and a
random prefix of the user stage (removed at the end). The data directory and the prefix are
written as `{DATA}` and `{STAGE}`; the tests put their own values back.

Usage: capture_put_get_goldens.py <out-dir> [case-name ...]
"""

import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

# Runs in order: later cases rely on what earlier ones uploaded.
CASES = [
    {"name": "put_wildcard", "sql": "PUT file://{DATA}/f*.csv @~/{STAGE}/",
     "formats": ["TABLE", "JSON", "CSV"], "fresh_stage_per_format": True},
    {"name": "put_existing_skipped", "sql": "PUT file://{DATA}/f*.csv @~/{STAGE}/",
     "formats": ["TABLE", "JSON"]},
    {"name": "put_no_compress_overwrite",
     "sql": "PUT file://{DATA}/f1.csv @~/{STAGE}/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE",
     "formats": ["CSV"]},
    {"name": "put_already_gzip", "sql": "PUT file://{DATA}/g.csv.gz @~/{STAGE}/",
     "formats": ["TABLE"]},
    {"name": "get_files", "sql": "GET @~/{STAGE}/ file://{DATA}/out/ PATTERN='.*f[12][.]csv[.]gz'",
     "formats": ["TABLE", "JSON", "CSV"]},
    {"name": "select_then_put",
     "sql": "SELECT 1 AS a; PUT file://{DATA}/f2.csv @~/{STAGE}/sub/ OVERWRITE=TRUE",
     "formats": ["TABLE", "CSV"]},
    {"name": "error_missing_file", "sql": "PUT file:///nonexistent/x.csv @~/{STAGE}/",
     "formats": ["TABLE"]},
    {"name": "error_directory", "sql": "PUT file:///tmp @~/{STAGE}/", "formats": ["TABLE"]},
    {"name": "error_unsupported_compression", "sql": "PUT file://{DATA}/z.xz @~/{STAGE}/",
     "formats": ["TABLE"]},
    {"name": "error_local_path", "sql": "GET @~/{STAGE}/ file:///nonexistent/", "formats": ["TABLE"]},
    {"name": "error_nothing_to_get", "sql": "GET @~/{STAGE}/none/ file://{DATA}/out/",
     "formats": ["TABLE"]},
]


def main():
    out_dir = sys.argv[1]
    only = set(sys.argv[2:])
    snow = os.environ["SNOW_BIN"]
    data = tempfile.mkdtemp(prefix="pg")
    stage = "goldens_" + uuid.uuid4().hex[:12]
    with open(os.path.join(data, "f1.csv"), "wb") as f:
        f.write(b"a,b\n1,2\n")
    with open(os.path.join(data, "f2.csv"), "wb") as f:
        f.write(b"x\n")
    with open(os.path.join(data, "g.csv.gz"), "wb") as f:
        f.write(gzip.compress(b"x\n", mtime=0))
    with open(os.path.join(data, "z.xz"), "wb") as f:
        f.write(b"x")
    os.mkdir(os.path.join(data, "out"))
    results = []
    try:
        for case in CASES:
            if only and case["name"] not in only:
                continue
            sql = case["sql"].replace("{DATA}", data).replace("{STAGE}", stage)
            runs = {}
            for fmt in case["formats"]:
                if case.get("fresh_stage_per_format"):
                    # Each format shows the same first upload.
                    subprocess.run([snow, "sql", "-x", "-q", f"REMOVE @~/{stage}/"],
                                   capture_output=True, check=True)
                proc = subprocess.run(
                    [snow, "sql", "-x", "-q", sql, "--format", fmt],
                    capture_output=True, text=True, env=dict(os.environ, COLUMNS="80"),
                )

                def clean(text):
                    return text.replace(data, "{DATA}").replace(stage, "{STAGE}")

                runs[fmt] = {"stdout": clean(proc.stdout), "stderr": clean(proc.stderr),
                             "exit": proc.returncode}
            results.append({"name": case["name"], "sql": case["sql"], "runs": runs})
            print(case["name"], file=sys.stderr)
    finally:
        subprocess.run([snow, "sql", "-x", "-q", f"REMOVE @~/{stage}/"], capture_output=True)
        shutil.rmtree(data)
    with open(os.path.join(out_dir, "cases.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
