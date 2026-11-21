"""`snow sql` templating goldens (ADR 0006), run by scripts/capture-template-goldens.sh.

For every case in tests/golden/template/cases.toml it runs snow 3.34.0's own `snow sql` in a child
Python process with statement execution replaced by a recorder, so nothing connects to Snowflake,
and writes tests/golden/template/<case>.json: per format, the statements snow would have sent
(`null` when it stopped before), its stdout, stderr and exit code. The project directory of a case
is written as <PROJECT> in the record. tests/it/template_golden.rs replays every case offline.
"""

import json
import os
import subprocess
import sys
import tempfile
import tomllib

RUNNER = r"""
import json, sys
out = sys.argv[1]
from snowflake.cli._plugins.sql import manager as m
def record(self, compiled, cursor_class):
    with open(out, "w", encoding="utf-8") as f:
        json.dump([c.statement for c in compiled], f)
    return
    yield
m.SqlManager._execute_compiled_statements = record
sys.argv = ["snow"] + sys.argv[2:]
from snowflake.cli._app.__main__ import main
main()
"""

# The environment of every run: nothing from the capturing machine leaks into the goldens.
BASE_ENV = {"SNOWFLAKE_ACCOUNT": "testacct", "SNOWFLAKE_USER": "tester", "LANG": "C.UTF-8"}


def case_args(case, work, project_dir):
    args = []
    if "query" in case:
        args += ["-q", case["query"]]
    for i, text in enumerate(case.get("files", [])):
        path = os.path.join(work, f"input{i + 1}.sql")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        args += ["-f", path]
    for variable in case.get("variables", []):
        args += ["-D", variable]
    for mode in case.get("templating", []):
        args += ["--enable-templating", mode]
    for override in case.get("env", []):
        args += ["--env", override]
    if "project" in case or case.get("project_arg"):
        args += ["--project", project_dir]
    if case.get("silent"):
        args.append("--silent")
    if case.get("enhanced_exit_codes"):
        args.append("--enhanced-exit-codes")
    return args


def capture(case, out_dir):
    name = case["name"]
    print(f"capturing template/{name}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as work:
        work = os.path.realpath(work)
        project_dir = os.path.join(work, "project")
        os.makedirs(project_dir)
        for file_name, text in case.get("project", {}).items():
            path = os.path.join(project_dir, file_name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        home = os.path.join(work, "home")
        os.makedirs(home, mode=0o700)
        for file_name, text in case.get("home_files", {}).items():
            path = os.path.join(home, file_name)
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w", encoding="utf-8") as f:
                f.write(text)
        env = dict(BASE_ENV, PATH=os.environ["PATH"], SNOWFLAKE_HOME=home, HOME=home)
        if case.get("unset_snowflake_home"):
            del env["SNOWFLAKE_HOME"]
        env.update(case.get("os_env", {}))
        outputs = {}
        for fmt in case.get("formats", ["table"]):
            record = os.path.join(work, "statements.json")
            if os.path.exists(record):
                os.remove(record)
            run = subprocess.run(
                [sys.executable, "-I", "-c", RUNNER, record, "sql", "-x",
                 *case_args(case, work, project_dir), "--format", fmt],
                capture_output=True, check=False, env=env, cwd=work,
            )
            statements = None
            if os.path.exists(record):
                with open(record, encoding="utf-8") as f:
                    statements = json.load(f)
            outputs[fmt] = {
                "exit": run.returncode,
                "statements": statements,
                "stdout": run.stdout.decode(),
                "stderr": run.stderr.decode(),
            }
    text = json.dumps({"case": case, "outputs": outputs}, indent=1, ensure_ascii=False)
    text = text.replace(project_dir, "<PROJECT>").replace(work, "<WORK>")
    with open(os.path.join(out_dir, f"{name}.json"), "w", encoding="utf-8") as f:
        f.write(text + "\n")


def main():
    out_dir, *only = sys.argv[1:]
    with open(os.path.join(out_dir, "cases.toml"), "rb") as f:
        cases = tomllib.load(f)["case"]
    names = {c["name"] for c in cases}
    for stale in os.listdir(out_dir):
        if stale.endswith(".json") and stale[:-5] not in names:
            os.remove(os.path.join(out_dir, stale))
    for case in cases:
        if not only or case["name"] in only:
            capture(case, out_dir)


if __name__ == "__main__":
    main()
