"""`snow sql` golden capture (ADR 0004, Decision 7), run by scripts/capture-goldens.sh --sql.

For every case in tests/golden/sql/cases.toml it records, in tests/golden/sql/<case>.json:
  - for each format: snow 3.34.0's stdout, stderr and exit code;
  - the SQL API exchanges of this crate's own request sequence for the same input (parent,
    children, partitions, and for failures the history lookups and the failed child's GET),
    recorded through a local HTTP proxy in front of the sandbox, replayed by tests/sql_golden.rs.

Query ids are replaced: in the exchanges by stable fake ids, in snow's stderr by a fixed token of
the same length. The account, user, role, database and warehouse never reach the files: only the
statement and parameters of each request are kept, and the capture fails if any of those names
appears in what it would write. Cases use synthetic SQL only (no tables).
"""

import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import tomllib
import urllib.error
import urllib.request

FORMATS = ("table", "plain", "json", "csv")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ID_TOKEN = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
SENSITIVE_VARS = (
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
    "SNOWFLAKE_ROLE",
    "SNOWFLAKE_DATABASE",
    "SNOWFLAKE_WAREHOUSE",
)


class Recorder:
    """A forwarding proxy that records every exchange."""

    def __init__(self, upstream):
        self.upstream = upstream
        self.exchanges = []
        self.lock = threading.Lock()
        recorder = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _forward(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                req = urllib.request.Request(recorder.upstream + self.path, data=body, method=method)
                for name in ("Authorization", "X-Snowflake-Authorization-Token-Type",
                             "Content-Type", "Accept", "User-Agent"):
                    if self.headers.get(name):
                        req.add_header(name, self.headers[name])
                try:
                    with urllib.request.urlopen(req, timeout=300) as resp:
                        status, raw = resp.status, resp.read()
                except urllib.error.HTTPError as err:
                    status, raw = err.code, err.read()
                path, _, query = self.path.partition("?")
                exchange = {"method": method, "path": path, "status": status,
                            "response": json.loads(raw)}
                if query.startswith("partition="):
                    exchange["partition"] = query.split("=", 1)[1]
                if body:
                    sent = json.loads(body)
                    exchange["statement"] = sent["statement"]
                    if "parameters" in sent:
                        exchange["parameters"] = sent["parameters"]
                with recorder.lock:
                    recorder.exchanges.append(exchange)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._forward("GET")

            def do_POST(self):
                self._forward("POST")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server.server_address[1]


def case_args(case, work):
    """The `snow sql` arguments of a case, and its stdin."""
    args = []
    if "query" in case:
        args += ["-q", case["query"]]
    for i, text in enumerate(case.get("files", [])):
        path = os.path.join(work, f"input{i + 1}.sql")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        args += ["-f", path]
    stdin = case.get("stdin")
    if stdin is not None:
        args.append("-i")
    if case.get("retain_comments"):
        args.append("--retain-comments")
    if case.get("silent"):
        args.append("--silent")
    for variable in case.get("variables", []):
        args += ["-D", variable]
    for mode in case.get("templating", []):
        args += ["--enable-templating", mode]
    if case.get("single_transaction"):
        args.append("--single-transaction")
    # `options` are raw extra arguments; `{spool}` is the spool file of the run.
    args += [a.replace("{spool}", os.path.join(work, "spool.out")) for a in case.get("options", [])]
    return args, (stdin or "").encode()


def stable_ids(text):
    mapping = {}

    def fake(match):
        uid = match.group(0)
        if uid not in mapping:
            mapping[uid] = f"01234567-0000-0000-0000-{len(mapping) + 1:012d}"
        return mapping[uid]

    return UUID.sub(fake, text)


def check_clean(name, text):
    for var in SENSITIVE_VARS:
        value = os.environ.get(var)
        if value and value.lower() in text.lower():
            raise SystemExit(f"case {name}: the output contains the value of {var}; change the SQL")


def capture(case, golden_dir, rs_bin):
    name = case["name"]
    print(f"capturing sql/{name}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as work:
        args, stdin = case_args(case, work)
        outputs = {}
        # `bare`: no --format flag (the format comes from `-o output_format`), recorded as "default".
        bare = case.get("bare", False)
        for fmt in case.get("formats", ["default"] if bare else FORMATS):
            spool = os.path.join(work, "spool.out")
            if os.path.exists(spool):
                os.remove(spool)
            out = subprocess.run(
                [os.environ["SNOW_BIN"], "sql", "-x", *args, *([] if bare else ["--format", fmt])],
                input=stdin, capture_output=True, check=False,
            )
            outputs[fmt] = {
                "exit": out.returncode,
                "stdout": out.stdout.decode(),
                "stderr": UUID.sub(ID_TOKEN, out.stderr.decode()),
            }
            if any("{spool}" in a for a in case.get("options", [])):
                with open(spool, encoding="utf-8") if os.path.exists(spool) else open(os.devnull) as f:
                    outputs[fmt]["spool"] = f.read()

        account = os.environ["SNOWFLAKE_ACCOUNT"]
        host = os.environ.get("SNOWFLAKE_HOST") or f"{account}.snowflakecomputing.com"
        recorder = Recorder(f"https://{host}")
        env = dict(os.environ, SNOWFLAKE_HOST="127.0.0.1", SNOWFLAKE_PORT=str(recorder.port),
                   SNOWFLAKE_PROTOCOL="http")
        rs = subprocess.run([rs_bin, "sql", "-x", *args, *([] if bare else ["--format", "json"])], input=stdin,
                            capture_output=True, check=False, env=env)
        recorder.server.shutdown()
        if not recorder.exchanges and not case.get("no_request"):
            raise SystemExit(f"case {name}: snow-rs sent no request (exit {rs.returncode})")

    record = {
        "case": case,
        "outputs": outputs,
        "exchanges": json.loads(stable_ids(json.dumps(recorder.exchanges))),
    }
    text = json.dumps(record, indent=1, ensure_ascii=False) + "\n"
    check_clean(name, text)
    with open(os.path.join(golden_dir, f"{name}.json"), "w", encoding="utf-8") as f:
        f.write(text)


def main():
    golden_dir, rs_bin, *only = sys.argv[1:]
    with open(os.path.join(golden_dir, "cases.toml"), "rb") as f:
        cases = tomllib.load(f)["case"]
    for case in cases:
        if not only or case["name"] in only:
            capture(case, golden_dir, rs_bin)


if __name__ == "__main__":
    main()
