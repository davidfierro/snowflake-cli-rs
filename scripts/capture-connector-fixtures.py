#!/usr/bin/env python3
"""Captures connector-protocol response shapes from the sandbox (ADR 0005, Decision 7).

Run by hand, like scripts/capture-goldens.sh, with a Python that has `cryptography` (the
snowflake-cli venv does):

    SNOWFLAKE_ACCOUNT=... SNOWFLAKE_USER=... SNOWFLAKE_PRIVATE_KEY_B64=... \\
        python3 scripts/capture-connector-fixtures.py

It signs in with the sandbox key pair, runs synthetic SQL only (a literal, SYSTEM$WAIT, a
generator), asks for PUT metadata without transferring anything, heartbeats, renews the session
and closes it, then writes each response body to tests/fixtures/connector/<name>.json with every
token, credential, key, URL, id and context value replaced by a fixed marker. Flows the sandbox
cannot run (password, MFA, browser, Okta, OAuth) are written by hand in the tests from the
connector's code (`src/session/flow_tests.rs` cites the shapes).
"""

import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.request
import uuid

from cryptography.hazmat.primitives import serialization

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "connector"

# Keys whose values are replaced, wherever they appear (case-insensitive substring match).
SENSITIVE = (
    "token", "secret", "key", "creds", "url", "presigned", "qrmk", "chunkheaders", "proof",
    "sessionid", "queryid", "requestid", "location", "storageaccount", "endpoint", "smkid",
    "databasename", "schemaname", "warehousename", "rolename", "id_token", "mfa", "aws",
    "username", "loginname", "path", "userid", "accountname", "accountid", "region",
)
# Session parameters kept by name (the rest go; they can describe the account).
KEPT_PARAMETERS = {"TIMEZONE", "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY"}


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def mask_context(text, names):
    """Every sandbox name (account, user, role, …) and request id in a string becomes a marker."""
    for name, marker in names:
        text = re.sub(re.escape(name), marker, text, flags=re.I)
    return UUID.sub("<uuid>", text)


def env(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"error: {name} is not set")
    return value


def scrub(value, key=""):
    lowered = key.lower()
    if isinstance(value, dict):
        return {k: scrub(v, k) for k, v in value.items()}
    if isinstance(value, list):
        if lowered == "parameters":
            return [scrub(p) for p in value if isinstance(p, dict) and p.get("name") in KEPT_PARAMETERS]
        return [scrub(v, key) for v in value]
    sensitive = lowered != "locationtype" and any(s in lowered for s in SENSITIVE)
    if isinstance(value, str) and sensitive:
        return f"<{key or 'value'}>"
    if isinstance(value, int) and not isinstance(value, bool) and sensitive:
        return 0
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return "<url>"
    return value


def jwt(account, user, pem):
    key = serialization.load_pem_private_key(pem, password=None)
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode()
    qualified = f"{account.split('.')[0].upper()}.{user.upper()}"
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": f"{qualified}.{fingerprint}", "sub": qualified, "iat": now, "exp": now + 3600}
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    signing = f"{enc(header)}.{enc(claims)}"
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    signature = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


class Snowflake:
    def __init__(self, account):
        self.base = f"https://{account}.snowflakecomputing.com"
        self.token = None
        self.master = None

    def post(self, path, body=None, token=None):
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(body or {}).encode(),
            method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        if token:
            request.add_header("Authorization", f'Snowflake Token="{token}"')
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read())

    def get(self, path):
        request = urllib.request.Request(self.base + path, headers={
            "Accept": "application/json", "Authorization": f'Snowflake Token="{self.token}"',
        })
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read())

    def query(self, sql):
        return self.post(
            f"/queries/v1/query-request?requestId={uuid.uuid4()}",
            {"sqlText": sql, "asyncExec": False, "sequenceId": 1, "querySubmissionTime": int(time.time() * 1000)},
            self.token,
        )


def login_body(account, user, authenticator, token):
    return {"data": {
        "CLIENT_APP_ID": "snowflake-cli-rs", "CLIENT_APP_VERSION": "capture",
        "ACCOUNT_NAME": account.split(".")[0], "LOGIN_NAME": user,
        "CLIENT_ENVIRONMENT": {"APPLICATION": "SNOWFLAKE_CLI"},
        "SESSION_PARAMETERS": {"PYTHON_CONNECTOR_QUERY_RESULT_FORMAT": "json"},
        "AUTHENTICATOR": authenticator, "TOKEN": token,
    }}


def main():
    account, user = env("SNOWFLAKE_ACCOUNT"), env("SNOWFLAKE_USER")
    pem = base64.b64decode(env("SNOWFLAKE_PRIVATE_KEY_B64"))
    sf = Snowflake(account)
    captured = {}
    path = f"/session/v1/login-request?request_id={uuid.uuid4()}"
    captured["login-request-jwt-invalid"] = sf.post(path, login_body(account, user, "SNOWFLAKE_JWT", "not.a.jwt"))
    answer = sf.post(path, login_body(account, user, "SNOWFLAKE_JWT", jwt(account, user, pem)))
    captured["login-request-success"] = answer
    sf.token, sf.master = answer["data"]["token"], answer["data"]["masterToken"]

    captured["query-request-select"] = sf.query("SELECT 1 AS N, 'a' AS S, TRUE AS B")
    captured["query-request-error"] = sf.query("SELECT * FROM SNOW_RS_NO_SUCH_TABLE_FOR_FIXTURES")
    running = sf.query("SELECT SYSTEM$WAIT(50)")
    captured["query-request-running"] = running
    if running.get("code") in ("333333", "333334"):
        time.sleep(2)
        captured["query-request-result"] = sf.get(running["data"]["getResultUrl"])
    chunked = sf.query("SELECT SEQ8() AS id, RANDSTR(20, RANDOM()) AS s FROM TABLE(GENERATOR(ROWCOUNT => 200000))")
    chunked["data"]["rowset"] = chunked["data"]["rowset"][:3]
    captured["query-request-chunked"] = chunked
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    captured["query-request-put"] = sf.query(f"PUT file:///nonexistent/fixture.csv @~/snow_rs_fixture_{stamp}/")
    captured["heartbeat"] = sf.post(f"/session/heartbeat?requestId={uuid.uuid4()}", None, sf.token)
    captured["token-request"] = sf.post(
        f"/session/token-request?requestId={uuid.uuid4()}",
        {"oldSessionToken": sf.token, "requestType": "RENEW"},
        sf.master,
    )
    new_token = captured["token-request"].get("data", {}).get("sessionToken") or sf.token
    captured["close"] = sf.post("/session?delete=true", {}, new_token)

    names = [
        (os.environ[var], f"<{var.lower()}>")
        for var in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_ROLE", "SNOWFLAKE_WAREHOUSE", "SNOWFLAKE_DATABASE")
        if os.environ.get(var)
    ]
    names.sort(key=lambda pair: -len(pair[0]))
    OUT.mkdir(parents=True, exist_ok=True)
    for name, body in captured.items():
        text = mask_context(json.dumps(scrub(body), indent=2, sort_keys=True), names)
        (OUT / f"{name}.json").write_text(text + "\n")
        print(f"wrote tests/fixtures/connector/{name}.json")


if __name__ == "__main__":
    main()
