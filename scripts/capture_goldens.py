"""Golden capture helper, run by scripts/capture-goldens.sh inside the snow venv.

Not meant to be run directly: the shell script sets up the venv, the temporary key file and an
empty SNOWFLAKE_HOME. Never prints the key, the JWT or any response row.
"""

import base64
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
import uuid

import jwt
from cryptography.hazmat.primitives import serialization

# statementHandle values are replaced by this, so goldens are stable across captures.
FIXED_HANDLE = "01234567-0000-0000-0000-000000000000"
LTZ = "timestamp_ltz"


def account_for_jwt(account):
    # Same rule as snowflake-connector-python's auth/keypair.py.
    if ".global" in account:
        account = account.split("-", 1)[0]
    else:
        account = account.split(".", 1)[0]
    return account.upper()


class SqlApi:
    def __init__(self):
        self.account = os.environ["SNOWFLAKE_ACCOUNT"]
        self.user = os.environ["SNOWFLAKE_USER"]
        host = os.environ.get("SNOWFLAKE_HOST") or f"{self.account}.snowflakecomputing.com"
        self.base = f"https://{host}"
        with open(os.environ["SNOWFLAKE_PRIVATE_KEY_FILE"], "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), password=None)
        der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
        self.context = {
            k: os.environ[f"SNOWFLAKE_{k.upper()}"]
            for k in ("database", "schema", "warehouse", "role")
            if os.environ.get(f"SNOWFLAKE_{k.upper()}")
        }

    def _jwt(self):
        qualified = f"{account_for_jwt(self.account)}.{self.user.upper()}"
        now = int(time.time())
        claims = {
            "iss": f"{qualified}.{self.fingerprint}",
            "sub": qualified,
            "iat": now,
            "exp": now + 3540,
        }
        return jwt.encode(claims, self.key, algorithm="RS256")

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self._jwt())
        req.add_header("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("Accept-Encoding", "gzip")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return resp.status, json.loads(raw)
        except urllib.error.HTTPError as err:
            raw = err.read()
            if err.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return err.code, json.loads(raw)

    def execute(self, sql):
        """Returns (first response, [partition 1..n bodies]) of one statement."""
        body = {"statement": sql, **self.context}
        status, resp = self._request("POST", f"/api/v2/statements?requestId={uuid.uuid4()}", body)
        while status == 202:
            time.sleep(1)
            status, resp = self._request("GET", f"/api/v2/statements/{resp['statementHandle']}")
        if status != 200:
            raise SystemExit(f"SQL API returned {status}: {resp.get('message')}")
        handle = resp["statementHandle"]
        partitions = []
        count = len(resp["resultSetMetaData"].get("partitionInfo", []))
        for i in range(1, count):
            status, part = self._request("GET", f"/api/v2/statements/{handle}?partition={i}")
            if status != 200:
                raise SystemExit(f"partition {i} returned {status}")
            partitions.append(part)
        return resp, partitions


def scrub(resp):
    handle = resp.get("statementHandle")
    text = json.dumps(resp)
    if handle:
        text = text.replace(handle, FIXED_HANDLE)
    return json.loads(text)


def capture(api, golden_dir, case):
    name, sql = case["name"], case["sql"]
    print(f"capturing {name}", file=sys.stderr)
    for fmt in ("json", "csv"):
        out = subprocess.run(
            [os.environ["SNOW_BIN"], "sql", "-x", "-q", sql, "--format", fmt],
            capture_output=True,
            check=False,
        )
        if out.returncode != 0:
            raise SystemExit(f"snow failed for case {name} ({fmt}), exit {out.returncode}")
        with open(os.path.join(golden_dir, f"{name}.{fmt}"), "wb") as f:
            f.write(out.stdout)

    first, partitions = api.execute(sql)
    record = {
        "sql": sql,
        "response": scrub(first),
        "partitions": partitions,
    }
    if any(c["type"] == LTZ for c in first["resultSetMetaData"]["rowType"]):
        params, _ = api.execute("SHOW PARAMETERS LIKE 'TIMEZONE'")
        record["show_parameters"] = scrub(params)
    with open(os.path.join(golden_dir, f"{name}.sqlapi.json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, ensure_ascii=False)
        f.write("\n")


def main():
    golden_dir = sys.argv[1]
    only = set(sys.argv[2:])
    with open(os.path.join(golden_dir, "cases.toml"), "rb") as f:
        cases = tomllib.load(f)["case"]
    api = SqlApi()
    for case in cases:
        if not only or case["name"] in only:
            capture(api, golden_dir, case)


if __name__ == "__main__":
    main()
