#!/usr/bin/env bash
# Benchmarks this CLI against the official snow on the Snowflake sandbox (ADR 0002, Decision 5).
#
# Run by hand, never by CI (CI has no credentials). See bench/README.md.
#
# Usage: bench/run.sh [scenario ...]     (default: all; names below)
#   RUNS=<n>         hyperfine runs per command (default 5, plus 1 warm-up)
#   SNOW_VENV=<dir>  reuse a venv that has snowflake-cli==3.34.0
#   NO_SNOW=1        skip the official snow
#   WRITE_RESULTS=1  merge the results of the scenarios that ran into bench/results.json
#                    (committed; the README command matrix is generated from it)
#
# Needs: hyperfine, python3, cargo, and the sandbox env SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER,
# SNOWFLAKE_PRIVATE_KEY_B64 (optionally SNOWFLAKE_ROLE, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_DATABASE).
# The key goes to a 0600 temp file deleted on exit; nothing here prints it, the account or
# any row: output goes to /dev/null and the queries only produce generator data.
set -euo pipefail

SNOW_VERSION=3.34.0
RUNS=${RUNS:-5}
repo_root=$(cd "$(dirname "$0")/.." && pwd)

for tool in hyperfine python3 cargo; do
    command -v "$tool" > /dev/null || { echo "error: $tool is not installed" >&2; exit 1; }
done
for var in SNOWFLAKE_ACCOUNT SNOWFLAKE_USER SNOWFLAKE_PRIVATE_KEY_B64; do
    if [ -z "${!var:-}" ]; then
        echo "error: $var is not set" >&2
        exit 1
    fi
done

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

cargo build --quiet --release --manifest-path "$repo_root/Cargo.toml" --bin snow-rs
rs_snow="$repo_root/target/release/snow-rs"

snow=""
if [ -z "${NO_SNOW:-}" ]; then
    venv=${SNOW_VENV:-$work/venv}
    if [ ! -x "$venv/bin/snow" ]; then
        python3 -m venv "$venv"
        "$venv/bin/pip" install --quiet "snowflake-cli==$SNOW_VERSION"
    fi
    "$venv/bin/snow" --version | grep -q "$SNOW_VERSION" || {
        echo "error: $venv does not have snowflake-cli $SNOW_VERSION" >&2
        exit 1
    }
    snow="$venv/bin/snow"
fi

key_file=$work/key.p8
(umask 077 && printenv SNOWFLAKE_PRIVATE_KEY_B64 | base64 -d > "$key_file")
mkdir -m 700 "$work/home" "$work/diag"
# One dummy connection for the connection scenarios; the ones that change the config restore
# it before every run. No scenario signs in with it (`-x` ignores it).
(umask 077 && printf '[connections.bench]\naccount = "bench"\nuser = "bench"\n' > "$work/config.base")
reset_config="install -m 600 $work/config.base $work/home/config.toml"
$reset_config
# Both CLIs: temporary connection (-x) from SNOWFLAKE_* only, key-pair JWT, no user config.
export SNOWFLAKE_HOME="$work/home" SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT
export SNOWFLAKE_PRIVATE_KEY_FILE="$key_file"
unset SNOWFLAKE_PRIVATE_KEY_B64

# Synthetic generator rows (no single quotes, so the SQL can be quoted for hyperfine's shell).
rows_sql() {
    echo "SELECT SEQ8() AS id, UNIFORM(1, 1000000, RANDOM()) AS n, RANDSTR(20, RANDOM()) AS s," \
        "UNIFORM(0::FLOAT, 1::FLOAT, RANDOM()) AS f," \
        "DATEADD(second, SEQ4(), TO_TIMESTAMP_NTZ(1704067200)) AS ts" \
        "FROM TABLE(GENERATOR(ROWCOUNT => $1))"
}

# Several statements in one run (ADR 0004, Decision 7).
multi_small_sql() { # USE SCHEMA, then 19 one-row queries
    local sql="USE SCHEMA INFORMATION_SCHEMA;" i
    for i in $(seq 1 19); do sql+=" SELECT $i AS n;"; done
    echo "$sql"
}
variant_sql() { # an OBJECT and an ARRAY per row, for JSON_EXT (keys via CHR: no single quotes)
    echo "SELECT OBJECT_CONSTRUCT(CHR(105) || CHR(100), SEQ8(), CHR(116), ARRAY_CONSTRUCT(RANDSTR(8, RANDOM()), SEQ8() % 7), CHR(110), OBJECT_CONSTRUCT(CHR(107), UNIFORM(1, 1000, RANDOM()))) AS o, ARRAY_CONSTRUCT(SEQ8(), 1.5, NULL) AS a FROM TABLE(GENERATOR(ROWCOUNT => 100000))"
}
multi_2x100k_sql() { echo "$(rows_sql 100000); $(rows_sql 100000)"; }
# The project of templated-project: `m` refers to `n`, which `--env` overrides.
mkdir "$work/project"
printf 'definition_version: 2\nenv:\n  n: 1\n  m: "<%% ctx.env.n %%>0"\n' > "$work/project/snowflake.yml"

# SQL scenarios (`snow sql -x -q … --format …`): name | format | query | compare with snow
# query: trivial, decimals (`--decimal-precision 3` on NUMBER values), a row count (generator
# rows), multi-small, multi-2x100k, templated (a `-D` variable in `<% %>`), templated-jinja (a
# JINJA loop), templated-project (`ctx.env` from a snowflake.yml with `--project` and `--env`),
# templating-none (multi-small with `--enable-templating NONE`), single-transaction
# (`--single-transaction` around two statements), source (`!source` of a one-statement file),
# local-only (the same with `--local-only`), variant (100k generator rows with an OBJECT and an
# ARRAY column) or secondary-roles (`--secondary-roles NONE` on a trivial query).
# The `put-*`/`get-*` scenarios move synthetic files (20 small CSV files, or one 100 MB file of
# random bytes sent as is) to and from a random prefix of the user stage, removed on exit; the
# `get-*` ones upload their files once first.
# The `output-file-*` and `quiet-*` scenarios add `-o output_file=<tmp file>` (removed before each
# run: snow appends) and `-o quiet=true` to the 100k-row query.
sql_scenarios="trivial-json json trivial yes
100k-csv csv 100000 yes
100k-json json 100000 yes
1m-csv csv 1000000 yes
1m-json json 1000000 yes
4m-csv csv 4000000 no
10m-csv csv 10000000 no
multi-small-json json multi-small yes
multi-2x100k-csv csv multi-2x100k yes
templated-json json templated yes
templated-jinja-json json templated-jinja yes
templated-project-json json templated-project yes
templating-none-json json templating-none yes
single-transaction-json json single-transaction yes
decimal-precision-json json decimals yes
source-json json source yes
local-only-json json local-only yes
json-ext json_ext variant yes
output-file-csv csv 100000 yes
quiet-csv csv 100000 yes
secondary-roles-json json secondary-roles yes
put-small-json json put-small yes
put-100mb-json json put-100mb yes
get-small-json json get-small yes
get-100mb-json json get-100mb yes"

printf 'SELECT 1 AS a;\n' > "$work/source.sql"

# PUT/GET files and the stage prefix (removed on exit, like the temp dir).
stage_prefix="snow_rs_bench_$(python3 -I -c 'import uuid; print(uuid.uuid4().hex[:12])')"
mkdir "$work/put-small" "$work/put-big" "$work/get-out"
for i in $(seq -w 1 20); do
    python3 -I -c 'import sys; sys.stdout.write("".join(f"{i},{i * 7}\n" for i in range(1000)))' \
        > "$work/put-small/f$i.csv"
done
head -c 100000000 /dev/urandom > "$work/put-big/big.bin"
cleanup() {
    "$rs_snow" sql -x -q "REMOVE @~/$stage_prefix/" > /dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

selected=" $* "
hyperfine_opts=(--shell bash --output null --style basic --runs "$RUNS" --warmup 1)
peak_rss() { # command... -> peak RSS of the child in KiB
    python3 -I -c '
import resource, subprocess, sys
subprocess.run(sys.argv[1:], stdout=subprocess.DEVNULL, check=True)
print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
' "$@"
}
# Median wall time in seconds from a hyperfine JSON export (1.x and 2.x formats).
seconds() {
    python3 -I -c '
import json, statistics, sys
r = json.load(open(sys.argv[1]))["results"][0]
if "summary" in r:
    print(r["summary"]["time_wall_clock"]["median"])
else:
    print(statistics.median(r["times"]))
' "$1"
}
human() { # seconds -> "1.23 s" / "178 ms"
    python3 -I -c 'import sys; m = float(sys.argv[1]); print(f"{m:.2f} s" if m >= 1 else f"{m * 1000:.0f} ms")' "$1"
}
ratio() {
    python3 -I -c 'import sys; print(f"{float(sys.argv[2]) / float(sys.argv[1]):.1f}x")' "$1" "$2"
}
mib() { python3 -I -c 'import sys; print(f"{int(sys.argv[1]) / 1024:.1f} MiB")' "$1"; }

results_file=$repo_root/bench/results.json
# record <name> <command> <rs_s> <rs_kib> [<snow_s> <snow_kib>]: merge one scenario into the results file.
record() {
    python3 -I - "$results_file" "$SNOW_VERSION" "$@" <<'PY'
import datetime, json, os, sys
path, version, name, command, rs_s, rs_kib, *snow = sys.argv[1:]
data = json.load(open(path)) if os.path.exists(path) else {"scenarios": []}
entry = {
    "name": name,
    "command": command,
    "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
    "snow_version": version,
    "rs": {"median_s": float(rs_s), "peak_rss_kib": int(rs_kib)},
    "snow": {"median_s": float(snow[0]), "peak_rss_kib": int(snow[1])} if snow else None,
}
scenarios = data["scenarios"]
for i, old in enumerate(scenarios):
    if old["name"] == name:
        scenarios[i] = entry
        break
else:
    scenarios.append(entry)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

table="| Scenario | snow-rs median | snow median | Speed-up | snow-rs peak RSS | snow peak RSS |
|---|---|---|---|---|---|"
# run_scenario <name> <command path> <compare yes|no> <rs command line> <snow arguments> [<prepare>]
#              [<snow prefix>]
# <prepare> is a shell command run before every execution (restores the config).
# The snow side runs "<snow prefix>$snow <snow arguments>"; both write to /dev/null (hyperfine
# --output null).
run_scenario() {
    local name=$1 command=$2 compare=$3 rs_cmd=$4 snow_args=$5 prepare=${6:-true}
    local snow_prefix=${7:-}
    echo ">> $name" >&2
    hyperfine "${hyperfine_opts[@]}" --prepare "$prepare" --export-json "$work/$name-rs.json" "$rs_cmd" >&2
    local rs_s rs_kib snow_s="" snow_kib="" snow_time="—" snow_rss="—" speedup="—"
    rs_s=$(seconds "$work/$name-rs.json")
    bash -c "$prepare"
    rs_kib=$(peak_rss bash -c "$rs_cmd")
    if [ -n "$snow" ] && [ "$compare" = yes ]; then
        hyperfine "${hyperfine_opts[@]}" --prepare "$prepare" --export-json "$work/$name-snow.json" \
            "$snow_prefix$snow $snow_args" >&2
        snow_s=$(seconds "$work/$name-snow.json")
        bash -c "$prepare"
        snow_kib=$(peak_rss bash -c "$snow_prefix$snow $snow_args")
        snow_time=$(human "$snow_s")
        snow_rss=$(mib "$snow_kib")
        speedup=$(ratio "$rs_s" "$snow_s")
    fi
    if [ -n "${WRITE_RESULTS:-}" ]; then
        # shellcheck disable=SC2086 # empty $snow_s/$snow_kib must expand to nothing
        record "$name" "$command" "$rs_s" "$rs_kib" $snow_s $snow_kib
    fi
    table+=$'\n'"| $name | $(human "$rs_s") | $snow_time | $speedup | $(mib "$rs_kib") | $snow_rss |"
}

# An unsigned OIDC ID token ({"alg":"none"} / iss + sub): both CLIs only read its claims.
oidc_token=eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lzc3VlciIsInN1YiI6Indvcmtsb2FkIn0.c2ln

# Scenarios of the ported commands and root options: name | command path | arguments (same for both
# CLIs) | prepare
# The `connection` ones need no network except `connection test`, which signs in to the sandbox.
command_scenarios="connection-list|connection list|connection list --format json|true
connection-test|connection test|connection test -x --format json|true
connection-test-diag|connection test|connection test -x --enable-diag --print-diag --diag-log-path $work/diag --format json|true
connection-add|connection add|connection add -n bench2 --account a --user u --no-interactive --format json|$reset_config
connection-remove|connection remove|connection remove bench --format json|$reset_config
connection-set-default|connection set-default|connection set-default bench --format json|$reset_config
connection-generate-jwt|connection generate-jwt|connection generate-jwt -x --account a --user u --private-key-file $key_file --format json|true
connection-generate-workload-identity-token|connection generate-workload-identity-token|connection generate-workload-identity-token -x --workload-identity-provider OIDC --token $oidc_token --format json|true
root-info|--info|--info|true
root-structure|--structure|--structure|true"
while IFS='|' read -r name command args prepare; do
    if [ "$#" -gt 0 ] && [[ "$selected" != *" $name "* ]]; then
        continue
    fi
    run_scenario "$name" "$command" yes "$rs_snow $args" "$args" "$prepare"
done <<< "$command_scenarios"

# Password sign-in on the connector protocol (ADR 0005 Decision 7): needs the user that
# scripts/sandbox/0005-connector-protocol.sql creates; skipped until its variables are set. The
# password reaches both CLIs through SNOWFLAKE_PASSWORD only (never on a command line).
if [ "$#" -eq 0 ] || [[ "$selected" == *" connection-test-password "* ]]; then
    if [ -n "${SNOWFLAKE_TEST_PASSWORD_USER:-}" ] && [ -n "${SNOWFLAKE_TEST_PASSWORD:-}" ]; then
        saved_user=$SNOWFLAKE_USER
        export SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE SNOWFLAKE_USER=$SNOWFLAKE_TEST_PASSWORD_USER
        export SNOWFLAKE_PASSWORD=$SNOWFLAKE_TEST_PASSWORD
        unset SNOWFLAKE_PRIVATE_KEY_FILE
        args="connection test -x --format json"
        run_scenario connection-test-password "connection test" yes "$rs_snow $args" "$args"
        export SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT SNOWFLAKE_USER=$saved_user
        export SNOWFLAKE_PRIVATE_KEY_FILE="$key_file"
        unset SNOWFLAKE_PASSWORD
    else
        echo ">> connection-test-password: skipped (SNOWFLAKE_TEST_PASSWORD_USER / SNOWFLAKE_TEST_PASSWORD not set)" >&2
    fi
fi
while read -r name format query compare; do
    if [ "$#" -gt 0 ] && [[ "$selected" != *" $name "* ]]; then
        continue
    fi
    extra="" prepare=true
    case $name in
        output-file-*)
            extra=" -o output_file=$work/spool.out"
            prepare="rm -f $work/spool.out" ;;
        quiet-*) extra=" -o quiet=true" ;;
    esac
    case $query in
        templated) sql="SELECT <% n %> AS n"; extra=" -D n=1" ;;
        templated-jinja)
            sql="{% for i in range(3) %}SELECT {{ i }} + {{ n }} AS n;{% endfor %}"
            extra=" -D n=1 --enable-templating JINJA" ;;
        templated-project)
            sql="SELECT <% ctx.env.n %> AS n, <% ctx.env.m %> AS m"
            extra=" --project $work/project --env n=2" ;;
        templating-none) sql=$(multi_small_sql); extra=" --enable-templating NONE" ;;
        single-transaction) sql="SELECT 1 AS a; SELECT 2 AS b"; extra=" --single-transaction" ;;
        source) sql="!source $work/source.sql" ;;
        local-only) sql="!source $work/source.sql"; extra=" --local-only" ;;
        trivial) sql="SELECT CURRENT_ROLE()" ;;
        secondary-roles) sql="SELECT CURRENT_ROLE()"; extra=" --secondary-roles NONE" ;;
        decimals)
            sql="SELECT 1.2345::NUMBER(10,4) AS a, 123456.789::NUMBER(12,3) AS b, 1/3 AS c"
            extra=" --decimal-precision 3" ;;
        put-small) sql="PUT file://$work/put-small/f*.csv @~/$stage_prefix/small/ OVERWRITE=TRUE" ;;
        put-100mb)
            sql="PUT file://$work/put-big/big.bin @~/$stage_prefix/big/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE" ;;
        get-small)
            "$rs_snow" sql -x -q "PUT file://$work/put-small/f*.csv @~/$stage_prefix/small/ OVERWRITE=TRUE" > /dev/null
            sql="GET @~/$stage_prefix/small/ file://$work/get-out/" ;;
        get-100mb)
            "$rs_snow" sql -x -q "PUT file://$work/put-big/big.bin @~/$stage_prefix/big/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE" > /dev/null
            sql="GET @~/$stage_prefix/big/ file://$work/get-out/" ;;
        multi-small) sql=$(multi_small_sql) ;;
        multi-2x100k) sql=$(multi_2x100k_sql) ;;
        variant) sql=$(variant_sql) ;;
        *) sql=$(rows_sql "$query") ;;
    esac
    args="sql -x -q '$sql' --format $format$extra"
    run_scenario "$name" sql "$compare" "$rs_snow $args" "$args" "$prepare"
done <<< "$sql_scenarios"

# The interactive session's start-up (`repl-startup`): on a pseudo-terminal, from launch to the
# first prompt (sign-in and `select current_version()` included), then `quit` (bench/repl_pty.py).
# Peak RSS is the largest process of the run: the CLI, or the Python driver when it is larger.
if [ "$#" -eq 0 ] || [[ "$selected" == *" repl-startup "* ]]; then
    repl_driver="python3 -I $repo_root/bench/repl_pty.py "
    run_scenario repl-startup sql yes "$repl_driver$rs_snow sql -x --no-prompt-exit-repl" \
        "sql -x --no-prompt-exit-repl" true "$repl_driver"
fi

echo
echo "$table"
