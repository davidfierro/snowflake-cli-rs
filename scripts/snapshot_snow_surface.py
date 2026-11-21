#!/usr/bin/env python3
"""Turns `snow --structure` (the official CLI's own JSON catalog of visible commands and options)
into docs/snow-surface.json. Not meant to be run by hand: see scripts/snapshot-snow-surface.sh.

Usage: snapshot_snow_surface.py <path-to-snow> <snow-version>   (JSON goes to stdout)

Global options are the root options plus the options most commands share (SHARED_SHARE); each
command still lists all of its own options, global ones included. `--help` is left out (every CLI has it). The output is deterministic, so a later
regeneration with the same snow version is byte-identical.
"""
import json
import os
import subprocess
import sys
import tempfile


# An option on at least this share of the commands (the output, logging and connection options)
# is global; the dbt passthrough commands have no options at all, so "every command" would be empty.
SHARED_SHARE = 0.75


def option(raw):
    flags = list(raw["flags"])
    name = next((f for f in flags if f.startswith("--")), flags[0])
    return {"name": name, "flags": flags}


def options(node):
    return {
        o["name"]: o
        for o in map(option, node.get("options", []))
        if "--help" not in o["flags"]
    }


def leaves(node, path, acc):
    children = node.get("commands")
    if children:
        for child in children:
            leaves(child, path + [child["name"]], acc)
    else:
        acc.append((path, options(node)))


def main():
    snow, version = sys.argv[1], sys.argv[2]
    with tempfile.TemporaryDirectory() as home:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "SNOWFLAKE_HOME": home}
        out = subprocess.run(
            [snow, "--structure"], env=env, check=True, capture_output=True, text=True
        ).stdout
    root = json.loads(out)
    found = []
    leaves(root, [], found)
    counts = {}
    for _, opts in found:
        for name in opts:
            counts[name] = counts.get(name, 0) + 1
    shared = {n for n, k in counts.items() if k >= SHARED_SHARE * len(found)}
    glob = options(root)
    for _, opts in found:
        for name in shared & set(opts):
            glob.setdefault(name, opts[name])
    snapshot = {
        "snow_version": version,
        "global_options": sorted(glob.values(), key=lambda o: o["name"]),
        "commands": [
            {
                "path": path,
                "options": sorted(opts.values(), key=lambda o: o["name"]),
            }
            for path, opts in sorted(found, key=lambda c: c[0])
        ],
    }
    json.dump(snapshot, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
