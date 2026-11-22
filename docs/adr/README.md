# Architecture decision records

Decisions that shape the code, with the alternatives considered and why one won.
Read the relevant ADR before changing what it covers; to change a decision, open a PR
that amends the ADR (or supersedes it with a new one) before or with the code.

## Conventions

- One file per decision: `NNNN-short-slug.md`, numbered in order, never renumbered.
- Sections: Status, Context, Decision (with alternatives and reasons), Consequences.
- Status is one of `Proposed`, `Accepted`, `Superseded by NNNN`. An ADR becomes
  `Accepted` when its PR is merged.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-stage-0-foundation.md) | Stage 0 foundation: transport, module boundaries, errors, crates and testing | Accepted |
| [0002](0002-parallel-partitions-and-streaming.md) | Parallel partition download and streaming results | Accepted |
| [0003](0003-connection-commands.md) | `snow connection` commands: config writer, crates and deviations from snow | Accepted |
| [0004](0004-sql-multi-statement-execution.md) | `snow sql`: multi-statement execution over the SQL API | Accepted |
| [0005](0005-connector-protocol-transport.md) | Connector-protocol transport: session sign-in, query-request and PUT/GET file transfer | Proposed |
| [0006](0006-sql-templating-engine.md) | `snow sql` templating: Jinja engine, `snowflake.yml` context, deviations from snow | Proposed |
| [0007](0007-release-pipeline.md) | Release pipeline: release-plz, dist, PyPI wheels and crates.io | Proposed |
