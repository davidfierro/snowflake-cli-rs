# ADR 0006: `snow sql` templating: Jinja engine, `snowflake.yml` context, deviations from snow

## Status

Proposed.

## Context

ADR 0004 (Decision 6) placed templating between the two statement splits and stage 3
ported LEGACY and STANDARD with plain variable names only. `snow` 3.34.0 does more:

- inside `&{ … }` and `<% … %>` it evaluates any Jinja2 expression (filters, literals,
  operators), and the text can hold Jinja2 `{# … #}` comments, which are removed;
- `--enable-templating JINJA` (and `ALL`) adds a full Jinja2 pass (`{{ }}`, `{% %}`), run after
  LEGACY/STANDARD on each whole input, with SQL comments protected, before the split;
- the data is the `-D` variables plus `ctx` (the project definition, `ctx.env.*` with `--env`,
  the process environment and the `env` section of `snowflake.yml`) and `fn.*` (identifier
  helpers), loaded only when the text has a template marker;
- two filters read files under the project root: `read_file_content` and
  `procedure_from_js_file`.

Jinja2 is a Python library; this crate needs a Rust engine that can be configured to behave the
same way, and a way to read `snowflake.yml` the way `snow` does.

## Decision 1: `minijinja` as the engine

`minijinja` 3.1 (Apache-2.0, by Jinja2's author, maintained; dependencies: `percent-encoding` for `urlencode`, `indexmap` for ordered maps). It implements
Jinja2's syntax and most of its builtins, and lets us set what `snow` sets:

| `snow` (Jinja2) | `minijinja` configuration |
|---|---|
| `variable_start/end_string` `&{`/`}` (LEGACY), `<%`/`%>` (STANDARD) | `SyntaxConfig::variable_delimiters` |
| `block_start/end_string` set to a random string (no blocks) | the same string as block delimiters |
| `keep_trailing_newline=True` | `keep_trailing_newline(true)` |
| `undefined=StrictUndefined` | `UndefinedBehavior::Strict` |
| `IgnoreAttrEnvironment` (attributes are mapping keys only) | plain values have no attributes; method calls are errors |
| `BaseLoader` (no templates to include) | no loader: `include`/`import`/`extends` fail |
| `read_file_content`, `procedure_from_js_file` filters | ported (`src/script/template.rs`), confined to the project root |
| Jinja2 turns `\r\n` and `\r` into `\n` | done before rendering |
| Python `str()` of values (`None`, `True`, `[1, 'a']`, `{'k': 1}`) | `minijinja`'s default formatting is the same |

Alternatives: `tera` (a different, non-Jinja2 syntax and semantics) and `askama` (compile-time
templates) cannot render user input as Jinja2. Embedding Python is out of the question for a
native binary. A hand-written evaluator (what stage 3 did for names) would have to grow into a
Jinja2 implementation.

## Decision 2: errors as `snow` reports them

`snow` reports a template error in one of three ways; `src/script/template.rs` classifies every
`minijinja` error into the same three:

- **Undefined** (`jinja2.UndefinedError`): without JINJA it is collected per statement
  (`SQL template rendering error: …` on stdout, then the `SQL rendering error` panel, exit 1).
  The message is rebuilt as Jinja2 words it from the undefined expression `minijinja` reports:
  `'x' is undefined`, `'str object' has no attribute 'y'`, `list object has no element 5`,
  `'snowflake.cli.api.utils.models.ProjectEnvironment object' has no attribute 'X'` (the parent
  value is evaluated to name its Python type). An unknown function or method is reported the
  same way, as Jinja2 does.
- **Click exceptions** (mixed syntaxes, reserved `ctx`/`fn`, `snowflake.yml` errors, `fn.*`
  argument errors, a file outside the project root): an `Error` panel, exit 1, with the feedback
  line only for `snow`'s own error classes. `Error::without_feedback` marks the plain
  `ClickException`s (`Invalid variable`, the reserved names, a path outside the root), which
  also fixes `-D` and the reserved names from stage 3. A `snowflake.yml` that cannot be read is
  `snow`'s `CliArgumentError` (`ErrorKind::Argument`): exit 1, or 2 with `--enhanced-exit-codes`;
  `SQL rendering error` exits 5 with it, everything else 1.
- **Anything else** (syntax errors, runtime errors, undefined values under JINJA, a missing
  file): `snow`'s `An unexpected exception occurred. …` text on stdout (TABLE/PLAIN, not with
  `--silent`), the feedback line on stderr, exit 1, no panel (`ErrorKind::Unexpected`). The
  most frequent messages are worded as Jinja2 words them (unclosed tag, empty expression,
  unclosed comment, division/modulo by zero, unknown filter or test, missing template); the
  others keep `minijinja`'s wording (deviation 1).

## Decision 3: `snowflake.yml`, `--project`, `--env`

`src/project/` ports what `snow sql` needs from `DefinitionManager` and
`render_definition_template`:

- The root is `--project` (made absolute) or the current directory, with no upward search;
  `snowflake.yml` there, merged (deep, mappings key by key) with `snowflake.local.yml` when both
  exist. It is read only when a statement has a template marker (`&{`, `<%`, `{{`), once, with
  `snow`'s 128 MB limit; a failure is `Failed to read snowflake.yml file: …`.
- YAML as PyYAML's `BaseLoader` reads it, with `saphyr-parser` (MIT/Apache-2.0) events: every
  scalar is a string, tags and merge keys are not interpreted, a repeated key is an error with
  `snow`'s message.
- `ctx.env.<name>` is `--env`, else the process environment variable, else the `env` section.
  `-D` variables are top-level names next to `ctx` and `fn` (never inside `ctx.env`).
- Definition 1.1 and 2: every `<% %>` value of the definition is rendered first, references
  between values followed recursively (`--env` and process variables used as they are), cycles
  and unknown or non-scalar references reported with `snow`'s messages; `fn.concat_ids`,
  `str_to_id`, `id_to_str`, `sanitize_id`, `get_username` are ported. Definition 1: values are
  not rendered, the `env` section is ignored, and `snow`'s warning is printed when a value looks
  templated.
- Validation stops at what decides the template context: `definition_version` (missing,
  unsupported, unparsable), the top-level keys each version accepts, and the type of the `env`
  values, with `snow`'s pydantic-shaped messages. The entity schemas are not validated
  (deviation 5): they belong to `snow object`/`snow app`.

## Decision 4: security

User input becomes SQL, so the engine must not reach further than `snow` does:

- No loader: templates cannot include other files. Only the two filters read files, after the
  path is resolved (symlinks included) and checked to be under the resolved project root; `~`
  expands to `$HOME` as in Python. Their errors match `snow`'s (outside the root, missing file,
  directory, over 128 MB).
- The process environment is reachable only as `ctx.env.<name>`, one variable at a time, as in
  `snow`; `ctx.env` cannot be iterated or printed whole (printing it shows only the `--env`
  overrides and the `env` section, as `snow`'s `ProjectEnvironment` repr does).
- No network access, no Python-style method calls, no attribute access other than mapping keys.
- A value is never rendered again by the same pass; with `ALL`, a STANDARD value that contains
  `{{ }}` is rendered by the JINJA pass, exactly as in `snow`.

## Decision 5: performance

Rendering is skipped for a statement without any marker (`&{` after the LEGACY transpilation,
`<%`, `{{`, `{%`, `{#`, or a `\r`), so templating that is on but unused costs a few string scans.
The comment placeholders of the JINJA pass are restored in one pass (`snow` replaces them one by
one). `tests/it/template_overhead.rs` (run by hand with `--release`) measures `compile` on 20,000
statements (1 MB): NONE 51 ms, default syntaxes without markers 54 ms, JINJA without markers
55 ms, a `<% n %>` in every statement 104 ms. End to end the difference disappears in the
network time (`bench/`: `multi-small-json` vs `templating-none-json`).

## Deviations from `snow` 3.34.0

1. Syntax and runtime errors other than the ones listed in Decision 2 keep `minijinja`'s wording
   (`snow` prints Jinja2's or Python's). The way they are reported (stdout text, feedback line,
   exit 1) is the same.
2. Builtins: Jinja2 filters missing from `minijinja` (`center`, `filesizeformat`,
   `forceescape`, `pprint`, `random`, `striptags`, `truncate`, `urlize`, `wordcount`,
   `wordwrap`, `xmlattr`) and globals (`lipsum`, `cycler`, `joiner`) are unknown filters or
   undefined names here; `minijinja`-only ones (`split`, `lines`, `bool`, `chain`, `zip`, …) are
   accepted where `snow` would fail.
3. `loop.index` and the other `loop` attributes work under JINJA; `snow`'s
   `IgnoreAttrEnvironment` makes them undefined (an error there).
4. Whole objects other than mappings, lists, scalars and `ctx.env` (for example `<% fn %>`)
   print differently; the type in an undefined message for a literal parent (`{'k': 1}['z']`)
   is inferred from the key.
5. `snowflake.yml`: entity schemas, `definition_version` 1.1 defaults other than `entities: {}`
   for version 2, the `!override` tag, and `snow`'s check that definition values use only names,
   attributes, calls and filters are not implemented; YAML syntax errors use `saphyr`'s wording.
6. `'x' in ctx.env` is not supported (`snow`'s `ProjectEnvironment` defines `__contains__`).
7. *(Amendment)* Config-file variables (below) are always strings: a `config.toml` number or
   boolean renders as Python's `str()` of it (`7`, `True`, `1.5`), but keeps no type for
   expressions such as `<% n + 1 %>`.

## Amendment: variables from the config files

`snow` 3.34.0 builds the top-level variables with `get_merged_variables(-D)`: the `variables`
section of its config provider, then `-D` over it. The default provider has no such section, so
the files only count with `SNOWFLAKE_CLI_CONFIG_V2_ENABLED` on (`1`, `true`, `yes`, `on`), and
then the alternative provider reads the SnowSQL INI files (`$SNOWFLAKE_HOME/config` when that
directory exists, else `/etc/snowsql.cnf`, `/etc/snowflake/snowsql.cnf`,
`/usr/local/etc/snowsql.cnf`, `~/.snowsql.cnf`, `~/.snowsql/config`, merged key by key with
`configparser`), then the first `config.toml` found (`--config-file`, else
`$SNOWFLAKE_HOME/config.toml` when that directory exists, else `./config.toml`, then
`~/.snowflake/config.toml`), whose `variables` replaces the whole section. A file open to
group/others (unless `SF_SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION` allows reading) or that fails to
parse is skipped; an interpolation error in a `connections…` or `variables` section drops all
SnowSQL files. `src/config/variables.rs` ports this, with the subset of `configparser` it needs
(sections, `=`/`:`, lowercased keys, comments, continuation lines, `DEFAULT`, `%%` and `%(name)s`).
`ctx.env` (`snowflake.yml`, `--env`) is unaffected. Only the variables follow the flag: this
crate does not read connections from SnowSQL files. Goldens: the `snowsql_*` and `config_toml_*`
cases of `tests/golden/template/`.

## Consequences

- `tests/golden/template/` holds 81 cases captured from the official CLI with
  `scripts/capture-template-goldens.sh` (no network: `snow sql` runs with statement execution
  replaced by a recorder); `tests/it/template_golden.rs` replays them: statements and stdout for
  the cases `snow` ran, the whole CLI output for the ones it stopped.
- New crates: `minijinja`, `saphyr-parser` (and `percent-encoding`, `indexmap` through it).
- `!source`/`!load` reuse `Templater::pre_render` for sourced files under JINJA.
