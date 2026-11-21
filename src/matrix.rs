//! The command/option compatibility matrix of the README.
//!
//! [`render`] is a pure function from the snapshot of the official snow
//! (`docs/snow-surface.json`), the ported surface read from the clap tree ([`ported_surface`])
//! and the benchmark results (`bench/results.json`) to Markdown. `tests/command_matrix.rs`
//! compares it with the README.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const START_MARKER: &str = "<!-- command-matrix:start -->";
pub const END_MARKER: &str = "<!-- command-matrix:end -->";

/// Sign-in methods (`authenticator` values). They are not options, so they get their own table;
/// "mock-tested only" means covered by mocked-server tests but not yet run against Snowflake.
/// The password and PAT rows become "ported" once their live tests run against the sandbox
/// extension of ADR 0005 Decision 8.
pub const AUTHENTICATORS: [(&str, &str); 11] = [
    ("SNOWFLAKE_JWT", "ported"),
    ("OAUTH", "ported, mock-tested only"),
    ("PROGRAMMATIC_ACCESS_TOKEN", "ported, mock-tested only"),
    ("WORKLOAD_IDENTITY", "ported, mock-tested only"),
    ("SNOWFLAKE (password)", "ported, mock-tested only"),
    (
        "SNOWFLAKE with an MFA passcode or Duo push",
        "ported, mock-tested only",
    ),
    ("USERNAME_PASSWORD_MFA", "ported, mock-tested only"),
    ("EXTERNALBROWSER", "ported, mock-tested only"),
    ("OAUTH_AUTHORIZATION_CODE", "ported, mock-tested only"),
    ("OAUTH_CLIENT_CREDENTIALS", "ported, mock-tested only"),
    (
        "https://<okta_account>.okta.com",
        "ported, mock-tested only",
    ),
];

/// `sql` statements the SQL API cannot run, so they need a connector session (ADR 0005). The stage's
/// cloud decides how the files move; the sandbox only has AWS.
pub const SESSION_STATEMENTS: [(&str, &str); 3] = [
    ("PUT / GET, stage on AWS S3", "ported"),
    ("PUT / GET, stage on Azure", "ported, mock-tested only"),
    (
        "PUT / GET, stage on Google Cloud Storage",
        "ported, mock-tested only",
    ),
];

/// One option of the official snow: its first long flag and every flag it answers to.
#[derive(Debug, Clone, Deserialize)]
pub struct SnowOption {
    pub name: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnowCommand {
    pub path: Vec<String>,
    /// Every option the command accepts, the shared (global) ones included.
    pub options: Vec<SnowOption>,
}

/// `docs/snow-surface.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub snow_version: String,
    pub global_options: Vec<SnowOption>,
    pub commands: Vec<SnowCommand>,
}

/// Median wall time and peak RSS of one CLI on one scenario.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Measure {
    pub median_s: f64,
    pub peak_rss_kib: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scenario {
    pub name: String,
    /// The command the scenario measures, as a path (`connection list`, `sql`).
    pub command: String,
    pub date: String,
    pub snow_version: String,
    pub rs: Measure,
    /// `None` when the scenario is not compared with the official snow.
    pub snow: Option<Measure>,
}

/// `bench/results.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Results {
    pub scenarios: Vec<Scenario>,
}

/// What this CLI accepts, read from its clap definition.
#[derive(Debug, Clone, Default)]
pub struct Ported {
    /// Every flag (`--long`, `-s`) accepted by at least one command, and the root.
    pub all_flags: BTreeSet<String>,
    /// Flags of the root command itself (`--version`, `--info`, …), global ones included.
    pub root_flags: BTreeSet<String>,
    /// Leaf commands by path, with the flags each accepts.
    pub commands: BTreeMap<Vec<String>, BTreeSet<String>>,
}

fn flags_of(cmd: &clap::Command) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() || arg.get_id() == "help" {
            continue;
        }
        let longs = arg
            .get_long()
            .into_iter()
            .chain(arg.get_all_aliases().into_iter().flatten());
        flags.extend(longs.map(|l| format!("--{l}")));
        let shorts = arg
            .get_short()
            .into_iter()
            .chain(arg.get_all_short_aliases().into_iter().flatten());
        flags.extend(shorts.map(|s| format!("-{s}")));
    }
    flags
}

fn collect(cmd: &clap::Command, path: &mut Vec<String>, out: &mut Ported) {
    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|c| c.get_name() != "help" && !c.is_hide_set())
        .collect();
    if subs.is_empty() {
        let flags = flags_of(cmd);
        out.all_flags.extend(flags.iter().cloned());
        out.commands.insert(path.clone(), flags);
    }
    for sub in subs {
        path.push(sub.get_name().to_string());
        collect(sub, path, out);
        path.pop();
    }
}

/// Reads the ported commands and options from a clap command tree (read-only introspection).
pub fn ported_surface(root: &clap::Command) -> Ported {
    let mut root = root.clone();
    root.build();
    let root_flags = flags_of(&root);
    let mut out = Ported {
        all_flags: root_flags.clone(),
        root_flags,
        ..Ported::default()
    };
    collect(&root, &mut Vec::new(), &mut out);
    // The root itself is a leaf only when the CLI has no subcommand.
    out.commands.remove(&Vec::new());
    out
}

fn is_ported(option: &SnowOption, flags: &BTreeSet<String>) -> bool {
    option.flags.iter().any(|f| flags.contains(f))
}

/// Commands that are ported but absent from the snapshot (a typo or a command snow does not
/// have): the matrix cannot place them.
fn unknown_commands(snapshot: &Snapshot, ported: &Ported) -> Vec<String> {
    let known: BTreeSet<_> = snapshot.commands.iter().map(|c| &c.path).collect();
    ported
        .commands
        .keys()
        .filter(|p| !known.contains(p))
        .map(|p| p.join(" "))
        .collect()
}

/// The command paths that `bench/run.sh` declares a scenario for: the second field of each
/// `command_scenarios` line, `sql` for the `sql_scenarios` block, and the command argument of each
/// literal `run_scenario <name> <command> …` call.
pub fn declared_commands(run_sh: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut block = None;
    for line in run_sh.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("command_scenarios=\"") {
            block = Some(true);
            if let Some(command) = rest.split('|').nth(1) {
                out.insert(command.to_string());
            }
        } else if line.starts_with("sql_scenarios=\"") {
            block = Some(false);
            out.insert("sql".to_string());
        } else if block == Some(true) {
            if let Some(command) = line.split('|').nth(1) {
                out.insert(command.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("run_scenario ") {
            let after_name = rest.split_once(' ').map_or("", |(_, r)| r);
            let command = match after_name.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next().unwrap_or(""),
                None => after_name.split(' ').next().unwrap_or(""),
            };
            if !command.is_empty() && !command.starts_with('$') {
                out.insert(command.to_string());
            }
        }
        if block.is_some() && line.ends_with('"') {
            block = None;
        }
    }
    out
}

/// Ported commands with no benchmark scenario: none in `results` and none declared in
/// `bench/run.sh` (`declared`, see [`declared_commands`]). A declared scenario without results
/// yet is fine; maintainers run it and commit the results.
pub fn unbenchmarked(
    ported: &Ported,
    results: &Results,
    declared: &BTreeSet<String>,
) -> Vec<String> {
    ported
        .commands
        .keys()
        .map(|p| p.join(" "))
        .filter(|name| {
            !declared.contains(name) && !results.scenarios.iter().any(|s| &s.command == name)
        })
        .collect()
}

fn ratio_text(r: f64) -> String {
    if r >= 10.0 {
        format!("{r:.0}")
    } else {
        format!("{r:.1}")
    }
}

fn time_text(s: f64) -> String {
    if s >= 1.0 {
        format!("{s:.2} s")
    } else {
        format!("{:.0} ms", s * 1000.0)
    }
}

fn mib_text(kib: u64) -> String {
    let mib = kib as f64 / 1024.0;
    if mib >= 10.0 {
        format!("{mib:.0} MiB")
    } else {
        format!("{mib:.1} MiB")
    }
}

/// `27× faster (158 ms vs 4.30 s)`, or `slower` when this CLI is the slower one.
fn time_cell(rs: &Measure, snow: &Measure) -> String {
    let (word, r) = if snow.median_s >= rs.median_s {
        ("faster", snow.median_s / rs.median_s)
    } else {
        ("slower", rs.median_s / snow.median_s)
    };
    format!(
        "{}× {word} ({} vs {})",
        ratio_text(r),
        time_text(rs.median_s),
        time_text(snow.median_s)
    )
}

/// `12× less (13 MiB vs 162 MiB)`, or `more`.
fn memory_cell(rs: &Measure, snow: &Measure) -> String {
    let (word, r) = if snow.peak_rss_kib >= rs.peak_rss_kib {
        ("less", snow.peak_rss_kib as f64 / rs.peak_rss_kib as f64)
    } else {
        ("more", rs.peak_rss_kib as f64 / snow.peak_rss_kib as f64)
    };
    format!(
        "{}× {word} ({} vs {})",
        ratio_text(r),
        mib_text(rs.peak_rss_kib),
        mib_text(snow.peak_rss_kib)
    )
}

fn code_list(names: &[&str]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

struct Row {
    name: String,
    status: &'static str,
    total: usize,
    done: usize,
    missing: Vec<String>,
}

/// The options of `cmd` that are not shared (`global`): the command's own options.
fn own_options<'a>(cmd: &'a SnowCommand, global: &'a BTreeSet<&str>) -> Vec<&'a SnowOption> {
    cmd.options
        .iter()
        .filter(|o| !global.contains(o.name.as_str()))
        .collect()
}

/// One row of the per-command tables. Only the command's own options are counted: the shared
/// ones are reported once, in the "Global options" table.
fn row(cmd: &SnowCommand, ported: &Ported, global: &BTreeSet<&str>) -> Row {
    let name = cmd.path.join(" ");
    let own = own_options(cmd, global);
    let total = own.len();
    match ported.commands.get(&cmd.path) {
        None => Row {
            name,
            status: "not ported",
            total,
            done: 0,
            missing: Vec::new(),
        },
        Some(flags) => {
            let missing: Vec<String> = own
                .iter()
                .filter(|o| !is_ported(o, flags))
                .map(|o| o.name.clone())
                .collect();
            Row {
                name,
                status: if missing.is_empty() {
                    "ported"
                } else {
                    "partial"
                },
                total,
                done: total - missing.len(),
                missing,
            }
        }
    }
}

/// Status of one shared option across the ported commands of the official snow: `ported` when
/// every ported command that takes it accepts it, `partial (k/n)` naming the ones that lack it,
/// `not ported` when none accepts it.
fn global_status(option: &SnowOption, snapshot: &Snapshot, ported: &Ported) -> String {
    let (mut taking, mut accepting, mut lacking) = (0, 0, Vec::new());
    for cmd in &snapshot.commands {
        let Some(flags) = ported.commands.get(&cmd.path) else {
            continue;
        };
        if !cmd.options.iter().any(|o| o.name == option.name) {
            continue;
        }
        taking += 1;
        if is_ported(option, flags) {
            accepting += 1;
        } else {
            lacking.push(cmd.path.join(" "));
        }
    }
    if taking == 0 {
        // No ported command takes it: a root option (`--version`, `--info`, …), or one of
        // snow's own commands that is not ported.
        if is_ported(option, &ported.root_flags) {
            "ported".into()
        } else {
            "not ported".into()
        }
    } else if accepting == 0 {
        "not ported".into()
    } else if lacking.is_empty() {
        "ported".into()
    } else {
        let names: Vec<&str> = lacking.iter().map(String::as_str).collect();
        format!(
            "partial ({accepting}/{taking}) without {}",
            code_list(&names)
        )
    }
}

/// Renders the matrix (everything between the README markers, markers excluded).
pub fn render(snapshot: &Snapshot, ported: &Ported, results: &Results) -> Result<String, String> {
    let unknown = unknown_commands(snapshot, ported);
    if !unknown.is_empty() {
        return Err(format!(
            "ported commands missing from docs/snow-surface.json: {}",
            unknown.join(", ")
        ));
    }
    let global: BTreeSet<&str> = snapshot
        .global_options
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    let rows: Vec<(&SnowCommand, Row)> = snapshot
        .commands
        .iter()
        .map(|c| (c, row(c, ported, &global)))
        .collect();
    let ported_rows: Vec<&Row> = rows
        .iter()
        .map(|(_, r)| r)
        .filter(|r| r.status != "not ported")
        .collect();
    let mut out = String::new();
    out.push_str(&format!(
        "**Commands ported: {}/{}.** Options ported per ported command: {}.\n\n",
        ported_rows.len(),
        rows.len(),
        ported_rows
            .iter()
            .map(|r| format!("`{}` {}/{}", r.name, r.done, r.total))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut groups: Vec<&str> = Vec::new();
    for (c, _) in &rows {
        if groups.last() != Some(&c.path[0].as_str()) {
            groups.push(&c.path[0]);
        }
    }
    for group in groups {
        out.push_str(&format!(
            "### `{group}`\n\n| Command | Status | Options ported | Missing options | Time vs snow | Memory vs snow |\n|---|---|---|---|---|---|\n"
        ));
        for (_, r) in rows.iter().filter(|(c, _)| c.path[0] == group) {
            let (time, memory) = match representative(&r.name, results) {
                Some(s) => s
                    .snow
                    .map(|snow| (time_cell(&s.rs, &snow), memory_cell(&s.rs, &snow)))
                    .unwrap_or_default(),
                None if r.status != "not ported" => {
                    ("not benchmarked".to_string(), "not benchmarked".to_string())
                }
                None => Default::default(),
            };
            let missing = code_list(&r.missing.iter().map(String::as_str).collect::<Vec<_>>());
            out.push_str(&format!(
                "| `{}` | {} | {}/{} | {} | {} | {} |\n",
                r.name, r.status, r.done, r.total, missing, time, memory
            ));
        }
        out.push('\n');
    }
    out.push_str("### Authenticators\n\nThe `authenticator` values of a connection. \"mock-tested only\": covered by tests against a mocked server, not yet run against Snowflake. The temporary credential cache (ID, MFA and OAuth tokens) is the connector's file cache on every OS, where `snow` uses the keychain on macOS and Windows (ADR 0005, Decision 3).\n\n| Authenticator | Status |\n|---|---|\n");
    for (name, status) in AUTHENTICATORS {
        out.push_str(&format!("| `{name}` | {status} |\n"));
    }
    out.push('\n');
    out.push_str("### `sql` statements that need a session\n\nThe SQL API cannot run them, so a run that has one signs in with the connector protocol and runs every statement on that session (ADR 0005).\n\n| Statement | Status |\n|---|---|\n");
    for (name, status) in SESSION_STATEMENTS {
        out.push_str(&format!("| {name} | {status} |\n"));
    }
    out.push('\n');
    out.push_str("### Global options\n\nOutput, logging and connection options that most commands share, plus the root options. Their status covers the ported commands that take them in snow: `partial (k/n)` means k of n accept the option, and names the ones that do not.\n\n| Option | Status |\n|---|---|\n");
    for o in &snapshot.global_options {
        out.push_str(&format!(
            "| `{}` | {} |\n",
            o.name,
            global_status(o, snapshot, ported)
        ));
    }
    out.push('\n');
    out.push_str(&scenario_section(snapshot, results));
    Ok(out)
}

/// The first scenario listed for the command.
fn representative<'a>(command: &str, results: &'a Results) -> Option<&'a Scenario> {
    results.scenarios.iter().find(|s| s.command == command)
}

fn scenario_section(snapshot: &Snapshot, results: &Results) -> String {
    let mut out = String::from(
        "### Benchmark scenarios\n\n| Scenario | Command | snow-rs median | snow median | snow-rs peak RSS | snow peak RSS |\n|---|---|---|---|---|---|\n",
    );
    for s in &results.scenarios {
        let (snow_time, snow_rss) = s
            .snow
            .map(|m| (time_text(m.median_s), mib_text(m.peak_rss_kib)))
            .unwrap_or_else(|| ("—".into(), "—".into()));
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} |\n",
            s.name,
            s.command,
            time_text(s.rs.median_s),
            snow_time,
            mib_text(s.rs.peak_rss_kib),
            snow_rss
        ));
    }
    let date = results.scenarios.iter().map(|s| s.date.as_str()).max();
    let versions: BTreeSet<&str> = results
        .scenarios
        .iter()
        .map(|s| s.snow_version.as_str())
        .collect();
    out.push_str(&format!(
        "\nCommands and options: snow {}. Benchmarks: {} against snow {}.\n",
        snapshot.snow_version,
        date.unwrap_or("not run"),
        versions.into_iter().collect::<Vec<_>>().join(", ")
    ));
    out
}

/// Replaces what is between the markers of `readme` with `matrix`.
pub fn splice(readme: &str, matrix: &str) -> Result<String, String> {
    let (before, rest) = readme
        .split_once(START_MARKER)
        .ok_or_else(|| format!("README has no {START_MARKER} marker"))?;
    let (_, after) = rest
        .split_once(END_MARKER)
        .ok_or_else(|| format!("README has no {END_MARKER} marker after the start marker"))?;
    Ok(format!(
        "{before}{START_MARKER}\n\n{matrix}{END_MARKER}{after}"
    ))
}

/// A readable line diff (`-` expected, `+` found) of the first differences; empty when equal.
pub fn diff(expected: &str, actual: &str) -> String {
    let (e, a): (Vec<&str>, Vec<&str>) = (expected.lines().collect(), actual.lines().collect());
    let mut out = String::new();
    let mut shown = 0;
    for i in 0..e.len().max(a.len()) {
        let (x, y) = (e.get(i), a.get(i));
        if x == y {
            continue;
        }
        if shown == 20 {
            out.push_str("… more differences\n");
            break;
        }
        shown += 1;
        out.push_str(&format!("line {}:\n", i + 1));
        if let Some(x) = x {
            out.push_str(&format!("- {x}\n"));
        }
        if let Some(y) = y {
            out.push_str(&format!("+ {y}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command};
    use std::collections::BTreeMap;

    fn opt(name: &str, flags: &[&str]) -> SnowOption {
        SnowOption {
            name: name.into(),
            flags: flags.iter().map(|f| (*f).into()).collect(),
        }
    }

    fn cmd(path: &[&str], options: Vec<SnowOption>) -> SnowCommand {
        SnowCommand {
            path: path.iter().map(|p| (*p).into()).collect(),
            options,
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            snow_version: "9.9.9".into(),
            global_options: vec![opt("--format", &["--format"]), opt("--info", &["--info"])],
            commands: vec![
                cmd(
                    &["grp", "full"],
                    vec![
                        opt("--format", &["--format"]),
                        opt("--all", &["--all", "-a"]),
                        opt("--x", &["--x"]),
                    ],
                ),
                cmd(
                    &["grp", "half"],
                    vec![
                        opt("--format", &["--format"]),
                        opt("--p", &["--p"]),
                        opt("--q", &["--q"]),
                    ],
                ),
                cmd(&["grp", "none"], vec![opt("--z", &["--z"])]),
                cmd(&["solo"], vec![]),
            ],
        }
    }

    fn clap_tree() -> Command {
        Command::new("snow")
            .arg(Arg::new("format").long("format").global(true))
            .subcommand(
                Command::new("grp")
                    .subcommand(
                        Command::new("full")
                            .arg(
                                Arg::new("all")
                                    .short('a')
                                    .long("all")
                                    .action(ArgAction::SetTrue),
                            )
                            .arg(Arg::new("x").long("xx").alias("x"))
                            .arg(Arg::new("secret").long("secret").hide(true)),
                    )
                    .subcommand(Command::new("half").arg(Arg::new("p").long("p"))),
            )
    }

    fn measure(s: f64, kib: u64) -> Measure {
        Measure {
            median_s: s,
            peak_rss_kib: kib,
        }
    }

    fn scenario(name: &str, command: &str, rs: Measure, snow: Option<Measure>) -> Scenario {
        Scenario {
            name: name.into(),
            command: command.into(),
            date: "2026-01-02".into(),
            snow_version: "9.9.9".into(),
            rs,
            snow,
        }
    }

    fn results() -> Results {
        Results {
            scenarios: vec![
                scenario(
                    "full-a",
                    "grp full",
                    measure(0.158, 13 * 1024),
                    Some(measure(4.3, 162 * 1024)),
                ),
                scenario("full-b", "grp full", measure(1.0, 1024), None),
                scenario(
                    "half",
                    "grp half",
                    measure(2.0, 20 * 1024),
                    Some(measure(1.0, 10 * 1024)),
                ),
            ],
        }
    }

    #[test]
    fn surface_reads_commands_and_flags_from_clap() {
        let p = ported_surface(&clap_tree());
        let full = &p.commands[&vec!["grp".to_string(), "full".to_string()]];
        assert!(
            ["--all", "-a", "--xx", "--x", "--format"]
                .iter()
                .all(|f| full.contains(*f))
        );
        assert!(!full.contains("--secret") && !full.contains("--help"));
        assert_eq!(p.commands.len(), 2);
        assert!(p.all_flags.contains("--p"));
    }

    #[test]
    fn surface_of_a_cli_without_subcommands_has_no_commands() {
        assert!(ported_surface(&Command::new("snow")).commands.is_empty());
    }

    #[test]
    fn render_reports_status_options_and_benchmarks() {
        let md = render(&snapshot(), &ported_surface(&clap_tree()), &results()).unwrap();
        assert!(md.contains("**Commands ported: 2/4.**"), "{md}");
        assert!(md.contains("`grp full` 2/2, `grp half` 1/2"));
        assert!(md.contains(
            "| `grp full` | ported | 2/2 |  | 27× faster (158 ms vs 4.30 s) | 12× less (13 MiB vs 162 MiB) |"
        ));
        assert!(md.contains("| `grp half` | partial | 1/2 | `--q` | 2.0× slower (2.00 s vs 1.00 s) | 2.0× more (20 MiB vs 10 MiB) |"));
        assert!(md.contains("| `grp none` | not ported | 0/1 |  |  |  |"));
        assert!(md.contains("| `solo` | not ported | 0/0 |  |  |  |"));
        assert!(md.contains("### `solo`"));
        assert!(md.contains("| `--format` | ported |"));
        assert!(md.contains("| `--info` | not ported |"));
        assert!(md.contains("### Authenticators"));
        assert!(md.contains("| `OAUTH` | ported, mock-tested only |"));
        assert!(md.contains("| `EXTERNALBROWSER` | ported, mock-tested only |"));
        assert!(md.find("### Authenticators") < md.find("### Global options"));
        assert!(md.contains("| PUT / GET, stage on AWS S3 | ported |"));
        assert!(md.contains("| PUT / GET, stage on Azure | ported, mock-tested only |"));
        assert!(
            md.find("### Authenticators") < md.find("### `sql` statements that need a session")
        );
        assert!(md.contains("| `full-b` | `grp full` | 1.00 s | — | 1.0 MiB | — |"));
        assert!(md.contains(
            "Commands and options: snow 9.9.9. Benchmarks: 2026-01-02 against snow 9.9.9."
        ));
    }

    #[test]
    fn render_counts_only_own_options_and_reports_global_status() {
        let format = opt("--format", &["--format"]);
        let snap = Snapshot {
            snow_version: "9.9.9".into(),
            global_options: vec![format.clone()],
            commands: vec![
                cmd(
                    &["grp", "full"],
                    vec![format.clone(), opt("--all", &["--all"])],
                ),
                cmd(
                    &["grp", "half"],
                    vec![format, opt("--p", &["--p"]), opt("--q", &["--q"])],
                ),
            ],
        };
        let ported = Ported {
            all_flags: ["--format", "--all", "--p"].map(String::from).into(),
            root_flags: BTreeSet::new(),
            commands: BTreeMap::from([
                (
                    vec!["grp".to_string(), "full".to_string()],
                    ["--format", "--all"].map(String::from).into(),
                ),
                (
                    vec!["grp".to_string(), "half".to_string()],
                    ["--p"].map(String::from).into(),
                ),
            ]),
        };
        let md = render(&snap, &ported, &Results { scenarios: vec![] }).unwrap();
        assert!(md.contains(
            "**Commands ported: 2/2.** Options ported per ported command: `grp full` 1/1, `grp half` 1/2."
        ));
        // The shared `--format` is not a missing option of `grp half`; only `--q` is.
        assert!(md.contains("| `grp full` | ported | 1/1 |  |"), "{md}");
        assert!(
            md.contains("| `grp half` | partial | 1/2 | `--q` |"),
            "{md}"
        );
        assert!(
            md.contains("| `--format` | partial (1/2) without `grp half` |"),
            "{md}"
        );
    }

    #[test]
    fn global_option_is_ported_or_not_ported_when_every_or_no_command_accepts_it() {
        let all = opt("--all", &["--all"]);
        let snap = Snapshot {
            snow_version: "9.9.9".into(),
            global_options: vec![all.clone(), opt("--none", &["--none"])],
            commands: vec![
                cmd(
                    &["grp", "full"],
                    vec![all.clone(), opt("--none", &["--none"])],
                ),
                cmd(&["grp", "other"], vec![all]),
            ],
        };
        let ported = Ported {
            all_flags: ["--all"].map(String::from).into(),
            root_flags: BTreeSet::new(),
            commands: BTreeMap::from([
                (
                    vec!["grp".to_string(), "full".to_string()],
                    ["--all"].map(String::from).into(),
                ),
                (
                    vec!["grp".to_string(), "other".to_string()],
                    ["--all"].map(String::from).into(),
                ),
            ]),
        };
        let md = render(&snap, &ported, &Results { scenarios: vec![] }).unwrap();
        assert!(md.contains("| `--all` | ported |"), "{md}");
        assert!(md.contains("| `--none` | not ported |"), "{md}");
    }

    #[test]
    fn root_options_are_ported_when_the_root_accepts_them() {
        let snap = Snapshot {
            snow_version: "9.9.9".into(),
            global_options: vec![opt("--info", &["--info"]), opt("--other", &["--other"])],
            commands: vec![cmd(&["grp", "full"], vec![])],
        };
        let ported = Ported {
            root_flags: ["--info"].map(String::from).into(),
            commands: BTreeMap::from([(
                vec!["grp".to_string(), "full".to_string()],
                BTreeSet::new(),
            )]),
            ..Ported::default()
        };
        let md = render(&snap, &ported, &Results { scenarios: vec![] }).unwrap();
        assert!(md.contains("| `--info` | ported |"), "{md}");
        assert!(md.contains("| `--other` | not ported |"), "{md}");
    }

    #[test]
    fn render_rejects_a_ported_command_snow_does_not_have() {
        let mut snap = snapshot();
        snap.commands
            .retain(|c| c.path.last().map(String::as_str) != Some("half"));
        let err = render(&snap, &ported_surface(&clap_tree()), &results()).unwrap_err();
        assert!(err.contains("grp half"), "{err}");
    }

    #[test]
    fn render_without_results_says_so() {
        let md = render(
            &snapshot(),
            &Ported::default(),
            &Results { scenarios: vec![] },
        )
        .unwrap();
        assert!(md.contains("Benchmarks: not run"));
    }

    #[test]
    fn unbenchmarked_lists_ported_commands_without_scenario() {
        let ported = ported_surface(&clap_tree());
        let none = BTreeSet::new();
        assert!(unbenchmarked(&ported, &results(), &none).is_empty());
        let mut r = results();
        r.scenarios.retain(|s| s.command != "grp half");
        assert_eq!(
            unbenchmarked(&ported, &r, &none),
            vec!["grp half".to_string()]
        );
    }

    #[test]
    fn a_declared_scenario_without_results_is_not_missing_and_renders_not_benchmarked() {
        let ported = ported_surface(&clap_tree());
        let mut r = results();
        r.scenarios.retain(|s| s.command != "grp half");
        let declared: BTreeSet<String> = ["grp half".to_string()].into();
        assert!(unbenchmarked(&ported, &r, &declared).is_empty());
        let md = render(&snapshot(), &ported, &r).unwrap();
        let row = md
            .lines()
            .find(|l| l.starts_with("| `grp half` |"))
            .unwrap();
        assert!(
            row.ends_with("| not benchmarked | not benchmarked |"),
            "{row}"
        );
        let none = md
            .lines()
            .find(|l| l.starts_with("| `grp none` |"))
            .unwrap();
        assert!(!none.contains("not benchmarked"), "{none}");
    }

    #[test]
    fn declared_commands_reads_every_kind_of_scenario_declaration() {
        let run_sh = r##"
# run_scenario commented connection
run_scenario() {
    local name=$1 command=$2
}
command_scenarios="a-one|grp one|grp one --x|true
a-two|--info|--info|true"
while IFS='|' read -r name command args prepare; do
    run_scenario "$name" "$command" yes "$args"
done <<< "$command_scenarios"
        run_scenario pw "connection test" yes "$rs_snow $args"
sql_scenarios="trivial-json json trivial yes
other json x no"
    run_scenario repl-startup sql yes "$driver"
"##;
        let got = declared_commands(run_sh);
        let want: BTreeSet<String> = ["grp one", "--info", "connection test", "sql"]
            .map(String::from)
            .into();
        assert_eq!(got, want);
    }

    #[test]
    fn declared_commands_of_the_real_script_cover_the_ported_commands() {
        let run_sh = include_str!("../bench/run.sh");
        let declared = declared_commands(run_sh);
        for c in ["connection list", "sql", "--info", "connection test"] {
            assert!(declared.contains(c), "{c}");
        }
    }

    #[test]
    fn splice_replaces_between_markers() {
        let readme = format!("a\n{START_MARKER}\nold\n{END_MARKER}\nb\n");
        let out = splice(&readme, "new\n").unwrap();
        assert_eq!(out, format!("a\n{START_MARKER}\n\nnew\n{END_MARKER}\nb\n"));
        assert_eq!(splice(&out, "new\n").unwrap(), out);
        assert!(splice("nothing", "x").is_err());
        assert!(splice(&format!("{START_MARKER} only"), "x").is_err());
    }

    #[test]
    fn diff_shows_changed_added_and_removed_lines() {
        assert_eq!(diff("a\nb\n", "a\nb\n"), "");
        assert_eq!(diff("a\nb\n", "a\nc\n"), "line 2:\n- b\n+ c\n");
        assert_eq!(diff("a\n", "a\nb\n"), "line 2:\n+ b\n");
        assert_eq!(diff("a\nb\n", "a\n"), "line 2:\n- b\n");
        let many_e = "x\n".repeat(30);
        let many_a = "y\n".repeat(30);
        assert!(diff(&many_e, &many_a).ends_with("… more differences\n"));
    }
}
