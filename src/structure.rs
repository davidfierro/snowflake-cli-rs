//! `snow --structure`: the JSON catalog of commands, arguments and options, in the shape snow
//! 3.34.0 prints, generated from the clap definitions so it cannot drift from them.

use clap::{Arg, ArgAction, Command};
use serde::Serialize;

/// One command or command group. Groups have `commands`, leaves have `arguments`/`options`;
/// the root has `options` and `commands`.
#[derive(Debug, Serialize)]
pub struct Node {
    pub name: String,
    pub help: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<Argument>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<Opt>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<Node>,
}

#[derive(Debug, Serialize)]
pub struct Argument {
    pub name: String,
    pub help: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Opt {
    pub name: String,
    pub help: String,
    pub required: bool,
    /// Long flag first, then the short one, then the aliases.
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

fn help_of(arg: &Arg) -> String {
    arg.get_long_help()
        .or_else(|| arg.get_help())
        .map(|h| h.to_string())
        .unwrap_or_default()
}

fn choices_of(arg: &Arg) -> Vec<String> {
    let upper = arg.is_ignore_case_set();
    arg.get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| {
            let name = v.get_name();
            if upper {
                name.to_uppercase()
            } else {
                name.to_string()
            }
        })
        .collect()
}

fn is_flag(arg: &Arg) -> bool {
    matches!(
        arg.get_action(),
        ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count
    )
}

fn option_of(arg: &Arg, id: String) -> Opt {
    let mut flags: Vec<String> = Vec::new();
    flags.extend(arg.get_long().map(|l| format!("--{l}")));
    flags.extend(arg.get_short().map(|s| format!("-{s}")));
    flags.extend(
        arg.get_visible_aliases()
            .into_iter()
            .flatten()
            .map(|a| format!("--{a}")),
    );
    let flag = is_flag(arg);
    let choices = choices_of(arg);
    let default = if flag {
        Some(serde_json::Value::Bool(false))
    } else {
        arg.get_default_values()
            .first()
            .map(|v| serde_json::Value::String(v.to_string_lossy().into_owned()))
    };
    Opt {
        name: id,
        help: help_of(arg),
        required: arg.is_required_set(),
        flags,
        is_flag: flag.then_some(true),
        default,
        choices,
    }
}

fn node_of(cmd: &Command, root: bool) -> Node {
    let subs: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|c| c.get_name() != "help" && !c.is_hide_set())
        .collect();
    let mut arguments = Vec::new();
    let mut options = Vec::new();
    // Groups list no options, except the root.
    if subs.is_empty() || root {
        // Global args are the root's, propagated to every command by clap: snow lists them once.
        for arg in cmd
            .get_arguments()
            .filter(|a| !a.is_hide_set() && (root || !a.is_global_set()))
        {
            let id = arg.get_id().as_str();
            if arg.is_positional() {
                arguments.push(Argument {
                    name: id.to_string(),
                    help: help_of(arg),
                    required: arg.is_required_set(),
                    choices: choices_of(arg),
                });
            } else if id == "help" {
                // snow lists `--help` for the root only, under the name `custom_help`.
                if root {
                    options.insert(
                        0,
                        Opt {
                            name: "custom_help".into(),
                            help: "Show this message and exit.".into(),
                            required: false,
                            flags: vec!["--help".into(), "-h".into()],
                            is_flag: Some(true),
                            default: None,
                            choices: Vec::new(),
                        },
                    );
                }
            } else {
                options.push(option_of(arg, id.to_string()));
            }
        }
    }
    let help = cmd
        .get_long_about()
        .or_else(|| cmd.get_about())
        .map(|h| h.to_string())
        .unwrap_or_default();
    Node {
        name: cmd.get_name().to_string(),
        help,
        arguments,
        options,
        commands: subs.into_iter().map(|c| node_of(c, false)).collect(),
    }
}

/// The catalog of `root` (a clap command, built here).
pub fn catalog(root: &Command) -> Node {
    let mut root = root.clone();
    root.build();
    node_of(&root, true)
}

/// `json.dumps(catalog, indent=4)` plus a newline.
pub fn to_json(node: &Node) -> String {
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    // Serializing plain structs of strings into a Vec cannot fail.
    if node.serialize(&mut ser).is_err() {
        return String::new();
    }
    let mut text = String::from_utf8_lossy(&out).into_owned();
    text.push('\n');
    text
}
