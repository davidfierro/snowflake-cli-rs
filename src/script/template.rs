//! Client-side templating of `snow sql` input (ADR 0004 Decision 6, ADR 0006), as `snow` 3.34.0
//! does it in `api/rendering/sql_templates.py`, `api/rendering/jinja.py`,
//! `_plugins/sql/snowsql_templating.py` and `_plugins/sql/manager.py`, with `minijinja` as the
//! Jinja engine.
//!
//! - LEGACY: `string.Template` with delimiter `&` turns `&name` and `&{name}` into `&{ name }`,
//!   which a Jinja environment with `&{` / `}` as variable delimiters then renders. STANDARD is
//!   the same environment with `<%` / `%>`. Both have Jinja's `{# … #}` comments and no blocks.
//!   With both enabled, the syntax present in the text picks the environment and mixing them is
//!   an error. JINJA is a default Jinja environment (`{{ }}`, `{% %}`, `{# #}`) run after them.
//! - Inside the delimiters is a full Jinja expression (filters, literals, operators, `ctx`,
//!   `fn`), with attribute access limited to mapping keys (no methods), undefined values an
//!   error, and the `read_file_content` / `procedure_from_js_file` filters confined to the
//!   project root.
//! - Without JINJA each statement is rendered on its own between the two splits and undefined
//!   variables are collected; with JINJA each input is rendered whole, comments protected,
//!   before the split, and any error stops the run.

use crate::env::Env;
use crate::project::{self, PROJECT_ENV_TYPE, ProjectEnv, ProjectSource};
use crate::script::py_repr;
use minijinja::syntax::SyntaxConfig;
use minijinja::value::{Value, ValueKind};
use minijinja::{Environment, ErrorKind as MjKind, UndefinedBehavior};
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// The `-D key=value` variables.
pub type Variables = BTreeMap<String, String>;

/// The enabled syntaxes. `Default` is `snow`'s: LEGACY and STANDARD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syntaxes {
    pub legacy: bool,
    pub standard: bool,
    pub jinja: bool,
}

impl Default for Syntaxes {
    fn default() -> Self {
        Self {
            legacy: true,
            standard: true,
            jinja: false,
        }
    }
}

pub const LEGACY_WARNING: &str = "Warning: &{ ... } syntax is deprecated and will no longer be supported. Use <% ... %> syntax instead.";

/// A template error, classified by how `snow` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// `jinja2.UndefinedError`: collected per statement (`SQL template rendering error: …`), or
    /// an unexpected exception under JINJA.
    Undefined(String),
    /// A click exception: an `Error` panel; `feedback` when `snow` adds its feedback line (its
    /// own error classes, not plain `ClickException`).
    Cli { message: String, feedback: bool },
    /// `snowflake.yml` could not be read (`CliArgumentError`): a panel, enhanced exit code 2.
    Project(String),
    /// Any other exception: `An unexpected exception occurred. …`.
    Unexpected(String),
}

/// The marker a filter or function attaches to a `minijinja` error to make it a [`TemplateError::Cli`].
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct CliFailure {
    message: String,
    feedback: bool,
}

/// The marker for an error `snow` raises as a plain Python exception.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct PythonFailure(String);

/// An error a template function raises as one of `snow`'s click exceptions.
pub fn cli_error(message: String, feedback: bool) -> minijinja::Error {
    minijinja::Error::new(MjKind::InvalidOperation, message.clone())
        .with_source(CliFailure { message, feedback })
}

fn python_error(message: String) -> minijinja::Error {
    minijinja::Error::new(MjKind::InvalidOperation, message.clone())
        .with_source(PythonFailure(message))
}

const NO_BLOCKS: &str = "___very___unique___block___to___disable___logic___blocks___";

fn base_env(root: &Path, env: &Env, syntax: SyntaxConfig, jinja: bool) -> Environment<'static> {
    let mut e = Environment::new();
    e.set_undefined_behavior(UndefinedBehavior::Strict);
    e.set_syntax(syntax);
    let home = env.get("HOME").map(PathBuf::from);
    let root = root.to_path_buf();
    {
        let (root, home) = (root.clone(), home.clone());
        e.add_filter("read_file_content", move |file: String| {
            read_in_root(&root, home.as_deref(), &file, "read_file_content")
        });
    }
    e.add_filter("procedure_from_js_file", move |file: String| {
        let code = read_in_root(&root, home.as_deref(), &file, "procedure_from_js_file")?;
        // snow renders its wrapper with the calling environment, so `{{ code }}` is only
        // replaced where `{{ }}` is the variable syntax.
        let code_slot = if jinja { code.as_str() } else { "{{ code }}" };
        Ok(format!(
            "var module = {{}};\nvar exports = {{}};\nmodule.exports = exports;\n(function() {{\n{code_slot}\n}})()\nreturn module.exports.apply(this, arguments);\n"
        ))
    });
    e
}

fn delimited_env(
    root: &Path,
    env: &Env,
    start: &'static str,
    end: &'static str,
) -> Environment<'static> {
    let syntax = SyntaxConfig::builder()
        .block_delimiters(NO_BLOCKS, NO_BLOCKS)
        .variable_delimiters(start, end)
        .keep_trailing_newline(true)
        .build();
    // The delimiters are constants that do not clash.
    base_env(root, env, syntax.unwrap_or_default(), false)
}

/// The `<% %>` environment `snow` also uses for `snowflake.yml` values.
pub fn client_engine(root: &Path, env: &Env) -> Environment<'static> {
    delimited_env(root, env, "<%", "%>")
}

fn jinja_engine(root: &Path, env: &Env) -> Environment<'static> {
    let syntax = SyntaxConfig::builder().keep_trailing_newline(true).build();
    base_env(root, env, syntax.unwrap_or_default(), true)
}

/// `read_file_content` / `procedure_from_js_file`: a file under the project root.
fn read_in_root(
    root: &Path,
    home: Option<&Path>,
    file: &str,
    filter: &str,
) -> Result<String, minijinja::Error> {
    let candidate = crate::config::expand_user_with(file, home);
    let target = project::absolute(&root.join(candidate));
    if !target.starts_with(project::absolute(root)) {
        return Err(cli_error(
            format!("{filter}: path '{file}' is outside the project root."),
            false,
        ));
    }
    project::read_limited(&target).map_err(|message| {
        if message.starts_with("File ") {
            cli_error(message, true)
        } else {
            python_error(message)
        }
    })
}

/// The variables a template uses that it does not set (`nested`: as `ctx.env.a` chains).
pub fn undeclared(
    engine: &Environment<'static>,
    text: &str,
    nested: bool,
) -> Result<HashSet<String>, minijinja::Error> {
    let engine: &Environment<'_> = engine;
    Ok(engine.template_from_str(text)?.undeclared_variables(nested))
}

/// Renders `text`, as Jinja does: line ends become `\n`.
fn render_with(
    engine: &Environment<'static>,
    text: &str,
    data: &Value,
) -> Result<String, TemplateError> {
    let text = normalize_newlines(text);
    engine
        .render_str(&text, data)
        .map_err(|e| classify(&e, engine, data))
}

fn normalize_newlines(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n").into()
    } else {
        text.into()
    }
}

/// The text of `err` as `snow` prints it (`str(exception)`).
pub fn message(err: &minijinja::Error, engine: &Environment<'static>, data: &Value) -> String {
    match classify(err, engine, data) {
        TemplateError::Undefined(m) | TemplateError::Unexpected(m) => m,
        TemplateError::Cli { message, .. } | TemplateError::Project(message) => message,
    }
}

/// Maps a `minijinja` error to the exception `snow` (Jinja2) raises, with its message.
fn classify(err: &minijinja::Error, engine: &Environment<'static>, data: &Value) -> TemplateError {
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        if let Some(cli) = cause.downcast_ref::<CliFailure>() {
            return TemplateError::Cli {
                message: cli.message.clone(),
                feedback: cli.feedback,
            };
        }
        if let Some(py) = cause.downcast_ref::<PythonFailure>() {
            return TemplateError::Unexpected(py.0.clone());
        }
        source = cause.source();
    }
    let detail = err.detail().unwrap_or_default();
    // "`a.b` is undefined", possibly inside another message: the undefined origin.
    let origin = detail.find("` is undefined").and_then(|end| {
        detail[..end]
            .rfind('`')
            .map(|start| &detail[start + 1..end])
    });
    if let Some(expr) = origin {
        return TemplateError::Undefined(undefined_message(expr, engine, data));
    }
    match err.kind() {
        MjKind::UndefinedError => TemplateError::Undefined(detail.to_string()),
        MjKind::TemplateNotFound => {
            // Jinja2's `TemplateNotFound` is just the name.
            let name = detail.split(['\'', '"']).nth(1).unwrap_or(detail);
            TemplateError::Unexpected(name.to_string())
        }
        MjKind::UnknownFunction => {
            let name = detail.strip_suffix(" is unknown").unwrap_or(detail);
            TemplateError::Undefined(format!("{} is undefined", py_repr(name)))
        }
        MjKind::UnknownMethod => {
            // "<type> has no method named <name>": Jinja looks the attribute up and finds none.
            let message = detail
                .split_once(" has no method named ")
                .map(|(kind, name)| {
                    let kind = match kind {
                        "string" => "str object",
                        "map" => "dict object",
                        "sequence" | "iterable" => "list object",
                        "number" => "int object",
                        "bool" => "bool object",
                        "none" => "None",
                        other => other,
                    };
                    format!("'{kind}' has no attribute {}", py_repr(name))
                })
                .unwrap_or_else(|| detail.to_string());
            TemplateError::Undefined(message)
        }
        // Jinja2 finds these when it compiles the template, outside any file.
        MjKind::UnknownFilter => TemplateError::Unexpected(format!(
            "No filter named '{}'.\n  File \"<introspection>\", line {}",
            detail
                .trim_start_matches("filter ")
                .trim_end_matches(" is unknown"),
            err.line().unwrap_or(1)
        )),
        MjKind::UnknownTest => TemplateError::Unexpected(format!(
            "No test named '{}'.\n  File \"<introspection>\", line {}",
            detail
                .trim_start_matches("test ")
                .trim_end_matches(" is unknown"),
            err.line().unwrap_or(1)
        )),
        _ => TemplateError::Unexpected(python_wording(detail).to_string()),
    }
}

/// Jinja2's wording for the errors met most often; anything else keeps `minijinja`'s.
fn python_wording(detail: &str) -> &str {
    match detail {
        "unexpected end of input, expected expression" => "unexpected 'end of template'",
        "unexpected end of input, expected end of variable block" => {
            "unexpected end of template, expected 'end of print statement'."
        }
        "unexpected end of variable block" => {
            "Expected an expression, got 'end of print statement'"
        }
        "unexpected end of comment" => "Missing end of comment tag",
        d if d.starts_with("unable to calculate ") && d.ends_with(" // 0") => {
            "integer division or modulo by zero"
        }
        d if d.starts_with("unable to calculate ") && d.ends_with(" % 0") => {
            "integer modulo by zero"
        }
        d if d.starts_with("unable to calculate ") && d.ends_with(" / 0") => "division by zero",
        d => d,
    }
}

/// Jinja2's `Undefined` message for the undefined expression `expr` (`a`, `a.b`, `a[0]`).
fn undefined_message(expr: &str, engine: &Environment<'_>, data: &Value) -> String {
    let Some((parent, last)) = split_last(expr) else {
        return format!("{} is undefined", py_repr(expr));
    };
    // minijinja shows a literal parent as `(...)`: guess its type from the key.
    let literal = parent == "(...)";
    let value = engine
        .compile_expression(parent)
        .and_then(|e| e.eval(data))
        .unwrap_or(Value::UNDEFINED);
    if value.is_undefined() && !literal {
        return undefined_message(parent, engine, data);
    }
    let kind = match (&last, literal) {
        (Last::Item(item), true) if item.starts_with(|c: char| c.is_ascii_digit() || c == '-') => {
            "list object".to_string()
        }
        (_, true) => "dict object".to_string(),
        _ => type_repr(&value),
    };
    match last {
        Last::Attr(name) => format!("'{kind}' has no attribute {}", py_repr(name)),
        Last::Item(item) => {
            let key = engine
                .compile_expression(item)
                .and_then(|e| e.eval(data))
                .unwrap_or(Value::UNDEFINED);
            match key.as_str() {
                Some(name) => format!("'{kind}' has no attribute {}", py_repr(name)),
                None => format!("{kind} has no element {key}"),
            }
        }
    }
}

enum Last<'a> {
    Attr(&'a str),
    Item(&'a str),
}

/// Splits `a.b[0]` into `a.b` and `[0]`; `None` for a bare name.
fn split_last(expr: &str) -> Option<(&str, Last<'_>)> {
    if let Some(inner) = expr.strip_suffix(']') {
        let mut depth = 0;
        for (i, c) in inner.char_indices().rev() {
            match c {
                ']' => depth += 1,
                '[' if depth == 0 => return Some((&expr[..i], Last::Item(&inner[i + 1..]))),
                '[' => depth -= 1,
                _ => {}
            }
        }
        return None;
    }
    expr.rfind('.')
        .map(|i| (&expr[..i], Last::Attr(&expr[i + 1..])))
}

/// Jinja2's `object_type_repr`.
fn type_repr(value: &Value) -> String {
    if value.downcast_object_ref::<ProjectEnv>().is_some() {
        return PROJECT_ENV_TYPE.into();
    }
    match value.kind() {
        ValueKind::None => "None".into(),
        ValueKind::Bool => "bool object".into(),
        ValueKind::Number if value.is_integer() => "int object".into(),
        ValueKind::Number => "float object".into(),
        ValueKind::String => "str object".into(),
        ValueKind::Seq => "list object".into(),
        ValueKind::Map => "dict object".into(),
        ValueKind::Plain => "function object".into(),
        _ => "object".into(),
    }
}

/// Whether `content` has any template marker (`snow` reads `snowflake.yml` only then).
fn has_sql_templates(content: &str) -> bool {
    content.contains("&{") || content.contains("<%") || content.contains("{{")
}

struct Engines {
    legacy: Environment<'static>,
    standard: Environment<'static>,
    jinja: Environment<'static>,
}

/// Renders the statements of one `snow sql` run.
pub struct Templater<'a> {
    variables: &'a Variables,
    syntaxes: Syntaxes,
    project: &'a ProjectSource,
    engines: OnceCell<Engines>,
}

impl<'a> Templater<'a> {
    pub fn new(variables: &'a Variables, syntaxes: Syntaxes, project: &'a ProjectSource) -> Self {
        Self {
            variables,
            syntaxes,
            project,
            engines: OnceCell::new(),
        }
    }

    pub fn syntaxes(&self) -> Syntaxes {
        self.syntaxes
    }

    fn engines(&self) -> &Engines {
        self.engines.get_or_init(|| {
            let (root, env) = (self.project.root(), self.project.env());
            Engines {
                legacy: delimited_env(root, env, "&{", "}"),
                standard: delimited_env(root, env, "<%", "%>"),
                jinja: jinja_engine(root, env),
            }
        })
    }

    /// One statement, JINJA off: the LEGACY transpilation, then LEGACY/STANDARD rendering.
    pub fn render_statement(
        &self,
        text: &str,
        notices: &mut Vec<String>,
    ) -> Result<String, TemplateError> {
        let transpiled;
        let mut text = text;
        if self.syntaxes.legacy {
            transpiled = transpile_legacy(text);
            text = &transpiled;
        }
        self.render(text, false, notices)
    }

    /// One whole input, JINJA on (`_jinja_pre_render`): comments protected, the LEGACY
    /// transpilation, LEGACY/STANDARD rendering, then Jinja.
    pub fn pre_render(
        &self,
        text: &str,
        notices: &mut Vec<String>,
    ) -> Result<String, TemplateError> {
        let (protected, saved) = protect_comments(text);
        let mut content = protected;
        if self.syntaxes.legacy {
            content = transpile_legacy(&content);
        }
        let rendered = self.render(&content, true, notices)?;
        Ok(saved.restore(rendered))
    }

    /// `snowflake_sql_jinja_render`.
    fn render(
        &self,
        content: &str,
        jinja: bool,
        notices: &mut Vec<String>,
    ) -> Result<String, TemplateError> {
        for reserved in ["ctx", "fn"] {
            if self.variables.contains_key(reserved) {
                return Err(TemplateError::Cli {
                    message: format!(
                        "{reserved} in user defined data. The `{reserved}` variable is reserved for CLI usage."
                    ),
                    feedback: false,
                });
            }
        }
        let syntaxes = self.syntaxes;
        let comments = content.contains("{#");
        let any = syntaxes.legacy || syntaxes.standard || jinja;
        let mut needed =
            comments || has_sql_templates(content) || (jinja && content.contains("{%"));
        if any {
            // Jinja turns every line end into `\n`, whatever the text.
            needed |= content.contains('\r');
        }
        if !needed || !any {
            return Ok(content.to_string());
        }
        let data = self.data(content, notices)?;
        let engines = self.engines();
        let env = match (syntaxes.legacy, syntaxes.standard) {
            (true, true) => {
                let old = has_syntax(&engines.legacy, "&{", content, &data)?;
                let new = has_syntax(&engines.standard, "<%", content, &data)?;
                if old && new {
                    return Err(TemplateError::Cli {
                        message: "The SQL query mixes &{ ... } syntax and <% ... %> syntax.".into(),
                        feedback: true,
                    });
                }
                if old {
                    notices.push(LEGACY_WARNING.into());
                    Some(&engines.legacy)
                } else {
                    Some(&engines.standard)
                }
            }
            (true, false) => Some(&engines.legacy),
            (false, true) => Some(&engines.standard),
            (false, false) => None,
        };
        let mut content = content.to_string();
        if let Some(env) = env {
            content = render_with(env, &content, &data)?;
        }
        if jinja {
            content = render_with(&engines.jinja, &content, &data)?;
        }
        Ok(content)
    }

    /// The template data: `ctx`/`fn` when the text has templates, then the `-D` variables.
    fn data(&self, content: &str, notices: &mut Vec<String>) -> Result<Value, TemplateError> {
        let mut data: Vec<(String, Value)> = Vec::new();
        if has_sql_templates(content) {
            data.extend(self.project.context(notices)?.iter().cloned());
        }
        for (k, v) in self.variables {
            data.retain(|(key, _)| key != k);
            data.push((k.clone(), Value::from(v.clone())));
        }
        Ok(Value::from_pairs(data))
    }
}

/// `_does_template_have_env_syntax`: the text parses and uses a variable.
fn has_syntax(
    engine: &Environment<'static>,
    start: &str,
    content: &str,
    data: &Value,
) -> Result<bool, TemplateError> {
    if !content.contains(start) && !content.contains("{#") {
        return Ok(false);
    }
    let content = normalize_newlines(content);
    undeclared(engine, &content, false)
        .map(|vars| !vars.is_empty())
        .map_err(|e| classify(&e, engine, data))
}

/// SQL comments replaced by placeholders (`_protect_sql_comments`).
pub struct SavedComments {
    nonce: String,
    comments: Vec<String>,
}

impl SavedComments {
    fn save(&mut self, text: &str) -> String {
        let placeholder = format!("__SQLC_{}_{}__", self.nonce, self.comments.len());
        self.comments.push(text.to_string());
        placeholder
    }

    /// Puts the comments back, in one pass over the text.
    pub fn restore(&self, sql: String) -> String {
        if self.comments.is_empty() {
            return sql;
        }
        let prefix = format!("__SQLC_{}_", self.nonce);
        let mut out = String::with_capacity(sql.len());
        let mut rest = sql.as_str();
        while let Some(at) = rest.find(&prefix) {
            out.push_str(&rest[..at]);
            let after = &rest[at + prefix.len()..];
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            let comment = after[..digits]
                .parse::<usize>()
                .ok()
                .filter(|_| after[digits..].starts_with("__"))
                .and_then(|i| self.comments.get(i));
            match comment {
                Some(comment) => {
                    out.push_str(comment);
                    rest = &after[digits + 2..];
                }
                None => {
                    out.push_str(&prefix);
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }
}

/// `_protect_sql_comments`: `--` line comments and (nested) `/* */` comments outside `'…'` and
/// `$$…$$` literals become placeholders, so Jinja never sees their content.
pub fn protect_comments(sql: &str) -> (String, SavedComments) {
    let mut saved = SavedComments {
        nonce: uuid::Uuid::new_v4().simple().to_string()[..12].to_string(),
        comments: Vec::new(),
    };
    let mut out = String::with_capacity(sql.len());
    let mut pos = 0;
    let mut i = 0;
    while i < sql.len() {
        let rest = &sql[i..];
        if rest.starts_with('\'') {
            // '[^']*(?:''[^']*)*'
            let mut j = i + 1;
            let mut closed = None;
            while let Some(q) = sql[j..].find('\'') {
                let end = j + q + 1;
                if sql[end..].starts_with('\'') {
                    j = end + 1;
                } else {
                    closed = Some(end);
                    break;
                }
            }
            if let Some(end) = closed {
                i = end;
                continue;
            }
        } else if rest.starts_with("$$") {
            if let Some(q) = sql[i + 2..].find("$$") {
                i = i + 2 + q + 2;
                continue;
            }
        } else if rest.starts_with("/*") {
            let mut depth = 1;
            let mut j = i + 2;
            while j < sql.len() && depth > 0 {
                if sql[j..].starts_with("/*") {
                    depth += 1;
                    j += 2;
                } else if sql[j..].starts_with("*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += sql[j..].chars().next().map_or(1, char::len_utf8);
                }
            }
            out.push_str(&sql[pos..i]);
            out.push_str(&saved.save(&sql[i..j]));
            pos = j;
            i = j;
            continue;
        } else if rest.starts_with("--") {
            let end = rest.find('\n').map_or(sql.len(), |n| i + n);
            out.push_str(&sql[pos..i]);
            out.push_str(&saved.save(&sql[i..end]));
            pos = end;
            i = end;
            continue;
        }
        i += rest.chars().next().map_or(1, char::len_utf8);
    }
    out.push_str(&sql[pos..]);
    (out, saved)
}

/// `string.Template` with delimiter `&` and `safe_substitute` of `&{ name }`: `&&` is `&`,
/// `&name` and `&{name}` (ASCII `[_a-z][_a-z0-9]*`, either case) become `&{ name }`, any other
/// `&` stays.
pub fn transpile_legacy(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(escaped) = after.strip_prefix('&') {
            out.push('&');
            rest = escaped;
        } else if let Some(braced) = after.strip_prefix('{') {
            let name = ascii_identifier(braced);
            if !name.is_empty() && braced[name.len()..].starts_with('}') {
                out.push_str(&format!("&{{ {name} }}"));
                rest = &braced[name.len() + 1..];
            } else {
                out.push('&');
                rest = after;
            }
        } else {
            let name = ascii_identifier(after);
            if name.is_empty() {
                out.push('&');
                rest = after;
            } else {
                out.push_str(&format!("&{{ {name} }}"));
                rest = &after[name.len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The longest `[_a-zA-Z][_a-zA-Z0-9]*` prefix of `text` (empty if there is none).
fn ascii_identifier(text: &str) -> &str {
    let bytes = text.as_bytes();
    if !bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return "";
    }
    let len = bytes
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    &text[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(dir: &Path, overrides: &[(&str, &str)], env: &[(&str, &str)]) -> ProjectSource {
        ProjectSource::new(
            Some(dir),
            overrides
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            Env::from_pairs(env.iter().copied()),
        )
    }

    fn vars(pairs: &[(&str, &str)]) -> Variables {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn render(
        text: &str,
        variables: &[(&str, &str)],
        syntaxes: Syntaxes,
    ) -> Result<String, TemplateError> {
        let dir = tempfile::tempdir().unwrap();
        let source = project(dir.path(), &[], &[]);
        let variables = vars(variables);
        let templater = Templater::new(&variables, syntaxes, &source);
        let mut notices = Vec::new();
        if syntaxes.jinja {
            templater.pre_render(text, &mut notices)
        } else {
            templater.render_statement(text, &mut notices)
        }
    }

    const LEGACY: Syntaxes = Syntaxes {
        legacy: true,
        standard: false,
        jinja: false,
    };
    const STANDARD: Syntaxes = Syntaxes {
        legacy: false,
        standard: true,
        jinja: false,
    };
    const NONE: Syntaxes = Syntaxes {
        legacy: false,
        standard: false,
        jinja: false,
    };
    const JINJA: Syntaxes = Syntaxes {
        legacy: false,
        standard: false,
        jinja: true,
    };

    #[test]
    fn legacy_transpilation() {
        assert_eq!(
            transpile_legacy("select &a, &{b}x"),
            "select &{ a }, &{ b }x"
        );
        assert_eq!(transpile_legacy("&&a &&&b"), "&a &&{ b }");
        assert_eq!(
            transpile_legacy("&1, a&, &, &$a, &é, &{a b}, &{"),
            "&1, a&, &, &$a, &é, &{a b}, &{"
        );
        assert_eq!(transpile_legacy("no ampersand"), "no ampersand");
    }

    #[test]
    fn syntaxes_left_out_are_not_rendered() {
        let v = [("a", "1")];
        assert_eq!(
            render("&a &{a} <% a %>", &v, LEGACY).unwrap(),
            "1 1 <% a %>"
        );
        assert_eq!(
            render("&a &{a} <% a %>", &v, STANDARD).unwrap(),
            "&a &{a} 1"
        );
        assert_eq!(
            render("&a <% a %> {# c #}\r\n", &v, NONE).unwrap(),
            "&a <% a %> {# c #}\r\n"
        );
        assert_eq!(
            render("{{ a }} <% a %> &a", &v, JINJA).unwrap(),
            "1 <% a %> &a"
        );
        // A value is not rendered again.
        assert_eq!(
            render("<% d %>", &[("d", "<% a %>")], Syntaxes::default()).unwrap(),
            "<% a %>"
        );
    }

    #[test]
    fn text_without_markers_is_returned_as_is() {
        let text = "select 'a' & 1 -- x\n";
        assert_eq!(render(text, &[], Syntaxes::default()).unwrap(), text);
    }

    #[test]
    fn reserved_names_are_refused_whatever_the_syntaxes() {
        for name in ["ctx", "fn"] {
            assert_eq!(
                render("select 1", &[(name, "x")], NONE).unwrap_err(),
                TemplateError::Cli {
                    message: format!(
                        "{name} in user defined data. The `{name}` variable is reserved for CLI usage."
                    ),
                    feedback: false,
                }
            );
        }
    }

    #[test]
    fn errors_are_classified_as_snow_reports_them() {
        let both = Syntaxes::default();
        let undefined = |m: &str| TemplateError::Undefined(m.to_string());
        let unexpected = |m: &str| TemplateError::Unexpected(m.to_string());
        let v = [("a", "q")];
        assert_eq!(
            render("<% zz %>", &v, both).unwrap_err(),
            undefined("'zz' is undefined")
        );
        assert_eq!(
            render("<% a.b %>", &v, both).unwrap_err(),
            undefined("'str object' has no attribute 'b'")
        );
        assert_eq!(
            render("<% {'k': 1}.z %>", &v, both).unwrap_err(),
            undefined("'dict object' has no attribute 'z'")
        );
        assert_eq!(
            render("<% a[10] %>", &v, both).unwrap_err(),
            undefined("str object has no element 10")
        );
        assert_eq!(
            render("<% a[\"it's\"] %>", &v, both).unwrap_err(),
            undefined("'str object' has no attribute \"it's\"")
        );
        assert_eq!(
            render("<% {'k': 1}.items() %>", &v, both).unwrap_err(),
            undefined("'dict object' has no attribute 'items'")
        );
        assert_eq!(
            render("<% a is nosuchtest %>", &v, both).unwrap_err(),
            unexpected("No test named 'nosuchtest'.\n  File \"<introspection>\", line 1")
        );
        assert_eq!(
            render("<% 5 % 0 %>", &v, both).unwrap_err(),
            unexpected("integer modulo by zero")
        );
        assert!(matches!(
            render("<% a + 1 %>", &v, both),
            Err(TemplateError::Unexpected(_))
        ));
        assert_eq!(
            render("{% extends 'x' %}", &v, JINJA).unwrap_err(),
            unexpected("x")
        );
    }

    #[test]
    fn values_render_as_python_prints_them() {
        let both = Syntaxes::default();
        assert_eq!(
            render("<% [1, 'a', none, true, 1.5, {'k': 'v'}] %>", &[], both).unwrap(),
            "[1, 'a', None, True, 1.5, {'k': 'v'}]"
        );
        assert_eq!(
            render("<% ctx %>", &[], both).unwrap(),
            "{'env': ProjectEnvironment(override_env={}, default_env={})}"
        );
    }

    #[test]
    fn python_names_for_types_and_strings() {
        assert_eq!(type_repr(&Value::from(())), "None");
        assert_eq!(type_repr(&Value::from(true)), "bool object");
        assert_eq!(type_repr(&Value::from(1)), "int object");
        assert_eq!(type_repr(&Value::from(1.5)), "float object");
        assert_eq!(type_repr(&Value::from(vec![1])), "list object");
        assert_eq!(type_repr(&Value::from_pairs([("a", 1)])), "dict object");
        assert_eq!(type_repr(&Value::from_function(|| 1)), "function object");
        assert_eq!(py_repr("a"), "'a'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("'\"\\\n\r\t"), "'\\'\"\\\\\\n\\r\\t'");
    }

    #[test]
    fn last_segment_of_an_undefined_expression() {
        assert!(split_last("a").is_none());
        assert!(matches!(
            split_last("a.b.c"),
            Some(("a.b", Last::Attr("c")))
        ));
        assert!(matches!(
            split_last("a[b[0]]"),
            Some(("a", Last::Item("b[0]")))
        ));
        assert!(split_last("a]").is_none());
    }

    #[test]
    fn comments_are_protected_outside_literals() {
        let sql = "select '--x' /* a /* b */ c */, $$ -- y $$ -- z\nselect 'it''s' -- w";
        let (protected, saved) = protect_comments(sql);
        assert!(protected.contains("'--x'"));
        assert!(protected.contains("$$ -- y $$"));
        assert!(protected.contains("'it''s'"));
        assert!(!protected.contains("/* a"));
        assert!(!protected.contains("-- z"));
        assert!(!protected.contains("-- w"));
        assert_eq!(saved.restore(protected), sql);
        // Unterminated literals are not literals; an unterminated comment runs to the end.
        let (protected, saved) = protect_comments("select 'a -- c\n$$ /* x");
        assert!(!protected.contains("-- c"));
        assert!(!protected.contains("/* x"));
        assert_eq!(saved.restore(protected), "select 'a -- c\n$$ /* x");
        // Text that only looks like a placeholder stays.
        let fake = format!("__SQLC_{}_x __SQLC_{}_99__", saved.nonce, saved.nonce);
        assert_eq!(saved.restore(fake.clone()), fake);
    }

    #[test]
    fn files_are_read_only_inside_the_project_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("a.txt"), "A").unwrap();
        std::fs::create_dir(root.join("home")).unwrap();
        let home = root.join("home");
        std::fs::write(home.join("h.txt"), "H").unwrap();
        assert_eq!(read_in_root(&root, Some(&home), "a.txt", "f").unwrap(), "A");
        assert_eq!(
            read_in_root(&root, Some(&home), "~/h.txt", "f").unwrap(),
            "H"
        );
        assert_eq!(
            read_in_root(
                &root,
                Some(&home),
                &root.join("a.txt").display().to_string(),
                "f"
            )
            .unwrap(),
            "A"
        );
        let outside = read_in_root(&root, None, "../x", "f").unwrap_err();
        assert!(
            outside
                .to_string()
                .contains("f: path '../x' is outside the project root.")
        );
        let missing = read_in_root(&root, None, "nope", "f").unwrap_err();
        assert!(missing.to_string().contains("[Errno 2]"));
        let dir_err = read_in_root(&root, None, "home", "f").unwrap_err();
        assert!(dir_err.to_string().contains("[Errno 21] Is a directory"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", root.join("link")).unwrap();
            assert!(read_in_root(&root, None, "link/hostname", "f").is_err());
        }
    }

    #[test]
    fn message_gives_the_text_of_any_error() {
        let engine = client_engine(Path::new("/"), &Env::default());
        let data = Value::from_pairs([("a", "q")]);
        let err = engine.render_str("<% zz %>", &data).unwrap_err();
        assert_eq!(message(&err, &engine, &data), "'zz' is undefined");
        let err = cli_error("boom".into(), true);
        assert_eq!(message(&err, &engine, &data), "boom");
        let err = engine.render_str("<% %>", &data).unwrap_err();
        assert_eq!(
            message(&err, &engine, &data),
            "Expected an expression, got 'end of print statement'"
        );
    }
}
