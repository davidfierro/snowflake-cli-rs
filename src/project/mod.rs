//! The template context a `snowflake.yml` gives `snow sql` (`ctx`, `ctx.env`, `fn`), as
//! `snow` 3.34.0 builds it (`DefinitionManager`, `load_project`, `render_definition_template`).
//!
//! - The project root is `--project` (made absolute) or the current directory; there is no
//!   upward search. `snowflake.yml` there is the definition, merged with `snowflake.local.yml`
//!   when both exist. No file: `ctx` holds only `env`.
//! - `ctx.env.<name>` is, in order: `--env name=value`, the process environment variable, the
//!   `env` section of the definition (definition 1.1 or later; with 1.0 the section is ignored).
//! - With definition 1.1 or later, every `<% … %>` value of the definition is rendered first,
//!   following references between values (`ctx.env.a` used by `ctx.env.b`), with the `fn.*`
//!   functions available; a cycle is an error.
//!
//! Only `definition_version` and the top-level keys are validated: the entity schemas are out of
//! scope until `snow object`/`snow app` are ported.

pub mod functions;
pub mod yaml;

use crate::env::Env;
use crate::script::template::{self, TemplateError, Variables};
use minijinja::value::{Object, ObjectRepr, Rest, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use yaml::Node;

pub const BASE_FILE: &str = "snowflake.yml";
pub const LOCAL_FILE: &str = "snowflake.local.yml";
/// `DEFAULT_SIZE_LIMIT_MB`.
pub const SIZE_LIMIT_MB: u64 = 128;

const VERSION_WARNING: &str = "Ignoring template pattern in project definition file. Update 'definition_version' to 1.1 or later in snowflake.yml to enable template expansion.";

/// The top-level template variables a project gives (`ctx`, `fn`).
pub type TopLevel = Vec<(String, Value)>;

/// Where the project is and what overrides its `env` section: `--project` and `--env`.
#[derive(Debug, Clone)]
pub struct ProjectSource {
    root: PathBuf,
    overrides: Variables,
    env: Env,
    loaded: RefCell<Option<Rc<TopLevel>>>,
}

impl ProjectSource {
    /// `project` is `--project` (`None`: the current directory).
    pub fn new(project: Option<&Path>, overrides: Variables, env: Env) -> Self {
        let cwd = std::env::current_dir().unwrap_or_default();
        let root = match project {
            Some(p) => absolute(&cwd.join(p)),
            None => cwd,
        };
        Self {
            root,
            overrides,
            env,
            loaded: RefCell::new(None),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    /// The top-level template variables (`ctx`, and `fn` with definition 1.1 or later), loaded
    /// on first use as `snow` does; a failure is reported (and retried) at every use.
    pub fn context(&self, notices: &mut Vec<String>) -> Result<Rc<TopLevel>, TemplateError> {
        if let Some(loaded) = self.loaded.borrow().as_ref() {
            return Ok(Rc::clone(loaded));
        }
        let loaded = Rc::new(self.load(notices).map_err(|message| {
            TemplateError::Project(format!("Failed to read snowflake.yml file: {message}"))
        })?);
        *self.loaded.borrow_mut() = Some(Rc::clone(&loaded));
        Ok(loaded)
    }

    fn load(&self, notices: &mut Vec<String>) -> Result<TopLevel, String> {
        let base = self.root.join(BASE_FILE);
        if !base.is_file() {
            return Ok(vec![(
                "ctx".into(),
                self.ctx_value(&Node::Map(Vec::new()), Vec::new()),
            )]);
        }
        let mut definition = yaml::parse(&read_limited(&base)?)?;
        let local = self.root.join(LOCAL_FILE);
        if local.is_file() {
            definition.merge(yaml::parse(&read_limited(&local)?)?);
        }
        let Node::Map(entries) = &definition else {
            return Err("project definition file should be a mapping".into());
        };
        let version = match definition.get("definition_version") {
            Some(Node::Str(v)) => v.clone(),
            Some(other) => {
                return Err(format!(
                    "Invalid version: '{}'",
                    python_str(&to_value(other))
                ));
            }
            None => {
                let mut lines = vec![
                    "Your project definition is missing the following field: 'definition_version'"
                        .to_string(),
                ];
                lines.extend(extra_fields(entries, &["definition_version"]));
                return Err(schema_error("_ProjectDefinitionBase", &lines));
            }
        };
        if !version
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(format!("Invalid version: '{version}'"));
        }
        let (title, allowed): (&str, &[&str]) = match version.as_str() {
            "1" => (
                "DefinitionV10",
                &["definition_version", "native_app", "snowpark", "streamlit"],
            ),
            "1.1" => (
                "DefinitionV11",
                &[
                    "definition_version",
                    "native_app",
                    "snowpark",
                    "streamlit",
                    "env",
                ],
            ),
            "2" => (
                "DefinitionV20",
                &["definition_version", "entities", "env", "mixins"],
            ),
            _ => {
                return Err(schema_error(
                    "_ProjectDefinitionBase",
                    &[format!(
                        "For field definition_version you provided '{version}'. This caused: Value error, Version {version} is not supported. Supported versions: 1, 1.1, 2"
                    )],
                ));
            }
        };
        let mut extras = Vec::new();
        if version != "1" {
            // pydantic's `Dict[str, Union[str, int, bool]]` on each value of `env`.
            if let Some(Node::Map(vars)) = definition.get("env") {
                for (k, v) in vars.iter().filter(|(_, v)| !matches!(v, Node::Str(_))) {
                    let input = python_str(&to_value(v));
                    extras.push(format!("For field env.{k}.int you provided '{input}'. This caused: Input should be a valid integer"));
                    extras.push(format!("For field env.{k}.bool you provided '{input}'. This caused: Input should be a valid boolean"));
                    extras.push(format!("Input should be a valid string for field 'env.{k}.str', you provided '{input}'."));
                }
            }
        }
        extras.extend(extra_fields(entries, allowed));
        let engine = template::client_engine(&self.root, &self.env);
        if version == "1" {
            if has_references(&engine, &definition).unwrap_or(true) {
                notices.push(VERSION_WARNING.into());
            }
            if !extras.is_empty() {
                return Err(schema_error(title, &extras));
            }
            return Ok(vec![(
                "ctx".into(),
                self.ctx_value(&definition, Vec::new()),
            )]);
        }
        if !extras.is_empty() {
            return Err(schema_error(title, &extras));
        }
        if version == "2" && definition.get("entities").is_none() {
            definition.merge(Node::Map(vec![("entities".into(), Node::Map(Vec::new()))]));
        }
        let env_section = match definition.get("env") {
            None => Vec::new(),
            Some(Node::Map(vars)) => {
                if let Some((name, _)) = vars.iter().find(|(_, v)| !matches!(v, Node::Str(_))) {
                    return Err(format!(
                        "Variable {name} in env section of project definition file should be a scalar"
                    ));
                }
                vars.clone()
            }
            Some(_) => {
                return Err("env section in project definition file should be a mapping".into());
            }
        };
        let functions = functions_value(&self.env);
        let mut resolver = Resolver {
            engine: &engine,
            definition: &definition,
            functions: &functions,
            source: self,
            resolved: BTreeMap::new(),
            visiting: BTreeSet::new(),
        };
        let mut chains = BTreeSet::new();
        collect_references(&engine, &definition, &mut chains)?;
        for chain in &chains {
            resolver.resolve(chain)?;
        }
        let context = nest(&resolver.resolved);
        let rendered = render_node(&engine, &definition, &context)?;
        let defaults = match rendered.get("env") {
            Some(Node::Map(vars)) => vars.iter().map(|(k, v)| (k.clone(), node_str(v))).collect(),
            _ => env_section
                .into_iter()
                .map(|(k, v)| (k, node_str(&v)))
                .collect(),
        };
        Ok(vec![
            ("ctx".into(), self.ctx_value(&rendered, defaults)),
            ("fn".into(), functions),
        ])
    }

    /// The definition as `ctx`, its `env` replaced by the lookup object.
    fn ctx_value(&self, definition: &Node, defaults: Vec<(String, String)>) -> Value {
        let mut entries: Vec<(String, Value)> = match definition {
            Node::Map(entries) => entries
                .iter()
                .filter(|(k, _)| k != "env")
                .map(|(k, v)| (k.clone(), to_value(v)))
                .collect(),
            _ => Vec::new(),
        };
        entries.push((
            "env".into(),
            Value::from_object(ProjectEnv {
                overrides: self.overrides.clone(),
                os: self.env.clone(),
                defaults,
            }),
        ));
        Value::from_pairs(entries)
    }
}

/// `ctx.env`: `snow`'s `ProjectEnvironment`.
#[derive(Debug)]
pub struct ProjectEnv {
    overrides: Variables,
    os: Env,
    defaults: Vec<(String, String)>,
}

/// How Jinja names the type of `ctx.env` in its messages.
pub const PROJECT_ENV_TYPE: &str = "snowflake.cli.api.utils.models.ProjectEnvironment object";

impl ProjectEnv {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.overrides
            .get(name)
            .map(String::as_str)
            .or_else(|| self.os.get(name))
            .or_else(|| {
                self.defaults
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
            })
    }
}

impl Object for ProjectEnv {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Plain
    }

    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        self.lookup(key.as_str()?).map(Value::from)
    }

    fn render(self: &Arc<Self>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = |pairs: Vec<(&String, &String)>| {
            Value::from_pairs(pairs.into_iter().map(|(k, v)| (k.clone(), v.clone())))
        };
        write!(
            f,
            "ProjectEnvironment(override_env={}, default_env={})",
            map(self.overrides.iter().collect()),
            map(self.defaults.iter().map(|(k, v)| (k, v)).collect())
        )
    }
}

/// The `fn` mapping.
fn functions_value(env: &Env) -> Value {
    let user = ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|k| env.get_non_empty(k))
        .unwrap_or_default()
        .to_string();
    let strings = |args: &[Value]| -> Vec<Option<String>> {
        args.iter()
            .map(|a| a.as_str().map(str::to_string))
            .collect()
    };
    let wrap = |name: &'static str,
                min: usize,
                max: Option<usize>,
                f: fn(&[String], &str) -> String,
                user: String| {
        Value::from_function(move |args: Rest<Value>| {
            functions::verify_arguments(name, &strings(&args), min, max)
                .map(|args| f(&args, &user))
                .map_err(|message| template::cli_error(message, true))
        })
    };
    Value::from_pairs([
        (
            "concat_ids",
            wrap(
                "concat_ids",
                1,
                None,
                |a, _| functions::concat_identifiers(a),
                user.clone(),
            ),
        ),
        (
            "get_username",
            wrap(
                "get_username",
                0,
                Some(1),
                |a, u| {
                    if u.is_empty() {
                        a.first().cloned().unwrap_or_default()
                    } else {
                        u.to_string()
                    }
                },
                user.clone(),
            ),
        ),
        (
            "id_to_str",
            wrap(
                "id_to_str",
                1,
                Some(1),
                |a, _| functions::identifier_to_str(&a[0]),
                user.clone(),
            ),
        ),
        (
            "sanitize_id",
            wrap(
                "sanitize_id",
                1,
                Some(1),
                |a, _| functions::sanitize_identifier(&a[0]),
                user.clone(),
            ),
        ),
        (
            "str_to_id",
            wrap(
                "str_to_id",
                1,
                Some(1),
                |a, _| functions::to_identifier(&a[0]),
                user,
            ),
        ),
    ])
}

/// Resolves the referenced variables of a definition, values referencing values first.
struct Resolver<'a> {
    engine: &'a minijinja::Environment<'static>,
    definition: &'a Node,
    functions: &'a Value,
    source: &'a ProjectSource,
    resolved: BTreeMap<String, Value>,
    visiting: BTreeSet<String>,
}

impl Resolver<'_> {
    fn resolve(&mut self, chain: &str) -> Result<(), String> {
        if self.resolved.contains_key(chain) {
            return Ok(());
        }
        let parts: Vec<&str> = chain.split('.').collect();
        if let ["ctx", "env", name] = parts.as_slice() {
            let overridden = self
                .source
                .overrides
                .get(*name)
                .map(String::as_str)
                .or_else(|| self.source.env.get(name));
            if let Some(value) = overridden {
                self.resolved.insert(chain.to_string(), Value::from(value));
                return Ok(());
            }
        }
        let raw = self.read(&parts, chain)?;
        let Some(text) = raw.as_str().map(str::to_string) else {
            self.resolved.insert(chain.to_string(), raw);
            return Ok(());
        };
        if !self.visiting.insert(chain.to_string()) {
            return Err(format!("Cycle detected in template variable {chain}"));
        }
        let mut deps = BTreeSet::new();
        references(self.engine, &text, &mut deps)?;
        for dep in &deps {
            self.resolve(dep)?;
        }
        let context: BTreeMap<String, Value> = deps
            .iter()
            .filter_map(|d| self.resolved.get(d).map(|v| (d.clone(), v.clone())))
            .collect();
        let value = render_str(self.engine, &text, &nest(&context))?;
        self.visiting.remove(chain);
        self.resolved.insert(chain.to_string(), Value::from(value));
        Ok(())
    }

    /// `TemplateVar.read_from_context` on `{ctx: definition, fn: functions}`.
    fn read(&self, parts: &[&str], chain: &str) -> Result<Value, String> {
        let not_found = || format!("Could not find template variable {chain}");
        let (first, rest) = parts.split_first().ok_or_else(not_found)?;
        let value = match *first {
            "ctx" => {
                let mut node = self.definition;
                for part in rest {
                    node = node.get(part).ok_or_else(not_found)?;
                }
                match node {
                    Node::Str(s) => Value::from(s.clone()),
                    _ => {
                        return Err(format!(
                            "Template variable {chain} does not have a scalar value"
                        ));
                    }
                }
            }
            "fn" => match rest {
                [] => {
                    return Err(format!(
                        "Template variable {chain} does not have a scalar value"
                    ));
                }
                [name] => self
                    .functions
                    .get_attr(name)
                    .ok()
                    .filter(|v| !v.is_undefined())
                    .ok_or_else(not_found)?,
                _ => return Err(not_found()),
            },
            _ => return Err(not_found()),
        };
        Ok(value)
    }
}

fn collect_references(
    engine: &minijinja::Environment<'static>,
    node: &Node,
    out: &mut BTreeSet<String>,
) -> Result<(), String> {
    match node {
        Node::Str(s) => references(engine, s, out),
        Node::Seq(items) => items
            .iter()
            .try_for_each(|n| collect_references(engine, n, out)),
        Node::Map(entries) => entries
            .iter()
            .try_for_each(|(_, n)| collect_references(engine, n, out)),
    }
}

fn has_references(engine: &minijinja::Environment<'static>, node: &Node) -> Result<bool, String> {
    let mut out = BTreeSet::new();
    collect_references(engine, node, &mut out)?;
    Ok(!out.is_empty())
}

/// The variable chains (`ctx.env.a`) a value references.
fn references(
    engine: &minijinja::Environment<'static>,
    text: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !text.contains("<%") {
        return Ok(());
    }
    let vars = template::undeclared(engine, text, true).map_err(|e| {
        format!(
            "Error parsing template from project definition file. Value: '{text}'. Error: {}",
            template::message(&e, engine, &Value::UNDEFINED)
        )
    })?;
    out.extend(vars);
    Ok(())
}

fn render_str(
    engine: &minijinja::Environment<'static>,
    text: &str,
    context: &Value,
) -> Result<String, String> {
    if !text.contains("<%") {
        return Ok(text.to_string());
    }
    engine
        .render_str(text, context)
        .map_err(|e| template::message(&e, engine, context))
}

fn render_node(
    engine: &minijinja::Environment<'static>,
    node: &Node,
    context: &Value,
) -> Result<Node, String> {
    Ok(match node {
        Node::Str(s) => Node::Str(render_str(engine, s, context)?),
        Node::Seq(items) => Node::Seq(
            items
                .iter()
                .map(|n| render_node(engine, n, context))
                .collect::<Result<_, _>>()?,
        ),
        Node::Map(entries) => Node::Map(
            entries
                .iter()
                .map(|(k, n)| Ok((k.clone(), render_node(engine, n, context)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

/// `{"ctx.env.a": v}` → `{ctx: {env: {a: v}}}`.
fn nest(flat: &BTreeMap<String, Value>) -> Value {
    #[derive(Default)]
    struct Tree(BTreeMap<String, Result<Value, Tree>>);
    fn insert(tree: &mut Tree, parts: &[&str], value: &Value) {
        let Some((first, rest)) = parts.split_first() else {
            return;
        };
        if rest.is_empty() {
            tree.0.insert(first.to_string(), Ok(value.clone()));
            return;
        }
        let entry = tree
            .0
            .entry(first.to_string())
            .or_insert_with(|| Err(Tree::default()));
        if let Err(sub) = entry {
            insert(sub, rest, value);
        }
    }
    fn build(tree: Tree) -> Value {
        Value::from_pairs(
            tree.0
                .into_iter()
                .map(|(k, v)| (k, v.unwrap_or_else(build))),
        )
    }
    let mut tree = Tree::default();
    for (chain, value) in flat {
        insert(&mut tree, &chain.split('.').collect::<Vec<_>>(), value);
    }
    build(tree)
}

fn to_value(node: &Node) -> Value {
    match node {
        Node::Str(s) => Value::from(s.clone()),
        Node::Seq(items) => Value::from(items.iter().map(to_value).collect::<Vec<_>>()),
        Node::Map(entries) => {
            Value::from_pairs(entries.iter().map(|(k, v)| (k.clone(), to_value(v))))
        }
    }
}

fn node_str(node: &Node) -> String {
    match node {
        Node::Str(s) => s.clone(),
        other => python_str(&to_value(other)),
    }
}

/// Python's `str()` of a value.
fn python_str(value: &Value) -> String {
    value.to_string()
}

/// pydantic's `extra_forbidden` errors for the top-level keys not in `allowed`.
fn extra_fields(entries: &[(String, Node)], allowed: &[&str]) -> Vec<String> {
    entries
        .iter()
        .filter(|(k, _)| !allowed.contains(&k.as_str()))
        .map(|(k, v)| format!("Extra inputs are not permitted. You provided field '{k}' with value '{}' that is not supported in given version.", python_str(&to_value(v))))
        .collect()
}

/// `SchemaValidationError`'s message.
fn schema_error(title: &str, lines: &[String]) -> String {
    format!(
        "During evaluation of {title} in project definition following errors were encountered:\n{}",
        lines.join("\n")
    )
}

/// `SecurePath.read_text(file_size_limit_mb=128)`.
pub fn read_limited(path: &Path) -> Result<String, String> {
    let resolved = absolute(path);
    let meta = std::fs::metadata(path).map_err(|_| {
        format!(
            "[Errno 2] No such file or directory: PosixPath('{}')",
            resolved.display()
        )
    })?;
    if meta.is_dir() {
        return Err(format!(
            "[Errno 21] Is a directory: PosixPath('{}')",
            resolved.display()
        ));
    }
    if meta.len() > SIZE_LIMIT_MB * 1024 * 1024 {
        return Err(format!(
            "File {} is too large (size limit: {SIZE_LIMIT_MB} KB)",
            resolved.display()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

/// `Path.resolve()` (non-strict): symlinks resolved where the path exists, `.`/`..` removed.
pub fn absolute(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    // The longest existing prefix may itself be a symlink.
    match (out.parent(), out.file_name()) {
        (Some(parent), Some(name)) if parent != out => absolute(parent).join(name),
        _ => out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(
        files: &[(&str, &str)],
        overrides: &[(&str, &str)],
    ) -> (Result<Rc<TopLevel>, TemplateError>, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        let source = ProjectSource::new(
            Some(dir.path()),
            overrides
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            Env::from_pairs([("OSVAR", "os")]),
        );
        let mut notices = Vec::new();
        let result = source.context(&mut notices);
        // A second call reuses what the first loaded.
        if let Ok(first) = &result {
            assert!(Rc::ptr_eq(first, &source.context(&mut Vec::new()).unwrap()));
        }
        (result, notices)
    }

    fn error(files: &[(&str, &str)]) -> String {
        match load(files, &[]).0 {
            Err(TemplateError::Project(message)) => message,
            other => panic!("{other:?}"),
        }
    }

    fn eval(top: &TopLevel, expr: &str) -> String {
        let env = minijinja::Environment::new();
        let ctx = Value::from_pairs(top.iter().cloned());
        env.compile_expression(expr)
            .unwrap()
            .eval(ctx)
            .unwrap()
            .to_string()
    }

    #[test]
    fn without_a_definition_ctx_has_only_env() {
        let (top, notices) = load(&[], &[("a", "cli")]);
        let top = top.unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(eval(&top, "ctx.env.a"), "cli");
        assert_eq!(eval(&top, "ctx.env.OSVAR"), "os");
        assert!(notices.is_empty());
        // A local file alone is ignored.
        let (top, _) = load(&[(LOCAL_FILE, "definition_version: 9\n")], &[]);
        assert_eq!(top.unwrap().len(), 1);
    }

    #[test]
    fn definition_values_are_rendered_and_merged() {
        let (top, _) = load(
            &[
                (
                    BASE_FILE,
                    "definition_version: '1.1'\nenv:\n  a: one\n  b: \"<% ctx.env.a %>-<% fn.sanitize_id('9') %>\"\nstreamlit:\n  pages: [\"<% ctx.env.b %>\"]\n",
                ),
                (LOCAL_FILE, "env:\n  a: local\n"),
            ],
            &[],
        );
        let top = top.unwrap();
        assert_eq!(eval(&top, "ctx.env.b"), "local-_9");
        assert_eq!(eval(&top, "ctx.streamlit.pages[0]"), "local-_9");
        assert_eq!(eval(&top, "fn.get_username('fb')"), "fb");
    }

    #[test]
    fn version_1_is_not_rendered_and_warns() {
        let (top, notices) = load(
            &[(
                BASE_FILE,
                "definition_version: 1\nstreamlit: {name: \"<% x %>\"}\n",
            )],
            &[],
        );
        assert_eq!(eval(&top.unwrap(), "ctx.streamlit.name"), "<% x %>");
        assert_eq!(notices, vec![VERSION_WARNING.to_string()]);
        let (_, notices) = load(
            &[(
                BASE_FILE,
                "definition_version: 1\nstreamlit: {name: \"<% %>\"}\n",
            )],
            &[],
        );
        assert_eq!(notices, vec![VERSION_WARNING.to_string()]);
        assert!(
            error(&[(BASE_FILE, "definition_version: 1\nenv: {}\n")])
                .contains("Extra inputs are not permitted. You provided field 'env'")
        );
    }

    #[test]
    fn invalid_definitions() {
        let failed = |m: &str| format!("Failed to read snowflake.yml file: {m}");
        assert_eq!(
            error(&[(BASE_FILE, "- 1\n")]),
            failed("project definition file should be a mapping")
        );
        assert_eq!(
            error(&[(BASE_FILE, "definition_version: [2]\n")]),
            failed("Invalid version: '['2']'")
        );
        assert_eq!(
            error(&[(BASE_FILE, "definition_version: abc\n")]),
            failed("Invalid version: 'abc'")
        );
        assert_eq!(
            error(&[(BASE_FILE, "definition_version: 2\nenv: x\n")]),
            failed("env section in project definition file should be a mapping")
        );
        assert_eq!(
            error(&[(
                BASE_FILE,
                "definition_version: 2\nenv:\n  a: \"<% ctx.env.b ~ %>\"\n"
            )]),
            failed(&format!(
                "Error parsing template from project definition file. Value: '<% ctx.env.b ~ %>'. Error: {}",
                error_detail("<% ctx.env.b ~ %>")
            ))
        );
        assert_eq!(
            error(&[(
                BASE_FILE,
                "definition_version: 2\nenv:\n  a: \"<% fn %>\"\n"
            )]),
            failed("Template variable fn does not have a scalar value")
        );
        assert_eq!(
            error(&[(
                BASE_FILE,
                "definition_version: 2\nenv:\n  a: \"<% fn.x.y %>\"\n"
            )]),
            failed("Could not find template variable fn.x.y")
        );
        assert_eq!(
            error(&[(
                BASE_FILE,
                "definition_version: 2\nenv:\n  a: \"<% other.x %>\"\n"
            )]),
            failed("Could not find template variable other.x")
        );
        assert_eq!(
            error(&[(
                BASE_FILE,
                "definition_version: 2\nenv:\n  a: \"<% ctx.env.b | int + 'x' %>\"\n  b: '1'\n"
            )]),
            failed(&error_detail_render("<% b | int + 'x' %>"))
        );
    }

    fn error_detail(text: &str) -> String {
        let engine = template::client_engine(Path::new("/"), &Env::default());
        let err = template::undeclared(&engine, text, true).unwrap_err();
        template::message(&err, &engine, &Value::UNDEFINED)
    }

    fn error_detail_render(text: &str) -> String {
        let engine = template::client_engine(Path::new("/"), &Env::default());
        let ctx = Value::from_pairs([("b", "1")]);
        let err = engine.render_str(text, &ctx).unwrap_err();
        template::message(&err, &engine, &ctx)
    }

    #[test]
    fn project_env_renders_like_python() {
        let env = Value::from_object(ProjectEnv {
            overrides: [("a".to_string(), "1".to_string())].into(),
            os: Env::default(),
            defaults: vec![("b".into(), "2".into())],
        });
        assert_eq!(
            env.to_string(),
            "ProjectEnvironment(override_env={'a': '1'}, default_env={'b': '2'})"
        );
        assert_eq!(env.get_attr("b").unwrap().to_string(), "2");
        assert!(env.get_attr("c").unwrap().is_undefined());
    }

    #[test]
    fn nested_contexts_and_strings() {
        let flat: BTreeMap<String, Value> = [
            ("ctx.env.a".to_string(), Value::from("1")),
            ("ctx.env.b".to_string(), Value::from("2")),
            ("x".to_string(), Value::from("3")),
        ]
        .into();
        let nested = nest(&flat);
        assert_eq!(
            nested.to_string(),
            "{'ctx': {'env': {'a': '1', 'b': '2'}}, 'x': '3'}"
        );
        assert_eq!(node_str(&Node::Seq(vec![Node::Str("a".into())])), "['a']");
    }

    #[test]
    fn files_are_read_with_snows_limits() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert!(
            read_limited(&root)
                .unwrap_err()
                .starts_with("[Errno 21] Is a directory")
        );
        assert!(
            read_limited(&root.join("x"))
                .unwrap_err()
                .starts_with("[Errno 2] No such file")
        );
        let big = root.join("big");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(SIZE_LIMIT_MB * 1024 * 1024 + 1).unwrap();
        assert_eq!(
            read_limited(&big).unwrap_err(),
            format!("File {} is too large (size limit: 128 KB)", big.display())
        );
    }

    #[test]
    fn paths_resolve_like_python() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(absolute(&root.join("./a/../b/./c")), root.join("b/c"));
        // Windows resolves `/` against a drive, so this is POSIX-only.
        #[cfg(unix)]
        assert_eq!(absolute(Path::new("/")), PathBuf::from("/"));
    }
}
