//! The statement list of a `snow sql` run, built as `snow` builds it (ADR 0004, Decision 2).

pub mod command;
pub mod source;
pub mod split;
pub mod template;

use crate::error::{Error, ErrorKind, Result};
use source::resolve;
pub use source::{Directive, FsSources, Sources};
pub use split::py_strip;
use split::split_statements;
use std::path::PathBuf;
use template::{TemplateError, Templater};

/// How the inputs are read.
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// `--retain-comments`: comments reach the server as part of the statement text.
    pub retain_comments: bool,
    /// `--single-transaction`: `BEGIN;` and `COMMIT;` go around the list.
    pub single_transaction: bool,
    /// `--local-only`: `!source`/`!load` refuse URLs.
    pub local_only: bool,
}

/// The text `snow` prints on stdout for an exception it does not expect.
pub fn unexpected_notice(message: &str) -> String {
    format!(
        "\nAn unexpected exception occurred. Use --debug option to see the traceback. Exception message:\n\n{message}"
    )
}

/// A template error that stops the run, as `snow` reports it. The text of an unexpected
/// exception goes to `notices` (snow prints it as a warning).
fn template_failure(err: TemplateError, notices: &mut Vec<String>) -> Error {
    match err {
        TemplateError::Cli { message, feedback } => {
            let err = Error::new(ErrorKind::Client, message);
            if feedback {
                err
            } else {
                err.without_feedback()
            }
        }
        TemplateError::Project(message) => Error::new(ErrorKind::Argument, message),
        TemplateError::Undefined(message) | TemplateError::Unexpected(message) => {
            notices.push(unexpected_notice(&message));
            Error::new(ErrorKind::Unexpected, message)
        }
    }
}

/// One statement to send: its text is both the echo and what goes into the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub text: String,
    /// Empty once comments are removed (`;`, `/* c */ ;`): the server ignores it inside a
    /// multi-statement request, so it is sent alone (Decision 1).
    pub empty: bool,
    /// A `PUT` or `GET` (the connector's rule, as the splitter applies it): the run needs a
    /// session (ADR 0005, Decision 1).
    pub put_or_get: bool,
    /// An interactive-session `!` command (`text` is its source): run by the client, never sent.
    pub command: Option<command::ReplCommand>,
    /// Ended with `;>` (`text` without it): submitted without waiting for it, on a session
    /// (`cursor.execute_async`); prints its query id and has no result of its own.
    pub asynchronous: bool,
}

/// One input of a run: the `-q` or stdin text, or one `-f` file (with its path, which the
/// cycle check of `!source` starts from).
#[derive(Debug, Clone)]
pub struct Input {
    pub text: String,
    pub file: Option<PathBuf>,
}

/// Builds the statement list from the inputs (the `-q` text, the stdin text, or each `-f` file
/// on its own), in order. Checks everything before anything is sent. `!source`/`!load` read
/// files from the disk and URLs over HTTPS.
///
/// `notices` receives the lines `snow` prints on stdout while rendering (the deprecation
/// warning, one line per undefined variable or unusable directive); the caller prints them,
/// whatever the result.
pub fn compile(
    inputs: &[String],
    options: &CompileOptions,
    templater: &Templater<'_>,
    notices: &mut Vec<String>,
) -> Result<Vec<Statement>> {
    let inputs: Vec<Input> = inputs
        .iter()
        .map(|text| Input {
            text: text.clone(),
            file: None,
        })
        .collect();
    compile_inputs(&inputs, options, templater, notices, &FsSources::default())
}

/// [`compile`] with the origin of each input and the loader of `!source` targets.
pub fn compile_inputs(
    inputs: &[Input],
    options: &CompileOptions,
    templater: &Templater<'_>,
    notices: &mut Vec<String>,
    sources: &dyn Sources,
) -> Result<Vec<Statement>> {
    let mut compiler = Compiler {
        options,
        templater,
        sources,
        notices,
        statements: Vec::new(),
        errors: 0,
        includes: 0,
    };
    for input in inputs {
        // The include budget is per input, as in `snow`.
        compiler.includes = 0;
        let mut seen = match &input.file {
            Some(path) => vec![resolve(path).display().to_string()],
            None => Vec::new(),
        };
        compiler.read(&input.text, &mut seen, 0)?;
    }
    let Compiler {
        mut statements,
        errors,
        ..
    } = compiler;
    if errors > 0 {
        return Err(Error::new(ErrorKind::Sql, "SQL rendering error"));
    }
    if statements.is_empty() {
        return Err(Error::new(
            ErrorKind::Client,
            "No SQL statements found to execute.",
        ));
    }
    if options.single_transaction {
        let statement = |text: &str| Statement {
            text: text.to_string(),
            empty: false,
            put_or_get: false,
            command: None,
            asynchronous: false,
        };
        statements.insert(0, statement("BEGIN;"));
        statements.push(statement("COMMIT;"));
    }
    Ok(statements)
}

struct Compiler<'a> {
    options: &'a CompileOptions,
    templater: &'a Templater<'a>,
    sources: &'a dyn Sources,
    notices: &'a mut Vec<String>,
    statements: Vec<Statement>,
    /// Statements that could not be compiled; reported together (`compile_statements`).
    errors: usize,
    includes: usize,
}

impl Compiler<'_> {
    fn error(&mut self, message: String) {
        self.notices.push(message);
        self.errors += 1;
    }

    /// `recursive_statement_reader`: the pieces of `text`, with `!source`/`!load` replaced by
    /// the pieces of their target. `seen` is the chain of sources being read.
    ///
    /// With JINJA, the whole text (an input or a sourced file) is rendered before it is split
    /// (`_jinja_pre_render`); without it, each piece is rendered on its own.
    fn read(&mut self, text: &str, seen: &mut Vec<String>, depth: usize) -> Result<()> {
        let options = self.options;
        let templater = self.templater;
        let jinja = templater.syntaxes().jinja;
        let pre_rendered;
        let mut text = text;
        if jinja {
            pre_rendered = templater
                .pre_render(text, self.notices)
                .map_err(|e| template_failure(e, self.notices))?;
            text = &pre_rendered;
        }
        for piece in split_statements(text, !options.retain_comments) {
            if piece.text.is_empty() {
                continue;
            }
            let rendered = if jinja {
                piece.text
            } else {
                match templater.render_statement(&piece.text, self.notices) {
                    Ok(text) => text,
                    Err(TemplateError::Undefined(message)) => {
                        self.error(format!("SQL template rendering error: {message}"));
                        continue;
                    }
                    Err(e) => return Err(template_failure(e, self.notices)),
                }
            };
            match source::parse(&rendered, options.local_only) {
                None => self.query(&rendered)?,
                Some(Directive::Invalid(message)) => self.error(message),
                Some(Directive::Repl(_)) => match command::compile(&rendered) {
                    Ok(command) => self.statements.push(Statement {
                        text: rendered,
                        empty: false,
                        put_or_get: false,
                        command: Some(command),
                        asynchronous: false,
                    }),
                    Err(message) => self.error(message),
                },
                Some(Directive::File(path_part)) => {
                    self.include(&path_part, false, seen, depth)?;
                }
                Some(Directive::Url(path_part)) => {
                    self.include(&path_part, true, seen, depth)?;
                }
            }
        }
        Ok(())
    }

    /// Reads the target of one `!source`/`!load` and the statements in it.
    fn include(
        &mut self,
        path_part: &str,
        url: bool,
        seen: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
        // `snow` raises `StopIteration` from its generator when the path is empty.
        let Some(target) = source::drop_comments_opt(path_part) else {
            return Err(template_failure(
                TemplateError::Unexpected("generator raised StopIteration".into()),
                self.notices,
            ));
        };
        let identity = if url {
            target.clone()
        } else {
            self.sources.canonical(&target)
        };
        if seen.contains(&identity) {
            self.error(format!("Recursion detected: {}", seen.join(" -> ")));
            return Ok(());
        }
        if depth >= source::MAX_DEPTH {
            self.error(format!(
                "Maximum !source nesting depth ({}) exceeded",
                source::MAX_DEPTH
            ));
            return Ok(());
        }
        if self.includes >= source::MAX_INCLUDES {
            self.error(format!(
                "Maximum number of !source/!load inclusions ({}) exceeded",
                source::MAX_INCLUDES
            ));
            return Ok(());
        }
        self.includes += 1;
        let loaded = if url {
            self.sources.fetch_url(&target, path_part)
        } else {
            self.sources.read_file(&target, path_part)
        };
        match loaded {
            Ok(content) => {
                seen.push(identity);
                let result = self.read(&content, seen, depth + 1);
                seen.pop();
                result
            }
            Err(message) => {
                self.error(message);
                Ok(())
            }
        }
    }

    /// An SQL statement of the list (`compile_statements`, then `execute_string`).
    fn query(&mut self, rendered: &str) -> Result<()> {
        if is_empty_statement(rendered) {
            return Ok(());
        }
        // `compile_statements`: the statement goes to `execute_async` as it is, without `;>`
        // (no second split).
        if let Some(text) = rendered.strip_suffix(";>") {
            self.statements.push(Statement {
                text: text.to_string(),
                empty: false,
                put_or_get: false,
                command: None,
                asynchronous: true,
            });
            return Ok(());
        }
        // `execute_string` → `execute_stream`: dedent, split again keeping comments.
        for part in split_statements(&dedent(rendered), false) {
            if part.text.is_empty() {
                continue;
            }
            let empty = split_statements(&part.text, true)
                .iter()
                .all(|p| p.text.is_empty() || p.text == ";");
            self.statements.push(Statement {
                put_or_get: part.put_or_get == Some(true),
                text: part.text,
                empty,
                command: None,
                asynchronous: false,
            });
        }
        Ok(())
    }
}

/// `snow`'s `_is_empty_statement`: every line is blank or starts with `--`.
fn is_empty_statement(text: &str) -> bool {
    py_splitlines(text).all(|line| {
        let stripped = py_strip(line);
        stripped.is_empty() || stripped.starts_with("--")
    })
}

/// Python's `str.splitlines()` (without the line ends).
fn py_splitlines(text: &str) -> impl Iterator<Item = &str> {
    let mut lines = text
        .split("\r\n")
        .flat_map(|s| {
            s.split([
                '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
                '\u{2029}',
            ])
        })
        .collect::<Vec<_>>();
    // A final line end does not start another line.
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines.into_iter()
}

/// `textwrap.dedent` (Python 3.13) on a stripped statement: its first line has no indent, so
/// the only change is that lines of spaces and tabs become empty.
fn dedent(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            if !line.is_empty() && line.chars().all(|c| c == ' ' || c == '\t') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Python's `repr()` of a string, as click quotes a file name and the connector
/// lists file names.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;
    use crate::project::ProjectSource;
    use template::{LEGACY_WARNING, Syntaxes, Variables};

    /// `compile` with the default syntaxes, no variables and no project.
    fn compile(
        inputs: &[String],
        options: &CompileOptions,
        notices: &mut Vec<String>,
    ) -> Result<Vec<Statement>> {
        compile_with(inputs, options, &[], Syntaxes::default(), notices)
    }

    fn compile_with(
        inputs: &[String],
        options: &CompileOptions,
        variables: &[(&str, &str)],
        syntaxes: Syntaxes,
        notices: &mut Vec<String>,
    ) -> Result<Vec<Statement>> {
        let variables: Variables = variables
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let project = ProjectSource::new(None, Variables::new(), Env::default());
        let templater = Templater::new(&variables, syntaxes, &project);
        super::compile(inputs, options, &templater, notices)
    }

    fn texts(inputs: &[&str], retain: bool) -> Result<Vec<String>> {
        let inputs: Vec<String> = inputs.iter().map(|s| s.to_string()).collect();
        let options = CompileOptions {
            retain_comments: retain,
            ..CompileOptions::default()
        };
        Ok(compile(&inputs, &options, &mut Vec::new())?
            .into_iter()
            .map(|s| s.text)
            .collect())
    }

    #[test]
    fn splits_each_input_and_keeps_the_order() {
        assert_eq!(
            texts(&["select 1; select 'a;b'", "select 3"], false).unwrap(),
            vec!["select 1;", "select 'a;b'", "select 3"]
        );
    }

    #[test]
    fn comments_are_removed_unless_retained() {
        let sql = "-- lead\nselect 1; -- tail\n/* only */\nselect 2;";
        assert_eq!(
            texts(&[sql], false).unwrap(),
            vec!["select 1;", "select 2;"]
        );
        assert_eq!(
            texts(&[sql], true).unwrap(),
            vec!["-- lead\nselect 1; -- tail", "/* only */\nselect 2;"]
        );
    }

    #[test]
    fn comment_only_pieces_are_dropped_and_nothing_left_is_an_error() {
        let err = texts(&["-- nothing\n", "\n"], true).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(err.message(), "No SQL statements found to execute.");
    }

    #[test]
    fn stray_semicolons_are_statements_flagged_empty() {
        let inputs = vec!["select 1;\n;\n/* c */ ;".to_string()];
        let statements = compile(&inputs, &CompileOptions::default(), &mut Vec::new()).unwrap();
        let flags: Vec<(&str, bool)> = statements
            .iter()
            .map(|s| (s.text.as_str(), s.empty))
            .collect();
        assert_eq!(flags, vec![("select 1;", false), (";", true), (";", true)]);
        let retained = compile(
            &inputs,
            &CompileOptions {
                retain_comments: true,
                ..CompileOptions::default()
            },
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(retained[2].text, "/* c */ ;");
        assert!(retained[2].empty);
    }

    #[test]
    fn asynchronous_statements_lose_their_suffix_and_are_not_split_again() {
        let inputs = vec!["select 1;> select 2;\n  select 3 ;>\nselect &v;>".to_string()];
        let mut notices = Vec::new();
        let list = compile_with(
            &inputs,
            &CompileOptions::default(),
            &[("v", "4; select 5")],
            Syntaxes::default(),
            &mut notices,
        )
        .unwrap();
        let flags: Vec<(&str, bool)> = list
            .iter()
            .map(|s| (s.text.as_str(), s.asynchronous))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("select 1", true),
                ("select 2;", false),
                ("select 3 ", true),
                // A `;` from a variable stays in the one asynchronous statement.
                ("select 4; select 5", true),
            ]
        );
        // A trailing comment hides the suffix: a plain statement, as in snow.
        assert_eq!(
            texts(&["select 1;> -- c"], true).unwrap(),
            vec!["select 1;> -- c"]
        );
        // `!` without a word is SQL (and fails on the server).
        assert_eq!(texts(&["! x"], false).unwrap(), vec!["! x"]);
    }

    #[test]
    fn interactive_commands_are_compiled_in_order() {
        let inputs = vec!["select 1; !set quiet=true; !spool off".to_string()];
        let list = compile(&inputs, &CompileOptions::default(), &mut Vec::new()).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].command, None);
        assert_eq!(
            list[1].command,
            Some(command::ReplCommand::Set(
                command::SetOption::Quiet,
                "true".into()
            ))
        );
        assert_eq!(list[1].text, "!set quiet=true;");
        assert_eq!(list[2].command, Some(command::ReplCommand::Spool(None)));
        // A bad command is a compilation error, reported with the others.
        let mut notices = Vec::new();
        let err = compile(
            &["!set x=1;\n!abort".to_string()],
            &CompileOptions::default(),
            &mut notices,
        )
        .unwrap_err();
        assert_eq!(err.message(), "SQL rendering error");
        assert_eq!(notices.len(), 2);
        assert!(notices[0].starts_with("Unknown option passed to 'set' command: 'x'."));
        assert!(notices[1].starts_with("No arguments passed to 'abort' command."));
    }

    #[test]
    fn whitespace_only_lines_are_emptied_as_dedent_does() {
        assert_eq!(
            texts(&["select 1\n   \n\t\nfrom t;"], false).unwrap(),
            vec!["select 1\n\n\nfrom t;"]
        );
    }

    #[test]
    fn python_splitlines() {
        assert_eq!(
            py_splitlines("a\r\nb\rc\n\u{2028}d\n").collect::<Vec<_>>(),
            vec!["a", "b", "c", "", "d"]
        );
        assert_eq!(py_splitlines("").count(), 0);
        assert!(is_empty_statement("  \n -- x\n"));
        assert!(!is_empty_statement("-- x\nselect"));
    }

    fn templated(sql: &str, variables: &[(&str, &str)]) -> (Result<Vec<Statement>>, Vec<String>) {
        let mut notices = Vec::new();
        let result = compile_with(
            &[sql.to_string()],
            &CompileOptions::default(),
            variables,
            Syntaxes::default(),
            &mut notices,
        );
        (result, notices)
    }

    #[test]
    fn templating_runs_between_the_splits() {
        // A `;` in a value does not split the first pass, but the second pass splits it
        // (and, quoted, still does not).
        let (result, notices) = templated(
            "select &v; select '<% q %>'; select <% w %>",
            &[("v", "1; select 9"), ("q", "a;b"), ("w", "2")],
        );
        let texts: Vec<String> = result.unwrap().into_iter().map(|s| s.text).collect();
        assert_eq!(
            texts,
            vec!["select 1;", "select 9;", "select 'a;b';", "select 2"]
        );
        assert_eq!(notices, vec![LEGACY_WARNING]);
    }

    #[test]
    fn rendering_errors_are_all_reported_before_anything_is_sent() {
        let (result, notices) = templated("select &a; select <% b %>; select 1", &[]);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Sql);
        assert_eq!(err.message(), "SQL rendering error");
        assert_eq!(
            notices,
            vec![
                LEGACY_WARNING.to_string(),
                "SQL template rendering error: 'a' is undefined".into(),
                "SQL template rendering error: 'b' is undefined".into(),
            ]
        );
    }

    #[test]
    fn a_fatal_rendering_error_stops_at_once() {
        let (result, notices) = templated("select <% a ", &[]);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(err.message().starts_with("unexpected end of template"));
        assert_eq!(notices, vec![unexpected_notice(err.message())]);
    }

    #[test]
    fn single_transaction_wraps_the_list_in_user_statements() {
        let options = CompileOptions {
            single_transaction: true,
            ..CompileOptions::default()
        };
        let statements = compile(
            &["select 1; select 2".to_string()],
            &options,
            &mut Vec::new(),
        )
        .unwrap();
        let texts: Vec<&str> = statements.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, vec!["BEGIN;", "select 1;", "select 2", "COMMIT;"]);
        assert!(statements.iter().all(|s| !s.empty));
        // Nothing to run is still an error: no empty transaction.
        let err = compile(&["-- c".to_string()], &options, &mut Vec::new()).unwrap_err();
        assert_eq!(err.message(), "No SQL statements found to execute.");
    }

    /// Files and URLs in memory, so the tests need neither a disk nor a network.
    struct Memory(std::collections::BTreeMap<&'static str, &'static str>);

    impl Sources for Memory {
        fn canonical(&self, path: &str) -> String {
            path.to_string()
        }
        fn read_file(&self, path: &str, path_part: &str) -> std::result::Result<String, String> {
            self.0
                .get(path)
                .map(|t| t.to_string())
                .ok_or_else(|| format!("Could not read: {path_part}"))
        }
        fn fetch_url(&self, url: &str, path_part: &str) -> std::result::Result<String, String> {
            self.0
                .get(url)
                .map(|t| t.to_string())
                .ok_or_else(|| format!("Could not fetch {path_part}: gone"))
        }
    }

    fn sourced(
        files: &[(&'static str, &'static str)],
        text: &str,
        file: Option<&str>,
        options: &CompileOptions,
    ) -> (Result<Vec<String>>, Vec<String>) {
        sourced_with(files, text, file, options, &[], Syntaxes::default())
    }

    fn sourced_with(
        files: &[(&'static str, &'static str)],
        text: &str,
        file: Option<&str>,
        options: &CompileOptions,
        variables: &[(&str, &str)],
        syntaxes: Syntaxes,
    ) -> (Result<Vec<String>>, Vec<String>) {
        let variables: Variables = variables
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let project = ProjectSource::new(None, Variables::new(), Env::default());
        let templater = Templater::new(&variables, syntaxes, &project);
        let memory = Memory(files.iter().copied().collect());
        let input = Input {
            text: text.to_string(),
            file: file.map(PathBuf::from),
        };
        let mut notices = Vec::new();
        let result = compile_inputs(&[input], options, &templater, &mut notices, &memory)
            .map(|s| s.into_iter().map(|s| s.text).collect());
        (result, notices)
    }

    #[test]
    fn sources_are_inlined_in_place_and_nest() {
        let files = [
            ("a.sql", "select 'a';\n!source b.sql;\nselect 'a2'"),
            ("b.sql", "select 'b'"),
            ("https://h/c.sql", "select 'c';"),
        ];
        let (result, notices) = sourced(
            &files,
            "select 0;\n!source a.sql;\n!load 'https://h/c.sql';\nselect 9",
            None,
            &CompileOptions::default(),
        );
        assert_eq!(
            result.unwrap(),
            vec![
                "select 0;",
                "select 'a';",
                "select 'b'",
                "select 'a2'",
                "select 'c';",
                "select 9"
            ]
        );
        assert!(notices.is_empty());
    }

    #[test]
    fn the_path_is_templated_and_comments_are_dropped() {
        let options = CompileOptions {
            retain_comments: true,
            ..CompileOptions::default()
        };
        let (result, _) = sourced_with(
            &[("a.sql", "select 1;")],
            "!source <% f %> -- the file",
            None,
            &options,
            &[("f", "a.sql")],
            Syntaxes::default(),
        );
        assert_eq!(result.unwrap(), vec!["select 1;"]);
    }

    #[test]
    fn with_jinja_a_sourced_file_is_rendered_whole_too() {
        let jinja = Syntaxes {
            legacy: false,
            standard: false,
            jinja: true,
        };
        let (result, notices) = sourced_with(
            &[(
                "a.sql",
                "{% for i in range(2) %}select {{ i }} + {{ n }};{% endfor %}",
            )],
            "!source a.sql;
select {{ n }}",
            None,
            &CompileOptions::default(),
            &[("n", "5")],
            jinja,
        );
        assert_eq!(
            result.unwrap(),
            vec!["select 0 + 5;", "select 1 + 5;", "select 5"]
        );
        assert!(notices.is_empty());
    }

    #[test]
    fn errors_are_all_reported_before_anything_runs() {
        let (result, notices) = sourced(
            &[],
            "!source nope.sql\n!source http://h/a\n!source ftp://h/a\n!nope\nselect 1",
            None,
            &CompileOptions::default(),
        );
        assert_eq!(result.unwrap_err().message(), "SQL rendering error");
        assert_eq!(
            notices,
            vec![
                "Could not read: nope.sql".to_string(),
                "Plaintext http:// sources are not allowed: http://h/a. Use https:// or a local file.".into(),
                "Unknown source: ftp://h/a".into(),
                "Unknown command: nope".into(),
            ]
        );
    }

    #[test]
    fn local_only_refuses_urls_and_not_files() {
        let options = CompileOptions {
            local_only: true,
            ..CompileOptions::default()
        };
        let (result, notices) = sourced(
            &[("a.sql", "select 1;"), ("https://h/c.sql", "select 2;")],
            "!source a.sql\n!source https://h/c.sql",
            None,
            &options,
        );
        assert!(result.is_err());
        assert_eq!(
            notices,
            vec!["Loading SQL from URLs is disabled (--local-only): https://h/c.sql"]
        );
    }

    #[test]
    fn a_cycle_names_the_chain_that_led_to_it() {
        let files = [("a.sql", "!source b.sql"), ("b.sql", "!source a.sql")];
        let (result, notices) = sourced(&files, "!source a.sql", None, &CompileOptions::default());
        assert!(result.is_err());
        assert_eq!(notices, vec!["Recursion detected: a.sql -> b.sql"]);
        // An `-f` file is the first link.
        let (_, notices) = sourced(
            &[("a.sql", "!source a.sql")],
            "!source a.sql",
            Some("top.sql"),
            &CompileOptions::default(),
        );
        assert_eq!(notices.len(), 1);
    }

    #[test]
    fn nesting_and_inclusions_are_bounded() {
        let chain: Vec<(&'static str, &'static str)> = (0..40)
            .map(|i| {
                let name: &'static str = Box::leak(format!("f{i}.sql").into_boxed_str());
                let body: &'static str =
                    Box::leak(format!("!source f{}.sql", i + 1).into_boxed_str());
                (name, body)
            })
            .collect();
        let (_, notices) = sourced(&chain, "!source f0.sql", None, &CompileOptions::default());
        assert_eq!(notices, vec!["Maximum !source nesting depth (32) exceeded"]);
        let many = "!source a.sql\n".repeat(40);
        let (_, notices) = sourced(
            &[("a.sql", "select 1;")],
            &many,
            None,
            &CompileOptions::default(),
        );
        assert_eq!(
            notices.len(),
            8,
            "inclusions beyond 32 are errors: {notices:?}"
        );
        assert_eq!(
            notices[0],
            "Maximum number of !source/!load inclusions (32) exceeded"
        );
    }

    #[test]
    fn an_empty_path_is_snows_unexpected_exception() {
        let (result, notices) = sourced(&[], "!source", None, &CompileOptions::default());
        let err = result.unwrap_err();
        // Printed on stdout like any unexpected exception, no panel.
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert_eq!(err.message(), "generator raised StopIteration");
        assert_eq!(
            notices,
            vec![unexpected_notice("generator raised StopIteration")]
        );
    }

    #[test]
    fn a_source_with_nothing_to_run_is_no_statements() {
        let (result, _) = sourced(
            &[("a.sql", "-- empty")],
            "!source a.sql",
            None,
            &CompileOptions::default(),
        );
        assert_eq!(
            result.unwrap_err().message(),
            "No SQL statements found to execute."
        );
    }
}
