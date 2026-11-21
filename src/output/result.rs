//! What a command returns, rendered in the four `--format`s the way snow renders its
//! `MessageResult`, `ObjectResult` and `CollectionResult`.

use crate::error::Result;
use crate::output::format::OutputFormat;
use crate::output::nonprintable::NON_PRINTABLE;
use crate::render::{json_quote, pyfmt, render_with_width};
use crate::sql::result::{Column, QueryResult, SfType, Value};
use std::io::Write;

/// A value of a result: the JSON subset commands need.
#[derive(Debug, Clone, PartialEq)]
pub enum Field {
    Null,
    Bool(bool),
    Int(i64),
    /// A Python `float`.
    Float(f64),
    Str(String),
    /// A Python `list`.
    List(Vec<Field>),
    /// An ordered mapping (a Python `dict`).
    Map(Vec<(String, Field)>),
}

impl Field {
    pub fn str(value: impl Into<String>) -> Self {
        Field::Str(value.into())
    }

    /// Python's `repr()` of the value (what snow prints inside a table cell).
    fn py_repr(&self) -> String {
        match self {
            Field::Null => "None".into(),
            Field::Bool(true) => "True".into(),
            Field::Bool(false) => "False".into(),
            Field::Int(i) => i.to_string(),
            Field::Float(f) => pyfmt::float_repr(*f),
            Field::Str(s) => py_str_repr(s),
            Field::List(items) => {
                let items: Vec<String> = items.iter().map(Field::py_repr).collect();
                format!("[{}]", items.join(", "))
            }
            Field::Map(items) => {
                let items: Vec<String> = items
                    .iter()
                    .map(|(k, v)| format!("{}: {}", py_str_repr(k), v.py_repr()))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
        }
    }

    /// `str()` of the value, as TABLE and PLAIN show a top-level cell.
    fn py_str(&self) -> String {
        match self {
            Field::Str(s) => s.clone(),
            other => other.py_repr(),
        }
    }

    /// `json.dumps(value, indent=4)` of a value nested `depth` levels deep.
    fn json(&self, depth: usize) -> String {
        match self {
            Field::Null => "null".into(),
            Field::Bool(b) => b.to_string(),
            Field::Int(i) => i.to_string(),
            Field::Float(f) => pyfmt::json_float(*f),
            Field::Str(s) => json_quote(s),
            Field::List(items) if items.is_empty() => "[]".into(),
            Field::List(items) => {
                let pad = "    ".repeat(depth + 1);
                let members: Vec<String> = items
                    .iter()
                    .map(|v| format!("{pad}{}", v.json(depth + 1)))
                    .collect();
                format!("[\n{}\n{}]", members.join(",\n"), "    ".repeat(depth))
            }
            Field::Map(items) if items.is_empty() => "{}".into(),
            Field::Map(items) => {
                let pad = "    ".repeat(depth + 1);
                let members: Vec<String> = items
                    .iter()
                    .map(|(k, v)| format!("{pad}{}: {}", json_quote(k), v.json(depth + 1)))
                    .collect();
                format!("{{\n{}\n{}}}", members.join(",\n"), "    ".repeat(depth))
            }
        }
    }

    fn to_value(&self, as_text: bool) -> Value {
        match self {
            Field::Null => Value::Null,
            Field::Bool(b) if !as_text => Value::Bool(*b),
            Field::Int(i) if !as_text => Value::Int(i128::from(*i)),
            other => Value::Text(other.py_str()),
        }
    }
}

/// Python's `repr()` of a `str`: single quotes unless the text has `'` and no `"`.
pub(crate) fn py_str_repr(text: &str) -> String {
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
            c if is_non_printable(c) => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Whether Python's `str.isprintable()` is false for `c`.
fn is_non_printable(c: char) -> bool {
    let n = c as u32;
    NON_PRINTABLE
        .binary_search_by(|&(lo, hi)| {
            if hi < n {
                std::cmp::Ordering::Less
            } else if lo > n {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The result of a command.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandResult {
    /// One line of text.
    Message(String),
    /// One record: key/value pairs.
    Object(Vec<(String, Field)>),
    /// Records with the same keys.
    Collection(Vec<Vec<(String, Field)>>),
    /// Results printed one after the other (snow's `MultipleResults`, TABLE and PLAIN only).
    Multiple(Vec<CommandResult>),
}

impl CommandResult {
    /// Writes the result to `out` in `format`.
    pub fn write(
        &self,
        format: OutputFormat,
        terminal_width: Option<usize>,
        out: &mut dyn Write,
    ) -> Result<()> {
        let table = |result: QueryResult, out: &mut dyn Write| {
            render_with_width(&result, format, terminal_width, out)
        };
        match (self, format) {
            (CommandResult::Multiple(results), _) => results
                .iter()
                .try_for_each(|r| r.write(format, terminal_width, out)),
            (CommandResult::Message(text), OutputFormat::Table | OutputFormat::Plain) => {
                write_text(out, &format!("{text}\n"))
            }
            (CommandResult::Message(text), OutputFormat::Json | OutputFormat::JsonExt) => {
                write_text(
                    out,
                    &(Field::Map(vec![("message".into(), Field::str(text.as_str()))]).json(0)
                        + "\n"),
                )
            }
            (CommandResult::Message(text), OutputFormat::Csv) => table(
                query_result(
                    &["message".to_string()],
                    &[vec![Field::str(text.as_str())]],
                    false,
                ),
                out,
            ),
            (CommandResult::Object(items), OutputFormat::Json | OutputFormat::JsonExt) => {
                write_text(out, &(Field::Map(items.clone()).json(0) + "\n"))
            }
            (CommandResult::Object(items), OutputFormat::Csv) => {
                let keys: Vec<String> = items.iter().map(|(k, _)| k.clone()).collect();
                let row: Vec<Field> = items.iter().map(|(_, v)| v.clone()).collect();
                table(query_result(&keys, &[row], false), out)
            }
            (CommandResult::Object(items), _) => {
                let rows: Vec<Vec<Field>> = items
                    .iter()
                    .map(|(k, v)| vec![Field::str(k.as_str()), v.clone()])
                    .collect();
                let keys = ["key".to_string(), "value".to_string()];
                table(query_result(&keys, &rows, true), out)
            }
            (CommandResult::Collection(records), OutputFormat::Json | OutputFormat::JsonExt) => {
                if records.is_empty() {
                    return write_text(out, "[]\n");
                }
                let items: Vec<String> = records
                    .iter()
                    .map(|r| format!("    {}", Field::Map(r.clone()).json(1)))
                    .collect();
                write_text(out, &format!("[\n{}\n]\n", items.join(",\n")))
            }
            (CommandResult::Collection(records), _) => {
                let keys: Vec<String> = records
                    .first()
                    .map(|r| r.iter().map(|(k, _)| k.clone()).collect())
                    .unwrap_or_default();
                let rows: Vec<Vec<Field>> = records
                    .iter()
                    .map(|r| r.iter().map(|(_, v)| v.clone()).collect())
                    .collect();
                table(query_result(&keys, &rows, false), out)
            }
        }
    }
}

fn write_text(out: &mut dyn Write, text: &str) -> Result<()> {
    use crate::error::{Error, ErrorKind};
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            Err(Error::new(ErrorKind::Client, "Failed to write the result.").with_source(e))
        }
        _ => Ok(()),
    }
}

/// A `QueryResult` of text (or bool/int) columns, so the existing renderers draw it.
/// `as_text` turns every cell into its `str()`, as the key/value table of an object does.
fn query_result(keys: &[String], rows: &[Vec<Field>], as_text: bool) -> QueryResult {
    let columns = keys
        .iter()
        .enumerate()
        .map(|(i, name)| Column {
            name: name.clone(),
            sf_type: match rows.first().and_then(|r| r.get(i)) {
                Some(Field::Bool(_)) if !as_text => SfType::Boolean,
                Some(Field::Int(_)) if !as_text => SfType::Fixed {
                    precision: 38,
                    scale: 0,
                },
                _ => SfType::Text,
            },
            nullable: true,
        })
        .collect();
    QueryResult {
        statement_handle: String::new(),
        columns,
        rows: rows
            .iter()
            .map(|r| r.iter().map(|f| f.to_value(as_text)).collect())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(result: &CommandResult, format: OutputFormat) -> String {
        let mut out = Vec::new();
        result.write(format, None, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn json_ext_prints_what_json_prints_for_command_results() {
        for result in [
            collection(),
            CommandResult::Message("done".into()),
            CommandResult::Object(vec![("k".into(), Field::str("v"))]),
        ] {
            assert_eq!(
                render(&result, OutputFormat::JsonExt),
                render(&result, OutputFormat::Json)
            );
        }
    }

    fn params() -> Field {
        Field::Map(vec![
            ("account".into(), Field::str("acc")),
            ("port".into(), Field::Int(443)),
            ("keep".into(), Field::Bool(true)),
        ])
    }

    fn collection() -> CommandResult {
        CommandResult::Collection(vec![
            vec![
                ("connection_name".into(), Field::str("dev")),
                ("parameters".into(), params()),
                ("is_default".into(), Field::Bool(false)),
            ],
            vec![
                ("connection_name".into(), Field::str("e")),
                ("parameters".into(), Field::Map(vec![])),
                ("is_default".into(), Field::Bool(true)),
            ],
        ])
    }

    #[test]
    fn python_repr_matches() {
        assert_eq!(py_str_repr("a"), "'a'");
        assert_eq!(py_str_repr("it's"), "\"it's\"");
        assert_eq!(py_str_repr("it's \"x\""), "'it\\'s \"x\"'");
        assert_eq!(
            py_str_repr("a\\b\n\t\r\u{1}\u{7f}é"),
            "'a\\\\b\\n\\t\\r\\x01\\x7fé'"
        );
        assert_eq!(py_str_repr("\u{a0}"), "'\\xa0'");
        assert_eq!(py_str_repr("\u{85}"), "'\\x85'");
        assert_eq!(py_str_repr("\u{200b}"), "'\\u200b'");
        assert_eq!(py_str_repr("\u{2028}"), "'\\u2028'");
        assert_eq!(py_str_repr("\u{e0080}"), "'\\U000e0080'");
        assert_eq!(py_str_repr("é中😀 x"), "'é中😀 x'");
        assert_eq!(
            params().py_repr(),
            "{'account': 'acc', 'port': 443, 'keep': True}"
        );
        assert_eq!(Field::Null.py_repr(), "None");
        assert_eq!(Field::Bool(false).py_repr(), "False");
    }

    #[test]
    fn floats_render_like_python() {
        let cases = [
            (1e-7, "1e-07", "1e-07"),
            (1e16, "1e+16", "1e+16"),
            (f64::NAN, "nan", "NaN"),
            (f64::INFINITY, "inf", "Infinity"),
            (f64::NEG_INFINITY, "-inf", "-Infinity"),
        ];
        for (f, text, json) in cases {
            let r = CommandResult::Object(vec![("v".into(), Field::Float(f))]);
            assert!(render(&r, OutputFormat::Table).contains(text), "{text}");
            assert!(render(&r, OutputFormat::Plain).contains(text), "{text}");
            assert!(
                render(&r, OutputFormat::Json).contains(&format!("\"v\": {json}\n")),
                "{json}"
            );
        }
    }

    #[test]
    fn message_in_every_format() {
        let m = CommandResult::Message("Wrote, \"x\"".into());
        assert_eq!(render(&m, OutputFormat::Table), "Wrote, \"x\"\n");
        assert_eq!(render(&m, OutputFormat::Plain), "Wrote, \"x\"\n");
        assert_eq!(
            render(&m, OutputFormat::Json),
            "{\n    \"message\": \"Wrote, \\\"x\\\"\"\n}\n"
        );
        assert_eq!(
            render(&m, OutputFormat::Csv),
            "message\n\"Wrote, \"\"x\"\"\"\n"
        );
    }

    #[test]
    fn object_in_every_format() {
        let o = CommandResult::Object(vec![
            ("Connection name".into(), Field::Null),
            ("Status".into(), Field::str("OK")),
        ]);
        assert_eq!(
            render(&o, OutputFormat::Table),
            "\
+-------------------------+
| key             | value |
|-----------------+-------|
| Connection name | None  |
| Status          | OK    |
+-------------------------+
"
        );
        assert_eq!(
            render(&o, OutputFormat::Json),
            "{\n    \"Connection name\": null,\n    \"Status\": \"OK\"\n}\n"
        );
        assert_eq!(
            render(&o, OutputFormat::Csv),
            "Connection name,Status\n,OK\n"
        );
        assert!(render(&o, OutputFormat::Plain).starts_with("key"));
    }

    #[test]
    fn collection_json_nests_objects_like_json_dumps() {
        assert_eq!(
            render(&collection(), OutputFormat::Json),
            "\
[
    {
        \"connection_name\": \"dev\",
        \"parameters\": {
            \"account\": \"acc\",
            \"port\": 443,
            \"keep\": true
        },
        \"is_default\": false
    },
    {
        \"connection_name\": \"e\",
        \"parameters\": {},
        \"is_default\": true
    }
]
"
        );
    }

    #[test]
    fn collection_csv_and_table_use_python_reprs() {
        assert_eq!(
            render(&collection(), OutputFormat::Csv),
            "connection_name,parameters,is_default\ndev,\"{'account': 'acc', 'port': 443, 'keep': True}\",False\ne,{},True\n"
        );
        let table = render(&collection(), OutputFormat::Table);
        assert!(
            table.contains(
                "| dev             | {'account': 'acc', 'port': 443, 'keep': True} | False      |"
            ),
            "{table}"
        );
    }

    #[test]
    fn empty_collection() {
        let empty = CommandResult::Collection(vec![]);
        assert_eq!(render(&empty, OutputFormat::Json), "[]\n");
        assert_eq!(render(&empty, OutputFormat::Csv), "");
        assert!(render(&empty, OutputFormat::Table).starts_with("No data"));
    }

    #[test]
    fn a_closed_pipe_is_not_an_error_but_other_write_errors_are() {
        struct Failing(std::io::ErrorKind);
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(self.0.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let m = CommandResult::Message("x".into());
        m.write(
            OutputFormat::Table,
            None,
            &mut Failing(std::io::ErrorKind::BrokenPipe),
        )
        .unwrap();
        let err = m
            .write(
                OutputFormat::Table,
                None,
                &mut Failing(std::io::ErrorKind::Other),
            )
            .unwrap_err();
        assert_eq!(err.message(), "Failed to write the result.");
    }
}
