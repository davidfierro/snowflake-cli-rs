//! `--format` renderers: JSON, CSV, TABLE, PLAIN (ADR 0001, Decision 6).
//!
//! JSON and CSV reproduce snow 3.34.0 byte for byte (golden tests); TABLE and PLAIN are visually
//! equivalent to it.

mod csv;
mod json;
mod pyjson;
pub(crate) use json::quote as json_quote;
pub(crate) mod pyfmt;
pub(crate) mod sanitize;
mod table;

use crate::codec::hex;
use crate::error::{Error, ErrorKind, Result};
use crate::output::format::OutputFormat;
use crate::sql::result::{Column, QueryResult, SfType, Value};
use std::io::{self, Write};

/// Why a renderer stopped: the output failed, or a row could not be read (ADR 0002, Decision 4).
enum Failure {
    Io(io::Error),
    Row(Error),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Io(e)
    }
}

/// Writes `result` to `out` in `format` (Decision 6). A BrokenPipe write error returns Ok.
pub fn render(result: &QueryResult, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    render_with_width(result, format, None, out)
}

/// Like [`render`]; `terminal_width` is the width of the terminal stdout is attached to, if it
/// is one. TABLE and PLAIN then fold cells to fit it, as snow does; otherwise columns take
/// their natural width. JSON and CSV ignore it.
pub fn render_with_width(
    result: &QueryResult,
    format: OutputFormat,
    terminal_width: Option<usize>,
    out: &mut dyn Write,
) -> Result<()> {
    let mut rows = result.rows.iter().map(|r| Ok(r.as_slice()));
    let written = match format {
        OutputFormat::Json | OutputFormat::JsonExt => json::write(
            &result.columns,
            &mut rows,
            format == OutputFormat::JsonExt,
            out,
        ),
        OutputFormat::Csv => csv::write(&result.columns, &mut rows, out),
        OutputFormat::Table => table::write(result, false, terminal_width, out).map_err(Into::into),
        OutputFormat::Plain => table::write(result, true, terminal_width, out).map_err(Into::into),
    };
    finish(written, out)
}

/// Writes the rows of `stream` to `out` in `format` as they arrive (CSV, JSON), or after the
/// last one (TABLE, PLAIN) (ADR 0002, Decision 3). A BrokenPipe write error returns Ok. An
/// `Err` row stops the output where it is, flushes what was written and returns that error.
pub fn render_stream(
    columns: &[Column],
    rows: &mut dyn Iterator<Item = Result<Vec<Value>>>,
    format: OutputFormat,
    terminal_width: Option<usize>,
    out: &mut dyn Write,
) -> Result<()> {
    let written = match format {
        OutputFormat::Json | OutputFormat::JsonExt => {
            json::write(columns, rows, format == OutputFormat::JsonExt, out)
        }
        OutputFormat::Csv => csv::write(columns, rows, out),
        OutputFormat::Table | OutputFormat::Plain => match rows.collect::<Result<Vec<_>>>() {
            Ok(rows) => {
                let result = QueryResult {
                    statement_handle: String::new(),
                    columns: columns.to_vec(),
                    rows,
                };
                let plain = format == OutputFormat::Plain;
                table::write(&result, plain, terminal_width, out).map_err(Into::into)
            }
            Err(e) => Err(Failure::Row(e)),
        },
    };
    finish(written, out)
}

/// Writes one result of a multi-statement run in JSON (ADR 0004, Decision 4), streaming its
/// rows; the caller writes the enclosing `[`, `,` and `]`. Errors as [`render_stream`].
pub fn render_json_multi(
    columns: &[Column],
    rows: &mut dyn Iterator<Item = Result<Vec<Value>>>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let written = json::write_multi(columns, rows, format == OutputFormat::JsonExt, out);
    finish(written, out)
}

/// Flushes `out` and maps the outcome: BrokenPipe is success, other write errors are Client
/// errors, a row error is returned as it is once what was written is flushed.
fn finish(written: std::result::Result<(), Failure>, out: &mut dyn Write) -> Result<()> {
    let flushed = out.flush();
    let io_error = match written {
        Err(Failure::Row(e)) => return Err(e),
        Err(Failure::Io(e)) => Some(e),
        Ok(()) => flushed.err(),
    };
    match io_error {
        Some(e) if e.kind() != io::ErrorKind::BrokenPipe => {
            Err(Error::new(ErrorKind::Client, "Failed to write the result.").with_source(e))
        }
        _ => Ok(()),
    }
}

/// `str(Decimal)` of a NUMBER/DECFLOAT value; DECFLOAT comes normalized from the connector.
fn decimal_text(raw: &str, column: &Column) -> String {
    pyfmt::decimal_str(raw, column.sf_type == SfType::Decfloat)
}

/// Text of a date/time value as `isoformat()` (`sep = 'T'`) or `str()` (`sep = ' '`).
fn temporal_text(value: &Value, sep: char) -> Option<String> {
    Some(match value {
        Value::Date(d) => pyfmt::date_iso(*d),
        Value::Time(t) => pyfmt::time_iso(*t),
        Value::TimestampNtz(dt) => pyfmt::datetime_iso(*dt, sep),
        Value::TimestampTz {
            local,
            offset_seconds,
        } => format!(
            "{}{}",
            pyfmt::datetime_iso(*local, sep),
            pyfmt::offset_iso(*offset_seconds)
        ),
        _ => return None,
    })
}

/// Python's `str()` of the value the connector returns, used by TABLE and PLAIN.
fn str_text(value: &Value, column: &Column) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Int(i) => i.to_string(),
        Value::Decimal(raw) => decimal_text(raw, column),
        Value::Float(f) => pyfmt::float_repr(*f),
        Value::Text(s) | Value::Json(s) => s.clone(),
        Value::Binary(b) => hex(b),
        other => temporal_text(other, ' ').unwrap_or_default(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn column(name: &str, sf_type: SfType) -> Column {
        Column {
            name: name.into(),
            sf_type,
            nullable: true,
        }
    }

    pub(crate) fn result(columns: Vec<Column>, rows: Vec<Vec<Value>>) -> QueryResult {
        QueryResult {
            statement_handle: "h".into(),
            columns,
            rows,
        }
    }

    pub(crate) fn rendered(result: &QueryResult, format: OutputFormat) -> String {
        let mut out = Vec::new();
        render(result, format, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    struct FailingWriter(io::ErrorKind);
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    fn one_cell() -> QueryResult {
        result(
            vec![column("A", SfType::Text)],
            vec![vec![Value::Text("x".into())]],
        )
    }

    #[test]
    fn broken_pipe_is_not_an_error() {
        for format in [
            OutputFormat::Json,
            OutputFormat::Csv,
            OutputFormat::Table,
            OutputFormat::Plain,
        ] {
            let mut out = FailingWriter(io::ErrorKind::BrokenPipe);
            assert!(render(&one_cell(), format, &mut out).is_ok());
        }
    }

    #[test]
    fn other_write_errors_are_reported() {
        let mut out = FailingWriter(io::ErrorKind::PermissionDenied);
        let err = render(&one_cell(), OutputFormat::Json, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
    }

    const FORMATS: [OutputFormat; 4] = [
        OutputFormat::Json,
        OutputFormat::Csv,
        OutputFormat::Table,
        OutputFormat::Plain,
    ];

    fn two_rows() -> QueryResult {
        result(
            vec![column("A", SfType::Text), column("B", SfType::Boolean)],
            vec![
                vec![Value::Text("x,y".into()), Value::Bool(true)],
                vec![Value::Null, Value::Bool(false)],
            ],
        )
    }

    fn streamed(
        columns: &[Column],
        rows: Vec<Result<Vec<Value>>>,
        format: OutputFormat,
    ) -> (Result<()>, String) {
        let mut out = Vec::new();
        let outcome = render_stream(columns, &mut rows.into_iter(), format, Some(40), &mut out);
        (outcome, String::from_utf8(out).unwrap())
    }

    #[test]
    fn render_stream_matches_render_for_every_format() {
        let empty = result(vec![column("A", SfType::Text)], vec![]);
        for r in [two_rows(), empty, one_cell()] {
            for format in FORMATS {
                let mut expected = Vec::new();
                render_with_width(&r, format, Some(40), &mut expected).unwrap();
                let rows = r.rows.iter().cloned().map(Ok).collect();
                let (outcome, actual) = streamed(&r.columns, rows, format);
                outcome.unwrap();
                assert_eq!(actual, String::from_utf8(expected).unwrap(), "{format:?}");
            }
        }
    }

    #[test]
    fn row_error_keeps_streamed_output_and_is_returned() {
        let r = two_rows();
        let rows = || {
            vec![
                Ok(r.rows[0].clone()),
                Err(Error::new(ErrorKind::Communication, "partition failed")),
                Ok(r.rows[1].clone()),
            ]
        };
        let (outcome, csv) = streamed(&r.columns, rows(), OutputFormat::Csv);
        assert_eq!(outcome.unwrap_err().message(), "partition failed");
        assert_eq!(csv, "A,B\n\"x,y\",True\n");
        let (outcome, json) = streamed(&r.columns, rows(), OutputFormat::Json);
        assert_eq!(outcome.unwrap_err().kind(), ErrorKind::Communication);
        // Unterminated on purpose: a half array must not look complete.
        assert_eq!(
            json,
            "[\n    {\n        \"A\": \"x,y\",\n        \"B\": true\n    }"
        );
        for format in [OutputFormat::Table, OutputFormat::Plain] {
            let (outcome, text) = streamed(&r.columns, rows(), format);
            assert!(outcome.is_err());
            assert_eq!(text, "", "{format:?} buffers, so nothing is written");
        }
    }

    #[test]
    fn render_stream_broken_pipe_is_not_an_error() {
        for format in FORMATS {
            let mut out = FailingWriter(io::ErrorKind::BrokenPipe);
            let r = one_cell();
            let mut rows = r.rows.clone().into_iter().map(Ok);
            assert!(render_stream(&r.columns, &mut rows, format, None, &mut out).is_ok());
        }
        let mut out = FailingWriter(io::ErrorKind::PermissionDenied);
        let r = one_cell();
        let mut rows = r.rows.clone().into_iter().map(Ok);
        let err = render_stream(&r.columns, &mut rows, OutputFormat::Csv, None, &mut out);
        assert_eq!(err.unwrap_err().kind(), ErrorKind::Client);
    }

    #[test]
    fn str_text_uses_python_str() {
        use jiff::civil::date;
        let c = column("C", SfType::Text);
        let cases = [
            (Value::Null, "None"),
            (Value::Bool(true), "True"),
            (Value::Bool(false), "False"),
            (Value::Int(-5), "-5"),
            (Value::Float(1e16), "1e+16"),
            (Value::Binary(vec![0xab, 1]), "ab01"),
            (Value::Json("[1]".into()), "[1]"),
            (
                Value::TimestampNtz(date(2024, 1, 2).at(3, 4, 5, 0)),
                "2024-01-02 03:04:05",
            ),
            (
                Value::TimestampTz {
                    local: date(2024, 1, 2).at(3, 4, 5, 0),
                    offset_seconds: 3600,
                },
                "2024-01-02 03:04:05+01:00",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(str_text(&value, &c), expected);
        }
        assert_eq!(
            str_text(
                &Value::Decimal("420".into()),
                &column("D", SfType::Decfloat)
            ),
            "4.2E+2"
        );
        assert_eq!(
            str_text(
                &Value::Decimal("4.20".into()),
                &column(
                    "D",
                    SfType::Fixed {
                        precision: 3,
                        scale: 2
                    }
                )
            ),
            "4.20"
        );
    }
}
