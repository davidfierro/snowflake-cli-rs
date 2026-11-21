//! CSV as snow writes it: header row, `\n` line ends, `csv.QUOTE_MINIMAL` quoting, text through
//! `sanitize_for_csv`. An empty result prints nothing.

use super::sanitize::sanitize_for_csv;
use super::{Failure, decimal_text, hex, pyfmt, temporal_text};
use crate::error::Result;
use crate::sql::result::{Column, Value};
use std::borrow::Borrow;
use std::io::{self, Write};

/// Writes each row as it arrives; the header goes out with the first row.
pub(super) fn write<R: Borrow<[Value]>>(
    columns: &[Column],
    rows: &mut dyn Iterator<Item = Result<R>>,
    out: &mut dyn Write,
) -> std::result::Result<(), Failure> {
    let mut first = true;
    for row in rows {
        let row = row.map_err(Failure::Row)?;
        if first {
            first = false;
            let header = columns.iter().map(|c| sanitize_for_csv(&c.name));
            write_record(out, header)?;
        }
        let fields = columns
            .iter()
            .zip(row.borrow())
            .map(|(column, value)| field(value, column));
        write_record(out, fields)?;
    }
    Ok(())
}

fn write_record(out: &mut dyn Write, fields: impl Iterator<Item = String>) -> io::Result<()> {
    for (i, field) in fields.enumerate() {
        if i > 0 {
            out.write_all(b",")?;
        }
        if field.contains([',', '"', '\n', '\r']) {
            write!(out, "\"{}\"", field.replace('"', "\"\""))?;
        } else {
            out.write_all(field.as_bytes())?;
        }
    }
    out.write_all(b"\n")
}

fn field(value: &Value, column: &Column) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Int(i) => i.to_string(),
        Value::Decimal(raw) => decimal_text(raw, column),
        Value::Float(f) => pyfmt::float_repr(*f),
        Value::Text(s) | Value::Json(s) => sanitize_for_csv(s),
        Value::Binary(b) => hex(b),
        other => temporal_text(other, 'T').unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::output::format::OutputFormat;
    use crate::sql::result::SfType;

    #[test]
    fn empty_result_prints_nothing() {
        let r = result(vec![column("A", SfType::Text)], vec![]);
        assert_eq!(rendered(&r, OutputFormat::Csv), "");
    }

    #[test]
    fn quotes_and_prefixes_like_snow() {
        let r = result(
            vec![
                column("=H", SfType::Text),
                column(
                    "N",
                    SfType::Fixed {
                        precision: 1,
                        scale: 0,
                    },
                ),
                column("B", SfType::Boolean),
                column("F", SfType::Real),
            ],
            vec![
                vec![
                    Value::Text("a,\"b\"".into()),
                    Value::Int(-5),
                    Value::Bool(true),
                    Value::Float(f64::NAN),
                ],
                vec![
                    Value::Text("-x".into()),
                    Value::Null,
                    Value::Bool(false),
                    Value::Float(f64::NEG_INFINITY),
                ],
            ],
        );
        assert_eq!(
            rendered(&r, OutputFormat::Csv),
            "'=H,N,B,F\n\"a,\"\"b\"\"\",-5,True,nan\n'-x,,False,-inf\n"
        );
    }
}
