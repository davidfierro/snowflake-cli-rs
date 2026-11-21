//! JSON as snow prints a query result: `json.dumps(row, indent=4)` per row, inside an array whose
//! items are indented by 4 more spaces, `ensure_ascii`, ANSI escapes removed from strings.

use super::pyjson;
use super::sanitize::sanitize_for_terminal;
use super::{Failure, decimal_text, hex, pyfmt, temporal_text};
use crate::error::Result;
use crate::sql::result::{Column, SfType, Value, uniquify_column_names};
use std::borrow::Borrow;
use std::io::Write;

/// Writes each object as it arrives. A row error leaves the array unterminated on purpose.
pub(super) fn write<R: Borrow<[Value]>>(
    columns: &[Column],
    rows: &mut dyn Iterator<Item = Result<R>>,
    ext: bool,
    out: &mut dyn Write,
) -> std::result::Result<(), Failure> {
    let keys = keys(columns);
    let mut first = true;
    for row in rows {
        let row = row.map_err(Failure::Row)?;
        out.write_all(if first { b"[\n" } else { b",\n" })?;
        first = false;
        out.write_all(object(&keys, columns, row.borrow(), ext).as_bytes())?;
    }
    out.write_all(if first { b"[]\n" } else { b"\n]\n" })?;
    Ok(())
}

/// One result of a multi-statement JSON run (ADR 0004, Decision 4): what `snow` writes with
/// `json.dump(result, indent=2)` through `textwrap.indent(chunk, "  ")`, with the outer `[`, `,`
/// and `]` left to the caller. A row error leaves the result unterminated on purpose.
pub(super) fn write_multi<R: Borrow<[Value]>>(
    columns: &[Column],
    rows: &mut dyn Iterator<Item = Result<R>>,
    ext: bool,
    out: &mut dyn Write,
) -> std::result::Result<(), Failure> {
    let keys = keys(columns);
    let mut first = true;
    for row in rows {
        let row = row.map_err(Failure::Row)?;
        out.write_all(if first { b"  [\n" } else { b"  ,\n" })?;
        first = false;
        if keys.is_empty() {
            out.write_all(b"    {}")?;
            continue;
        }
        let mut text = String::from("    {");
        for (i, (key, (column, value))) in keys
            .iter()
            .zip(columns.iter().zip(row.borrow()))
            .enumerate()
        {
            if i > 0 {
                text.push_str("  ,");
            }
            text.push_str("\n      ");
            text.push_str(key);
            // `": "` and then the value's chunks, each indented by `textwrap.indent`.
            text.push_str("  : ");
            for chunk in value_chunks(value, column, ext, 2, 2) {
                text.push_str(&pyjson::indent_chunk(&chunk, "  "));
            }
        }
        text.push_str("\n    }");
        out.write_all(text.as_bytes())?;
    }
    out.write_all(if first { b"  []" } else { b"\n  ]" })?;
    Ok(())
}

/// The JSON keys: sanitized names, de-duplicated again, quoted.
fn keys(columns: &[Column]) -> Vec<String> {
    let sanitized: Vec<String> = columns
        .iter()
        .map(|c| sanitize_for_terminal(&c.name))
        .collect();
    uniquify_column_names(&sanitized)
        .iter()
        .map(|k| quote(k))
        .collect()
}

/// One row: `{` and `}` indented by 4, members by 8.
fn object(keys: &[String], columns: &[Column], row: &[Value], ext: bool) -> String {
    if keys.is_empty() {
        return "    {}".into();
    }
    let members: Vec<String> = keys
        .iter()
        .zip(columns.iter().zip(row))
        .map(|(key, (column, value))| {
            // Nested JSON_EXT values are dumped at indent 4 inside the row, which then sits
            // 4 spaces in.
            let value = value_chunks(value, column, ext, 4, 1).concat();
            format!("        {key}: {}", value.replace('\n', "\n    "))
        })
        .collect();
    format!("    {{\n{}\n    }}", members.join(",\n"))
}

/// The chunks `json.dump` writes for a cell. With `ext`, VARIANT, OBJECT and ARRAY text that
/// parses as JSON is written as the value it holds (snow's `JSON_EXT`), re-indented by `indent`
/// from `level`; otherwise, and for text that does not parse, it is the string.
fn value_chunks(
    value: &Value,
    column: &Column,
    ext: bool,
    indent: usize,
    level: usize,
) -> Vec<String> {
    if ext
        && matches!(
            column.sf_type,
            SfType::Variant | SfType::Object | SfType::Array
        )
        && let Value::Json(text) | Value::Text(text) = value
        && let Some(parsed) = pyjson::parse(text)
    {
        return pyjson::chunks(&pyjson::sanitize(parsed), indent, level);
    }
    vec![value_json(value, column)]
}

fn value_json(value: &Value, column: &Column) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Decimal(raw) => quote(&decimal_text(raw, column)),
        Value::Float(f) => pyfmt::json_float(*f),
        Value::Text(s) | Value::Json(s) => quote(&sanitize_for_terminal(s)),
        Value::Binary(b) => quote(&hex(b)),
        other => quote(&temporal_text(other, 'T').unwrap_or_default()),
    }
}

/// A JSON string as Python's `json.dumps` writes it with `ensure_ascii=True`.
pub(crate) fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::output::format::OutputFormat;
    use crate::sql::result::SfType;

    #[test]
    fn empty_result_is_an_empty_array() {
        let r = result(vec![column("A", SfType::Text)], vec![]);
        assert_eq!(rendered(&r, OutputFormat::Json), "[]\n");
    }

    #[test]
    fn rows_are_indented_like_snow() {
        let r = result(
            vec![
                column(
                    "A",
                    SfType::Fixed {
                        precision: 1,
                        scale: 0,
                    },
                ),
                column("B", SfType::Boolean),
            ],
            vec![
                vec![Value::Int(1), Value::Bool(true)],
                vec![Value::Null, Value::Bool(false)],
            ],
        );
        assert_eq!(
            rendered(&r, OutputFormat::Json),
            "[\n    {\n        \"A\": 1,\n        \"B\": true\n    },\n    {\n        \"A\": null,\n        \"B\": false\n    }\n]\n"
        );
    }

    fn multi(r: &crate::sql::QueryResult) -> String {
        let mut out = Vec::new();
        let mut rows = r.rows.iter().map(|row| Ok(row.as_slice()));
        assert!(write_multi(&r.columns, &mut rows, false, &mut out).is_ok());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn multi_statement_results_use_snows_indented_layout() {
        let fixed = SfType::Fixed {
            precision: 1,
            scale: 0,
        };
        let r = result(
            vec![column("A", fixed.clone()), column("B", SfType::Text)],
            vec![
                vec![Value::Int(1), Value::Text("s".into())],
                vec![Value::Null, Value::Text("t".into())],
            ],
        );
        assert_eq!(
            multi(&r),
            "  [\n    {\n      \"A\"  :   1  ,\n      \"B\"  :   \"s\"\n    }  ,\n    {\n      \"A\"  :   null  ,\n      \"B\"  :   \"t\"\n    }\n  ]"
        );
        assert_eq!(multi(&result(vec![column("A", fixed)], vec![])), "  []");
        assert_eq!(multi(&result(vec![], vec![vec![]])), "  [\n    {}\n  ]");
    }

    #[test]
    fn zero_columns_render_empty_objects() {
        let r = result(vec![], vec![vec![]]);
        assert_eq!(rendered(&r, OutputFormat::Json), "[\n    {}\n]\n");
    }

    #[test]
    fn strings_use_ensure_ascii_escapes() {
        assert_eq!(quote("café,\"x\""), r#""caf\u00e9,\"x\"""#);
        assert_eq!(quote("😀"), r#""\ud83d\ude00""#);
        assert_eq!(
            quote("a\\b\n\r\t\u{8}\u{c}\u{7}\u{7f}"),
            r#""a\\b\n\r\t\b\f\u0007\u007f""#
        );
    }

    #[test]
    fn keys_collapsed_by_sanitizing_are_uniquified() {
        let r = result(
            vec![column("X\x1b[1m", SfType::Text), column("X", SfType::Text)],
            vec![vec![Value::Text("a".into()), Value::Text("b".into())]],
        );
        let out = rendered(&r, OutputFormat::Json);
        assert!(out.contains("\"X\": \"a\""));
        assert!(out.contains("\"X_2\": \"b\""));
    }

    fn ext_result() -> crate::sql::QueryResult {
        result(
            vec![
                column("O", SfType::Object),
                column("A", SfType::Array),
                column("V", SfType::Variant),
                column("T", SfType::Text),
            ],
            vec![
                vec![
                    Value::Json("{\"a\":[1,{\"b\":null}],\"c\":{}}".into()),
                    Value::Json("[]".into()),
                    Value::Json("\"s\"".into()),
                    Value::Text("{\"not\":\"parsed\"}".into()),
                ],
                vec![
                    Value::Null,
                    Value::Json("not json".into()),
                    Value::Json("1.50".into()),
                    Value::Null,
                ],
            ],
        )
    }

    #[test]
    fn json_ext_parses_semi_structured_columns_only() {
        let out = rendered(&ext_result(), OutputFormat::JsonExt);
        assert_eq!(
            out,
            "[\n    {\n        \"O\": {\n            \"a\": [\n                1,\n                {\n                    \"b\": null\n                }\n            ],\n            \"c\": {}\n        },\n        \"A\": [],\n        \"V\": \"s\",\n        \"T\": \"{\\\"not\\\":\\\"parsed\\\"}\"\n    },\n    {\n        \"O\": null,\n        \"A\": \"not json\",\n        \"V\": 1.5,\n        \"T\": null\n    }\n]\n"
        );
        // JSON keeps the text as it came.
        let plain = rendered(&ext_result(), OutputFormat::Json);
        assert!(plain.contains("\"O\": \"{\\\"a\\\":[1,{\\\"b\\\":null}],\\\"c\\\":{}}\""));
    }

    #[test]
    fn json_ext_in_a_multi_statement_run_indents_each_chunk() {
        let mut out = Vec::new();
        let r = ext_result();
        let mut rows = r.rows.iter().take(1).map(|row| Ok(row.as_slice()));
        assert!(write_multi(&r.columns, &mut rows, true, &mut out).is_ok());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "  [\n    {\n      \"O\"  :   {\n        \"a\"  :   [\n          1  ,\n          {\n            \"b\"  :   null\n          }\n        ]  ,\n        \"c\"  :   {}\n      }  ,\n      \"A\"  :   []  ,\n      \"V\"  :   \"s\"  ,\n      \"T\"  :   \"{\\\"not\\\":\\\"parsed\\\"}\"\n    }\n  ]"
        );
    }

    #[test]
    fn floats_use_python_repr_and_json_specials() {
        let c = column("F", SfType::Real);
        assert_eq!(value_json(&Value::Float(f64::NAN), &c), "NaN");
        assert_eq!(value_json(&Value::Float(f64::INFINITY), &c), "Infinity");
        assert_eq!(
            value_json(&Value::Float(f64::NEG_INFINITY), &c),
            "-Infinity"
        );
        assert_eq!(value_json(&Value::Float(1e-5), &c), "1e-05");
    }
}
