//! `JSON_EXT` support: what `json.loads` followed by `json.dumps(indent=n)` does to the text of a
//! VARIANT, OBJECT or ARRAY cell (snow's `RespectingColumnTypesRowMapper`), chunk by chunk like
//! CPython's pure-Python encoder, so the multi-statement layout (which indents each chunk) can be
//! reproduced.

use super::json::quote;
use super::pyfmt;
use super::sanitize::sanitize_for_terminal;
use crate::sql::result::uniquify_column_names;

/// Nesting beyond this is left as the raw text (CPython would raise `RecursionError`).
const MAX_DEPTH: usize = 400;

/// A parsed JSON value. Numbers keep Python's int/float split.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Json {
    Null,
    Bool(bool),
    /// Canonical decimal digits of a Python `int`.
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    /// Insertion-ordered; a repeated key keeps its first position and its last value.
    Object(Vec<(String, Json)>),
}

/// `json.loads(text)`; `None` where Python raises (the caller then keeps the raw text).
pub(super) fn parse(text: &str) -> Option<Json> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    (parser.pos == parser.bytes.len()).then_some(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        let found = self.text[self.pos..].starts_with(literal);
        if found {
            self.pos += literal.len();
        }
        found
    }

    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_DEPTH {
            return None;
        }
        match *self.bytes.get(self.pos)? {
            b'"' => self.string().map(Json::Str),
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'n' => self.eat("null").then_some(Json::Null),
            b't' => self.eat("true").then_some(Json::Bool(true)),
            b'f' => self.eat("false").then_some(Json::Bool(false)),
            b'N' => self.eat("NaN").then_some(Json::Float(f64::NAN)),
            b'I' => self.eat("Infinity").then_some(Json::Float(f64::INFINITY)),
            b'-' if self.text[self.pos..].starts_with("-Infinity") => {
                self.pos += "-Infinity".len();
                Some(Json::Float(f64::NEG_INFINITY))
            }
            _ => self.number(),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        self.pos - start
    }

    /// `-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?`
    fn number(&mut self) -> Option<Json> {
        let start = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.bytes.get(self.pos)? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }
        let int_end = self.pos;
        let mut is_float = false;
        if self.bytes.get(self.pos) == Some(&b'.') {
            let save = self.pos;
            self.pos += 1;
            if self.digits() == 0 {
                self.pos = save;
            } else {
                is_float = true;
            }
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            let save = self.pos;
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                self.pos = save;
            } else {
                is_float = true;
            }
        }
        if is_float {
            return self.text[start..self.pos].parse().ok().map(Json::Float);
        }
        self.pos = int_end;
        let digits = &self.text[start..int_end];
        Some(Json::Int(if digits == "-0" { "0" } else { digits }.into()))
    }

    fn hex4(&mut self) -> Option<u32> {
        let chunk = self.text.get(self.pos..self.pos + 4)?;
        if !chunk.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        self.pos += 4;
        u32::from_str_radix(chunk, 16).ok()
    }

    /// A string in strict mode. A lone surrogate (which Rust cannot hold) is a failure.
    fn string(&mut self) -> Option<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let rest = &self.text[self.pos..];
            let c = rest.chars().next()?;
            self.pos += c.len_utf8();
            match c {
                '"' => return Some(out),
                '\\' => {
                    let escape = *self.bytes.get(self.pos)?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                if !self.eat("\\u") {
                                    return None;
                                }
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return None;
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            out.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                c if (c as u32) < 0x20 => return None,
                c => out.push(c),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Json> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Some(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.bytes.get(self.pos)? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(Json::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Json> {
        self.pos += 1;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Some(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return None;
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return None;
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            match members.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => members.push((key, value)),
            }
            self.skip_ws();
            match self.bytes.get(self.pos)? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some(Json::Object(members));
                }
                _ => return None,
            }
        }
    }
}

/// `_sanitize_json_tree`: ANSI escapes removed from strings and keys; keys that collapse to the
/// same name are made unique.
pub(super) fn sanitize(json: Json) -> Json {
    match json {
        Json::Str(s) => Json::Str(sanitize_for_terminal(&s)),
        Json::Array(items) => Json::Array(items.into_iter().map(sanitize).collect()),
        Json::Object(members) => {
            let (keys, values): (Vec<String>, Vec<Json>) = members
                .into_iter()
                .map(|(k, v)| (sanitize_for_terminal(&k), sanitize(v)))
                .unzip();
            Json::Object(
                uniquify_column_names(&keys)
                    .into_iter()
                    .zip(values)
                    .collect(),
            )
        }
        other => other,
    }
}

fn scalar(json: &Json) -> Option<String> {
    Some(match json {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Int(digits) => digits.clone(),
        Json::Float(f) => pyfmt::json_float(*f),
        Json::Str(s) => quote(s),
        _ => return None,
    })
}

/// The chunks `json.JSONEncoder(indent=indent).iterencode` yields for `json` inside a container
/// whose own indent level is `level`.
pub(super) fn chunks(json: &Json, indent: usize, level: usize) -> Vec<String> {
    let mut out = Vec::new();
    encode(json, indent, level, &mut out);
    out
}

fn pad(indent: usize, level: usize) -> String {
    format!("\n{}", " ".repeat(indent * level))
}

fn encode(json: &Json, indent: usize, level: usize, out: &mut Vec<String>) {
    match json {
        Json::Array(items) if items.is_empty() => out.push("[]".into()),
        Json::Object(members) if members.is_empty() => out.push("{}".into()),
        Json::Array(items) => {
            let level = level + 1;
            let newline = pad(indent, level);
            let mut buf = format!("[{newline}");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    buf = format!(",{newline}");
                }
                match scalar(item) {
                    Some(text) => out.push(buf.clone() + &text),
                    None => {
                        out.push(buf.clone());
                        encode(item, indent, level, out);
                    }
                }
            }
            out.push(pad(indent, level - 1));
            out.push("]".into());
        }
        Json::Object(members) => {
            let level = level + 1;
            let newline = pad(indent, level);
            out.push("{".into());
            out.push(newline.clone());
            for (i, (key, value)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(format!(",{newline}"));
                }
                out.push(quote(key));
                out.push(": ".into());
                match scalar(value) {
                    Some(text) => out.push(text),
                    None => encode(value, indent, level, out),
                }
            }
            out.push(pad(indent, level - 1));
            out.push("}".into());
        }
        other => out.extend(scalar(other)),
    }
}

/// `textwrap.indent(chunk, "  ")`: every line with something other than whitespace gets the
/// prefix, including the first one, which may continue a line begun by an earlier chunk.
pub(super) fn indent_chunk(chunk: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(chunk.len() + prefix.len());
    for line in chunk.split_inclusive('\n') {
        if !line.trim().is_empty() {
            out.push_str(prefix);
        }
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dumps(text: &str, indent: usize, level: usize) -> String {
        chunks(&sanitize(parse(text).unwrap()), indent, level).concat()
    }

    #[test]
    fn parses_like_json_loads() {
        assert_eq!(
            parse(" [1, 2.5, -0, -0.0] "),
            Some(Json::Array(vec![
                Json::Int("1".into()),
                Json::Float(2.5),
                Json::Int("0".into()),
                Json::Float(-0.0),
            ]))
        );
        assert_eq!(parse("1E2"), Some(Json::Float(100.0)));
        assert_eq!(
            parse("12345678901234567890123"),
            Some(Json::Int("12345678901234567890123".into()))
        );
        assert_eq!(parse("-Infinity"), Some(Json::Float(f64::NEG_INFINITY)));
        assert!(matches!(parse("NaN"), Some(Json::Float(f)) if f.is_nan()));
        assert_eq!(
            parse("\"a\\u00e9\\ud83d\\ude00\\/\""),
            Some(Json::Str("aé😀/".into()))
        );
        assert_eq!(
            parse("{\"a\":1,\"b\":2,\"a\":3}"),
            Some(Json::Object(vec![
                ("a".into(), Json::Int("3".into())),
                ("b".into(), Json::Int("2".into()))
            ]))
        );
    }

    #[test]
    fn rejects_what_json_loads_rejects() {
        for bad in [
            "",
            "x",
            "01",
            "1.",
            "1e",
            ".5",
            "+1",
            "[1,]",
            "{\"a\":1,}",
            "{1:2}",
            "{\"a\" 1}",
            "[1 2]",
            "\"a",
            "\"a\nb\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\ud800\\u0041\"",
            "\"\\u12\"",
            "[1] x",
            "nul",
            "tru",
            "-",
            "-x",
            "{",
            "[",
            "[1",
            "{\"a\":",
            "\"\\",
            "\"\\u",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert_eq!(parse(&deep), None);
    }

    #[test]
    fn number_edge_cases() {
        // "1.x" and "1ex" parse the integer part, then fail on what follows.
        assert_eq!(parse("1.x"), None);
        assert_eq!(parse("1ex"), None);
        assert_eq!(
            parse("[1.5e+3]"),
            Some(Json::Array(vec![Json::Float(1500.0)]))
        );
        assert_eq!(parse("1e400"), Some(Json::Float(f64::INFINITY)));
    }

    #[test]
    fn dumps_with_indent() {
        assert_eq!(dumps("[]", 4, 1), "[]");
        assert_eq!(dumps("{}", 4, 1), "{}");
        assert_eq!(dumps("7", 4, 1), "7");
        assert_eq!(
            dumps(
                r#"{"a":[1,"x",{"b":null}],"c":{},"d":[],"e":true,"f":1.0,"g":NaN,"h":-Infinity,"i":1e400}"#,
                4,
                1
            ),
            "{\n        \"a\": [\n            1,\n            \"x\",\n            {\n                \"b\": null\n            }\n        ],\n        \"c\": {},\n        \"d\": [],\n        \"e\": true,\n        \"f\": 1.0,\n        \"g\": NaN,\n        \"h\": -Infinity,\n        \"i\": Infinity\n    }"
        );
    }

    #[test]
    fn sanitizes_strings_and_keys() {
        assert_eq!(
            dumps("{\"a\\u001b[1m\":\"x\\u001b[0m\",\"a\":2}", 2, 0),
            "{\n  \"a\": \"x\",\n  \"a_2\": 2\n}"
        );
    }

    #[test]
    fn chunks_indent_like_textwrap() {
        assert_eq!(indent_chunk(": ", "  "), "  : ");
        assert_eq!(indent_chunk("\n    ", "  "), "\n    ");
        assert_eq!(indent_chunk(",\n    ", "  "), "  ,\n    ");
        assert_eq!(indent_chunk("[\n    1", "  "), "  [\n      1");
        assert_eq!(indent_chunk("", "  "), "");
    }
}
