//! Statement splitter: a line-by-line port of `split_statements` and `_concatenate_statements`
//! from `snowflake-connector-python` 4.8.1, `src/snowflake/connector/util_text.py`, with the
//! default delimiter `;` (ADR 0004, Decision 2). Its quirks are `snow`'s behaviour and are kept.
//!
//! Original: Copyright 2020 Snowflake Inc. (NOTICE of snowflake-connector-python).
//! Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//! except in compliance with the License. You may obtain a copy of the License at
//! <http://www.apache.org/licenses/LICENSE-2.0>. Unless required by applicable law or agreed to
//! in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//! WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
//! the specific language governing permissions and limitations under the License.
//! Modified: ported to Rust; the delimiter is fixed to `;`; each piece also records whether it
//! ended with `;` and whether it is a `!` command line.

/// One piece of the input, as the connector yields it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// Text as the connector yields it (stripped; ends with `;` when terminated).
    pub text: String,
    /// The splitter saw this piece end with `;` (or `;>`).
    pub terminated: bool,
    /// `Some(true)` for PUT/GET, `None` for an empty or comment-only piece.
    pub put_or_get: Option<bool>,
    /// A `!` command line.
    pub command: bool,
}

/// Python's `str.isspace()` for one character.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python's `str.strip()` (no arguments).
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

/// `line[a:b]` with Python's clamping, on a line held as characters.
fn slice(line: &[char], a: usize, b: usize) -> String {
    let b = b.min(line.len());
    if a >= b {
        String::new()
    } else {
        line[a..b].iter().collect()
    }
}

fn starts_with(line: &[char], col: usize, prefix: &str) -> bool {
    prefix
        .chars()
        .enumerate()
        .all(|(k, p)| line.get(col + k) == Some(&p))
}

/// `"://" not in line[col0:col + 3]`.
fn no_url(line: &[char], col0: usize, col: usize) -> bool {
    !slice(line, col0, col + 3).contains("://")
}

/// `^\s*--` on `line[col:]`.
fn comment_follows(line: &[char], col: usize) -> bool {
    let rest = &line[col.min(line.len())..];
    let start = rest
        .iter()
        .position(|c| !py_isspace(*c))
        .unwrap_or(rest.len());
    starts_with(rest, start, "--")
}

/// `^\s*$` on `line[col:]` (`$` also matches before a final newline).
fn blank_follows(line: &[char], col: usize) -> bool {
    line[col.min(line.len())..].iter().all(|c| py_isspace(*c))
}

/// Lines with their `\n` ending, as `StringIO.readline()` yields them.
fn lines(text: &str) -> impl Iterator<Item = Vec<char>> + '_ {
    text.split_inclusive('\n').map(|l| l.chars().collect())
}

/// Splits `text` into statements and `!` commands, exactly as the connector does.
pub fn split_statements(text: &str, remove_comments: bool) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut in_quote = false;
    let mut ch_quote = '\'';
    let mut in_comment = false;
    let mut in_double_dollars = false;
    let mut statement: Vec<(String, bool)> = Vec::new();

    for line in lines(text) {
        let len_line = line.len();
        let mut col = 0usize;
        let mut col0 = 0usize;
        loop {
            if col >= len_line {
                if col0 < col {
                    if !in_comment && !in_quote && !in_double_dollars {
                        statement.push((slice(&line, col0, col), true));
                        if statement.len() == 1 && statement[0].0.is_empty() {
                            statement.clear();
                        }
                    } else if !in_comment {
                        statement.push((slice(&line, col0, col), true));
                    } else if !remove_comments {
                        statement.push((slice(&line, col0, col), false));
                    }
                }
                break;
            } else if in_comment {
                if starts_with(&line, col, "*/") {
                    in_comment = false;
                    if !remove_comments {
                        statement.push((slice(&line, col0, col + 2), false));
                    }
                    col += 2;
                    col0 = col;
                } else {
                    col += 1;
                }
            } else if in_double_dollars {
                if starts_with(&line, col, "$$") {
                    in_double_dollars = false;
                    statement.push((slice(&line, col0, col + 2), false));
                    col += 2;
                    col0 = col;
                } else {
                    col += 1;
                }
            } else if in_quote {
                let c = line[col];
                if c == '\\'
                    && col < len_line - 1
                    && (line[col + 1] == ch_quote || line[col + 1] == '\\')
                {
                    col += 2;
                } else if c == ch_quote {
                    if (col < len_line - 1 && line[col + 1] != ch_quote) || col == len_line - 1 {
                        in_quote = false;
                        statement.push((slice(&line, col0, col + 1), true));
                        col += 1;
                        col0 = col;
                    } else {
                        col += 2;
                    }
                } else {
                    col += 1;
                }
            } else {
                let c = line[col];
                if c == '\'' || c == '"' {
                    in_quote = true;
                    ch_quote = c;
                    col += 1;
                } else if c == ' ' || c == '\t' {
                    statement.push((slice(&line, col0, col + 1), true));
                    col += 1;
                    col0 = col;
                } else if (starts_with(&line, col, "--") || starts_with(&line, col, "//"))
                    && no_url(&line, col0, col)
                {
                    statement.push((slice(&line, col0, col), true));
                    if remove_comments {
                        statement.push(("\n".into(), true));
                    } else {
                        statement.push((slice(&line, col, len_line), false));
                    }
                    col = len_line + 1;
                    col0 = col;
                } else if starts_with(&line, col, "/*") && no_url(&line, col0, col) {
                    let end = if remove_comments { col } else { col + 2 };
                    statement.push((slice(&line, col0, end), false));
                    col += 2;
                    col0 = col;
                    in_comment = true;
                } else if starts_with(&line, col, "$$") {
                    statement.push((slice(&line, col0, col + 2), true));
                    col += 2;
                    col0 = col;
                    in_double_dollars = true;
                } else if c == ';' {
                    // `RE_START`/`RE_END` for the `;` delimiter reduce to this character test.
                    statement.push((slice(&line, col0, col) + ";", true));
                    col += 1;
                    if line.get(col) == Some(&'>') {
                        col += 1;
                        if let Some(last) = statement.last_mut() {
                            last.0.push('>');
                        }
                    }
                    if comment_follows(&line, col) || blank_follows(&line, col) {
                        if !remove_comments {
                            statement.push((slice(&line, col, len_line), false));
                        }
                        col = len_line;
                    }
                    while col < len_line && (line[col] == ' ' || line[col] == '\t') {
                        col += 1;
                    }
                    out.push(concatenate(&statement, true));
                    col0 = col;
                    statement.clear();
                } else if col == 0 && c == '!' {
                    if !statement.is_empty() {
                        out.push(concatenate(&statement, false));
                        statement.clear();
                    }
                    let full: String = line.iter().collect();
                    let stripped = py_strip(&full);
                    let text = stripped.strip_suffix(';').unwrap_or(stripped);
                    out.push(Piece {
                        text: py_strip(text).to_string(),
                        terminated: false,
                        put_or_get: Some(false),
                        command: true,
                    });
                    break;
                } else {
                    col += 1;
                }
            }
        }
    }
    if !statement.is_empty() {
        out.push(concatenate(&statement, false));
    }
    out
}

/// `_concatenate_statements`: the parts joined and stripped, with the PUT/GET flag.
fn concatenate(parts: &[(String, bool)], terminated: bool) -> Piece {
    let mut text = String::new();
    let mut put_or_get = None;
    for (part, is_statement) in parts {
        text.push_str(part);
        if put_or_get.is_none() && *is_statement && py_strip(part).chars().count() >= 3 {
            let head: String = part.chars().take(3).collect::<String>().to_uppercase();
            put_or_get = Some(head == "PUT" || head == "GET");
        }
    }
    Piece {
        text: py_strip(&text).to_string(),
        terminated,
        put_or_get,
        command: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(text: &str, remove_comments: bool) -> Vec<String> {
        split_statements(text, remove_comments)
            .into_iter()
            .map(|p| p.text)
            .collect()
    }

    #[test]
    fn semicolons_in_strings_identifiers_comments_and_dollars_do_not_split() {
        assert_eq!(
            texts("select 'a;b', \"c;d\" /* ; */, $$ ; $$; select 2", true),
            vec!["select 'a;b', \"c;d\" , $$ ; $$;", "select 2"]
        );
        assert_eq!(texts("select 1 -- ; x\n;", true), vec!["select 1 \n;"]);
    }

    #[test]
    fn escapes_inside_quotes() {
        assert_eq!(
            texts("select 'it''s;', 'a\\';b'; select 2;", true),
            vec!["select 'it''s;', 'a\\';b';", "select 2;"]
        );
    }

    #[test]
    fn comments_are_kept_or_removed() {
        let sql = "-- head\nselect 1; -- tail\nselect /* in */ 2;";
        assert_eq!(texts(sql, true), vec!["select 1;", "select  2;"]);
        assert_eq!(
            texts(sql, false),
            vec!["-- head\nselect 1; -- tail", "select /* in */ 2;"]
        );
        assert_eq!(texts("select 1 // c\n;", false), vec!["select 1 // c\n;"]);
    }

    #[test]
    fn urls_are_not_comments() {
        assert_eq!(
            texts("select 'x' from s3://a//b;", true),
            vec!["select 'x' from s3://a//b;"]
        );
    }

    #[test]
    fn flags_terminated_command_put_get_and_async() {
        let pieces = split_statements("put file://x @s;\n!source a.sql\nselect 1;>\nget", true);
        assert_eq!(pieces.len(), 4);
        assert_eq!(pieces[0].put_or_get, Some(true));
        assert!(pieces[0].terminated);
        assert!(pieces[1].command);
        assert_eq!(pieces[1].text, "!source a.sql");
        assert_eq!(pieces[2].text, "select 1;>");
        assert!(pieces[2].terminated);
        assert_eq!(pieces[3].text, "get");
        assert!(!pieces[3].terminated);
        assert_eq!(pieces[3].put_or_get, Some(true));
    }

    #[test]
    fn empty_and_comment_only_pieces() {
        let pieces = split_statements("\n\n", true);
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].text, "");
        assert_eq!(pieces[0].put_or_get, None);
        assert_eq!(texts(";", true), vec![";"]);
        assert!(split_statements("", true).is_empty());
    }

    #[test]
    fn python_whitespace_helpers() {
        assert!(py_isspace('\u{1f}') && py_isspace('\u{a0}') && !py_isspace('x'));
        assert_eq!(py_strip("\u{1c} a \n"), "a");
        assert_eq!(slice(&['a', 'b'], 3, 5), "");
    }
}
