//! TABLE and PLAIN: a port of snow's `ascii_table.py` layout (rich's `box.ASCII` look).
//!
//! TABLE: `+---+` top and bottom rules without joints, `| a | b |` rows, `|---+---|` under the
//! header. PLAIN: the same cells without borders, columns separated by two spaces. Columns take
//! their natural width, or share the terminal width (cells folded) when one is given.

use super::sanitize::sanitize_for_terminal;
use super::str_text;
use crate::sql::result::QueryResult;
use std::io::{self, Write};
use unicode_width::UnicodeWidthStr;

const NO_DATA: &[u8] = b"No data\n\n";
/// A column is not shrunk below this width (or its natural width, if smaller).
const COLUMN_FLOOR: usize = 8;

pub(super) fn write(
    result: &QueryResult,
    plain: bool,
    terminal_width: Option<usize>,
    out: &mut dyn Write,
) -> io::Result<()> {
    if result.rows.is_empty() {
        return out.write_all(NO_DATA);
    }
    let header: Vec<String> = result
        .columns
        .iter()
        .map(|c| normalize_cell(&c.name))
        .collect();
    let rows: Vec<Vec<String>> = result
        .rows
        .iter()
        .map(|row| {
            result
                .columns
                .iter()
                .zip(row)
                .map(|(column, value)| normalize_cell(&str_text(value, column)))
                .collect()
        })
        .collect();
    let preferred = preferred_widths(&header, &rows);
    let widths = match terminal_width {
        Some(width) => allocate_tty_widths(&preferred, width, plain),
        None => preferred,
    };
    let layout = Layout {
        widths,
        plain,
        wrap: terminal_width.is_some(),
    };
    let mut text = String::new();
    if !plain {
        text.push_str(&layout.horizontal_rule());
    }
    layout.push_record(&mut text, &header);
    if !plain {
        text.push_str(&layout.header_rule());
    }
    for row in &rows {
        layout.push_record(&mut text, row);
    }
    if !plain {
        text.push_str(&layout.horizontal_rule());
    }
    out.write_all(text.as_bytes())
}

/// snow's `normalize_cell`: printable ASCII as is; otherwise ANSI escapes removed, then every
/// other control character except newline and tab (snow strips only BEL, BS, VT, FF, CR; the
/// rest could still drive the terminal), and tabs expanded to 8 columns.
fn normalize_cell(text: &str) -> String {
    if text.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return text.to_string();
    }
    let stripped: String = sanitize_for_terminal(text)
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    expand_tabs(&stripped)
}

/// Python's `str.expandtabs(8)`.
fn expand_tabs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut column = 0;
    for c in text.chars() {
        match c {
            '\t' => {
                let spaces = 8 - column % 8;
                out.push_str(&" ".repeat(spaces));
                column += spaces;
            }
            '\n' => {
                out.push(c);
                column = 0;
            }
            _ => {
                out.push(c);
                column += 1;
            }
        }
    }
    out
}

fn preferred_widths(header: &[String], rows: &[Vec<String>]) -> Vec<usize> {
    let mut widths = vec![1; header.len()];
    for record in std::iter::once(header).chain(rows.iter().map(Vec::as_slice)) {
        for (width, cell) in widths.iter_mut().zip(record) {
            for line in cell.split('\n') {
                *width = (*width).max(line.width());
            }
        }
    }
    widths
}

/// snow's `allocate_tty_widths`: shrink the widest columns first, never below
/// `min(natural, COLUMN_FLOOR)`, until the table fits `console_width`.
fn allocate_tty_widths(preferred: &[usize], console_width: usize, plain: bool) -> Vec<usize> {
    let n = preferred.len();
    let floors: Vec<usize> = preferred.iter().map(|w| (*w).min(COLUMN_FLOOR)).collect();
    let chrome = if plain {
        2 * n.saturating_sub(1)
    } else {
        3 * n + 1
    };
    let available = console_width.saturating_sub(chrome);
    let mut widths = preferred.to_vec();
    loop {
        let total: usize = widths.iter().sum();
        if total <= available {
            return widths;
        }
        let excess = total - available;
        let shrinkable: Vec<usize> = (0..n).filter(|&i| widths[i] > floors[i]).collect();
        let Some(widest) = shrinkable.iter().map(|&i| widths[i]).max() else {
            return widths;
        };
        let group: Vec<usize> = shrinkable
            .iter()
            .copied()
            .filter(|&i| widths[i] == widest)
            .collect();
        let next_lower = shrinkable
            .iter()
            .map(|&i| widths[i])
            .filter(|&w| w < widest)
            .max()
            .unwrap_or(0);
        let step = group
            .iter()
            .map(|&i| widths[i] - floors[i].max(next_lower))
            .min()
            .unwrap_or(0);
        if step * group.len() <= excess {
            for &i in &group {
                widths[i] -= step;
            }
            continue;
        }
        let (base, remainder) = (excess / group.len(), excess % group.len());
        for (offset, &i) in group.iter().enumerate() {
            let decrease = (base + usize::from(offset < remainder)).min(widths[i] - floors[i]);
            widths[i] -= decrease;
        }
        return widths.into_iter().map(|w| w.max(1)).collect();
    }
}

struct Layout {
    widths: Vec<usize>,
    plain: bool,
    wrap: bool,
}

impl Layout {
    fn horizontal_rule(&self) -> String {
        let n = self.widths.len();
        let inner = self.widths.iter().sum::<usize>() + 2 * n + n.saturating_sub(1);
        format!("+{}+\n", "-".repeat(inner))
    }

    fn header_rule(&self) -> String {
        let body: Vec<String> = self.widths.iter().map(|w| "-".repeat(w + 2)).collect();
        format!("|{}|\n", body.join("+"))
    }

    fn push_record(&self, text: &mut String, cells: &[String]) {
        let folded: Vec<Vec<String>> = cells
            .iter()
            .zip(&self.widths)
            .map(|(cell, &width)| split_cell(cell, width, self.wrap))
            .collect();
        let height = folded.iter().map(Vec::len).max().unwrap_or(1);
        for line in 0..height {
            let pieces: Vec<String> = folded
                .iter()
                .zip(&self.widths)
                .map(|(column, &width)| pad(column.get(line).map_or("", String::as_str), width))
                .collect();
            if self.plain {
                text.push_str(&pieces.join("  "));
            } else {
                text.push_str("| ");
                text.push_str(&pieces.join(" | "));
                text.push_str(" |");
            }
            text.push('\n');
        }
    }
}

fn split_cell(cell: &str, width: usize, wrap: bool) -> Vec<String> {
    let parts = cell.split('\n').map(String::from);
    if !wrap {
        return parts.collect();
    }
    parts.flat_map(|part| fold(&part, width.max(1))).collect()
}

/// Chops `part` into pieces at most `width` cells wide (rich's `chop_cells`).
fn fold(part: &str, width: usize) -> Vec<String> {
    if part.width() <= width {
        return vec![part.to_string()];
    }
    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    for c in part.chars() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if current_width + w > width && !current.is_empty() {
            pieces.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(c);
        current_width += w;
    }
    pieces.push(current);
    pieces
}

fn pad(piece: &str, width: usize) -> String {
    let size = piece.width();
    if size >= width {
        piece.to_string()
    } else {
        format!("{piece}{}", " ".repeat(width - size))
    }
}

#[cfg(test)]
mod tests {
    use super::super::render_with_width;
    use super::super::test_support::*;
    use super::*;
    use crate::output::format::OutputFormat;
    use crate::sql::result::{SfType, Value};
    use jiff::civil::date;

    fn sample() -> QueryResult {
        result(
            vec![
                column(
                    "A",
                    SfType::Fixed {
                        precision: 2,
                        scale: 0,
                    },
                ),
                column("B", SfType::Text),
                column("C", SfType::Text),
                column("D", SfType::Boolean),
                column("E", SfType::Text),
                column("F", SfType::Text),
                column("G", SfType::TimestampTz { scale: 9 }),
            ],
            vec![
                vec![
                    Value::Int(1),
                    Value::Text("longer text".into()),
                    Value::Null,
                    Value::Bool(true),
                    Value::Text("ñ日本".into()),
                    Value::Text("l1\nl2".into()),
                    Value::TimestampTz {
                        local: date(2024, 1, 2).at(3, 4, 5, 500_000_000),
                        offset_seconds: 7200,
                    },
                ],
                vec![
                    Value::Int(22),
                    Value::Text("x".into()),
                    Value::Text("y".into()),
                    Value::Bool(false),
                    Value::Text("a".into()),
                    Value::Text("b".into()),
                    Value::Null,
                ],
            ],
        )
    }

    /// Captured from `snow sql -x --format table` (3.34.0) for the same query.
    #[test]
    fn table_matches_snow() {
        assert_eq!(
            rendered(&sample(), OutputFormat::Table),
            "\
+---------------------------------------------------------------------------------+
| A  | B           | C    | D     | E     | F  | G                                |
|----+-------------+------+-------+-------+----+----------------------------------|
| 1  | longer text | None | True  | ñ日本 | l1 | 2024-01-02 03:04:05.500000+02:00 |
|    |             |      |       |       | l2 |                                  |
| 22 | x           | y    | False | a     | b  | None                             |
+---------------------------------------------------------------------------------+
"
        );
    }

    /// Captured from `snow sql -x --format plain` (3.34.0) for the same query.
    #[test]
    fn plain_matches_snow() {
        assert_eq!(
            rendered(&sample(), OutputFormat::Plain),
            "\
A   B            C     D      E      F   G                               
1   longer text  None  True   ñ日本  l1  2024-01-02 03:04:05.500000+02:00
                                     l2                                  
22  x            y     False  a      b   None                            
"
        );
    }

    #[test]
    fn empty_result_says_no_data() {
        let r = result(vec![column("A", SfType::Text)], vec![]);
        assert_eq!(rendered(&r, OutputFormat::Table), "No data\n\n");
        assert_eq!(rendered(&r, OutputFormat::Plain), "No data\n\n");
    }

    #[test]
    fn cells_are_sanitized() {
        assert_eq!(normalize_cell("\x1b[31mred\x1b[0m\u{7}"), "red");
        assert_eq!(normalize_cell("a\tb\nc\td\r"), "a       b\nc       d");
        assert_eq!(normalize_cell("plain"), "plain");
        assert_eq!(normalize_cell("\x1b\x00]52;c;x\x1b\x00\\"), "]52;c;x\\");
        assert_eq!(normalize_cell("\x1b[2\x00J"), "[2J");
        assert_eq!(normalize_cell("\u{9b}2J\u{7f}"), "2J");
    }

    #[test]
    fn terminal_width_folds_the_widest_columns() {
        let r = result(
            vec![column("ID", SfType::Text), column("TEXT", SfType::Text)],
            vec![vec![
                Value::Text("1".into()),
                Value::Text("abcdefghijklmnopqrstuvwxyz".into()),
            ]],
        );
        let mut out = Vec::new();
        render_with_width(&r, OutputFormat::Table, Some(20), &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\
+------------------+
| ID | TEXT        |
|----+-------------|
| 1  | abcdefghijk |
|    | lmnopqrstuv |
|    | wxyz        |
+------------------+
"
        );
    }

    #[test]
    fn tty_allocation_follows_snow() {
        assert_eq!(allocate_tty_widths(&[2, 26], 20, false), vec![2, 11]);
        assert_eq!(allocate_tty_widths(&[30, 30], 40, true), vec![19, 19]);
        assert_eq!(allocate_tty_widths(&[30, 30, 5], 20, false), vec![8, 8, 5]);
        assert_eq!(allocate_tty_widths(&[10, 20], 100, false), vec![10, 20]);
        assert_eq!(allocate_tty_widths(&[20, 15], 30, false), vec![11, 12]);
    }

    #[test]
    fn fold_respects_wide_characters() {
        assert_eq!(fold("日本日本", 4), vec!["日本", "日本"]);
        assert_eq!(fold("日", 1), vec!["日"]);
        assert_eq!(split_cell("ab\ncd", 1, true), vec!["a", "b", "c", "d"]);
        assert_eq!(pad("toolong", 3), "toolong");
    }
}
