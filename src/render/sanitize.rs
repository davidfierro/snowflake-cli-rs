//! snow's `sanitize_for_terminal` and `sanitize_for_csv` (`snowflake/cli/api/sanitizers.py`).

const ESC: char = '\x1b';

/// Removes 7-bit C1 ANSI escape sequences: `ESC` + one of `@`-`Z`, `\`-`_`, or a CSI sequence
/// (`ESC [`, parameter bytes `0`-`?`, intermediate bytes ` `-`/`, final byte `@`-`~`).
///
/// Unlike snow's regex, an `ESC` that starts no such sequence is dropped too (the rest is
/// kept): terminals still parse `ESC NUL ]…` as an OSC or `ESC [ 2 NUL J` as a CSI, so a lone
/// `ESC` left in result data could drive the terminal (found in security review).
pub(crate) fn sanitize_for_terminal(text: &str) -> String {
    if !text.contains(ESC) {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ESC {
            i += 1 + escape_len(&chars[i + 1..]).unwrap_or(0);
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Length of the escape sequence after `ESC`, if `rest` starts with one.
fn escape_len(rest: &[char]) -> Option<usize> {
    match rest.first()? {
        '[' => {
            let mut j = 1;
            while rest.get(j).is_some_and(|c| ('0'..='?').contains(c)) {
                j += 1;
            }
            while rest.get(j).is_some_and(|c| (' '..='/').contains(c)) {
                j += 1;
            }
            rest.get(j)
                .is_some_and(|c| ('@'..='~').contains(c))
                .then_some(j + 1)
        }
        c if ('@'..='Z').contains(c) || ('\\'..='_').contains(c) => Some(1),
        _ => None,
    }
}

/// Removes the C1 control characters (U+0080–U+009F); U+009B is a one-character CSI.
pub(crate) fn strip_c1(text: &str) -> String {
    text.chars()
        .filter(|c| !('\u{80}'..='\u{9f}').contains(c))
        .collect()
}

/// [`sanitize_for_terminal`] and [`strip_c1`], then a `'` prefix when the text starts with a character a
/// spreadsheet treats as a formula (`=`, `+`, `-`, `@`, tab, CR).
pub(crate) fn sanitize_for_csv(text: &str) -> String {
    let clean = strip_c1(&sanitize_for_terminal(text));
    if clean.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{clean}")
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_csi_and_fe_sequences() {
        assert_eq!(sanitize_for_terminal("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(sanitize_for_terminal("a\x1bMb"), "ab");
        assert_eq!(sanitize_for_terminal("a\x1b\\b"), "ab");
        assert_eq!(sanitize_for_terminal("\x1b[1;2 qx"), "x");
        assert_eq!(sanitize_for_terminal("plain"), "plain");
    }

    /// Security review finding: an ESC that starts no recognised sequence must not survive,
    /// or terminals still parse what follows (`ESC NUL ]` opens an OSC, `ESC [ 2 NUL J` clears).
    #[test]
    fn drops_every_unmatched_escape() {
        assert_eq!(sanitize_for_terminal("a\x1b[12"), "a[12");
        assert_eq!(sanitize_for_terminal("a\x1b"), "a");
        assert_eq!(sanitize_for_terminal("a\x1bab"), "aab");
        assert_eq!(sanitize_for_terminal("é\x1b[0mñ"), "éñ");
        assert_eq!(
            sanitize_for_terminal("\x1b\x00]52;c;x\x1b\x00\\"),
            "\x00]52;c;x\x00\\"
        );
        assert_eq!(sanitize_for_terminal("\x1b[2\x00J"), "[2\x00J");
        assert!(!sanitize_for_terminal("\x1b\x1b\x1b[").contains('\x1b'));
    }

    #[test]
    fn strips_c1_controls() {
        assert_eq!(strip_c1("\u{9b}2J x\u{80}\u{9f}é"), "2J xé");
    }

    #[test]
    fn csv_text_has_no_escape_or_c1_control() {
        assert_eq!(sanitize_for_csv("\u{9b}2J"), "2J");
        assert_eq!(sanitize_for_csv("\x1b\x00]0;t"), "\x00]0;t");
    }

    #[test]
    fn csv_prefixes_formulas() {
        for (input, expected) in [
            ("=1+1", "'=1+1"),
            ("+x", "'+x"),
            ("-y", "'-y"),
            ("@z", "'@z"),
            ("\ttab", "'\ttab"),
            ("\rcr", "'\rcr"),
            ("a=b", "a=b"),
            ("\x1b[0m=x", "'=x"),
        ] {
            assert_eq!(sanitize_for_csv(input), expected);
        }
    }
}
