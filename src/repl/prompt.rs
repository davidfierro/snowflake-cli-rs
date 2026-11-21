//! `--prompt-format`: the interactive-session prompt from a template with session placeholders,
//! as `snow` 3.34.0 expands it (`prompt_format.py`).
//!
//! - Placeholders (case-insensitive): `[user]`, `[host]`, `[account]`, `[role]`,
//!   `[warehouse]`, `[database]`, `[schema]`, `[connection]`; a missing value is `(no user)`, …
//! - `\n` is a newline; `\[`, `\]` and `\\` are literal; other backslashes stay as they are.
//! - `[#rrggbb]` and `[bg:#rrggbb]` colour the text after them; other `[...]` tokens are dropped
//!   (and warned about once at start).

use crate::render::sanitize::sanitize_for_terminal;
use regex::Regex;
use std::sync::OnceLock;

/// The prompt when no format is set, or when a format renders to nothing.
pub const DEFAULT_PROMPT: &str = " > ";

const PLACEHOLDERS: [&str; 8] = [
    "user",
    "host",
    "account",
    "role",
    "warehouse",
    "database",
    "schema",
    "connection",
];

/// The values of the placeholders (`session_prompt_values`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptValues {
    pub user: Option<String>,
    pub host: Option<String>,
    pub account: Option<String>,
    pub role: Option<String>,
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub connection: Option<String>,
}

impl PromptValues {
    fn get(&self, name: &str) -> Option<&str> {
        match name {
            "user" => self.user.as_deref(),
            "host" => self.host.as_deref(),
            "account" => self.account.as_deref(),
            "role" => self.role.as_deref(),
            "warehouse" => self.warehouse.as_deref(),
            "database" => self.database.as_deref(),
            "schema" => self.schema.as_deref(),
            _ => self.connection.as_deref(),
        }
    }
}

/// How many colours the terminal gets (prompt_toolkit's `ColorDepth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    /// No colour (`NO_COLOR`, a dumb terminal).
    None,
    /// The 256-colour palette: prompt_toolkit's default.
    Palette256,
    /// 24-bit colour (`PROMPT_TOOLKIT_COLOR_DEPTH=DEPTH_24_BIT`).
    TrueColor,
}

impl ColorDepth {
    /// prompt_toolkit's choice from the environment: `NO_COLOR`, then
    /// `PROMPT_TOOLKIT_COLOR_DEPTH`, then `TERM` (`dumb` has none).
    pub fn from_env(env: &crate::env::Env) -> Self {
        if env.get_non_empty("NO_COLOR").is_some() {
            return Self::None;
        }
        match env.get("PROMPT_TOOLKIT_COLOR_DEPTH") {
            Some("DEPTH_1_BIT") => return Self::None,
            Some("DEPTH_24_BIT") => return Self::TrueColor,
            Some("DEPTH_4_BIT" | "DEPTH_8_BIT") => return Self::Palette256,
            _ => {}
        }
        match env.get("TERM") {
            Some(term) if term == "dumb" || term.starts_with("dumb") => Self::None,
            _ => Self::Palette256,
        }
    }
}

/// A rendered prompt: the visible text, and the same with colour escapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub raw: String,
    pub styled: String,
}

impl Prompt {
    pub fn plain(text: &str) -> Self {
        Self {
            raw: text.to_string(),
            styled: text.to_string(),
        }
    }
}

fn token_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[allow(clippy::unwrap_used)] // a constant pattern, checked by the tests
        Regex::new(r"\\\\|\\\[|\\\]|\\n|\[[^\[\]]*\]").unwrap()
    })
}

fn escape(token: &str) -> Option<&'static str> {
    match token {
        "\\\\" => Some("\\"),
        "\\[" => Some("["),
        "\\]" => Some("]"),
        "\\n" => Some("\n"),
        _ => None,
    }
}

/// `[#rrggbb]` (foreground) or `[bg:#rrggbb]` (background): the target and the colour.
fn colour(token: &str) -> Option<(bool, (u8, u8, u8))> {
    let content = token.strip_prefix('[')?.strip_suffix(']')?;
    let (background, hex) = match content.get(..3) {
        Some(prefix) if prefix.eq_ignore_ascii_case("bg:") => (true, &content[3..]),
        _ => (false, content),
    };
    let hex = hex.strip_prefix('#')?;
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some((background, (byte(0)?, byte(2)?, byte(4)?)))
}

/// `_sanitize_prompt_text`: escapes out, and the C0 controls but TAB and LF.
fn sanitize(text: &str) -> String {
    sanitize_for_terminal(text)
        .chars()
        .filter(|c| !matches!(c, '\x00'..='\x08' | '\x0b'..='\x1f' | '\x7f'))
        .collect()
}

/// The `[...]` tokens of `template` that are neither placeholders, colours nor escapes, in
/// order, each once.
pub fn unknown_tokens(template: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for m in token_pattern().find_iter(template) {
        let token = m.as_str();
        if escape(token).is_some() || colour(token).is_some() {
            continue;
        }
        let name = token[1..token.len() - 1].to_lowercase();
        let shown = sanitize(token);
        if !PLACEHOLDERS.contains(&name.as_str()) && !seen.contains(&shown) {
            seen.push(shown);
        }
    }
    seen
}

/// The warning printed at start when the format has unknown tokens.
pub fn unknown_token_warning(tokens: &[String]) -> String {
    let listed: Vec<String> = tokens.iter().map(|t| format!("'{t}'")).collect();
    let supported: Vec<String> = PLACEHOLDERS.iter().map(|p| format!("[{p}]")).collect();
    format!(
        "Ignoring unknown prompt placeholder(s) {}. Supported placeholders are {}. Use \\[ \\] \\\\ for literal brackets and backslash.",
        listed.join(", "),
        supported.join(", ")
    )
}

type Style = (Option<(u8, u8, u8)>, Option<(u8, u8, u8)>);

/// Expands `template` (`format_repl_prompt_for_terminal`).
pub fn render(template: Option<&str>, values: &PromptValues, depth: ColorDepth) -> Prompt {
    let Some(template) = template.filter(|t| !t.is_empty()) else {
        return Prompt::plain(DEFAULT_PROMPT);
    };
    let mut fragments: Vec<(Style, String)> = Vec::new();
    let mut style: Style = (None, None);
    let mut push = |style: Style, text: &str| {
        let text = sanitize(text);
        if text.is_empty() {
            return;
        }
        match fragments.last_mut() {
            Some((last, previous)) if *last == style => previous.push_str(&text),
            _ => fragments.push((style, text)),
        }
    };
    let mut cursor = 0;
    for m in token_pattern().find_iter(template) {
        push(style, &template[cursor..m.start()]);
        let token = m.as_str();
        if let Some((background, rgb)) = colour(token) {
            if background {
                style.1 = Some(rgb);
            } else {
                style.0 = Some(rgb);
            }
        } else if let Some(text) = escape(token) {
            push(style, text);
        } else {
            let name = token[1..token.len() - 1].to_lowercase();
            if PLACEHOLDERS.contains(&name.as_str()) {
                let value = values.get(&name).map(sanitize).unwrap_or_default();
                if value.is_empty() {
                    push(style, &format!("(no {name})"));
                } else {
                    push(style, &value);
                }
            }
        }
        cursor = m.end();
    }
    push(style, &template[cursor..]);
    if fragments.is_empty() {
        return Prompt::plain(DEFAULT_PROMPT);
    }
    let raw: String = fragments.iter().map(|(_, t)| t.as_str()).collect();
    let mut styled = String::new();
    for ((fg, bg), text) in &fragments {
        let codes = escape_codes(*fg, *bg, depth);
        if codes.is_empty() {
            styled.push_str(text);
        } else {
            styled.push_str(&format!("\x1b[0;{codes}m{text}\x1b[0m"));
        }
    }
    Prompt { raw, styled }
}

fn escape_codes(fg: Option<(u8, u8, u8)>, bg: Option<(u8, u8, u8)>, depth: ColorDepth) -> String {
    let code = |rgb: (u8, u8, u8), base: u8| match depth {
        ColorDepth::None => None,
        ColorDepth::TrueColor => Some(format!("{base};2;{};{};{}", rgb.0, rgb.1, rgb.2)),
        ColorDepth::Palette256 => Some(format!("{base};5;{}", closest_256(rgb))),
    };
    [fg.and_then(|c| code(c, 38)), bg.and_then(|c| code(c, 48))]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(";")
}

/// prompt_toolkit's `_256ColorCache`: the closest of colours 16-255 (the 16 ANSI colours depend
/// on the terminal's scheme, so they are skipped).
fn closest_256((r, g, b): (u8, u8, u8)) -> usize {
    const LEVELS: [i32; 6] = [0x00, 0x5F, 0x87, 0xAF, 0xD7, 0xFF];
    let mut table: Vec<(i32, i32, i32)> = (0..217)
        .map(|i| (LEVELS[(i / 36) % 6], LEVELS[(i / 6) % 6], LEVELS[i % 6]))
        .collect();
    table.extend((1..22).map(|i| {
        let v = 8 + i * 10;
        (v, v, v)
    }));
    let (r, g, b) = (i32::from(r), i32::from(g), i32::from(b));
    let mut best = (i32::MAX, 0);
    for (i, (r2, g2, b2)) in table.into_iter().enumerate() {
        let d = (r - r2).pow(2) + (g - g2).pow(2) + (b - b2).pow(2);
        if d < best.0 {
            best = (d, i + 16);
        }
    }
    best.1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> PromptValues {
        PromptValues {
            user: Some("ME".into()),
            database: Some("DB".into()),
            role: Some("R\x1b[31m\r".into()),
            ..Default::default()
        }
    }

    fn raw(template: &str) -> String {
        render(Some(template), &values(), ColorDepth::Palette256).raw
    }

    #[test]
    fn no_format_is_the_default_prompt() {
        assert_eq!(
            render(None, &values(), ColorDepth::Palette256),
            Prompt::plain(" > ")
        );
        assert_eq!(raw(""), " > ");
        assert_eq!(raw("[nope]"), " > ", "renders to nothing");
        assert_eq!(raw("[#ff0000]"), " > ");
    }

    #[test]
    fn placeholders_are_case_insensitive_and_missing_ones_named() {
        assert_eq!(
            raw("[USER]#[warehouse]@[Database].[schema]> "),
            "ME#(no warehouse)@DB.(no schema)> "
        );
        assert_eq!(
            raw("[host][account][connection]"),
            "(no host)(no account)(no connection)"
        );
        assert_eq!(raw("[role]"), "R", "escapes and CR are removed");
    }

    #[test]
    fn escapes() {
        assert_eq!(raw(r"a\nb"), "a\nb");
        assert_eq!(raw(r"\[user\] \\ \N \x"), r"[user] \ \N \x");
        assert_eq!(raw(r"\\[user]"), r"\ME");
        assert_eq!(raw("[bad] x"), " x");
    }

    #[test]
    fn colours_style_the_text_after_them() {
        let p = render(
            Some("[#FF0000]a[bg:#0000ff]b[user]"),
            &values(),
            ColorDepth::Palette256,
        );
        assert_eq!(p.raw, "abME");
        assert_eq!(
            p.styled,
            "\x1b[0;38;5;196ma\x1b[0m\x1b[0;38;5;196;48;5;21mbME\x1b[0m"
        );
        let p = render(Some("[#010203]a"), &values(), ColorDepth::TrueColor);
        assert_eq!(p.styled, "\x1b[0;38;2;1;2;3ma\x1b[0m");
        let p = render(Some("[#010203]a"), &values(), ColorDepth::None);
        assert_eq!(p.styled, "a");
        assert_eq!(closest_256((0x80, 0x80, 0x80)), 244);
    }

    #[test]
    fn unknown_tokens_are_listed_once() {
        assert_eq!(
            unknown_tokens("[user][x][#fff][x][bg:#123456][Y]\\[z\\]"),
            vec!["[x]", "[#fff]", "[Y]"]
        );
        assert_eq!(
            unknown_token_warning(&["[x]".into()]),
            "Ignoring unknown prompt placeholder(s) '[x]'. Supported placeholders are [user], [host], [account], [role], [warehouse], [database], [schema], [connection]. Use \\[ \\] \\\\ for literal brackets and backslash."
        );
    }

    #[test]
    fn colour_depth_from_the_environment() {
        let env = |pairs: &[(&str, &str)]| crate::env::Env::from_pairs(pairs.iter().copied());
        assert_eq!(ColorDepth::from_env(&env(&[])), ColorDepth::Palette256);
        assert_eq!(
            ColorDepth::from_env(&env(&[("NO_COLOR", "1")])),
            ColorDepth::None
        );
        assert_eq!(
            ColorDepth::from_env(&env(&[("PROMPT_TOOLKIT_COLOR_DEPTH", "DEPTH_24_BIT")])),
            ColorDepth::TrueColor
        );
        assert_eq!(
            ColorDepth::from_env(&env(&[("PROMPT_TOOLKIT_COLOR_DEPTH", "DEPTH_1_BIT")])),
            ColorDepth::None
        );
        assert_eq!(
            ColorDepth::from_env(&env(&[("PROMPT_TOOLKIT_COLOR_DEPTH", "DEPTH_4_BIT")])),
            ColorDepth::Palette256
        );
        assert_eq!(
            ColorDepth::from_env(&env(&[("TERM", "dumb")])),
            ColorDepth::None
        );
    }
}
