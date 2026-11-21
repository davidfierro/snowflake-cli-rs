//! `--format` values.

use clap::ValueEnum;

/// Output format of a command result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "UPPER")]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    #[value(name = "JSON_EXT")]
    JsonExt,
    Csv,
    Plain,
}

impl OutputFormat {
    /// `OutputFormat.is_json`: JSON and JSON_EXT print the same structure.
    pub fn is_json(self) -> bool {
        matches!(self, OutputFormat::Json | OutputFormat::JsonExt)
    }

    /// `OutputFormat.allowed_values`.
    pub const ALLOWED: &'static str = "TABLE, JSON, JSON_EXT, CSV, PLAIN";

    /// `OutputFormat.from_string`: trimmed, case-insensitive.
    pub fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "TABLE" => Some(OutputFormat::Table),
            "JSON" => Some(OutputFormat::Json),
            "JSON_EXT" => Some(OutputFormat::JsonExt),
            "CSV" => Some(OutputFormat::Csv),
            "PLAIN" => Some(OutputFormat::Plain),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_like_snow() {
        assert_eq!(
            OutputFormat::from_name(" json_ext "),
            Some(OutputFormat::JsonExt)
        );
        assert_eq!(OutputFormat::from_name("Csv"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::from_name("xml"), None);
        assert_eq!(OutputFormat::from_name(""), None);
        assert!(OutputFormat::JsonExt.is_json() && OutputFormat::Json.is_json());
        assert!(!OutputFormat::Csv.is_json());
    }
}
