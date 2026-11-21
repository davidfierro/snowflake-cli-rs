//! Typed result of one statement (ADR 0001, Decisions 2 and 6).

/// All rows of all partitions of one statement.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryResult {
    pub statement_handle: String,
    /// Names already de-duplicated (Decision 6).
    pub columns: Vec<Column>,
    /// `rows[i].len() == columns.len()`.
    pub rows: Vec<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub sf_type: SfType,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfType {
    Fixed {
        precision: u8,
        scale: u8,
    },
    Real,
    Decfloat,
    Text,
    Binary,
    Boolean,
    Date,
    Time {
        scale: u8,
    },
    TimestampNtz {
        scale: u8,
    },
    TimestampLtz {
        scale: u8,
    },
    TimestampTz {
        scale: u8,
    },
    Variant,
    Object,
    Array,
    /// A rowType the client does not know yet (e.g. "vector", "geography"); values stay Text.
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// FIXED with scale 0 (NUMBER(38,0) needs i128).
    Int(i128),
    /// FIXED with scale > 0, DECFLOAT: the exact digits returned ("1.50").
    Decimal(String),
    /// REAL, incl. NaN and ±inf.
    Float(f64),
    Text(String),
    Binary(Vec<u8>),
    Date(jiff::civil::Date),
    Time(jiff::civil::Time),
    TimestampNtz(jiff::civil::DateTime),
    /// TIMESTAMP_TZ, and TIMESTAMP_LTZ converted to the session time zone.
    TimestampTz {
        local: jiff::civil::DateTime,
        offset_seconds: i32,
    },
    /// VARIANT / OBJECT / ARRAY, text exactly as returned.
    Json(String),
}

impl SfType {
    /// Maps a SQL API `rowType` entry to a type. Precision and scale default to 0 when absent.
    pub(crate) fn from_row_type(
        type_name: &str,
        precision: Option<i64>,
        scale: Option<i64>,
    ) -> Self {
        let small = |v: Option<i64>| v.and_then(|v| u8::try_from(v).ok()).unwrap_or(0);
        let scale_u8 = small(scale);
        match type_name.to_ascii_lowercase().as_str() {
            "fixed" => SfType::Fixed {
                precision: small(precision),
                scale: scale_u8,
            },
            "real" => SfType::Real,
            "decfloat" => SfType::Decfloat,
            "text" => SfType::Text,
            "binary" => SfType::Binary,
            "boolean" => SfType::Boolean,
            "date" => SfType::Date,
            "time" => SfType::Time { scale: scale_u8 },
            "timestamp_ntz" => SfType::TimestampNtz { scale: scale_u8 },
            "timestamp_ltz" => SfType::TimestampLtz { scale: scale_u8 },
            "timestamp_tz" => SfType::TimestampTz { scale: scale_u8 },
            "variant" => SfType::Variant,
            "object" => SfType::Object,
            "array" => SfType::Array,
            other => SfType::Other(other.to_string()),
        }
    }
}

/// De-duplicates column names as snow's `QueryResult._uniquify_column_names`: the first
/// occurrence keeps its name, later ones get `_2`, `_3`, … skipping names already taken.
pub(crate) fn uniquify_column_names(names: &[String]) -> Vec<String> {
    use std::collections::{HashMap, HashSet};
    let mut used: HashSet<String> = names.iter().cloned().collect();
    let mut counters: HashMap<&str, usize> = HashMap::new();
    let mut unique = Vec::with_capacity(names.len());
    for name in names {
        match counters.get(name.as_str()).copied() {
            None => {
                unique.push(name.clone());
                counters.insert(name, 1);
            }
            Some(last) => {
                let mut index = last + 1;
                let mut candidate = format!("{name}_{index}");
                while used.contains(&candidate) {
                    index += 1;
                    candidate = format!("{name}_{index}");
                }
                used.insert(candidate.clone());
                unique.push(candidate);
                counters.insert(name, index);
            }
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn duplicate_names_get_counters_skipping_taken_names() {
        assert_eq!(
            uniquify_column_names(&names(&["A", "A", "A_2", "A", "B"])),
            names(&["A", "A_3", "A_2", "A_4", "B"])
        );
        assert_eq!(
            uniquify_column_names(&names(&["X", "Y"])),
            names(&["X", "Y"])
        );
    }

    #[test]
    fn row_types_map_to_sf_types() {
        assert_eq!(
            SfType::from_row_type("fixed", Some(38), Some(2)),
            SfType::Fixed {
                precision: 38,
                scale: 2
            }
        );
        assert_eq!(
            SfType::from_row_type("FIXED", None, None),
            SfType::Fixed {
                precision: 0,
                scale: 0
            }
        );
        assert_eq!(SfType::from_row_type("real", None, None), SfType::Real);
        assert_eq!(
            SfType::from_row_type("decfloat", Some(38), None),
            SfType::Decfloat
        );
        assert_eq!(SfType::from_row_type("text", None, None), SfType::Text);
        assert_eq!(SfType::from_row_type("binary", None, None), SfType::Binary);
        assert_eq!(
            SfType::from_row_type("boolean", None, None),
            SfType::Boolean
        );
        assert_eq!(SfType::from_row_type("date", None, None), SfType::Date);
        assert_eq!(
            SfType::from_row_type("time", Some(0), Some(9)),
            SfType::Time { scale: 9 }
        );
        assert_eq!(
            SfType::from_row_type("timestamp_ntz", Some(0), Some(3)),
            SfType::TimestampNtz { scale: 3 }
        );
        assert_eq!(
            SfType::from_row_type("timestamp_ltz", Some(0), Some(9)),
            SfType::TimestampLtz { scale: 9 }
        );
        assert_eq!(
            SfType::from_row_type("timestamp_tz", Some(0), Some(9)),
            SfType::TimestampTz { scale: 9 }
        );
        assert_eq!(
            SfType::from_row_type("variant", None, None),
            SfType::Variant
        );
        assert_eq!(SfType::from_row_type("object", None, None), SfType::Object);
        assert_eq!(SfType::from_row_type("array", None, None), SfType::Array);
        assert_eq!(
            SfType::from_row_type("vector", None, None),
            SfType::Other("vector".into())
        );
        assert_eq!(
            SfType::from_row_type("fixed", Some(1000), Some(-1)),
            SfType::Fixed {
                precision: 0,
                scale: 0
            }
        );
    }
}
