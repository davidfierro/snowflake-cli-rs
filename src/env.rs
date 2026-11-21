//! Injectable snapshot of the environment variables.

use std::collections::BTreeMap;
use std::fmt;

/// Snapshot of the process environment. Tests build one from pairs and never touch the real env.
///
/// Values may be credentials (`PRIVATE_KEY_PASSPHRASE`, `SNOWFLAKE_PRIVATE_KEY_RAW`, …), so
/// `Debug` prints variable names only.
#[derive(Clone, Default)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// Variables of the current process. Names or values that are not valid Unicode are skipped,
    /// as no variable snow reads can contain them.
    pub fn from_process() -> Self {
        Self {
            vars: std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect(),
        }
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// The value of `name` when it is set and not empty (snow ignores empty variables for most
    /// settings).
    pub(crate) fn get_non_empty(&self, name: &str) -> Option<&str> {
        self.get(name).filter(|v| !v.is_empty())
    }

    /// Every `(name, value)`, in name order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// `(suffix, value)` of every variable whose name starts with `prefix`, in name order.
    pub(crate) fn with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.vars
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .take_while(move |(k, _)| k.starts_with(prefix))
            .map(move |(k, v)| (&k[prefix.len()..], v.as_str()))
    }
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Env")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_values_from_pairs() {
        let env = Env::from_pairs([("A", "1"), ("EMPTY", "")]);
        assert_eq!(env.get("A"), Some("1"));
        assert_eq!(env.get("EMPTY"), Some(""));
        assert_eq!(env.get("MISSING"), None);
        assert_eq!(env.get_non_empty("EMPTY"), None);
        assert_eq!(env.get_non_empty("A"), Some("1"));
    }

    #[test]
    fn debug_prints_names_but_never_values() {
        let env = Env::from_pairs([("PRIVATE_KEY_PASSPHRASE", "hunter2-marker")]);
        let debug = format!("{env:?}");
        assert!(debug.contains("PRIVATE_KEY_PASSPHRASE"));
        assert!(!debug.contains("hunter2-marker"));
    }

    #[test]
    fn with_prefix_yields_suffixes_in_order() {
        let env = Env::from_pairs([
            ("SNOWFLAKE_CONNECTIONS_DEV_USER", "u"),
            ("SNOWFLAKE_CONNECTIONS_DEV_ACCOUNT", "a"),
            ("SNOWFLAKE_CONNECTIONS_PROD_USER", "p"),
            ("SNOWFLAKE_USER", "g"),
        ]);
        let got: Vec<_> = env.with_prefix("SNOWFLAKE_CONNECTIONS_DEV_").collect();
        assert_eq!(got, vec![("ACCOUNT", "a"), ("USER", "u")]);
    }

    #[test]
    fn from_process_reads_the_real_environment() {
        // PATH is set in every environment the tests run in (cargo needs it).
        let env = Env::from_process();
        assert!(env.get("PATH").is_some());
    }
}
