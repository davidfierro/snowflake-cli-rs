//! The `fn.*` templating functions of a `snowflake.yml` (definition 1.1 or later), ported from
//! `snow`'s `api/utils/templating_functions.py` and `api/project/util.py`.

/// `[a-zA-Z_][a-zA-Z0-9_$]{0,254}`
fn is_valid_unquoted_identifier(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 255
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'$')
}

/// `"((""|[^"]){0,255})"`
fn is_valid_quoted_identifier(id: &str) -> bool {
    let Some(inner) = id.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) else {
        return false;
    };
    if id.len() < 2 {
        return false;
    }
    let mut count = 0;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' && chars.next_if_eq(&'"').is_none() {
            return false;
        }
        count += 1;
    }
    count <= 255
}

fn is_valid_identifier(id: &str) -> bool {
    is_valid_unquoted_identifier(id) || is_valid_quoted_identifier(id)
}

fn to_quoted_identifier(value: &str) -> String {
    if is_valid_quoted_identifier(value) {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// `fn.str_to_id`.
pub fn to_identifier(name: &str) -> String {
    if is_valid_identifier(name) {
        name.to_string()
    } else {
        to_quoted_identifier(name)
    }
}

/// `fn.id_to_str`.
pub fn identifier_to_str(id: &str) -> String {
    if is_valid_quoted_identifier(id) {
        id[1..id.len() - 1].replace("\"\"", "\"")
    } else {
        id.to_string()
    }
}

/// `fn.concat_ids`.
pub fn concat_identifiers(ids: &[String]) -> String {
    let quoted = ids.iter().any(|id| is_valid_quoted_identifier(id));
    let joined: String = ids.iter().map(|id| identifier_to_str(id)).collect();
    if quoted {
        to_quoted_identifier(&joined)
    } else {
        to_identifier(&joined)
    }
}

/// `fn.sanitize_id`.
pub fn sanitize_identifier(input: &str) -> String {
    let mut value: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if !value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        value.insert(0, '_');
    }
    value.chars().take(255).collect()
}

/// The argument checks of `TemplatingFunctions._verify_str_arguments`.
pub fn verify_arguments(
    name: &str,
    args: &[Option<String>],
    min: usize,
    max: Option<usize>,
) -> Result<Vec<String>, String> {
    if args.len() < min {
        return Err(format!("{name} requires at least {min} argument(s)"));
    }
    if let Some(max) = max.filter(|max| args.len() > *max) {
        return Err(format!("{name} supports at most {max} argument(s)"));
    }
    args.iter()
        .map(|a| {
            a.clone()
                .ok_or_else(|| format!("{name} only accepts String values"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identifiers() {
        assert_eq!(to_identifier("abc_1$"), "abc_1$");
        assert_eq!(to_identifier("a b"), "\"a b\"");
        assert_eq!(to_identifier("\"a b\""), "\"a b\"");
        assert_eq!(to_identifier("1a"), "\"1a\"");
        assert_eq!(to_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(to_identifier(""), "\"\"");
        assert_eq!(
            to_identifier(&"a".repeat(256)),
            format!("\"{}\"", "a".repeat(256))
        );
        assert_eq!(identifier_to_str("\"a\"\"b\""), "a\"b");
        assert_eq!(identifier_to_str("ab"), "ab");
        assert_eq!(identifier_to_str("\"a\"b\""), "\"a\"b\"");
        assert_eq!(identifier_to_str("\""), "\"");
        assert!(!is_valid_quoted_identifier(&format!(
            "\"{}\"",
            "a".repeat(256)
        )));
    }

    #[test]
    fn concat() {
        assert_eq!(concat_identifiers(&v(&["a", "b"])), "ab");
        assert_eq!(concat_identifiers(&v(&["a", "y z"])), "\"ay z\"");
        assert_eq!(concat_identifiers(&v(&["\"a\"", "b"])), "\"ab\"");
        assert_eq!(concat_identifiers(&v(&["", "y z"])), "\"y z\"");
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_identifier("a-b c$"), "abc$");
        assert_eq!(sanitize_identifier("9x"), "_9x");
        assert_eq!(sanitize_identifier("é"), "_");
        assert_eq!(sanitize_identifier(&"a".repeat(300)).len(), 255);
    }

    #[test]
    fn argument_checks() {
        let s = |x: &str| Some(x.to_string());
        assert_eq!(
            verify_arguments("concat_ids", &[], 1, None).unwrap_err(),
            "concat_ids requires at least 1 argument(s)"
        );
        assert_eq!(
            verify_arguments("str_to_id", &[s("a"), s("b")], 1, Some(1)).unwrap_err(),
            "str_to_id supports at most 1 argument(s)"
        );
        assert_eq!(
            verify_arguments("id_to_str", &[None], 1, Some(1)).unwrap_err(),
            "id_to_str only accepts String values"
        );
        assert_eq!(
            verify_arguments("x", &[s("a")], 0, None).unwrap(),
            v(&["a"])
        );
    }
}
