//! `snowflake.yml` as `snow` reads it: PyYAML's `BaseLoader`, so every scalar is a string (no
//! numbers, booleans or nulls; an empty value is `""`), merge keys (`<<`) and tags are not
//! interpreted, and a key repeated in one mapping is an error.

use saphyr_parser::{Event, Parser};
use std::collections::BTreeMap;

/// A YAML node, mappings in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Str(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    /// The value of `key` in a mapping.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `snow`'s `deep_merge_dicts`: mappings merge key by key, anything else is replaced.
    pub fn merge(&mut self, overrides: Node) {
        let (Node::Map(base), Node::Map(over)) = (&mut *self, overrides.clone()) else {
            *self = overrides;
            return;
        };
        for (key, value) in over {
            match base.iter_mut().find(|(k, _)| *k == key) {
                Some((_, existing))
                    if matches!(existing, Node::Map(_)) && matches!(value, Node::Map(_)) =>
                {
                    existing.merge(value)
                }
                Some((_, existing)) => *existing = value,
                None => base.push((key, value)),
            }
        }
    }
}

/// Parses the first document of `text`; an empty document is an empty mapping.
pub fn parse(text: &str) -> Result<Node, String> {
    let mut builder = Builder::default();
    for event in Parser::new_from_str(text) {
        let (event, _) = event.map_err(|e| e.to_string())?;
        if builder.event(event)? {
            break;
        }
    }
    Ok(builder.root.unwrap_or(Node::Map(Vec::new())))
}

enum Frame {
    Seq(usize, Vec<Node>),
    Map(usize, Vec<(String, Node)>, Option<String>),
}

#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    anchors: BTreeMap<usize, Node>,
    root: Option<Node>,
}

impl Builder {
    /// Handles one event; `true` once the first document is complete.
    fn event(&mut self, event: Event<'_>) -> Result<bool, String> {
        match event {
            Event::Scalar(value, _, anchor, _) => self.push(Node::Str(value.into_owned()), anchor),
            Event::Alias(id) => {
                let node = self
                    .anchors
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| "found undefined alias".to_string())?;
                self.push(node, 0)
            }
            Event::SequenceStart(anchor, _) => {
                self.stack.push(Frame::Seq(anchor, Vec::new()));
                Ok(())
            }
            Event::MappingStart(anchor, _) => {
                self.stack.push(Frame::Map(anchor, Vec::new(), None));
                Ok(())
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let (node, anchor) = match self.stack.pop() {
                    Some(Frame::Seq(anchor, items)) => (Node::Seq(items), anchor),
                    Some(Frame::Map(anchor, entries, _)) => (Node::Map(entries), anchor),
                    None => return Err("unbalanced YAML events".into()),
                };
                self.push(node, anchor)
            }
            Event::DocumentEnd => return Ok(self.root.is_some()),
            _ => Ok(()),
        }
        .map(|()| false)
    }

    fn push(&mut self, node: Node, anchor: usize) -> Result<(), String> {
        if anchor > 0 {
            self.anchors.insert(anchor, node.clone());
        }
        match self.stack.last_mut() {
            None => self.root = Some(node),
            Some(Frame::Seq(_, items)) => items.push(node),
            Some(Frame::Map(_, entries, pending)) => match pending.take() {
                None => {
                    let Node::Str(key) = node else {
                        return Err("mapping keys must be scalars".into());
                    };
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(format!(
                            "While loading the project definition file, duplicate key was found: {key}"
                        ));
                    }
                    *pending = Some(key);
                }
                Some(key) => entries.push((key, node)),
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Node {
        Node::Str(v.into())
    }

    #[test]
    fn every_scalar_is_a_string_as_with_base_loader() {
        let node = parse("a:\nb: ~\nc: 007\nd: true\ne: 'q'\nf: [1, x]\n").unwrap();
        assert_eq!(
            node,
            Node::Map(vec![
                ("a".into(), s("")),
                ("b".into(), s("~")),
                ("c".into(), s("007")),
                ("d".into(), s("true")),
                ("e".into(), s("q")),
                ("f".into(), Node::Seq(vec![s("1"), s("x")])),
            ])
        );
    }

    #[test]
    fn anchors_aliases_and_tags() {
        let node = parse("a: &x {k: v}\nb: *x\nc: !override [1]\n'<<': *x\n").unwrap();
        let k = Node::Map(vec![("k".into(), s("v"))]);
        assert_eq!(node.get("a"), Some(&k));
        assert_eq!(node.get("b"), Some(&k));
        assert_eq!(node.get("c"), Some(&Node::Seq(vec![s("1")])));
        assert_eq!(node.get("<<"), Some(&k));
        assert_eq!(s("x").get("a"), None);
    }

    #[test]
    fn errors() {
        assert_eq!(
            parse("env:\n  a: 1\n  a: 2\n").unwrap_err(),
            "While loading the project definition file, duplicate key was found: a"
        );
        assert!(parse("a: [1\n").is_err());
        assert!(parse("? [a]\n: 1\n").unwrap_err().contains("scalars"));
        assert!(parse("a: *nope\n").is_err());
    }

    #[test]
    fn empty_documents_are_empty_mappings_and_only_the_first_counts() {
        assert_eq!(parse("").unwrap(), Node::Map(Vec::new()));
        assert_eq!(parse("a: 1\n---\nb: 2\n").unwrap().get("b"), None);
        assert_eq!(parse("- 1\n").unwrap(), Node::Seq(vec![s("1")]));
    }

    #[test]
    fn deep_merge() {
        let mut base = parse("a: {x: 1, y: 2}\nb: [1]\nc: q\n").unwrap();
        base.merge(parse("a: {y: 3, z: 4}\nb: [2]\nd: new\n").unwrap());
        assert_eq!(
            base,
            parse("a: {x: 1, y: 3, z: 4}\nb: [2]\nc: q\nd: new\n").unwrap()
        );
        let mut scalar = s("x");
        scalar.merge(s("y"));
        assert_eq!(scalar, s("y"));
    }
}
