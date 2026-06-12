//! Abstract syntax tree for `.waza` rules.
//!
//! The parser produces these types; the engine consumes them. Neither
//! the AST nor the parser ever knows concrete module field names — a
//! [`FieldPath`] is an opaque `module.event_type.field` triple.

use std::time::Duration;

use crate::detection::event::{CmpOp, RuleValue};

/// Fully-qualified field reference: `"kernel_callback.process_create.pid"`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldPath {
    pub module: String,
    pub event_type: String,
    pub field: String,
}

impl FieldPath {
    /// Parse a dotted path. Exactly three segments are required; the
    /// `field` segment may itself contain dots (unlikely, but `splitn`
    /// keeps it lossless).
    pub fn parse(s: &str) -> Option<Self> {
        let p: Vec<&str> = s.splitn(3, '.').collect();
        if p.len() != 3 || p.iter().any(|seg| seg.is_empty()) {
            return None;
        }
        Some(FieldPath {
            module: p[0].into(),
            event_type: p[1].into(),
            field: p[2].into(),
        })
    }
}

/// A boolean condition over event fields.
#[derive(Debug, Clone)]
pub enum Condition {
    Compare {
        path: FieldPath,
        op: CmpOp,
        value: RuleValue,
    },
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    /// Collect the `(module, event_type)` pairs referenced by this
    /// condition. Drives the engine's inverted index so an event only
    /// hits the rules that actually mention its type.
    pub fn collect_event_refs(&self, refs: &mut Vec<(String, String)>) {
        match self {
            Condition::Compare { path, .. } => {
                let k = (path.module.clone(), path.event_type.clone());
                if !refs.contains(&k) {
                    refs.push(k);
                }
            }
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_event_refs(refs);
                b.collect_event_refs(refs);
            }
            Condition::Not(a) => a.collect_event_refs(refs),
        }
    }

    /// Visit every [`FieldPath`] in the tree. Used for schema validation
    /// at load time.
    pub fn collect_field_paths<'a>(&'a self, out: &mut Vec<&'a FieldPath>) {
        match self {
            Condition::Compare { path, .. } => out.push(path),
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_field_paths(out);
                b.collect_field_paths(out);
            }
            Condition::Not(a) => a.collect_field_paths(out),
        }
    }
}

/// One detection rule: a named group of OR-ed condition lines, a
/// correlation window, and the actions to run on match.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    /// Multiple lines in a Detection group = implicit OR between them.
    pub conditions: Vec<Condition>,
    /// Temporal correlation window (default 5s, overridable via `window:`).
    pub window: Duration,
    pub actions: Vec<Action>,
}

/// Action triggered when a rule matches. Extensible: add a variant here
/// and a match arm in `actions.rs`.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Log,
    Alert(String),
    KillProcess,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_path_parses_three_segments() {
        let fp = FieldPath::parse("kernel_callback.process_create.pid").unwrap();
        assert_eq!(fp.module, "kernel_callback");
        assert_eq!(fp.event_type, "process_create");
        assert_eq!(fp.field, "pid");
    }

    #[test]
    fn field_path_rejects_malformed() {
        assert!(FieldPath::parse("a.b").is_none());
        assert!(FieldPath::parse("a..c").is_none());
        assert!(FieldPath::parse("").is_none());
    }

    #[test]
    fn collect_event_refs_dedup() {
        let p = FieldPath::parse("m.e.f").unwrap();
        let p2 = FieldPath::parse("m.e.g").unwrap();
        let cond = Condition::And(
            Box::new(Condition::Compare {
                path: p,
                op: CmpOp::Eq,
                value: RuleValue::Int(1),
            }),
            Box::new(Condition::Compare {
                path: p2,
                op: CmpOp::Eq,
                value: RuleValue::Int(2),
            }),
        );
        let mut refs = Vec::new();
        cond.collect_event_refs(&mut refs);
        assert_eq!(refs, vec![("m".to_string(), "e".to_string())]);
    }
}
