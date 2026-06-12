//! Dynamic events — the in-memory representation a `.waza` rule evaluates
//! against.
//!
//! The whole point of this type is that the agent does **not** know the
//! field names of any module at compile time. A [`LogEvent`] carries a
//! `module` / `event_type` pair plus a free-form `fields` map; the rule
//! engine matches `FieldPath`s against that map purely by string lookup.
//! Adding a new module (or a new field to an existing one) requires zero
//! changes here — see `CLAUDE.md` §10.
//!
//! [`FieldValue`] is a *closed* enum rather than `serde_json::Value`: it
//! keeps the comparison logic total and the hot path allocation-free,
//! while still covering every scalar a module field can hold.

use std::collections::HashMap;
use std::time::Instant;

/// Typed value of an event field. Closed enum: covers every scalar type a
/// module field can carry. Preferred over `serde_json::Value` so the
/// comparison logic in [`FieldValue::compare`] stays total and cheap.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
}

impl FieldValue {
    /// Unified comparison used by the rule engine. Mismatched types
    /// (e.g. `Int` field vs. `Str` rule literal) return `false` rather
    /// than panicking — a typo in a `.waza` rule must never crash the
    /// agent.
    pub fn compare(&self, op: &CmpOp, rhs: &RuleValue) -> bool {
        match (self, rhs) {
            (FieldValue::Int(l), RuleValue::Int(r)) => op.apply_ord(l, r),
            (FieldValue::Float(l), RuleValue::Float(r)) => op.apply_ord(l, r),
            (FieldValue::Str(l), RuleValue::Str(r)) => op.apply_str(l, r),
            (FieldValue::Bool(l), RuleValue::Bool(r)) => op.apply_eq(l, r),
            _ => false,
        }
    }
}

/// A normalised event produced by **any** module. `fields` is dynamic —
/// that is what makes the agent versatile.
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// e.g. `"kernel_callback"`.
    pub module: String,
    /// e.g. `"process_create"`.
    pub event_type: String,
    /// e.g. `"pid" -> Int(4688)`.
    pub fields: HashMap<String, FieldValue>,
    /// Ingest instant, used for temporal correlation windows.
    pub timestamp: Instant,
}

impl LogEvent {
    #[inline]
    pub fn get_field(&self, field: &str) -> Option<&FieldValue> {
        self.fields.get(field)
    }
}

/// Comparison operator parsed from a `.waza` expression.
#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Contains,
    StartsWith,
}

impl CmpOp {
    pub fn apply_ord<T: PartialOrd>(&self, l: &T, r: &T) -> bool {
        match self {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            CmpOp::Lt => l < r,
            CmpOp::Gt => l > r,
            CmpOp::Le => l <= r,
            CmpOp::Ge => l >= r,
            _ => false,
        }
    }

    pub fn apply_eq<T: PartialEq>(&self, l: &T, r: &T) -> bool {
        match self {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            _ => false,
        }
    }

    pub fn apply_str(&self, l: &str, r: &str) -> bool {
        match self {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            CmpOp::Contains => l.contains(r),
            CmpOp::StartsWith => l.starts_with(r),
            _ => false,
        }
    }
}

/// Literal value on the rule side — what an event field is compared
/// against.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_int_ordering() {
        let v = FieldValue::Int(4688);
        assert!(v.compare(&CmpOp::Eq, &RuleValue::Int(4688)));
        assert!(v.compare(&CmpOp::Ge, &RuleValue::Int(4688)));
        assert!(v.compare(&CmpOp::Gt, &RuleValue::Int(4000)));
        assert!(!v.compare(&CmpOp::Lt, &RuleValue::Int(4000)));
    }

    #[test]
    fn compare_str_ops() {
        let v = FieldValue::Str("C:\\malware.exe".to_string());
        assert!(v.compare(&CmpOp::Contains, &RuleValue::Str("malware".to_string())));
        assert!(v.compare(&CmpOp::StartsWith, &RuleValue::Str("C:\\".to_string())));
        assert!(!v.compare(&CmpOp::Eq, &RuleValue::Str("other".to_string())));
    }

    #[test]
    fn compare_bool() {
        let v = FieldValue::Bool(true);
        assert!(v.compare(&CmpOp::Eq, &RuleValue::Bool(true)));
        assert!(v.compare(&CmpOp::Ne, &RuleValue::Bool(false)));
    }

    #[test]
    fn compare_incompatible_types_is_false() {
        // CLAUDE.md §8: Int field vs Str literal must be false, never panic.
        let v = FieldValue::Int(4688);
        assert!(!v.compare(&CmpOp::Eq, &RuleValue::Str("4688".to_string())));
        let v = FieldValue::Str("4688".to_string());
        assert!(!v.compare(&CmpOp::Eq, &RuleValue::Int(4688)));
        // Ordering op on a string-side mismatch is also false.
        assert!(!v.compare(&CmpOp::Lt, &RuleValue::Int(9999)));
    }
}
