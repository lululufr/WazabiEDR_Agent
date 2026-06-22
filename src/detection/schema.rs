//! Schema registry — optional, validation-only.
//!
//! The rule engine matches fields purely dynamically and does **not**
//! need a schema to function (see `CLAUDE.md` principle #1: zero
//! hardcoding of module fields). This registry exists only so the agent
//! can *validate* the `FieldPath`s referenced by loaded `.waza` rules
//! and emit a warning on a likely typo — fail-fast, but soft (a missing
//! schema never blocks startup or matching).
//!
//! Schemas are declared in an optional JSON file pointed at by the
//! `detection.schema_path` config key (the transitional approach from
//! `CLAUDE.md` §4: the driver speaks a fixed binary protocol and plugins
//! carry author-defined payloads, so neither emits a schema on the wire
//! yet). When no schema file is configured the registry is simply empty
//! and validation is skipped.
//!
//! Deviation from the `CLAUDE.md` skeleton: this project keeps a minimal
//! dependency set (see `Cargo.toml`), so we use `RwLock<HashMap>` instead
//! of `dashmap` (explicitly allowed by the spec) and `eprintln!` instead
//! of `tracing`.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// One module's self-description, as declared in the schema JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDeclaration {
    pub module: String,
    pub events: Vec<EventSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSchema {
    pub name: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub name: String,
    pub field_type: FieldType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Int,
    Float,
    String,
    Bool,
}

/// Registry: `module -> event_type -> (field_name -> field_type)`.
///
/// Guarded by a single `RwLock`: registration happens at load time (and
/// is rare), lookups are read-mostly. There is no global-lock contention
/// concern here because validation runs once per rule reload, not on the
/// hot event path.
pub struct SchemaRegistry {
    inner: RwLock<HashMap<String, HashMap<String, HashMap<String, FieldType>>>>,
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Register (or replace) one module's schema.
    pub fn register(&self, decl: SchemaDeclaration) {
        let mut event_map = HashMap::new();
        for event in decl.events {
            let field_map: HashMap<String, FieldType> = event
                .fields
                .into_iter()
                .map(|f| (f.name, f.field_type))
                .collect();
            event_map.insert(event.name, field_map);
        }
        match self.inner.write() {
            Ok(mut g) => {
                g.insert(decl.module.clone(), event_map);
            }
            Err(p) => {
                p.into_inner().insert(decl.module.clone(), event_map);
            }
        }
        eprintln!("[waza] schema registered for module '{}'", decl.module);
    }

    /// Load every declaration from a parsed JSON array and register them.
    pub fn register_all(&self, decls: Vec<SchemaDeclaration>) {
        for d in decls {
            self.register(d);
        }
    }

    /// `true` when no schema has been registered. Callers skip validation
    /// entirely in that case (a missing schema is not an error).
    pub fn is_empty(&self) -> bool {
        match self.inner.read() {
            Ok(g) => g.is_empty(),
            Err(p) => p.into_inner().is_empty(),
        }
    }

    /// Validate that `field` exists for a given `(module, event_type)`.
    /// Returns the declared [`FieldType`] when known, `None` otherwise.
    /// Used for fail-fast validation of rules at load time.
    pub fn validate_field(&self, module: &str, event_type: &str, field: &str) -> Option<FieldType> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.get(module)?.get(event_type)?.get(field).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SchemaDeclaration {
        SchemaDeclaration {
            module: "kernel_callback".into(),
            events: vec![EventSchema {
                name: "process_create".into(),
                fields: vec![
                    FieldSchema {
                        name: "pid".into(),
                        field_type: FieldType::Int,
                    },
                    FieldSchema {
                        name: "image_path".into(),
                        field_type: FieldType::String,
                    },
                ],
            }],
        }
    }

    #[test]
    fn register_and_validate() {
        let reg = SchemaRegistry::new();
        assert!(reg.is_empty());
        reg.register(sample());
        assert!(!reg.is_empty());
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "pid"),
            Some(FieldType::Int)
        );
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "image_path"),
            Some(FieldType::String)
        );
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "nope"),
            None
        );
        assert_eq!(reg.validate_field("other", "x", "y"), None);
    }

    #[test]
    fn parse_from_json() {
        let json = r#"
        [
          { "module": "kernel_callback",
            "events": [
              { "name": "process_create",
                "fields": [ {"name":"pid","field_type":"int"} ] }
            ] }
        ]"#;
        let decls: Vec<SchemaDeclaration> = serde_json::from_str(json).unwrap();
        let reg = SchemaRegistry::new();
        reg.register_all(decls);
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "pid"),
            Some(FieldType::Int)
        );
    }
}
