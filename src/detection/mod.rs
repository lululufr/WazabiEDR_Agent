//! Local Waza detection layer.
//!
//! Wiring (see `CLAUDE.md` §11): each module's events are normalised into
//! a dynamic [`event::LogEvent`] → an inverted index in
//! [`waza::engine::RuleEngine`] routes the event to only the rules that
//! reference its type → recursive evaluation over a sliding temporal
//! window decides whether a rule fires → matched [`waza::ast::Action`]s
//! run via [`actions::execute`]. No module field name is known at compile
//! time.
//!
//! This module owns the *facade* the rest of the agent talks to:
//! [`DetectionEngine`] hides the thread-safe sharing and hot-reload of
//! the rule set behind a single `process()` entry point, mirroring the
//! manifest-store pattern already used by the plugin server
//! (`RwLock<Arc<…>>` + a polling reload thread).

pub mod actions;
pub mod event;
pub mod schema;
pub mod waza {
    pub mod ast;
    pub mod engine;
    pub mod parser;
}

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::shutdown::SHUTDOWN;
use event::{FieldValue, LogEvent};
use schema::{SchemaDeclaration, SchemaRegistry};
use waza::ast::Action;
use waza::engine::RuleEngine;

/// A rule match worth reporting to the server, handed off to the
/// control-plane thread over a bounded channel so the (hot) detection
/// path never blocks on the network. The control plane maps this into
/// the server's `AlertIn` JSON and POSTs it to `/agents/{id}/alerts`.
///
/// Built only for matches whose actions include `Alert`/`KillProcess` —
/// a `Log`-only match is bookkeeping, not an alert.
#[derive(Debug, Clone)]
pub struct AgentAlert {
    /// The matched rule's name. Doubles as `rule_id` server-side: local
    /// `.waza` rules carry no UUID, and `AlertIn.rule_id` is a free-form
    /// string, so the name is the most useful stable identifier we have.
    pub rule_name: String,
    /// `"kill"` if any action was `KillProcess`, else `"alert"`. Maps to
    /// the server's `action_taken` enum.
    pub action_taken: &'static str,
    /// Originating module (e.g. `"kernel_callback"`, `"plugin"`) — a
    /// valid value of the server's `AgentModule` enum.
    pub module: String,
    /// Wall-clock emission time, ISO-8601 UTC. Sampled here because a
    /// [`LogEvent`] only carries a monotonic `Instant`.
    pub ts: String,
    /// The triggering event's scalar fields (plus `event_type`), as a JSON
    /// object — sent as the alert's `evidence`.
    pub evidence: serde_json::Value,
}

/// Convert a single [`FieldValue`] to its `serde_json` scalar.
fn field_value_to_json(v: &FieldValue) -> serde_json::Value {
    match v {
        FieldValue::Int(i) => serde_json::Value::from(*i),
        FieldValue::Float(f) => serde_json::Value::from(*f),
        FieldValue::Str(s) => serde_json::Value::from(s.clone()),
        FieldValue::Bool(b) => serde_json::Value::from(*b),
    }
}

/// Convert one `serde_json` scalar to a [`FieldValue`]. Nested
/// objects/arrays are dropped (`None`) — the rule language compares
/// scalars only. Numbers prefer `i64`, falling back to `f64`.
pub fn json_to_field_value(v: &serde_json::Value) -> Option<FieldValue> {
    match v {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(FieldValue::Int)
            .or_else(|| n.as_f64().map(FieldValue::Float)),
        serde_json::Value::String(s) => Some(FieldValue::Str(s.clone())),
        serde_json::Value::Bool(b) => Some(FieldValue::Bool(*b)),
        _ => None,
    }
}

/// Flatten a JSON object's top-level scalar entries into a field map.
/// Non-scalar values are skipped. Used by both the kernel and plugin
/// ingest paths to build a [`LogEvent`] from the payload they already
/// serialise for the spool.
pub fn flatten_fields(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> std::collections::HashMap<String, FieldValue> {
    let mut map = std::collections::HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        if let Some(fv) = json_to_field_value(v) {
            map.insert(k.clone(), fv);
        }
    }
    map
}

/// The detection facade shared across the kernel pump and plugin workers.
pub struct DetectionEngine {
    /// Hot-swappable rule engine. A reload replaces the inner `Arc`; live
    /// `process()` calls keep using the `Arc` they cloned.
    engine: RwLock<Arc<RuleEngine>>,
    /// Optional schema, used only for load-time validation of rules.
    schema: SchemaRegistry,
    rules_path: PathBuf,
    default_window: Duration,
    /// Bounded channel to the control-plane alert sender. `None` when
    /// alert forwarding is off (no control plane, or `send_alerts:false`).
    /// `try_send` is used so a full channel drops the alert rather than
    /// stalling the detection hot path.
    alert_tx: Option<SyncSender<AgentAlert>>,
}

impl DetectionEngine {
    /// Build the engine from a rules file (+ optional schema file).
    ///
    /// Returns `Err` only when the rules file can't be parsed — the
    /// caller treats that as "detection disabled" and the rest of the
    /// agent starts normally. A missing/unreadable schema file is a
    /// soft warning (validation skipped), never fatal.
    pub fn load(
        rules_path: &Path,
        schema_path: Option<&Path>,
        default_window: Duration,
    ) -> Result<Self, String> {
        let schema = SchemaRegistry::new();
        if let Some(sp) = schema_path {
            load_schema_into(&schema, sp);
        }

        let rules = waza::parser::parse_file_with_window(rules_path, default_window)?;
        validate_rules(&rules, &schema);
        let count = rules.len();
        let engine = RuleEngine::new(rules);
        eprintln!(
            "[waza] loaded {} rule(s) from {}",
            count,
            rules_path.display()
        );

        Ok(Self {
            engine: RwLock::new(Arc::new(engine)),
            schema,
            rules_path: rules_path.to_path_buf(),
            default_window,
            alert_tx: None,
        })
    }

    /// Attach the control-plane alert sink. Builder-style so [`load`] keeps
    /// a stable signature for tests; called once from `main` when the
    /// control plane is up and `send_alerts` is on.
    ///
    /// [`load`]: Self::load
    pub fn with_alert_sink(mut self, alert_tx: Option<SyncSender<AgentAlert>>) -> Self {
        self.alert_tx = alert_tx;
        self
    }

    /// HOT PATH: evaluate one event and run any triggered actions.
    /// Takes a brief read lock just to clone the current engine `Arc`,
    /// then releases it before evaluating — keeps the critical section
    /// minimal so a concurrent reload never blocks ingest.
    pub fn process(&self, event: LogEvent) {
        let engine = {
            let g = match self.engine.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            Arc::clone(&g)
        };
        for (rule_name, acts) in engine.process_event(&event) {
            for action in &acts {
                actions::execute(&rule_name, action, &event);
            }
            // Forward alert-worthy matches to the control plane (if wired).
            // A `Log`-only match is local bookkeeping, not an alert.
            if let Some(tx) = &self.alert_tx {
                self.emit_alert(tx, &rule_name, &acts, &event);
            }
        }
    }

    /// Build an [`AgentAlert`] for a match and hand it to the control
    /// plane. No-op if the match carried no `Alert`/`KillProcess` action.
    /// Uses `try_send`: a saturated channel drops the alert (counted on
    /// the control side) rather than blocking the detection thread.
    fn emit_alert(
        &self,
        tx: &SyncSender<AgentAlert>,
        rule_name: &str,
        acts: &[Action],
        event: &LogEvent,
    ) {
        let has_kill = acts.iter().any(|a| matches!(a, Action::KillProcess));
        let has_alert = acts.iter().any(|a| matches!(a, Action::Alert(_)));
        if !has_kill && !has_alert {
            return;
        }
        let action_taken = if has_kill { "kill" } else { "alert" };

        let mut evidence: serde_json::Map<String, serde_json::Value> = event
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), field_value_to_json(v)))
            .collect();
        // Carry the event type into evidence — `AlertIn` has no dedicated
        // field for it, but it's valuable triage context server-side.
        evidence.insert(
            "event_type".to_string(),
            serde_json::Value::from(event.event_type.clone()),
        );

        let alert = AgentAlert {
            rule_name: rule_name.to_string(),
            action_taken,
            module: event.module.clone(),
            ts: crate::util::time::now_iso8601(),
            evidence: serde_json::Value::Object(evidence),
        };
        // Drop-on-full: alerts are best-effort relative to keeping the
        // detection path non-blocking. The control side counts drops.
        let _ = tx.try_send(alert);
    }

    /// Re-parse the rules file and atomically swap the engine. On parse
    /// failure the previous engine is kept (better stale than empty).
    /// Note: correlation windows reset on reload (fresh engine) — an
    /// acceptable trade-off given reloads are rare operator actions.
    fn reload(&self) -> Result<(), String> {
        let rules = waza::parser::parse_file_with_window(&self.rules_path, self.default_window)?;
        validate_rules(&rules, &self.schema);
        let count = rules.len();
        let new_engine = Arc::new(RuleEngine::new(rules));
        match self.engine.write() {
            Ok(mut g) => *g = new_engine,
            Err(p) => *p.into_inner() = new_engine,
        }
        eprintln!("[waza] rules reloaded — {} rule(s)", count);
        Ok(())
    }
}

/// Load + register schema declarations from a JSON file. Best-effort:
/// any failure logs a warning and leaves the registry empty (validation
/// is then skipped).
fn load_schema_into(reg: &SchemaRegistry, path: &Path) {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<Vec<SchemaDeclaration>>(&bytes) {
            Ok(decls) => reg.register_all(decls),
            Err(e) => eprintln!(
                "[waza] schema file {} ignored (parse error: {})",
                path.display(),
                e
            ),
        },
        Err(e) => eprintln!(
            "[waza] schema file {} not loaded ({}) — rule validation skipped",
            path.display(),
            e
        ),
    }
}

/// Warn about rule field paths that aren't in the schema (likely typos).
/// No-op when no schema is loaded.
fn validate_rules(rules: &[waza::ast::Rule], schema: &SchemaRegistry) {
    if schema.is_empty() {
        return;
    }
    for rule in rules {
        for cond in &rule.conditions {
            let mut paths = Vec::new();
            cond.collect_field_paths(&mut paths);
            for p in paths {
                if schema
                    .validate_field(&p.module, &p.event_type, &p.field)
                    .is_none()
                {
                    eprintln!(
                        "[waza] rule '{}' references unknown field '{}.{}.{}' \
                         (not in schema — check for a typo)",
                        rule.name, p.module, p.event_type, p.field
                    );
                }
            }
        }
    }
}

/// Spawn the rule-reload thread. Polls the rules file fingerprint
/// (mtime + size) every `interval`, re-parsing and swapping the engine
/// when it changes. Returns `None` if the thread couldn't be spawned
/// (rare; OOM) — detection still works, rules just aren't hot-reloaded.
///
/// Polls in 250 ms slices so `SHUTDOWN` is observed promptly, matching
/// the plugin server's reload loop.
pub fn spawn_reload(engine: Arc<DetectionEngine>, interval: Duration) -> Option<JoinHandle<()>> {
    let path = engine.rules_path.clone();
    thread::Builder::new()
        .name("wedr-waza-reload".into())
        .spawn(move || {
            let mut last_fp = fingerprint(&path);
            let slices = (interval.as_millis() / 250).max(1) as u64;
            while !SHUTDOWN.load(Ordering::Acquire) {
                for _ in 0..slices {
                    if SHUTDOWN.load(Ordering::Acquire) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(250));
                }
                let fp = fingerprint(&path);
                if fp == last_fp {
                    continue;
                }
                match engine.reload() {
                    Ok(()) => last_fp = fp,
                    Err(e) => {
                        eprintln!("[waza] reload failed ({}); keeping previous rules", e);
                        // Don't update last_fp: retry next tick (operator
                        // may be mid-edit and the file momentarily invalid).
                    }
                }
            }
        })
        .ok()
}

/// Cheap change signal for a file: (modified-time-nanos, size). Returns
/// `(0, 0)` when the file is missing/unreadable so a later successful
/// stat registers as a change.
fn fingerprint(path: &Path) -> (u128, u64) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (mtime, m.len())
        }
        Err(_) => (0, 0),
    }
}
