//! Rule engine: inverted index + sliding correlation window + recursive
//! evaluation.
//!
//! This is the performance-critical component. The inverted index maps
//! `(module, event_type)` to the rule indices that reference it, so the
//! hot path (`process_event`) only ever evaluates the rules that can
//! possibly match the incoming event — never an O(n_rules) scan.
//!
//! Each rule owns its own sliding window of recent events, evicted in
//! O(1) from the front of a `VecDeque`. A leaf `Compare` matches if
//! *any* event currently in the window satisfies it, which is what makes
//! multi-event / multi-module correlation possible.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::ast::*;
use crate::detection::event::LogEvent;

type EventKey = (String, String);
type RuleIndex = HashMap<EventKey, Vec<usize>>;

/// FIFO sliding window of recent events for one rule.
struct CorrelationWindow {
    events: VecDeque<LogEvent>,
    max_age: Duration,
}

impl CorrelationWindow {
    fn new(max_age: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            max_age,
        }
    }

    fn push(&mut self, e: LogEvent) {
        self.events.push_back(e);
        self.evict();
    }

    /// Drop events older than `max_age` from the front. O(1) per drop.
    fn evict(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.events.front() {
            if now.duration_since(front.timestamp) > self.max_age {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    index: RuleIndex,
    windows: Vec<Mutex<CorrelationWindow>>,
}

impl RuleEngine {
    /// Build the inverted index once, at load time.
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut index: RuleIndex = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            for cond in &rule.conditions {
                let mut refs = Vec::new();
                cond.collect_event_refs(&mut refs);
                for key in refs {
                    index.entry(key).or_default().push(idx);
                }
            }
        }
        let windows = rules
            .iter()
            .map(|r| Mutex::new(CorrelationWindow::new(r.window)))
            .collect();
        Self {
            rules,
            index,
            windows,
        }
    }

    /// Number of loaded rules. Used by tests and available for
    /// diagnostics.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// HOT PATH: called for every received event. Returns the
    /// `(rule_name, actions)` of every rule that fired.
    pub fn process_event(&self, event: &LogEvent) -> Vec<(String, Vec<Action>)> {
        let key = (event.module.clone(), event.event_type.clone());
        let mut triggered = Vec::new();

        // ① O(1) lookup: only rules that mention this event type are
        //    considered. An event no rule references costs one hash miss.
        let Some(rule_indices) = self.index.get(&key) else {
            return triggered;
        };

        for &idx in rule_indices {
            let rule = &self.rules[idx];
            let snapshot = {
                let mut w = match self.windows[idx].lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                w.push(event.clone());
                // Clone the window contents so the lock is released before
                // the (potentially deeper) recursive evaluation runs.
                w.events.clone()
            };
            // ② A rule matches if AT LEAST ONE of its lines is true (OR).
            if rule.conditions.iter().any(|c| eval(c, &snapshot)) {
                triggered.push((rule.name.clone(), rule.actions.clone()));
            }
        }
        triggered
    }
}

/// Recursively evaluate a condition against the window snapshot. A leaf
/// `Compare` is true if THERE EXISTS an event in the window satisfying it
/// — this is what enables cross-event, cross-module correlation.
fn eval(cond: &Condition, window: &VecDeque<LogEvent>) -> bool {
    match cond {
        Condition::Compare { path, op, value } => window.iter().any(|e| {
            e.module == path.module
                && e.event_type == path.event_type
                && e.get_field(&path.field)
                    .map(|v| v.compare(op, value))
                    .unwrap_or(false)
        }),
        Condition::And(a, b) => eval(a, window) && eval(b, window),
        Condition::Or(a, b) => eval(a, window) || eval(b, window),
        Condition::Not(a) => !eval(a, window),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::event::{CmpOp, FieldValue, RuleValue};
    use std::collections::HashMap;

    fn ev(module: &str, et: &str, fields: &[(&str, FieldValue)]) -> LogEvent {
        let mut map = HashMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string(), v.clone());
        }
        LogEvent {
            module: module.into(),
            event_type: et.into(),
            fields: map,
            timestamp: Instant::now(),
        }
    }

    fn cmp(path: &str, op: CmpOp, v: RuleValue) -> Condition {
        Condition::Compare {
            path: FieldPath::parse(path).unwrap(),
            op,
            value: v,
        }
    }

    #[test]
    fn single_event_matches_compare() {
        let rule = Rule {
            name: "r1".into(),
            conditions: vec![cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )],
            window: Duration::from_secs(5),
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        let fired = engine.process_event(&ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        ));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, "r1");
    }

    #[test]
    fn unindexed_event_evaluates_no_rule() {
        let rule = Rule {
            name: "r1".into(),
            conditions: vec![cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )],
            window: Duration::from_secs(5),
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        // Event type referenced by no rule → index miss → nothing fires.
        let fired = engine.process_event(&ev(
            "kernel_callback",
            "thread_exit",
            &[("tid", FieldValue::Int(1))],
        ));
        assert!(fired.is_empty());
    }

    #[test]
    fn correlation_and_across_modules_in_window() {
        // One rule line: requires BOTH a kernel process_create AND a
        // minifilter file_create to be present in the window.
        let cond = Condition::And(
            Box::new(cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )),
            Box::new(cmp(
                "minifilter.file_create.name",
                CmpOp::Eq,
                RuleValue::Str("malware.exe".into()),
            )),
        );
        let rule = Rule {
            name: "corr".into(),
            conditions: vec![cond],
            window: Duration::from_secs(5),
            actions: vec![Action::Alert("suspicious".into())],
        };
        let engine = RuleEngine::new(vec![rule]);

        // First event alone → no match (only half the AND).
        let fired = engine.process_event(&ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        ));
        assert!(fired.is_empty());

        // Second event arrives within the window → AND satisfied.
        let fired = engine.process_event(&ev(
            "minifilter",
            "file_create",
            &[("name", FieldValue::Str("malware.exe".into()))],
        ));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, "corr");
    }

    #[test]
    fn correlation_misses_when_event_aged_out() {
        let cond = Condition::And(
            Box::new(cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )),
            Box::new(cmp(
                "minifilter.file_create.name",
                CmpOp::Eq,
                RuleValue::Str("malware.exe".into()),
            )),
        );
        let rule = Rule {
            name: "corr".into(),
            conditions: vec![cond],
            window: Duration::from_millis(50),
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);

        // Inject a process_create with a stale timestamp directly so we
        // don't have to sleep: simulate it being older than the 50ms window.
        let mut stale = ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        );
        stale.timestamp = Instant::now() - Duration::from_millis(200);
        let _ = engine.process_event(&stale);

        // The fresh file_create arrives; the stale process_create should
        // have been evicted, so the AND cannot be satisfied.
        let fired = engine.process_event(&ev(
            "minifilter",
            "file_create",
            &[("name", FieldValue::Str("malware.exe".into()))],
        ));
        assert!(fired.is_empty());
    }
}
