use std::any::type_name;
use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::core::{Detail, Plugin, core};
use crate::rules::Rule;

fn number(rule: &Rule, name: &str) -> f64 {
    rule.number(name).unwrap_or_else(|reason| core().abort(&reason))
}

/// Perform delay and crash, blocking the thread as contention does.
fn hold(rule: &Rule) {
    match rule.action.kind.as_str() {
        "delay" => std::thread::sleep(Duration::from_secs_f64(number(rule, "ms") / 1000.0)),
        "crash" => core().crash(rule.action.parameters.get("code").and_then(Value::as_i64).unwrap_or(1) as i32),
        _ => {}
    }
}

/// The error a call point returns under a fail rule; a function's error type receives it through From.
#[derive(Debug)]
pub struct Injected {
    pub point: String,
}

impl fmt::Display for Injected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "faultpoint: injected error at {}", self.point)
    }
}

impl std::error::Error for Injected {}

/// Whether a guarded error path runs: its natural condition, or forced by a fail rule.
pub fn branch(point: &str, taken: bool) -> bool {
    let core = core();
    if !core.enabled {
        return taken;
    }
    let rule = core.decide(point);
    let taken = match &rule {
        Some(rule) => {
            hold(rule);
            taken || rule.action.kind == "fail"
        }
        None => taken,
    };
    core.observe(point, if taken { "taken" } else { "not_taken" }, 0.0, rule.as_ref(), Detail::new());
    taken
}

/// The result of a detector, negated by a negate rule.
pub fn check(point: &str, result: bool) -> bool {
    let core = core();
    if !core.enabled {
        return result;
    }
    let rule = core.decide(point);
    let result = match &rule {
        Some(rule) => {
            hold(rule);
            result != (rule.action.kind == "negate")
        }
        None => result,
    };
    core.observe(point, if result { "true" } else { "false" }, 0.0, rule.as_ref(), Detail::new());
    result
}

/// One iteration of a loop, delayed by a delay rule to model contention.
pub fn loop_iteration(point: &str) {
    let core = core();
    if !core.enabled {
        return;
    }
    let rule = core.decide(point);
    if let Some(rule) = &rule {
        hold(rule);
    }
    core.observe(point, "iteration", 0.0, rule.as_ref(), Detail::new());
}

/// A business value, replaced by a set rule or offset by a shift rule.
pub fn value<T: Serialize + DeserializeOwned>(point: &str, observed: T) -> T {
    let core = core();
    if !core.enabled {
        return observed;
    }
    let rule = core.decide(point);
    let mut result = observed;
    if let Some(rule) = &rule {
        hold(rule);
        let replaced = match rule.action.kind.as_str() {
            "set" => rule.action.parameters.get("value").cloned(),
            "shift" => serde_json::to_value(&result).ok().and_then(|current| current.as_f64())
                .map(|current| Value::from(current + number(rule, "amount"))),
            _ => None,
        };
        if let Some(replaced) = replaced {
            result = serde_json::from_value(replaced)
                .unwrap_or_else(|error| core.abort(&format!("rule {} does not fit the value at {point}: {error}", rule.id)));
        }
    }
    let quantity = serde_json::to_value(&result).ok().and_then(|current| current.as_f64()).unwrap_or(0.0);
    core.observe(point, "observed", quantity, rule.as_ref(), Detail::new());
    result
}

/// A clock reading a shift rule can move.
pub trait ClockReading {
    fn shifted(self, seconds: f64) -> Self;
}

impl ClockReading for SystemTime {
    fn shifted(self, seconds: f64) -> Self {
        let offset = Duration::from_secs_f64(seconds.abs());
        if seconds >= 0.0 { self + offset } else { self - offset }
    }
}

impl ClockReading for Instant {
    fn shifted(self, seconds: f64) -> Self {
        let offset = Duration::from_secs_f64(seconds.abs());
        if seconds >= 0.0 { self + offset } else { self.checked_sub(offset).unwrap_or(self) }
    }
}

/// A clock reading, moved by a shift rule's seconds.
pub fn clock<T: ClockReading>(point: &str, reading: T) -> T {
    let core = core();
    if !core.enabled {
        return reading;
    }
    let rule = core.decide(point);
    let mut reading = reading;
    if let Some(rule) = &rule {
        hold(rule);
        if rule.action.kind == "shift" {
            reading = reading.shifted(number(rule, "amount"));
        }
    }
    core.observe(point, "read", 0.0, rule.as_ref(), Detail::new());
    reading
}

/// Whether a resource was acquired: its natural outcome, or rejected by a fail rule.
pub fn acquire(point: &str, acquired: bool) -> bool {
    let core = core();
    if !core.enabled {
        return acquired;
    }
    let rule = core.decide(point);
    let acquired = match &rule {
        Some(rule) => {
            hold(rule);
            acquired && rule.action.kind != "fail"
        }
        None => acquired,
    };
    core.observe(point, if acquired { "acquired" } else { "rejected" }, 0.0, rule.as_ref(), Detail::new());
    acquired
}

/// The result of a call, observed and, under a fail rule, replaced by an injected error.
pub fn call<T, E: From<Injected>>(point: &str, result: Result<T, E>) -> Result<T, E> {
    let core = core();
    if !core.enabled {
        return result;
    }
    let rule = core.decide(point);
    let result = match &rule {
        Some(rule) => {
            hold(rule);
            if rule.action.kind == "fail" { Err(Injected { point: point.into() }.into()) } else { result }
        }
        None => result,
    };
    match &result {
        Ok(_) => core.observe(point, "ok", 0.0, rule.as_ref(), Detail::new()),
        Err(_) => core.observe(point, "error", 0.0, rule.as_ref(), Detail::from([("error", type_name::<E>().to_owned())])),
    }
    result
}

inventory::submit! {
    Plugin {
        name: "points",
        kinds: &[
            ("branch", &["fail", "delay", "crash"]),
            ("call", &["fail", "delay", "crash"]),
            ("check", &["negate", "delay", "crash"]),
            ("loop", &["delay", "crash"]),
            ("value", &["set", "shift", "delay", "crash"]),
            ("clock", &["shift", "delay", "crash"]),
            ("acquire", &["fail", "delay", "crash"]),
        ],
        rule_source: None, sink: None, context: None,
    }
}
