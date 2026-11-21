use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, Once, RwLock};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::Settings;
use crate::rules::{Rule, RuleSet, point_parts};

/// The exit status of a process faultpoint stops, for rules it cannot obey or an error of its own.
const ABORT_EXIT: i32 = 70;

/// What tells executions of one outcome apart, by bounded values under the keys spec/kinds.json gives the kind;
/// its keys are sorted, so that one detail has one form.
pub type Detail = BTreeMap<&'static str, String>;

/// One execution of a point, as the core hands it to the observation sink.
pub struct Observation<'a> {
    pub experiment: &'a str,
    pub point: &'a str,
    pub outcome: &'a str,
    pub scope: String,
    pub rule: Option<&'a str>,
    pub quantity: f64,
    pub trace_id: Option<String>,
    pub detail: Detail,
}

pub trait RuleSource: Send {
    /// Deliver the first rule set before returning, then every change.
    fn start(self: Box<Self>, apply: Box<dyn Fn(Result<RuleSet, String>) + Send + Sync>);
}

pub trait ObservationSink: Send + Sync {
    fn add(&self, observation: Observation<'_>);
    fn flush(&self);
}

pub trait ContextProvider: Send + Sync {
    fn baggage(&self, key: &str) -> Option<String>;
    fn trace_id(&self) -> Option<String>;
}

/// A compiled-in plugin, enabled by name from the configuration: the kinds it serves with the
/// actions it implements, and the rule source, sink or context provider it supplies.
pub struct Plugin {
    pub name: &'static str,
    pub kinds: &'static [(&'static str, &'static [&'static str])],
    pub rule_source: Option<fn(&Settings, &Value) -> Option<Box<dyn RuleSource>>>,
    pub sink: Option<fn(&Settings, &Value) -> Option<Box<dyn ObservationSink>>>,
    pub context: Option<fn(&Settings, &Value) -> Box<dyn ContextProvider>>,
    /// Why the plugin cannot obey a rule of this service, asked of every rule when its rule set loads, for what an
    /// action's parameters ask that the plugin cannot do; a plugin passes over the kinds it does not serve.
    pub check: Option<fn(&Rule) -> Option<String>>,
}

inventory::collect!(Plugin);

#[derive(Default)]
struct RuleState {
    experiment: String,
    rules: HashMap<String, Vec<Rule>>,
}

#[derive(Default)]
struct Counter {
    matches: u64,
    injections: u64,
    drawn: u64,
}

/// Obtains rules, selects the rule of an execution and hands observations to the sink; every
/// kind's semantics lives in the plugins.
pub struct Core {
    pub settings: Settings,
    pub enabled: bool,
    declared: HashMap<&'static str, HashSet<&'static str>>,
    checks: Vec<fn(&Rule) -> Option<String>>,
    state: RwLock<Arc<RuleState>>,
    counters: Mutex<HashMap<String, Counter>>,
    sink: Option<Box<dyn ObservationSink>>,
    context: Option<Box<dyn ContextProvider>>,
    sources: Mutex<Vec<Box<dyn RuleSource>>>,
}

static CORE: LazyLock<Core> = LazyLock::new(|| Core::new(Settings::from_environment()));
static STARTED: Once = Once::new();

/// Run faultpoint's own work where the application's code runs, or on a thread of faultpoint: a panic of it is an
/// error of faultpoint, never one the application should meet or one that should end a thread alone, so it stops the
/// process, after the panic hook has printed where it happened.
pub fn own<T>(work: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|panic| {
        let message = panic.downcast_ref::<&str>().map(|text| (*text).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic without a message".to_owned());
        core().abort(&format!("internal error: {message}"))
    })
}

/// The process's core, whose rule sources have delivered their first rule set.
pub fn core() -> &'static Core {
    let core = &*CORE;
    STARTED.call_once(|| {
        for source in std::mem::take(&mut *core.sources.lock().unwrap()) {
            source.start(Box::new(|result| match result {
                Ok(ruleset) => CORE.apply(ruleset),
                Err(reason) => CORE.abort(&format!("unusable rules: {reason}")),
            }));
        }
    });
    core
}

impl Core {
    fn new(settings: Settings) -> Core {
        let enabled = settings.rules.is_some() || settings.report.is_some();
        if enabled && settings.service.is_empty() {
            panic!("faultpoint: FAULTPOINT_SERVICE is required when faultpoint is enabled");
        }
        let mut core = Core {
            settings, enabled, declared: HashMap::new(), checks: Vec::new(), state: RwLock::default(), counters: Mutex::default(),
            sink: None, context: None, sources: Mutex::default(),
        };
        if !enabled {
            return core;
        }
        let chosen = core.settings.config.plugins.clone();
        for plugin in inventory::iter::<Plugin> {
            if chosen.as_ref().is_some_and(|names| !names.iter().any(|name| name == plugin.name)) {
                continue;
            }
            let options = core.settings.config.options(plugin.name);
            // A kind served by several plugins accepts only the actions every one of them implements.
            for (kind, actions) in plugin.kinds {
                let offered: HashSet<&'static str> = actions.iter().copied().collect();
                core.declared.entry(kind).and_modify(|known| known.retain(|action| offered.contains(action))).or_insert(offered);
            }
            core.checks.extend(plugin.check);
            if let Some(sink) = plugin.sink.and_then(|build| build(&core.settings, &options)) {
                core.sink = Some(sink);
            }
            if let Some(build) = plugin.context {
                core.context = Some(build(&core.settings, &options));
            }
            if let Some(source) = plugin.rule_source.and_then(|build| build(&core.settings, &options)) {
                core.sources.get_mut().unwrap().push(source);
            }
        }
        core
    }

    /// Install a rule set; a rule of this service for a kind a plugin serves must use an action
    /// that plugin implements, and rules of other services or kinds are left to their processes.
    pub fn apply(&self, ruleset: RuleSet) {
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();
        for rule in ruleset.rules {
            let (service, kind) = point_parts(&rule.point).expect("validated when parsed");
            let Some(actions) = self.declared.get(kind) else { continue };
            if service != self.settings.service {
                continue;
            }
            if !actions.contains(rule.action.kind.as_str()) {
                self.abort(&format!("rule {}: not every plugin of this process serving it implements {} at a {kind} point",
                                    rule.id, rule.action.kind));
            }
            if let Some(refusal) = self.checks.iter().find_map(|check| check(&rule)) {
                self.abort(&format!("rule {}: {refusal}", rule.id));
            }
            rules.entry(rule.point.clone()).or_default().push(rule);
        }
        if let Some(sink) = &self.sink {
            sink.flush();
        }
        *self.counters.lock().unwrap() = HashMap::new();
        *self.state.write().unwrap() = Arc::new(RuleState { experiment: ruleset.experiment, rules });
    }

    /// The first rule of a point whose scope matches the current request and whose trigger fires.
    pub fn decide(&self, point: &str) -> Option<Rule> {
        self.decide_among(point, |_| true)
    }

    /// The first rule of a point among the rules of the given actions whose scope matches the current request and
    /// whose trigger fires. Only those rules are counted, so that a point deciding before and after its operation
    /// counts a rule only where it can act.
    pub fn decide_among(&self, point: &str, actions: fn(&str) -> bool) -> Option<Rule> {
        let state = self.state.read().unwrap().clone();
        for rule in state.rules.get(point)? {
            if !actions(&rule.action.kind) || !rule.scope.iter().all(|(key, value)| self.baggage(key).as_deref() == Some(value.as_str())) {
                continue;
            }
            let mut counters = self.counters.lock().unwrap();
            let counter = counters.entry(rule.id.clone()).or_default();
            counter.matches += 1;
            if counter.matches <= rule.trigger.skip || rule.trigger.limit.is_some_and(|limit| counter.injections >= limit) {
                continue;
            }
            let digest = Sha256::digest(format!("{}:{}:{}", self.settings.seed, rule.id, counter.drawn).as_bytes());
            counter.drawn += 1;
            let draw = f64::from(u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])) / 4_294_967_296.0;
            if draw >= rule.trigger.probability {
                continue;
            }
            counter.injections += 1;
            return Some(rule.clone());
        }
        None
    }

    pub fn observe(&self, point: &str, outcome: &str, quantity: f64, rule: Option<&Rule>, detail: Detail) {
        let Some(sink) = &self.sink else { return };
        let state = self.state.read().unwrap().clone();
        sink.add(Observation {
            experiment: &state.experiment, point, outcome, quantity, rule: rule.map(|rule| rule.id.as_str()),
            scope: self.baggage(&self.settings.scope_key).unwrap_or_default(),
            trace_id: self.context.as_ref().and_then(|context| context.trace_id()), detail,
        });
    }

    fn baggage(&self, key: &str) -> Option<String> {
        self.context.as_ref().and_then(|context| context.baggage(key))
    }

    pub fn crash(&self, code: i32) -> ! {
        if let Some(sink) = &self.sink {
            sink.flush();
        }
        std::process::exit(code)
    }

    /// End the process when rules cannot be obeyed, so that no experiment runs under rules it did not ask for; what was
    /// observed is written first, and the process stops even when writing it panics, whose message the panic hook
    /// has printed.
    pub fn abort(&self, reason: &str) -> ! {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.flush()));
        eprintln!("faultpoint: {reason}; stopping the process");
        std::process::exit(ABORT_EXIT)
    }

    /// Write the pending observations; a process calls it before a graceful exit.
    pub fn flush(&self) {
        if let Some(sink) = &self.sink {
            sink.flush();
        }
    }
}
