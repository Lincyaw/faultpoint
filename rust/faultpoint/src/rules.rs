use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::core::{RuleSource, own};

pub fn point_id(service: &str, kind: &str, locator: &str) -> String {
    assert!(!service.contains(':'), "faultpoint: a service name cannot contain ':': {service}");
    format!("{service}:{kind}:{locator}")
}

/** The service and kind of a point id, which is <service>:<kind>:<locator>. */
pub fn point_parts(point: &str) -> Result<(&str, &str), String> {
    let mut parts = point.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(service), Some(kind), Some(locator)) if !service.is_empty() && !kind.is_empty() && !locator.is_empty() => {
            Ok((service, kind))
        }
        _ => Err(format!("a point id is <service>:<kind>:<locator>: {point}")),
    }
}

/** An action is a kind and free parameters, which the plugin that executes it interprets;
spec/kinds.json and `faultpoint check` validate them before a rule set is installed. */
#[derive(Clone, Debug, Deserialize)]
pub struct Action {
    pub kind: String,
    #[serde(flatten)]
    pub parameters: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    #[serde(default)]
    pub skip: u64,
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(default = "certain")]
    pub probability: f64,
}

fn certain() -> f64 {
    1.0
}

impl Default for Trigger {
    fn default() -> Self {
        Trigger { skip: 0, limit: None, probability: 1.0 }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub point: String,
    pub action: Action,
    #[serde(default)]
    pub scope: HashMap<String, String>,
    #[serde(default)]
    pub trigger: Trigger,
}

impl Rule {
    pub fn number(&self, name: &str) -> Result<f64, String> {
        self.action.parameters.get(name).and_then(Value::as_f64)
            .ok_or_else(|| format!("rule {}: a {} action needs a numeric {name}", self.id, self.action.kind))
    }

    pub fn text(&self, name: &str) -> Option<&str> {
        self.action.parameters.get(name).and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub experiment: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /** Parse a rule set and check its generic structure; the kinds and actions are checked by plugins. */
    pub fn parse(text: &str) -> Result<RuleSet, String> {
        let ruleset: RuleSet = serde_json::from_str(text).map_err(|error| error.to_string())?;
        if ruleset.experiment.is_empty() {
            return Err("a rule set needs an experiment".into());
        }
        let mut seen = HashSet::new();
        for rule in &ruleset.rules {
            if rule.id.is_empty() || !seen.insert(rule.id.as_str()) {
                return Err(format!("rule id {:?} is empty or repeats", rule.id));
            }
            point_parts(&rule.point)?;
            if !(rule.trigger.probability > 0.0 && rule.trigger.probability <= 1.0) || rule.trigger.limit == Some(0) {
                return Err(format!("rule {}: a probability is in (0, 1] and a limit at least 1", rule.id));
            }
        }
        Ok(ruleset)
    }
}

/** The default rule source: the rule set file named by FAULTPOINT_RULES, reloaded when it changes. */
pub struct FileRuleSource {
    pub path: PathBuf,
    pub interval: Duration,
}

impl FileRuleSource {
    fn modified(&self) -> Result<SystemTime, String> {
        std::fs::metadata(&self.path).and_then(|metadata| metadata.modified()).map_err(|error| error.to_string())
    }

    fn read(&self) -> Result<RuleSet, String> {
        RuleSet::parse(&std::fs::read_to_string(&self.path).map_err(|error| error.to_string())?)
    }
}

impl RuleSource for FileRuleSource {
    fn start(self: Box<Self>, apply: Box<dyn Fn(Result<RuleSet, String>) + Send + Sync>) {
        let mut modified = self.modified().ok();
        apply(self.read());
        std::thread::spawn(move || loop {
            std::thread::sleep(self.interval);
            own(|| match self.modified() {
                Ok(time) if Some(time) == modified => {}
                Ok(time) => {
                    modified = Some(time);
                    apply(self.read());
                }
                Err(error) => apply(Err(error)),
            });
        });
    }
}
