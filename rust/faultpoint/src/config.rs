use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Map, Value};

/// A dependency crate whose code gets points, limited to some kinds when kinds is given.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEntry {
    pub include: String,
    pub kinds: Option<Vec<String>>,
}

/// Which placement rules the rewriter applies, the clock reads it recognises, and the dependency crates whose
/// code gets points besides the crate being rewritten.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Placement {
    pub branch: bool,
    pub check: bool,
    #[serde(rename = "loop")]
    pub loops: bool,
    pub call: bool,
    pub clock: Vec<String>,
    pub scope: Vec<ScopeEntry>,
    pub exclude: Vec<String>,
}

impl Default for Placement {
    fn default() -> Self {
        Placement {
            branch: true,
            check: true,
            loops: true,
            call: true,
            clock: vec!["SystemTime::now".into(), "Instant::now".into()],
            scope: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

/** The file FAULTPOINT_CONFIG names: the plugins to enable, their options and the placement. */
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /** The enabled plugins; every compiled-in plugin when absent. */
    pub plugins: Option<Vec<String>>,
    pub options: Map<String, Value>,
    pub placement: Placement,
}

impl Config {
    pub fn read(path: Option<&str>) -> Config {
        match path {
            Some(path) => serde_json::from_str(&std::fs::read_to_string(path).expect("faultpoint: cannot read FAULTPOINT_CONFIG"))
                .expect("faultpoint: FAULTPOINT_CONFIG is not a valid configuration"),
            None => Config::default(),
        }
    }

    pub fn options(&self, plugin: &str) -> Value {
        self.options.get(plugin).cloned().unwrap_or(Value::Object(Map::new()))
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub service: String,
    pub rules: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub scope_key: String,
    pub seed: i64,
    pub config: Config,
}

fn variable(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

impl Settings {
    /** The settings of the FAULTPOINT_ environment variables and of the file FAULTPOINT_CONFIG names. */
    pub fn from_environment() -> Settings {
        Settings {
            service: variable("FAULTPOINT_SERVICE").unwrap_or_default(),
            rules: variable("FAULTPOINT_RULES").map(PathBuf::from),
            report: variable("FAULTPOINT_REPORT").map(PathBuf::from),
            scope_key: variable("FAULTPOINT_SCOPE_KEY").unwrap_or_else(|| "fp.scope".into()),
            seed: variable("FAULTPOINT_SEED").map_or(0, |seed| seed.parse().expect("faultpoint: FAULTPOINT_SEED is an integer")),
            config: Config::read(variable("FAULTPOINT_CONFIG").as_deref()),
        }
    }
}
