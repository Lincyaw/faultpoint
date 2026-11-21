use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Settings;
use crate::core::{Detail, Observation, ObservationSink, Plugin, own};

/// One line of an observation file, as spec/observation.schema.json defines.
#[derive(Serialize)]
pub struct ObservationRecord {
    pub experiment: String,
    pub service: String,
    pub process: String,
    pub start: f64,
    pub end: f64,
    pub point: String,
    pub outcome: String,
    pub scope: String,
    pub rule: Option<String>,
    pub count: u64,
    pub total: f64,
    pub exemplars: Vec<String>,
    pub detail: Detail,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JsonlOptions {
    pub flush_seconds: f64,
    pub exemplars: usize,
    /// The share of traces whose ids are kept as exemplars, for hot library paths; counts stay exact.
    pub exemplar_rate: f64,
}

impl Default for JsonlOptions {
    fn default() -> Self {
        JsonlOptions { flush_seconds: 2.0, exemplars: 5, exemplar_rate: 1.0 }
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("the clock is after 1970").as_secs_f64()
}

type TallyKey = (String, String, String, String, Option<String>, Detail);

struct Tally {
    records: HashMap<TallyKey, ObservationRecord>,
    start: f64,
}

/// The default observation sink: observations aggregated per window and appended as JSON Lines.
pub struct JsonlSink {
    path: PathBuf,
    service: String,
    process: String,
    exemplars: usize,
    exemplar_rate: f64,
    tally: Arc<Mutex<Tally>>,
}

impl JsonlSink {
    pub fn start(path: PathBuf, service: String, options: JsonlOptions) -> Arc<JsonlSink> {
        let sink = Arc::new(JsonlSink {
            path, service, exemplars: options.exemplars, exemplar_rate: options.exemplar_rate,
            process: format!("{}:{}", gethostname::gethostname().to_string_lossy(), std::process::id()),
            tally: Arc::new(Mutex::new(Tally { records: HashMap::new(), start: now() })),
        });
        let flushing = Arc::clone(&sink);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs_f64(options.flush_seconds));
            own(|| flushing.flush());
        });
        sink
    }
}

impl ObservationSink for Arc<JsonlSink> {
    fn add(&self, observation: Observation<'_>) {
        let key = (observation.experiment.to_owned(), observation.point.to_owned(), observation.outcome.to_owned(),
                   observation.scope.clone(), observation.rule.map(str::to_owned), observation.detail.clone());
        let mut tally = self.tally.lock().unwrap();
        let record = tally.records.entry(key).or_insert_with(|| ObservationRecord {
            experiment: observation.experiment.into(), service: self.service.clone(), process: self.process.clone(),
            start: 0.0, end: 0.0, point: observation.point.into(), outcome: observation.outcome.into(),
            scope: observation.scope, rule: observation.rule.map(str::to_owned), count: 0, total: 0.0, exemplars: vec![],
            detail: observation.detail,
        });
        record.count += 1;
        record.total += observation.quantity;
        // A trace is sampled by its id, so that every process keeps or skips the same traces.
        let sampled = |trace_id: &String| u64::from_str_radix(&trace_id[trace_id.len().saturating_sub(8)..], 16)
            .is_ok_and(|tail| ((tail % 10_000) as f64) < self.exemplar_rate * 10_000.0);
        if let Some(trace_id) = observation.trace_id.filter(|trace_id| record.exemplars.len() < self.exemplars && sampled(trace_id)) {
            record.exemplars.push(trace_id);
        }
    }

    fn flush(&self) {
        let end = now();
        let mut tally = self.tally.lock().unwrap();
        let start = std::mem::replace(&mut tally.start, end);
        let mut lines = Vec::new();
        for (_, mut record) in tally.records.drain() {
            record.start = start;
            record.end = end;
            serde_json::to_writer(&mut lines, &record).expect("a record serialises");
            lines.push(b'\n');
        }
        if lines.is_empty() {
            return;
        }
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)
            .expect("faultpoint: cannot open the observation file");
        file.write_all(&lines).expect("faultpoint: cannot write observations");
    }
}

fn jsonl_sink(settings: &Settings, options: &Value) -> Option<Box<dyn ObservationSink>> {
    let path = settings.report.clone()?;
    let options: JsonlOptions = serde_json::from_value(options.clone()).expect("faultpoint: invalid jsonl options");
    Some(Box::new(JsonlSink::start(path, settings.service.clone(), options)))
}

inventory::submit! {
    Plugin { name: "jsonl", kinds: &[], rule_source: None, sink: Some(jsonl_sink), context: None, check: None }
}
