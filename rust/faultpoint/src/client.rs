use std::future::Future;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use opentelemetry::context::FutureExt;
use opentelemetry::propagation::{TextMapCompositePropagator, TextMapPropagator};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{Detail, Plugin, core, millis_since, own};
use crate::rules::{Rule, point_id};

pub const DEFAULT_HTTP_FAILURE_STATUS: u16 = 503;
pub const DEFAULT_GRPC_FAILURE_CODE: i32 = 14;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientOptions {
    pub identifier_segment: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            identifier_segment: r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$".into(),
        }
    }
}

pub static IDENTIFIER_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    let options: ClientOptions = serde_json::from_value(core().settings.config.options("client"))
        .expect("faultpoint: invalid client options");
    Regex::new(&options.identifier_segment).expect("faultpoint: invalid identifier_segment")
});

pub static PROPAGATOR: LazyLock<TextMapCompositePropagator> = LazyLock::new(|| {
    TextMapCompositePropagator::new(vec![Box::new(TraceContextPropagator::new()), Box::new(BaggagePropagator::new())])
});

/// The method, destination and bounded path of an outgoing HTTP or unary gRPC call.
pub fn locator(method: &str, authority: &str, path: &str) -> String {
    let path = path.split('/').map(|segment| {
        if IDENTIFIER_SEGMENT.is_match(segment) { "{}" } else { segment }
    }).collect::<Vec<_>>().join("/");
    format!("{method} {authority}{path}")
}

/// The wire headers bridge independently versioned OpenTelemetry clients without a shared SDK type.
pub fn context(headers: &http::HeaderMap) -> opentelemetry::Context {
    PROPAGATOR.extract(&HeaderExtractor(headers))
}

/// The native client's result classification, supplied inside its instrumented build copy.
pub struct Completion {
    pub outcome: String,
    pub detail: Detail,
    pub successful: bool,
}

pub struct Deadline<E> {
    pub duration: Duration,
    pub failure: fn() -> E,
}

/// One caller-visible exchange; cancellation records only what the adapter actually knows.
pub struct Exchange {
    pub point: String,
    pub rule: Option<Rule>,
    pub started: Instant,
    pub context: opentelemetry::Context,
    pub completion: Option<Completion>,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        own(|| {
            let completion = self.completion.take().unwrap_or(Completion {
                outcome: "error".into(), detail: Detail::new(), successful: false,
            });
            let _attached = self.context.clone().attach();
            let elapsed = millis_since(self.started);
            core().observe(&self.point, &completion.outcome, elapsed, elapsed, self.rule.as_ref(), completion.detail);
        });
    }
}

/// Execute an outgoing call with the native client's response and error constructors. The operation is lazy,
/// so a failure before execution sends nothing; a delayed call runs while its caller remains alive.
pub async fn call<T, E, F, H>(locator: String, context: opentelemetry::Context, operation: F,
                             failure: H, classify: fn(&Result<T, E>) -> Completion,
                             deadline: Option<Deadline<E>>) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    H: Fn(&Rule) -> Result<T, E>,
{
    if !core().enabled {
        return operation.await;
    }
    let parent = context.clone();
    async move {
        let (point, rule) = own(|| {
            let point = point_id(&core().settings.service, "rpc_client", &locator);
            let rule = core().decide_among(&point, |action| action != "fail_after");
            (point, rule)
        });
        let mut exchange = Exchange {
            point, rule, started: Instant::now(), context: context.clone(), completion: None,
        };
        let rule = exchange.rule.clone();
        let execution = async { match rule.as_ref().map(|rule| (rule, rule.action.kind.as_str())) {
            Some((rule, "delay")) => {
                let delay = own(|| Duration::from_secs_f64(
                    rule.number("ms").unwrap_or_else(|reason| core().abort(&reason)) / 1000.0));
                tokio::join!(operation, tokio::time::sleep(delay)).0
            }
            Some((rule, "fail")) => {
                if rule.action.parameters.contains_key("ms") {
                    let delay = own(|| Duration::from_secs_f64(
                        rule.number("ms").unwrap_or_else(|reason| core().abort(&reason)) / 1000.0));
                    tokio::time::sleep(delay).await;
                }
                own(|| failure(rule))
            }
            Some((rule, "crash")) => core().crash(
                rule.action.parameters.get("code").and_then(Value::as_i64).unwrap_or(1) as i32),
            Some((rule, action)) => core().abort(&format!("rule {}: {action} is not implemented at {}", rule.id, exchange.point)),
            None => operation.await,
        }};
        let result = match deadline {
            Some(deadline) => match tokio::time::timeout(deadline.duration, execution).await {
                Ok(result) => result,
                Err(_) => Err(own(deadline.failure)),
            },
            None => execution.await,
        };
        own(|| {
            let mut completion = classify(&result);
            let result = if completion.successful {
                match core().decide_among(&exchange.point, |action| action == "fail_after") {
                    Some(rule) => {
                        let result = failure(&rule);
                        completion = classify(&result);
                        exchange.rule = Some(rule);
                        result
                    }
                    None => result,
                }
            } else {
                result
            };
            match exchange.rule.as_ref().map(|rule| rule.action.kind.as_str()) {
                Some("fail") => { completion.detail.insert("sent", "false".into()); }
                Some("fail_after") => { completion.detail.insert("sent", "true".into()); }
                _ => {}
            }
            exchange.completion = Some(completion);
            result
        })
    }.with_context(parent).await
}

/// Reject protocol parameters before requests begin, including a numeric gRPC status outside its error range.
pub fn check_rule(rule: &Rule) -> Option<String> {
    if !matches!(rule.action.kind.as_str(), "fail" | "fail_after") {
        return None;
    }
    let Some((_, locator)) = rule.point.split_once(":rpc_client:") else { return None };
    let parameters = &rule.action.parameters;
    if locator.starts_with("gRPC ") {
        if parameters.contains_key("status") || parameters.contains_key("error") {
            return Some("a gRPC failure names its native code".into());
        }
        if parameters.contains_key("code") && rule.text("code")
            .and_then(|code| code.parse::<i32>().ok()).is_none_or(|code| !(1..=16).contains(&code)) {
            return Some("gRPC code must be from 1 to 16".into());
        }
    } else {
        if parameters.contains_key("code") {
            return Some("HTTP failures use status, not code".into());
        }
        if parameters.contains_key("status") && parameters.get("status").and_then(Value::as_u64)
            .is_none_or(|status| !(100..=599).contains(&status)) {
            return Some("HTTP status must be an integer from 100 to 599".into());
        }
        if parameters.contains_key("error") && !matches!(rule.text("error"), Some("timeout" | "refused")) {
            return Some("HTTP error must be timeout or refused".into());
        }
        if parameters.contains_key("status") && parameters.contains_key("error") {
            return Some("an HTTP failure names either status or error".into());
        }
    }
    None
}

inventory::submit! {
    Plugin {
        name: "client", kinds: &[("rpc_client", &["fail", "fail_after", "delay", "crash"])],
        rule_source: None, sink: None, context: None, check: Some(check_rule),
    }
}
