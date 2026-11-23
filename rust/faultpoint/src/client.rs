use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
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
pub const GRPC_METHOD: &str = "gRPC";

pub fn grpc_failure_code(rule: &Rule) -> i32 {
    rule.text("code").map_or(DEFAULT_GRPC_FAILURE_CODE, |code| code.parse()
        .unwrap_or_else(|_| core().abort(&format!("rule {}: gRPC code must be from 1 to 16", rule.id))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientOptions {
    pub identifier_segment: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            identifier_segment: r"^(\d+|([A-Za-z][A-Za-z0-9_]*-)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$".into(),
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
    own(|| {
        let path = path.split('/').map(|segment| {
            if IDENTIFIER_SEGMENT.is_match(segment) { "{}" } else { segment }
        }).collect::<Vec<_>>().join("/");
        format!("{method} {authority}{path}")
    })
}

/// The wire headers bridge independently versioned OpenTelemetry clients without a shared SDK type.
pub fn context(headers: &http::HeaderMap) -> opentelemetry::Context {
    own(|| PROPAGATOR.extract(&HeaderExtractor(headers)))
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

pub struct Deadlines<E> {
    pub request: Option<Deadline<E>>,
    pub transport: Option<Deadline<E>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ChannelMetadata {
    pub uri: Option<http::Uri>,
    pub timeout: Option<Duration>,
}

/// Readiness metadata is scoped to one poll operation, never shared across unrelated channels.
#[derive(Clone, Default)]
pub struct EndpointProbe(Arc<Mutex<Vec<ChannelMetadata>>>);

impl EndpointProbe {
    pub async fn capture<F: Future>(&self, readiness: F) -> F::Output {
        readiness.with_context(opentelemetry::Context::current().with_value(self.clone())).await
    }

    pub fn record(uri: Option<http::Uri>, timeout: Option<Duration>) {
        if let Some(probe) = opentelemetry::Context::current().get::<Self>() {
            own(|| {
                let mut found = probe.0.lock().expect("an endpoint probe is not poisoned");
                let channel = ChannelMetadata { uri, timeout };
                if !found.contains(&channel) { found.push(channel); }
            });
        }
    }

    pub fn channel(&self) -> Option<ChannelMetadata> {
        own(|| {
            let mut found = self.0.lock().expect("an endpoint probe is not poisoned");
            match found.len() {
                0 => None,
                1 => found.pop(),
                _ => Some(ChannelMetadata { uri: None, timeout: None }),
            }
        })
    }
}

pub struct TransportTarget<'a, E> {
    pub uri: &'a http::Uri,
    pub path: &'a str,
    pub deadline: Option<Deadline<E>>,
}

/// One caller-visible exchange; cancellation records only what the adapter actually knows.
pub struct Exchange {
    pub point: String,
    pub rule: Option<Rule>,
    pub started: Instant,
    pub context: opentelemetry::Context,
    pub completion: Option<Completion>,
}

impl Exchange {
    pub fn complete<T, E, H>(&mut self, result: Result<T, E>, failure: H,
                             classify: fn(&Result<T, E>) -> Completion) -> Result<T, E>
    where H: Fn(&Rule) -> Result<T, E> {
        own(|| {
            let mut completion = classify(&result);
            let result = if completion.successful {
                match core().decide_among(&self.point, |action| action == "fail_after") {
                    Some(rule) => {
                        let result = failure(&rule);
                        completion = classify(&result);
                        self.rule = Some(rule);
                        result
                    }
                    None => result,
                }
            } else { result };
            match self.rule.as_ref().map(|rule| rule.action.kind.as_str()) {
                Some("fail") => { completion.detail.insert("sent", "false".into()); }
                Some("fail_after") => { completion.detail.insert("sent", "true".into()); }
                _ => {}
            }
            self.completion = Some(completion);
            result
        })
    }
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

/// A unary request carries its exchange to the transport that knows the selected endpoint.
#[derive(Clone)]
pub struct TransportCall {
    exchange: Arc<Mutex<Option<Exchange>>>,
    origin: Option<String>,
}

impl TransportCall {
    pub fn execute<T, E, O, F, H>(&self, target: TransportTarget<'_, E>, operation: F, failure: H)
        -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>>
    where T: Send + 'static, E: Send + 'static, O: Future<Output = Result<T, E>> + Send + 'static,
          F: FnOnce() -> O, H: FnOnce(&Rule) -> Result<T, E> + Send + 'static {
        let rule = own(|| {
            let mut held = self.exchange.lock().expect("a transport exchange is not poisoned");
            let exchange = held.as_mut()?;
            exchange.point = point_id(&core().settings.service, "rpc_client", &locator(GRPC_METHOD,
                self.origin.as_deref().unwrap_or_else(|| target.uri.authority().map_or("", |authority| authority.as_str())), target.path));
            let _attached = exchange.context.clone().attach();
            exchange.rule = core().decide_among(&exchange.point, |action| action != "fail_after");
            exchange.rule.clone()
        });
        // The native transport owns uninjected deadlines, including its queueing boundary.
        let deadline = if rule.is_some() { target.deadline } else { None };
        let execution: Pin<Box<dyn Future<Output = Result<T, E>> + Send>> = match rule.as_ref().map(|rule| rule.action.kind.as_str()) {
            Some("fail") => Box::pin(async move {
                let rule = rule.expect("a fail has a rule");
                if rule.action.parameters.contains_key("ms") {
                    let delay = own(|| Duration::from_secs_f64(rule.number("ms")
                        .unwrap_or_else(|reason| core().abort(&reason)) / 1000.0));
                    tokio::time::sleep(delay).await;
                }
                own(|| failure(&rule))
            }),
            Some("delay") => {
                let delay = own(|| Duration::from_secs_f64(rule.expect("a delay has a rule").number("ms")
                    .unwrap_or_else(|reason| core().abort(&reason)) / 1000.0));
                let operation = operation();
                Box::pin(async move { tokio::join!(operation, tokio::time::sleep(delay)).0 })
            }
            Some("crash") => core().crash(rule.expect("a crash has a rule")
                .action.parameters.get("code").and_then(Value::as_i64).unwrap_or(1) as i32),
            Some(action) => core().abort(&format!("{action} is not implemented at a unary transport")),
            None => Box::pin(operation()),
        };
        match deadline {
            Some(deadline) => Box::pin(async move {
                match tokio::time::timeout(deadline.duration, execution).await {
                    Ok(result) => result,
                    Err(_) => Err(own(deadline.failure)),
                }
            }),
            None => execution,
        }
    }
}

/// The caller owns completion, even if a buffered transport retains the request after cancellation.
pub struct DeferredCall {
    pub transport: TransportCall,
}

impl DeferredCall {
    pub fn new(locator: String, context: opentelemetry::Context, origin: Option<String>) -> Self {
        Self { transport: TransportCall { exchange: Arc::new(Mutex::new(Some(Exchange {
            point: point_id(&core().settings.service, "rpc_client", &locator), rule: None,
            started: Instant::now(), context, completion: None,
        }))), origin } }
    }

    pub async fn call<T, E, F, H>(self, operation: F, failure: H, classify: fn(&Result<T, E>) -> Completion,
                                 deadline: Option<Deadline<E>>) -> Result<T, E>
    where F: Future<Output = Result<T, E>>, H: Fn(&Rule) -> Result<T, E> {
        let context = own(|| self.transport.exchange.lock().expect("a transport exchange is not poisoned")
            .as_ref().expect("a live unary call owns its exchange").context.clone());
        async move {
            let result = match deadline {
                Some(deadline) => match tokio::time::timeout(deadline.duration, operation).await {
                    Ok(result) => result,
                    Err(_) => Err(own(deadline.failure)),
                },
                None => operation.await,
            };
            own(|| self.transport.exchange.lock().expect("a transport exchange is not poisoned").as_mut()
                .expect("a live unary call owns its exchange").complete(result, failure, classify))
        }.with_context(context).await
    }
}

impl Drop for DeferredCall {
    fn drop(&mut self) {
        let exchange = own(|| self.transport.exchange.lock().expect("a transport exchange is not poisoned").take());
        drop(exchange);
    }
}

/// Execute an outgoing call with the native client's response and error constructors. The operation is lazy,
/// so a failure before execution sends nothing; a delayed call runs while its caller remains alive.
pub async fn call<T, E, F, H>(locator: String, context: opentelemetry::Context, operation: F,
                             failure: H, classify: fn(&Result<T, E>) -> Completion,
                             deadlines: Deadlines<E>) -> Result<T, E>
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
        let deadline = deadlines.request.into_iter().chain(deadlines.transport.filter(|_| rule.is_some()))
            .min_by_key(|deadline| deadline.duration);
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
        exchange.complete(result, failure, classify)
    }.with_context(parent).await
}

/// Reject protocol parameters before requests begin, including a numeric gRPC status outside its error range.
pub fn check_rule(rule: &Rule) -> Option<String> {
    let Some((_, locator)) = rule.point.split_once(":rpc_client:") else { return None };
    let grpc = locator.split_once(' ').filter(|(method, _)| *method == GRPC_METHOD);
    if grpc.is_some_and(|(_, target)| target.starts_with('/')) {
        return Some("a gRPC client injection requires an endpoint authority; custom transports must use with_origin".into());
    }
    if !matches!(rule.action.kind.as_str(), "fail" | "fail_after") {
        return None;
    }
    let parameters = &rule.action.parameters;
    if grpc.is_some() {
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
