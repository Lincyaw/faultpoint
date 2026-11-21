use std::any::type_name;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context as Poll, Poll as Ready};
use std::time::{Duration, Instant};

use http::{Request, Response, StatusCode};
use opentelemetry::context::FutureExt;
use opentelemetry::propagation::{TextMapCompositePropagator, TextMapPropagator};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{Detail, Plugin, core, millis_since, own};
use crate::rules::{Rule, point_id};

const DEFAULT_FAILURE_STATUS: u16 = 503;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct TowerOptions {
    identifier_segment: String,
}

impl Default for TowerOptions {
    fn default() -> Self {
        TowerOptions {
            identifier_segment: r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$".into(),
        }
    }
}

static IDENTIFIER_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    let options: TowerOptions = serde_json::from_value(core().settings.config.options("tower"))
        .expect("faultpoint: invalid tower options");
    Regex::new(&options.identifier_segment).expect("faultpoint: invalid identifier_segment")
});

static PROPAGATOR: LazyLock<TextMapCompositePropagator> = LazyLock::new(|| {
    TextMapCompositePropagator::new(vec![Box::new(TraceContextPropagator::new()), Box::new(BaggagePropagator::new())])
});

/// A request path with identifier segments replaced, so that one route is one point.
pub fn path_template(path: &str) -> String {
    path.split('/').map(|segment| if IDENTIFIER_SEGMENT.is_match(segment) { "{}" } else { segment })
        .collect::<Vec<_>>().join("/")
}

fn status_outcome(status: StatusCode) -> String {
    format!("{}xx", status.as_u16() / 100)
}

fn failure<B: Default>(rule_status: Option<&Value>) -> Response<B> {
    let status = rule_status.and_then(Value::as_u64).map_or(DEFAULT_FAILURE_STATUS, |status| status as u16);
    let mut response = Response::new(B::default());
    *response.status_mut() = StatusCode::from_u16(status).expect("a validated status");
    response
}

/// The rpc_server point of every request a tower service handles; it restores the caller's trace
/// context and baggage for the handler.
#[derive(Clone, Copy, Default)]
pub struct FaultpointLayer;

impl<S> tower::Layer<S> for FaultpointLayer {
    type Service = FaultpointService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FaultpointService { inner }
    }
}

#[derive(Clone)]
pub struct FaultpointService<S> {
    inner: S,
}

impl<S, RequestBody, ResponseBody> tower::Service<Request<RequestBody>> for FaultpointService<S>
where
    S: tower::Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Default + Send + 'static,
{
    type Response = Response<ResponseBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Poll<'_>) -> Ready<Result<(), S::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let core = core();
        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);
        if !core.enabled {
            return Box::pin(inner.call(request));
        }
        // The inner service is the application's, and its panics are its own; deciding and observing the exchange
        // around it is faultpoint's own work.
        let (parent, point, rule) = own(|| {
            let parent = PROPAGATOR.extract(&HeaderExtractor(request.headers()));
            let point = point_id(&core.settings.service, "rpc_server",
                                 &format!("{} {}", request.method(), path_template(request.uri().path())));
            let rule = {
                let _attached = parent.clone().attach();
                core.decide_among(&point, |action| action != "fail_after")
            };
            (parent, point, rule)
        });
        let context = parent.clone();
        Box::pin(async move {
            let mut exchange = Exchange { point, rule, started: Instant::now(), context, answered: None };
            let rule = exchange.rule.clone();
            let kind = rule.as_ref().map(|rule| rule.action.kind.as_str());
            // A fail rule with ms waits as a delay does, before it fails.
            if let Some(rule) = rule.as_ref().filter(|rule| kind == Some("delay")
                || (kind == Some("fail") && rule.action.parameters.contains_key("ms"))) {
                let delay = own(|| Duration::from_secs_f64(rule.number("ms").unwrap_or_else(|reason| core.abort(&reason)) / 1000.0));
                tokio::time::sleep(delay).await;
            }
            if let (Some(rule), Some("crash")) = (&rule, kind) {
                core.crash(rule.action.parameters.get("code").and_then(Value::as_i64).unwrap_or(1) as i32);
            }
            let response = match (&rule, kind) {
                (Some(rule), Some("fail")) => Ok(own(|| failure(rule.action.parameters.get("status")))),
                _ => inner.call(request).await,
            };
            own(|| {
                // Only a 2xx or 3xx answer is one a fail_after rule replaces and counts.
                let response = match response {
                    Ok(answer) if answer.status().is_success() || answer.status().is_redirection() => {
                        match core.decide_among(&exchange.point, |action| action == "fail_after") {
                            Some(replacing) => {
                                let replaced = failure(replacing.action.parameters.get("status"));
                                exchange.rule = Some(replacing);
                                Ok(replaced)
                            }
                            None => Ok(answer),
                        }
                    }
                    other => other,
                };
                exchange.answered = Some(match &response {
                    Ok(response) => (status_outcome(response.status()),
                                     Detail::from([("status", response.status().as_u16().to_string()), ("abandoned", "false".into())])),
                    Err(_) => ("error".to_owned(), Detail::from([("error", type_name::<S::Error>().to_owned()), ("abandoned", "false".into())])),
                });
                response
            })
        }.with_context(parent))
    }
}

/// A request's observation, made when its future ends. A future dropped before the service answered, as the server
/// drops it when the client goes away, was abandoned.
struct Exchange {
    point: String,
    rule: Option<Rule>,
    started: Instant,
    context: opentelemetry::Context,
    answered: Option<(String, Detail)>,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        own(|| {
            let (outcome, detail) = self.answered.take()
                .unwrap_or_else(|| ("error".to_owned(), Detail::from([("abandoned", "true".to_owned())])));
            let _attached = self.context.clone().attach();
            let elapsed = millis_since(self.started);
            core().observe(&self.point, &outcome, elapsed, elapsed, self.rule.as_ref(), detail);
        });
    }
}

inventory::submit! {
    Plugin {
        name: "tower",
        kinds: &[("rpc_server", &["fail", "fail_after", "delay", "crash"])],
        rule_source: None, sink: None, context: None, check: None,
    }
}
