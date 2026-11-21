use std::time::Duration;

use opentelemetry::Context;
use opentelemetry::baggage::BaggageExt;
use opentelemetry::trace::TraceContextExt;
use serde_json::Value;

use crate::config::Settings;
use crate::core::{ContextProvider, Plugin, RuleSource};
use crate::rules::FileRuleSource;

const RULES_POLL: Duration = Duration::from_millis(500);

/// The default context provider: OpenTelemetry baggage and trace context of the current context.
pub struct OtelContext;

impl ContextProvider for OtelContext {
    fn baggage(&self, key: &str) -> Option<String> {
        Context::current().baggage().get(key).map(|value| value.as_str().to_owned())
    }

    fn trace_id(&self) -> Option<String> {
        let context = Context::current();
        let span = context.span();
        let span_context = span.span_context();
        span_context.is_valid().then(|| span_context.trace_id().to_string())
    }
}

fn otel_context(_: &Settings, _: &Value) -> Box<dyn ContextProvider> {
    Box::new(OtelContext)
}

fn file_rules(settings: &Settings, _: &Value) -> Option<Box<dyn RuleSource>> {
    let path = settings.rules.clone()?;
    Some(Box::new(FileRuleSource { path, interval: RULES_POLL }))
}

inventory::submit! {
    Plugin { name: "otel", kinds: &[], rule_source: None, sink: None, context: Some(otel_context), check: None }
}

inventory::submit! {
    Plugin { name: "file", kinds: &[], rule_source: Some(file_rules), sink: None, context: None, check: None }
}
