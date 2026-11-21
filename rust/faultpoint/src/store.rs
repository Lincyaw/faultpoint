//! Store points for the sqlx and redis-rs calls the rewriter finds in a build copy. The rewritten call site
//! passes the operation's future and hooks that build the client's own values, so this crate depends on
//! neither client.

use std::any::type_name;
use std::collections::HashMap;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlparser::ast::{Statement, visit_relations};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::core::{Detail, Plugin, core};
use crate::rules::{Rule, point_id};

/// spec/redis-commands.json, the table every SDK reads.
const REDIS_COMMANDS: &str = include_str!("../../../spec/redis-commands.json");

static KEY_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    let table: Value = serde_json::from_str(REDIS_COMMANDS).expect("the shared Redis table is JSON");
    let options = core().settings.config.options("store");
    let pattern = options.get("key_identifier").or_else(|| table.get("key_identifier"))
        .and_then(Value::as_str).expect("a key identifier pattern").to_owned();
    Regex::new(&pattern).expect("faultpoint: invalid key_identifier")
});

static STATEMENTS: LazyLock<Mutex<HashMap<String, (&'static str, String)>>> = LazyLock::new(Mutex::default);

/// What a rewritten call site supplies: the client's error for an injected failure, the value an empty read
/// or a dropped write answers with, whether a read's value is empty, and the code a store gave an error, such as
/// a SQLSTATE or the prefix of a Redis error reply.
pub struct Hooks<T, E> {
    pub failure: fn() -> E,
    pub substitute: fn() -> Result<T, E>,
    pub is_empty: fn(&T) -> bool,
    pub code: fn(&E) -> Option<String>,
}

/// The kind and locator of a SQL statement: a query is read and anything else written, the tables it
/// touches and the hash of its normalised text. Text the parser rejects is written, since no query
/// form a database accepts is outside the PostgreSQL dialect's grammar.
pub fn sql_point(sql: &str) -> (&'static str, String) {
    let mut statements = STATEMENTS.lock().unwrap();
    if let Some(known) = statements.get(sql) {
        return known.clone();
    }
    let point = match Parser::parse_sql(&PostgreSqlDialect {}, sql) {
        Ok(parsed) => {
            let reads = !parsed.is_empty() && parsed.iter().all(|statement| matches!(statement, Statement::Query(_)));
            let mut tables = std::collections::BTreeSet::new();
            let _ = visit_relations(&parsed, |relation| {
                tables.insert(relation.to_string());
                ControlFlow::<()>::Continue(())
            });
            let shape = parsed.iter().map(ToString::to_string).collect::<Vec<_>>().join(";");
            let table = if tables.is_empty() { "-".to_owned() } else { tables.into_iter().collect::<Vec<_>>().join("+") };
            (if reads { "store_read" } else { "store_write" }, format!("{table}#{}", digest(&shape)))
        }
        Err(_) => ("store_write", format!("-#{}", digest(sql))),
    };
    statements.insert(sql.to_owned(), point.clone());
    point
}

fn digest(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The locator of a Redis command: its name and the shape of its key, with identifier runs replaced by {}.
pub fn redis_locator(name: &str, key: Option<&str>) -> String {
    match key {
        Some(key) => format!("{name} {}", KEY_IDENTIFIER.replace_all(key, "{}")),
        None => name.to_owned(),
    }
}

/// Text of a Redis key a call site passes, for the key shape of its point.
pub trait KeyText {
    fn key_text(&self) -> String;
}

macro_rules! key_text_by_display {
    ($($type:ty),*) => {$(impl KeyText for $type { fn key_text(&self) -> String { self.to_string() } })*};
}

key_text_by_display!(str, String, i32, i64, u32, u64, usize, isize);

impl KeyText for [u8] {
    fn key_text(&self) -> String {
        String::from_utf8_lossy(self).into_owned()
    }
}

impl KeyText for Vec<u8> {
    fn key_text(&self) -> String {
        String::from_utf8_lossy(self).into_owned()
    }
}

impl<T: KeyText + ?Sized> KeyText for &T {
    fn key_text(&self) -> String {
        (**self).key_text()
    }
}

fn number(rule: &Rule, name: &str) -> f64 {
    rule.number(name).unwrap_or_else(|reason| core().abort(&reason))
}

/// Run a store operation as the point of the given kind and locator.
pub async fn store<T, E, F>(kind: &'static str, locator: String, operation: F, hooks: Hooks<T, E>) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let core = core();
    if !core.enabled {
        return operation.await;
    }
    let point = point_id(&core.settings.service, kind, &locator);
    let rule = core.decide(&point);
    let started = Instant::now();
    let action = rule.as_ref().map_or("", |rule| rule.action.kind.as_str());
    let result = match (action, &rule) {
        ("delay", Some(rule)) => {
            tokio::time::sleep(Duration::from_secs_f64(number(rule, "ms") / 1000.0)).await;
            operation.await
        }
        ("crash", Some(rule)) => core.crash(rule.action.parameters.get("code").and_then(Value::as_i64).unwrap_or(1) as i32),
        ("fail", _) => Err((hooks.failure)()),
        ("empty" | "drop", _) => (hooks.substitute)(),
        ("fail_after", _) => operation.await.and_then(|_| Err((hooks.failure)())),
        ("", _) => operation.await,
        (other, Some(rule)) => core.abort(&format!("rule {}: {other} is not implemented at {point}", rule.id)),
        (_, None) => unreachable!("an action comes from a rule"),
    };
    // An injected empty reply is empty whatever the client's type tells; otherwise the call site's hook decides.
    let (outcome, detail) = match &result {
        Err(error) => {
            let mut detail = Detail::from([("error", type_name::<E>().to_owned())]);
            detail.extend((hooks.code)(error).map(|code| ("code", code)));
            ("error", detail)
        }
        Ok(_) if action == "empty" => ("empty", Detail::new()),
        Ok(value) if kind == "store_read" || kind == "consume" => {
            (if (hooks.is_empty)(value) { "empty" } else { "rows" }, Detail::new())
        }
        Ok(_) => ("ok", Detail::new()),
    };
    core.observe(&point, outcome, started.elapsed().as_secs_f64() * 1000.0, rule.as_ref(), detail);
    result
}

/// A sqlx call: the point of its SQL statement.
pub async fn sql<T, E, F>(sql: &str, operation: F, hooks: Hooks<T, E>) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let (kind, locator) = sql_point(sql);
    store(kind, locator, operation, hooks).await
}

pub(crate) fn redis_kind(name: &str) -> Option<&'static str> {
    static KINDS: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
        let table: Value = serde_json::from_str(REDIS_COMMANDS).expect("the shared Redis table is JSON");
        table["commands"].as_object().expect("a commands object").iter().map(|(name, command)| {
            let kind = match command["kind"].as_str() {
                Some("store_read") => "store_read",
                Some("store_write") => "store_write",
                Some("publish") => "publish",
                Some("consume") => "consume",
                other => panic!("faultpoint: unknown Redis command kind {other:?}"),
            };
            (name.clone(), kind)
        }).collect()
    });
    KINDS.get(name).copied()
}

/// A redis-rs command whose name the rewriter read from the call site.
pub async fn redis<T, E, F>(name: &'static str, key: Option<String>, operation: F, hooks: Hooks<T, E>) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match redis_kind(name) {
        Some(kind) => store(kind, redis_locator(name, key.as_deref()), operation, hooks).await,
        None => operation.await,
    }
}

inventory::submit! {
    Plugin {
        name: "store",
        kinds: &[
            ("store_read", &["fail", "empty", "delay", "crash"]),
            ("store_write", &["fail", "fail_after", "drop", "delay", "crash"]),
            ("publish", &["fail", "fail_after", "drop", "delay", "crash"]),
            ("consume", &["fail", "empty", "delay", "crash"]),
        ],
        rule_source: None, sink: None, context: None,
    }
}
