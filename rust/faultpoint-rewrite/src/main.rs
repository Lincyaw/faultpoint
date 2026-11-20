//! Copies a Rust crate and places branch, call, check, loop and clock points in the copy, and wires
//! the tower layer at `axum::serve`; the copy depends on the faultpoint crate, the original never does.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use faultpoint::config::{Config, Placement};
use faultpoint::rules::point_id;
use quote::{ToTokens, quote};
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit_mut::{self, VisitMut};
use syn::{Block, Expr, ExprIf, ExprReturn, ImplItemFn, ItemFn, ItemImpl, ReturnType, Stmt, Type, parse_quote};

const MANIFEST_FILE: &str = "faultpoint-manifest.json";
const IGNORED: [&str; 3] = ["target", ".git", SCOPE_DIRECTORY];
/// Where the copies of the dependency crates the placement scope names go, inside the rewritten copy.
const SCOPE_DIRECTORY: &str = "faultpoint-scope";
/// Crates that never get points: the SDK, what it observes through, and logging.
const ALWAYS_EXCLUDED: [&str; 6] = ["faultpoint", "tracing", "tracing-core", "log", "opentelemetry", "opentelemetry_sdk"];
const CODE_WIDTH: usize = 120;

/// One point of the manifest, as spec/manifest.schema.json defines.
#[derive(Serialize)]
struct PointEntry {
    id: String,
    kind: &'static str,
    file: String,
    line: usize,
    function: String,
    code: String,
}

struct Scope {
    name: String,
    check: Option<String>,
    /// The error type a call point converts into, when the function returns one that accepts `Injected`.
    error: Option<Type>,
    closures: usize,
}

/// Places the points of one source file.
struct Placer<'a> {
    service: &'a str,
    path: String,
    placement: &'a Placement,
    /// "<crate>@<version>/" for a dependency crate, empty for the crate being rewritten, which alone gets boundaries.
    prefix: &'a str,
    /// The kinds a dependency crate's scope entry allows; None allows every kind.
    kinds: Option<&'a [String]>,
    scopes: Vec<Scope>,
    owner: Option<String>,
    ordinals: HashMap<String, usize>,
    points: Vec<PointEntry>,
    serves: bool,
    stores: bool,
}

fn last_segments(path: &syn::Path, count: usize) -> String {
    let names: Vec<String> = path.segments.iter().map(|segment| segment.ident.to_string()).collect();
    names[names.len().saturating_sub(count)..].join("::")
}

/// The error type of `anyhow::Result<T>` or `Result<T, E>` when E is `anyhow::Error` or a boxed error.
fn injectable_error(output: &ReturnType) -> Option<Type> {
    let ReturnType::Type(_, returned) = output else { return None };
    let Type::Path(path) = returned.as_ref() else { return None };
    let last = path.path.segments.last()?;
    if last.ident != "Result" {
        return None;
    }
    if last_segments(&path.path, 2) == "anyhow::Result" {
        return Some(parse_quote!(::anyhow::Error));
    }
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else { return None };
    let Some(syn::GenericArgument::Type(error)) = arguments.args.iter().nth(1) else { return None };
    let text = error.to_token_stream().to_string().replace(' ', "");
    (text == "anyhow::Error" || (text.starts_with("Box<dyn") && text.contains("Error"))).then(|| error.clone())
}

fn returns_bool(output: &ReturnType) -> bool {
    matches!(output, ReturnType::Type(_, returned) if returned.to_token_stream().to_string() == "bool")
}

fn literal_bool(expression: &Expr) -> bool {
    matches!(expression, Expr::Lit(literal) if matches!(literal.lit, syn::Lit::Bool(_)))
}

/// Whether a function computes some of its boolean results, judged from its returns and tail.
fn computes_bool(block: &Block) -> bool {
    struct Returns(Vec<Expr>);
    impl VisitMut for Returns {
        fn visit_expr_return_mut(&mut self, node: &mut ExprReturn) {
            self.0.extend(node.expr.as_deref().cloned());
        }
        fn visit_expr_closure_mut(&mut self, _: &mut syn::ExprClosure) {}
        fn visit_item_fn_mut(&mut self, _: &mut ItemFn) {}
    }
    let mut returns = Returns(Vec::new());
    returns.visit_block_mut(&mut block.clone());
    if let Some(Stmt::Expr(tail, None)) = block.stmts.last() {
        returns.0.push(tail.clone());
    }
    returns.0.iter().any(|expression| !literal_bool(expression))
}

/// Whether a block returns an error directly: `return Err(..)`, `Err(..)?` or `bail!`.
fn guards_error(block: &Block) -> bool {
    block.stmts.iter().any(|statement| {
        let expression = match statement {
            Stmt::Expr(expression, _) => expression,
            Stmt::Macro(item) => return item.mac.path.segments.last().is_some_and(|segment| segment.ident == "bail"),
            _ => return false,
        };
        match expression {
            Expr::Return(returned) => returned.expr.as_deref().is_some_and(|value| value.to_token_stream().to_string().starts_with("Err")),
            Expr::Try(attempt) => attempt.expr.to_token_stream().to_string().starts_with("Err"),
            Expr::Macro(item) => item.mac.path.segments.last().is_some_and(|segment| segment.ident == "bail"),
            _ => false,
        }
    })
}

fn constant_range(expression: &Expr) -> bool {
    matches!(expression, Expr::Range(range) if range.end.as_deref().is_some_and(|end| matches!(end, Expr::Lit(_))))
}

impl Placer<'_> {
    /// Whether a placement rule is switched on and the code's scope allows its kind.
    fn allows(&self, kind: &str) -> bool {
        let switched = match kind {
            "branch" => self.placement.branch,
            "check" => self.placement.check,
            "loop" => self.placement.loops,
            "call" => self.placement.call,
            _ => !self.placement.clock.is_empty(),
        };
        switched && self.kinds.is_none_or(|kinds| kinds.iter().any(|allowed| allowed == kind))
    }

    fn place(&mut self, kind: &'static str, node: &impl ToTokens, hashed: bool) -> String {
        let function = self.scopes.last().map_or("<module>".to_owned(), |scope| scope.name.clone());
        let tokens = node.to_token_stream();
        let text = tokens.to_string();
        let mut locator = format!("{}{}:{function}", self.prefix, self.path);
        if hashed {
            let digest = Sha256::digest(text.as_bytes());
            let base = format!("{locator}#{}", digest[..4].iter().map(|byte| format!("{byte:02x}")).collect::<String>());
            let ordinal = self.ordinals.entry(base.clone()).or_default();
            locator = if *ordinal == 0 { base.clone() } else { format!("{base}.{ordinal}") };
            *ordinal += 1;
        }
        let id = point_id(self.service, kind, &locator);
        self.points.push(PointEntry {
            id: id.clone(), kind, file: format!("{}{}", self.prefix, self.path), line: tokens.span().start().line, function,
            code: text.lines().next().unwrap_or_default().chars().take(CODE_WIDTH).collect(),
        });
        id
    }

    fn enter(&mut self, name: String, signature: &syn::Signature, block: &Block) {
        let mut scope = Scope { name, check: None, error: None, closures: 0 };
        if self.allows("call") {
            scope.error = injectable_error(&signature.output);
        }
        self.scopes.push(scope);
        if self.allows("check") && returns_bool(&signature.output) && computes_bool(block) {
            let check = self.place("check", &signature.ident, false);
            self.scopes.last_mut().expect("entered").check = Some(check);
        }
    }

    /// Wrap a function's tail expression in its check, after its body was visited.
    fn leave(&mut self, block: &mut Block) {
        let scope = self.scopes.pop().expect("entered");
        if let (Some(check), Some(Stmt::Expr(tail, None))) = (scope.check, block.stmts.last_mut()) {
            *tail = parse_quote!(::faultpoint::check(#check, #tail));
        }
    }

    fn nested(&mut self) -> &mut Scope {
        let outer = self.scopes.last_mut().map(|scope| {
            scope.closures += 1;
            format!("{}.closure{}", scope.name, scope.closures)
        });
        self.scopes.push(Scope { name: outer.unwrap_or_else(|| "<module>.closure".into()), check: None, error: None, closures: 0 });
        self.scopes.last_mut().expect("pushed")
    }

    fn mark_loop(&mut self, anchor: &impl ToTokens, body: &mut Block) {
        let id = self.place("loop", anchor, true);
        body.stmts.insert(0, parse_quote!(::faultpoint::loop_iteration(#id);));
    }

    fn clock_read(&self, expression: &Expr) -> bool {
        matches!(expression, Expr::Call(call) if matches!(call.func.as_ref(),
            Expr::Path(path) if call.args.is_empty() && self.placement.clock.contains(&last_segments(&path.path, 2))))
    }
}

/// The tower layer goes on the router `axum::serve` receives, before any `into_make_service*` call.
fn layered(service: &mut Expr) {
    if let Expr::MethodCall(call) = service
        && call.method.to_string().starts_with("into_make_service")
    {
        layered(&mut call.receiver);
        return;
    }
    let router = service.clone();
    *service = parse_quote!(#router.layer(::faultpoint::tower::FaultpointLayer));
}

impl VisitMut for Placer<'_> {
    fn visit_item_impl_mut(&mut self, node: &mut ItemImpl) {
        let owner = self.owner.replace(node.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit_mut::visit_item_impl_mut(self, node);
        self.owner = owner;
    }

    /// A const fn is left alone: it cannot call the SDK.
    fn visit_item_fn_mut(&mut self, node: &mut ItemFn) {
        if node.sig.constness.is_some() {
            return;
        }
        self.enter(node.sig.ident.to_string(), &node.sig, &node.block);
        visit_mut::visit_item_fn_mut(self, node);
        self.leave(&mut node.block);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut ImplItemFn) {
        if node.sig.constness.is_some() {
            return;
        }
        let name = format!("{}.{}", self.owner.clone().unwrap_or_default(), node.sig.ident);
        self.enter(name, &node.sig, &node.block);
        visit_mut::visit_impl_item_fn_mut(self, node);
        self.leave(&mut node.block);
    }

    fn visit_expr_closure_mut(&mut self, node: &mut syn::ExprClosure) {
        self.nested();
        visit_mut::visit_expr_closure_mut(self, node);
        self.scopes.pop();
    }

    fn visit_expr_async_mut(&mut self, node: &mut syn::ExprAsync) {
        self.nested();
        visit_mut::visit_expr_async_mut(self, node);
        self.scopes.pop();
    }

    fn visit_expr_return_mut(&mut self, node: &mut ExprReturn) {
        visit_mut::visit_expr_return_mut(self, node);
        if let (Some(check), Some(value)) = (self.scopes.last().and_then(|scope| scope.check.clone()), node.expr.as_mut()) {
            *value = parse_quote!(::faultpoint::check(#check, #value));
        }
    }

    fn visit_expr_if_mut(&mut self, node: &mut ExprIf) {
        let guards = self.allows("branch") && !self.scopes.is_empty() && !matches!(node.cond.as_ref(), Expr::Let(_))
            && guards_error(&node.then_branch);
        let id = guards.then(|| self.place("branch", &node.cond, true));
        visit_mut::visit_expr_if_mut(self, node);
        if let Some(id) = id {
            let condition = &node.cond;
            node.cond = parse_quote!(::faultpoint::branch(#id, #condition));
        }
    }

    fn visit_expr_for_loop_mut(&mut self, node: &mut syn::ExprForLoop) {
        visit_mut::visit_expr_for_loop_mut(self, node);
        if self.allows("loop") && !self.scopes.is_empty() && !constant_range(&node.expr) {
            let (pattern, iterated) = (&node.pat, &node.expr);
            let anchor = quote!(#pattern in #iterated);
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_while_mut(&mut self, node: &mut syn::ExprWhile) {
        visit_mut::visit_expr_while_mut(self, node);
        if self.allows("loop") && !self.scopes.is_empty() {
            let anchor = node.cond.clone();
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_loop_mut(&mut self, node: &mut syn::ExprLoop) {
        visit_mut::visit_expr_loop_mut(self, node);
        if self.allows("loop") && !self.scopes.is_empty() {
            let anchor = node.body.clone();
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if self.scopes.is_empty() {
            visit_mut::visit_expr_mut(self, node);
            return;
        }
        if self.allows("clock") && self.clock_read(node) {
            let id = self.place("clock", node, true);
            visit_mut::visit_expr_mut(self, node);
            *node = parse_quote!(::faultpoint::clock(#id, #node));
            return;
        }
        let error = self.scopes.last().and_then(|scope| scope.error.clone());
        if let (Expr::Try(attempt), Some(error)) = (&*node, error) {
            let id = self.place("call", &attempt.expr, true);
            let Expr::Try(attempt) = node else { unreachable!() };
            visit_mut::visit_expr_mut(self, &mut attempt.expr);
            let inner = &attempt.expr;
            *node = parse_quote!(::faultpoint::call(#id, (#inner).map_err(<#error as ::core::convert::From<_>>::from))?);
            return;
        }
        visit_mut::visit_expr_mut(self, node);
        if !self.prefix.is_empty() {
            return;
        }
        if let Expr::Call(call) = node
            && let Expr::Path(path) = call.func.as_ref()
            && last_segments(&path.path, 2) == "axum::serve"
            && call.args.len() == 2
        {
            layered(call.args.iter_mut().nth(1).expect("two arguments"));
            self.serves = true;
        }
        if let Some(store) = sqlx_store(node).or_else(|| redis_store(node)) {
            *node = store;
            self.stores = true;
        }
    }
}

/// The call that starts a method chain, with the chain's methods from the call outwards.
fn chain(expression: &Expr) -> Option<(&syn::ExprCall, Vec<&syn::ExprMethodCall>)> {
    let mut methods = Vec::new();
    let mut current = expression;
    loop {
        match current {
            Expr::MethodCall(method) => {
                methods.push(method);
                current = &method.receiver;
            }
            Expr::Call(call) => {
                methods.reverse();
                return Some((call, methods));
            }
            _ => return None,
        }
    }
}

fn path_of(call: &syn::ExprCall) -> Option<&syn::Path> {
    match call.func.as_ref() {
        Expr::Path(path) => Some(&path.path),
        _ => None,
    }
}

/// A SQL argument the copy can evaluate twice: a literal, a constant path, or a reference to one.
fn repeatable(sql: &Expr) -> bool {
    match sql {
        Expr::Lit(_) | Expr::Path(_) => true,
        Expr::Reference(reference) => repeatable(&reference.expr),
        _ => false,
    }
}

/// `sqlx::query*(SQL)...fetch_one|fetch_all|fetch_optional|execute(executor)` as a store point; the hooks
/// build sqlx's own values, so the SDK does not depend on sqlx.
fn sqlx_store(expression: &Expr) -> Option<Expr> {
    let Expr::MethodCall(execution) = expression else { return None };
    let (root, _) = chain(expression)?;
    let path = path_of(root)?;
    let starts = path.segments.first().is_some_and(|segment| segment.ident == "sqlx")
        && path.segments.last().is_some_and(|segment| ["query", "query_as", "query_scalar"].contains(&segment.ident.to_string().as_str()));
    let sql = root.args.first()?;
    if !starts || execution.args.len() != 1 || !repeatable(sql) {
        return None;
    }
    let (substitute, is_empty): (Expr, Expr) = match execution.method.to_string().as_str() {
        "fetch_one" => (parse_quote!(|| ::std::result::Result::Err(::sqlx::Error::RowNotFound)), parse_quote!(|_| false)),
        "fetch_all" => (parse_quote!(|| ::std::result::Result::Ok(::std::vec::Vec::new())), parse_quote!(|rows| rows.is_empty())),
        "fetch_optional" => (parse_quote!(|| ::std::result::Result::Ok(::std::option::Option::None)), parse_quote!(|row| row.is_none())),
        "execute" => (parse_quote!(|| ::std::result::Result::Ok(::core::default::Default::default())), parse_quote!(|_| false)),
        _ => return None,
    };
    Some(parse_quote!(::faultpoint::store::sql(#sql, #expression, ::faultpoint::store::Hooks {
        failure: || ::sqlx::Error::Protocol(::std::string::String::from("faultpoint: injected store failure")),
        substitute: #substitute,
        is_empty: #is_empty,
    })))
}

/// spec/redis-commands.json, which the SDK reads as well.
static REDIS_COMMANDS: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../spec/redis-commands.json")).expect("the shared Redis table is JSON")
});

fn string_literal(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(text), .. }) => Some(text.value()),
        Expr::Reference(reference) => string_literal(&reference.expr),
        _ => None,
    }
}

/// The key argument of a command by the shared table's rule, among the `.arg(..)` arguments of the chain.
fn key_argument<'a>(rule: &serde_json::Value, arguments: &[&'a Expr]) -> Option<&'a Expr> {
    if let Some(index) = rule.as_u64() {
        return arguments.get(index as usize).copied();
    }
    let rule = rule.as_str()?;
    if let Some(token) = rule.strip_prefix("after:") {
        let index = arguments.iter().position(|argument| string_literal(argument).is_some_and(|text| text.eq_ignore_ascii_case(token)))?;
        return arguments.get(index + 1).copied();
    }
    let at: usize = rule.strip_prefix("numkeys:")?.parse().ok()?;
    arguments.get(at + 1).copied()
}

/// The key text a point uses, taken before the chain moves the key; the SDK templates it at runtime.
fn key_text(key: &Expr) -> Expr {
    parse_quote!(::std::option::Option::Some(::faultpoint::store::KeyText::key_text(&#key)))
}

/// `redis::cmd("NAME")...query_async(connection)` as a Redis point; the hooks build redis-rs's own values.
fn redis_store(expression: &Expr) -> Option<Expr> {
    let Expr::MethodCall(execution) = expression else { return None };
    let (root, methods) = chain(expression)?;
    let path = path_of(root)?;
    if execution.method != "query_async" || last_segments(path, 2) != "redis::cmd" {
        return None;
    }
    let name = string_literal(root.args.first()?)?.to_uppercase();
    let command = REDIS_COMMANDS["commands"].get(&name)?;
    let arguments: Vec<&Expr> = methods.iter().filter(|method| method.method == "arg").filter_map(|method| method.args.first()).collect();
    let key: Expr = match key_argument(&command["key"], &arguments) {
        Some(key) => key_text(key),
        None => parse_quote!(::std::option::Option::None),
    };
    // An empty read answers nil; a dropped write is acknowledged with Redis's status reply.
    let substitute: Expr = if command.get("empty").is_some() {
        parse_quote!(|| ::redis::FromRedisValue::from_redis_value(&::redis::Value::Nil))
    } else {
        parse_quote!(|| ::redis::FromRedisValue::from_redis_value(&::redis::Value::Okay))
    };
    // Arguments run left to right, so the key's text is taken before the chain moves the key, and the chain's
    // temporaries live to the end of the statement as they did before.
    Some(parse_quote!(::faultpoint::store::redis(#name, #key, #expression, ::faultpoint::store::Hooks {
        failure: || ::redis::RedisError::from((::redis::ErrorKind::IoError, "faultpoint: injected Redis failure")),
        substitute: #substitute,
        is_empty: |_| false,
    })))
}

fn copy_tree(source: &Path, target: &Path, files: &mut Vec<PathBuf>) {
    std::fs::create_dir_all(target).expect("cannot create the target directory");
    for entry in std::fs::read_dir(source).expect("cannot read the source directory") {
        let entry = entry.expect("cannot read a directory entry");
        let name = entry.file_name();
        if IGNORED.iter().any(|ignored| name == *ignored) {
            continue;
        }
        let destination = target.join(&name);
        if entry.file_type().expect("cannot read a file type").is_dir() {
            copy_tree(&entry.path(), &destination, files);
            continue;
        }
        std::fs::copy(entry.path(), &destination).expect("cannot copy a file");
        if destination.extension().is_some_and(|extension| extension == "rs") {
            files.push(destination);
        }
    }
}

/// The copy depends on the SDK with the features of the boundaries the rewrite wired.
fn require_sdk(target: &Path, sdk: &Path, features: &[&str]) {
    let manifest_path = target.join("Cargo.toml");
    let mut manifest: toml_edit::DocumentMut = std::fs::read_to_string(&manifest_path).expect("cannot read Cargo.toml")
        .parse().expect("Cargo.toml is not valid TOML");
    let mut dependency = toml_edit::InlineTable::new();
    dependency.insert("path", sdk.display().to_string().into());
    if !features.is_empty() {
        dependency.insert("features", toml_edit::Array::from_iter(features.iter().copied()).into());
    }
    manifest["dependencies"]["faultpoint"] = toml_edit::value(dependency);
    std::fs::write(&manifest_path, manifest.to_string()).expect("cannot write Cargo.toml");
}

/// The points placed in the given files of a copy, which are rewritten in place, and whether they wired a server
/// boundary and a store boundary.
fn place_files(files: &[PathBuf], root: &Path, prefix: &str, kinds: Option<&[String]>, service: &str,
               placement: &Placement) -> (Vec<PointEntry>, bool, bool) {
    let (mut points, mut serves, mut stores) = (Vec::new(), false, false);
    for file in files {
        let path = file.strip_prefix(root).expect("under the root").display().to_string();
        let mut syntax = syn::parse_file(&std::fs::read_to_string(file).expect("cannot read a source file"))
            .unwrap_or_else(|error| panic!("cannot parse {path}: {error}"));
        let mut placer = Placer { service, path, placement, prefix, kinds, scopes: Vec::new(), owner: None,
                                  ordinals: HashMap::new(), points: Vec::new(), serves: false, stores: false };
        placer.visit_file_mut(&mut syntax);
        serves |= placer.serves;
        stores |= placer.stores;
        if !placer.points.is_empty() || placer.serves || placer.stores {
            std::fs::write(file, prettyplease::unparse(&syntax)).expect("cannot write a source file");
        }
        points.extend(placer.points);
    }
    (points, serves, stores)
}

/// Copies each dependency crate the placement scope names into the copy, places points in its library sources under
/// "<crate>@<version>/", and patches the copy's crates.io dependency onto that copy.
fn place_scope(target: &Path, sdk: &Path, service: &str, placement: &Placement) -> Vec<PointEntry> {
    let metadata = cargo_metadata::MetadataCommand::new().manifest_path(target.join("Cargo.toml")).exec()
        .expect("cargo metadata failed on the copy");
    let manifest_path = target.join("Cargo.toml");
    let mut manifest: toml_edit::DocumentMut = std::fs::read_to_string(&manifest_path).expect("cannot read Cargo.toml")
        .parse().expect("Cargo.toml is not valid TOML");
    let mut points = Vec::new();
    let excluded: Vec<&str> = ALWAYS_EXCLUDED.iter().copied().chain(placement.exclude.iter().map(String::as_str)).collect();
    for entry in placement.scope.iter().filter(|entry| !excluded.contains(&entry.include.as_str())) {
        let packages: Vec<_> = metadata.packages.iter().filter(|package| package.name == entry.include).collect();
        let [package] = packages[..] else {
            panic!("the scope names {}, which the dependency graph holds {} times", entry.include, packages.len());
        };
        let name = format!("{}-{}", package.name, package.version);
        let copy = target.join(SCOPE_DIRECTORY).join(&name);
        let mut files = Vec::new();
        copy_tree(package.manifest_path.parent().expect("a manifest is in a directory").as_std_path(), &copy, &mut files);
        let library = package.targets.iter().find(|each| each.is_kind(cargo_metadata::TargetKind::Lib))
            .unwrap_or_else(|| panic!("{name} has no library target"));
        let sources = copy.join(library.src_path.parent().expect("a source file is in a directory")
            .strip_prefix(package.manifest_path.parent().expect("a manifest is in a directory")).expect("sources are in the package"));
        files.retain(|file| file.starts_with(&sources));
        files.sort();
        let prefix = format!("{}@{}/", package.name, package.version);
        points.extend(place_files(&files, &copy, &prefix, entry.kinds.as_deref(), service, placement).0);
        require_sdk(&copy, sdk, &[]);
        let mut patch = toml_edit::InlineTable::new();
        patch.insert("path", format!("{SCOPE_DIRECTORY}/{name}").into());
        let patches = manifest["patch"].or_insert(toml_edit::table()).as_table_mut().expect("[patch] is a table");
        patches.set_implicit(true);
        patches["crates-io"].or_insert(toml_edit::table())[package.name.as_str()] = toml_edit::value(patch);
    }
    std::fs::write(&manifest_path, manifest.to_string()).expect("cannot write Cargo.toml");
    points
}

fn argument(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|index| arguments.get(index + 1)).cloned()
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let (Some(service), Some(source), Some(target), Some(sdk)) = (argument(&arguments, "--service"),
        argument(&arguments, "--source"), argument(&arguments, "--target"), argument(&arguments, "--sdk")) else {
        eprintln!("usage: faultpoint-rewrite --service NAME --source CRATE --target COPY --sdk FAULTPOINT_CRATE [--config FILE]");
        std::process::exit(2);
    };
    let config = Config::read(argument(&arguments, "--config").as_deref());
    std::fs::create_dir_all(&target).expect("cannot create the target directory");
    let source = std::fs::canonicalize(source).expect("cannot find the source crate");
    let target = std::fs::canonicalize(target).expect("cannot find the target directory");
    let sdk = std::fs::canonicalize(sdk).expect("cannot find the faultpoint crate");
    if target.starts_with(&source) {
        eprintln!("the copy must be outside the source crate");
        std::process::exit(2);
    }
    let mut files = Vec::new();
    copy_tree(&source, &target, &mut files);
    files.sort();
    let (mut points, serves, stores) = place_files(&files, &target, "", None, &service, &config.placement);
    let features: Vec<&str> = [(serves, "tower"), (stores, "store")].into_iter()
        .filter_map(|(wired, feature)| wired.then_some(feature)).collect();
    require_sdk(&target, &sdk, &features);
    points.extend(place_scope(&target, &sdk, &service, &config.placement));
    let manifest = serde_json::json!({"service": service, "language": "rust", "points": points});
    std::fs::write(target.join(MANIFEST_FILE), serde_json::to_string_pretty(&manifest).expect("serialises") + "\n")
        .expect("cannot write the manifest");
    println!("{} points placed in {}", points.len(), target.display());
}
