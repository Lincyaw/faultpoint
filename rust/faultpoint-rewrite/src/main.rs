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
const IGNORED: [&str; 2] = ["target", ".git"];
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
    scopes: Vec<Scope>,
    owner: Option<String>,
    ordinals: HashMap<String, usize>,
    points: Vec<PointEntry>,
    serves: bool,
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
    fn place(&mut self, kind: &'static str, node: &impl ToTokens, hashed: bool) -> String {
        let function = self.scopes.last().map_or("<module>".to_owned(), |scope| scope.name.clone());
        let tokens = node.to_token_stream();
        let text = tokens.to_string();
        let mut locator = format!("{}:{function}", self.path);
        if hashed {
            let digest = Sha256::digest(text.as_bytes());
            let base = format!("{locator}#{}", digest[..4].iter().map(|byte| format!("{byte:02x}")).collect::<String>());
            let ordinal = self.ordinals.entry(base.clone()).or_default();
            locator = if *ordinal == 0 { base.clone() } else { format!("{base}.{ordinal}") };
            *ordinal += 1;
        }
        let id = point_id(self.service, kind, &locator);
        self.points.push(PointEntry {
            id: id.clone(), kind, file: self.path.clone(), line: tokens.span().start().line, function,
            code: text.lines().next().unwrap_or_default().chars().take(CODE_WIDTH).collect(),
        });
        id
    }

    fn enter(&mut self, name: String, signature: &syn::Signature, block: &Block) {
        let mut scope = Scope { name, check: None, error: None, closures: 0 };
        if self.placement.call {
            scope.error = injectable_error(&signature.output);
        }
        self.scopes.push(scope);
        if self.placement.check && returns_bool(&signature.output) && computes_bool(block) {
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

    fn visit_item_fn_mut(&mut self, node: &mut ItemFn) {
        self.enter(node.sig.ident.to_string(), &node.sig, &node.block);
        visit_mut::visit_item_fn_mut(self, node);
        self.leave(&mut node.block);
    }

    fn visit_impl_item_fn_mut(&mut self, node: &mut ImplItemFn) {
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
        let guards = self.placement.branch && !self.scopes.is_empty() && !matches!(node.cond.as_ref(), Expr::Let(_))
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
        if self.placement.loops && !self.scopes.is_empty() && !constant_range(&node.expr) {
            let (pattern, iterated) = (&node.pat, &node.expr);
            let anchor = quote!(#pattern in #iterated);
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_while_mut(&mut self, node: &mut syn::ExprWhile) {
        visit_mut::visit_expr_while_mut(self, node);
        if self.placement.loops && !self.scopes.is_empty() {
            let anchor = node.cond.clone();
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_loop_mut(&mut self, node: &mut syn::ExprLoop) {
        visit_mut::visit_expr_loop_mut(self, node);
        if self.placement.loops && !self.scopes.is_empty() {
            let anchor = node.body.clone();
            self.mark_loop(&anchor, &mut node.body);
        }
    }

    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if self.scopes.is_empty() {
            visit_mut::visit_expr_mut(self, node);
            return;
        }
        if self.clock_read(node) {
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
        if let Expr::Call(call) = node
            && let Expr::Path(path) = call.func.as_ref()
            && last_segments(&path.path, 2) == "axum::serve"
            && call.args.len() == 2
        {
            layered(call.args.iter_mut().nth(1).expect("two arguments"));
            self.serves = true;
        }
    }
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

fn require_sdk(target: &Path, sdk: &Path, serves: bool) {
    let manifest_path = target.join("Cargo.toml");
    let mut manifest: toml_edit::DocumentMut = std::fs::read_to_string(&manifest_path).expect("cannot read Cargo.toml")
        .parse().expect("Cargo.toml is not valid TOML");
    let mut dependency = toml_edit::InlineTable::new();
    dependency.insert("path", sdk.display().to_string().into());
    if serves {
        dependency.insert("features", toml_edit::Array::from_iter(["tower"]).into());
    }
    manifest["dependencies"]["faultpoint"] = toml_edit::value(dependency);
    std::fs::write(&manifest_path, manifest.to_string()).expect("cannot write Cargo.toml");
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
    let mut points = Vec::new();
    let mut serves = false;
    for file in files {
        let path = file.strip_prefix(&target).expect("under the target").display().to_string();
        let mut syntax = syn::parse_file(&std::fs::read_to_string(&file).expect("cannot read a source file"))
            .unwrap_or_else(|error| panic!("cannot parse {path}: {error}"));
        let mut placer = Placer { service: &service, path, placement: &config.placement, scopes: Vec::new(), owner: None,
                                  ordinals: HashMap::new(), points: Vec::new(), serves: false };
        placer.visit_file_mut(&mut syntax);
        serves |= placer.serves;
        if !placer.points.is_empty() || placer.serves {
            std::fs::write(&file, prettyplease::unparse(&syntax)).expect("cannot write a source file");
        }
        points.extend(placer.points);
    }
    require_sdk(&target, &sdk, serves);
    let manifest = serde_json::json!({"service": service, "language": "rust", "points": points});
    std::fs::write(target.join(MANIFEST_FILE), serde_json::to_string_pretty(&manifest).expect("serialises") + "\n")
        .expect("cannot write the manifest");
    println!("{} points placed in {}", points.len(), target.display());
}
