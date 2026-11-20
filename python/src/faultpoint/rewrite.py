import ast
import hashlib
import shutil
from collections import Counter
from pathlib import Path
from typing import Final

from faultpoint.manifest import Manifest, PointEntry
from faultpoint.rules import PointKind, point_id

MANIFEST_FILE: Final = "faultpoint-manifest.json"
IGNORED: Final = (".git", ".venv", "__pycache__", "node_modules")
CLOCK_CALLS: Final = frozenset({("time", "time"), ("datetime", "now"), ("datetime", "utcnow")})
CODE_WIDTH: Final = 120

type Function = ast.FunctionDef | ast.AsyncFunctionDef


def own_returns(function: Function) -> list[ast.Return]:
    """The return statements of a function, not of the functions and classes it defines."""
    returns: list[ast.Return] = []
    pending: list[ast.AST] = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Return):
            returns.append(node)
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            pending.extend(ast.iter_child_nodes(node))
    return returns


def returns_bool(function: Function) -> bool:
    match function.returns:
        case ast.Name(id="bool") | ast.Constant(value="bool"):
            return any(node.value is not None and not isinstance(node.value, ast.Constant)
                       for node in own_returns(function))
    return False


def constant_range(loop: ast.For | ast.AsyncFor) -> bool:
    match loop.iter:
        case ast.Call(func=ast.Name(id="range"), args=arguments):
            return all(isinstance(argument, ast.Constant) for argument in arguments)
    return False


def clock_call(call: ast.Call) -> bool:
    match call.func:
        case ast.Attribute(value=ast.Name(id=owner), attr=name):
            return (owner, name) in CLOCK_CALLS
        case ast.Attribute(value=ast.Attribute(attr=owner), attr=name):
            return (owner, name) in CLOCK_CALLS
    return False


def point_call(function: str, point: str, *arguments: ast.expr) -> ast.Call:
    target = ast.Attribute(value=ast.Attribute(value=ast.Name(id="faultpoint", ctx=ast.Load()),
                                               attr="points", ctx=ast.Load()),
                           attr=function, ctx=ast.Load())
    return ast.Call(func=target, args=[ast.Constant(value=point), *arguments], keywords=[])


class PointPlacer(ast.NodeTransformer):
    """Places branch, check, loop and clock points in one module."""

    def __init__(self, service: str, path: str, source: str) -> None:
        self.service = service
        self.path = path
        self.source = source
        self.scopes: list[str] = []
        self.checks: list[str | None] = []
        self.ordinals: Counter[str] = Counter()
        self.points: list[PointEntry] = []

    def place(self, kind: PointKind, node: ast.stmt | ast.expr, anchor: ast.AST | None) -> str:
        function = ".".join(self.scopes) or "<module>"
        locator = f"{self.path}:{function}"
        if anchor is not None:
            digest = hashlib.sha256(ast.dump(anchor, annotate_fields=False).encode()).hexdigest()[:8]
            base = f"{locator}#{digest}"
            ordinal = self.ordinals[base]
            self.ordinals[base] += 1
            locator = base if ordinal == 0 else f"{base}.{ordinal}"
        identity = point_id(self.service, kind, locator)
        code = (ast.get_source_segment(self.source, node) or "").splitlines()[0][:CODE_WIDTH]
        self.points.append(PointEntry(id=identity, kind=kind, file=self.path, line=node.lineno,
                                      function=function, code=code))
        return identity

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        self.scopes.append(node.name)
        self.generic_visit(node)
        self.scopes.pop()
        return node

    def visit_function(self, node: Function) -> Function:
        self.scopes.append(node.name)
        self.checks.append(self.place(PointKind.CHECK, node, None) if returns_bool(node) else None)
        self.generic_visit(node)
        self.checks.pop()
        self.scopes.pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self.visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self.visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        self.checks.append(None)
        self.generic_visit(node)
        self.checks.pop()
        return node

    def visit_Return(self, node: ast.Return) -> ast.Return:
        self.generic_visit(node)
        check = self.checks[-1] if self.checks else None
        if check is not None and node.value is not None:
            node.value = point_call("check", check, node.value)
        return node

    def visit_If(self, node: ast.If) -> ast.If:
        guards = any(isinstance(statement, ast.Raise) and statement.exc is not None
                     for statement in node.body)
        point = self.place(PointKind.BRANCH, node, node.test) if guards else None
        self.generic_visit(node)
        if point is not None:
            node.test = point_call("branch", point, node.test)
        return node

    def visit_loop(self, node: ast.For | ast.AsyncFor | ast.While, anchor: ast.AST) -> ast.stmt:
        point = self.place(PointKind.LOOP, node, anchor)
        self.generic_visit(node)
        node.body.insert(0, ast.Expr(value=point_call("loop", point)))
        return node

    def visit_For(self, node: ast.For) -> ast.stmt:
        if constant_range(node):
            self.generic_visit(node)
            return node
        return self.visit_loop(node, ast.Tuple(elts=[node.target, node.iter], ctx=ast.Load()))

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.stmt:
        return self.visit_loop(node, ast.Tuple(elts=[node.target, node.iter], ctx=ast.Load()))

    def visit_While(self, node: ast.While) -> ast.stmt:
        return self.visit_loop(node, node.test)

    def visit_Call(self, node: ast.Call) -> ast.expr:
        point = self.place(PointKind.CLOCK, node, node) if clock_call(node) else None
        self.generic_visit(node)
        return node if point is None else point_call("clock", point, node)


def import_position(module: ast.Module) -> int:
    """After the docstring and the __future__ imports, where an inserted import is legal."""
    position = 0
    for index, statement in enumerate(module.body):
        match statement:
            case ast.Expr(value=ast.Constant(value=str())) if index == 0:
                position = 1
            case ast.ImportFrom(module="__future__"):
                position = index + 1
    return position


def rewrite_module(source: str, service: str, path: str) -> tuple[str | None, list[PointEntry]]:
    """A module's instrumented source and its points; no source when it holds no point."""
    module = ast.parse(source)
    placer = PointPlacer(service, path, source)
    placer.visit(module)
    if not placer.points:
        return None, []
    module.body.insert(import_position(module),
                       ast.Import(names=[ast.alias(name="faultpoint.points")]))
    return ast.unparse(ast.fix_missing_locations(module)) + "\n", placer.points


def rewrite_tree(source: Path, target: Path, service: str) -> Manifest:
    """Copy a source tree to a target and instrument every Python module of the copy."""
    shutil.copytree(source, target, ignore=shutil.ignore_patterns(*IGNORED))
    points: list[PointEntry] = []
    for module in sorted(target.rglob("*.py")):
        relative = module.relative_to(target).as_posix()
        rewritten, placed = rewrite_module(module.read_text(encoding="utf-8"), service, relative)
        if rewritten is not None:
            module.write_text(rewritten, encoding="utf-8")
        points.extend(placed)
    manifest = Manifest(service=service, language="python", points=tuple(points))
    (target / MANIFEST_FILE).write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return manifest
