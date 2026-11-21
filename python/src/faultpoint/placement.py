import ast
import copy
import functools
import hashlib
import importlib.metadata
import importlib.util
from collections import Counter
from importlib.machinery import PathFinder
from pathlib import Path
from typing import Final, Self

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field

from faultpoint.points import PointKind
from faultpoint.rules import STRICT, point_id

POINTS_MODULE: Final = "faultpoint.points"
MANIFEST_FILE: Final = "faultpoint-manifest.json"
EXCLUDED_DIRECTORIES: Final = frozenset({"site-packages", "dist-packages", ".venv", "__pycache__", ".git",
                                         "node_modules"})
DEFAULT_CLOCK: Final = ("time.time", "datetime.now", "datetime.utcnow")
CODE_WIDTH: Final = 120
MODULE_NAME: Final = r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$"
SDK_DISTRIBUTION: Final = "faultpoint"
ALWAYS_EXCLUDED: Final = ("faultpoint", "opentelemetry", "logging")
NO_EXTRA: Final = {"extra": ""}
PACKAGE_INIT: Final = "__init__"

type Function = ast.FunctionDef | ast.AsyncFunctionDef


class ScopeEntry(BaseModel):
    """An installed package whose pure-Python modules get points, of the given kinds only when kinds is given."""

    model_config = STRICT

    include: str = Field(pattern=MODULE_NAME)
    kinds: tuple[PointKind, ...] | None = None


class Placement(BaseModel):
    """The placement rules that run, the dotted names of the calls that read the clock, and the installed packages
    placed besides the service's own source."""

    model_config = STRICT

    branch: bool = True
    check: bool = True
    loop: bool = True
    call: bool = True
    clock: tuple[str, ...] = DEFAULT_CLOCK
    scope: tuple[ScopeEntry, ...] = ()
    exclude: tuple[str, ...] = ()
    """Modules that get no points with their submodules, besides faultpoint and the distributions it depends on,
    OpenTelemetry and logging."""

    def limited(self, kinds: tuple[PointKind, ...] | None) -> Self:
        """The placement rules of the given kinds only."""
        if kinds is None:
            return self
        return self.model_copy(update={
            "branch": self.branch and PointKind.BRANCH in kinds, "check": self.check and PointKind.CHECK in kinds,
            "loop": self.loop and PointKind.LOOP in kinds, "call": self.call and PointKind.CALL in kinds,
            "clock": self.clock if PointKind.CLOCK in kinds else ()})


class PointEntry(BaseModel):
    """One fault point placed in a source file."""

    model_config = STRICT

    id: str
    kind: str
    file: str
    line: int
    function: str
    code: str
    """The first line of the instrumented source."""
    actions: tuple[str, ...] | None = None
    """The actions this point implements when narrower than its kind's; None means all of its kind's."""


class Manifest(BaseModel):
    model_config = STRICT

    service: str
    language: str
    points: tuple[PointEntry, ...]
    errors: tuple[str, ...] = ()
    """The error names the service's build registers, which a fail rule may name."""


class Library(BaseModel):
    """An included package: the directory of its modules, the label of its point ids, and its placement rules."""

    model_config = ConfigDict(frozen=True)

    name: str
    directory: Path
    label: str
    placement: Placement

    def owns(self, module: str) -> bool:
        return module == self.name or module.startswith(f"{self.name}.")


def placeable(path: Path, root: Path) -> bool:
    """Whether a module is the service's own source under the root rather than an installed package."""
    return path.is_relative_to(root) and EXCLUDED_DIRECTORIES.isdisjoint(path.relative_to(root).parts)


@functools.cache
def sdk_packages() -> frozenset[str]:
    """The top-level packages of faultpoint and of every distribution it depends on, which get no points, so that
    no point runs inside the runtime that records points."""
    distributions = {SDK_DISTRIBUTION}
    pending = [SDK_DISTRIBUTION]
    while pending:
        for requirement in map(Requirement, importlib.metadata.distribution(pending.pop()).requires or ()):
            name = canonicalize_name(requirement.name)
            if (requirement.marker is None or requirement.marker.evaluate(NO_EXTRA)) and name not in distributions:
                distributions.add(name)
                pending.append(name)
    return frozenset(package for package, owners in importlib.metadata.packages_distributions().items()
                     if any(canonicalize_name(owner) in distributions for owner in owners))


def package_locations(name: str) -> list[str]:
    """The directories of an installed package, found without importing it or its parents."""
    parent = name.rpartition(".")[0]
    spec = PathFinder.find_spec(name, package_locations(parent) if parent else None)
    if spec is None or spec.submodule_search_locations is None:
        raise ModuleNotFoundError(f"the placement scope includes {name}, which is not an installed package")
    return list(spec.submodule_search_locations)


def module_parts(relative: Path) -> tuple[str, ...]:
    """The dotted name parts of the module a source file is, relative to a directory on the path or a package."""
    parts = relative.with_suffix("").parts
    return parts[:-1] if parts[-1] == PACKAGE_INIT else parts


class Scope:
    """Where points are placed: the service's own source under the root and the included installed packages,
    except excluded modules."""

    def __init__(self, root: Path, placement: Placement) -> None:
        self.root = root.resolve()
        self.placement = placement
        distributions = importlib.metadata.packages_distributions()
        self.libraries = tuple(Library(
            name=entry.include, directory=Path(package_locations(entry.include)[0]).resolve(),
            label=f"{entry.include}@{importlib.metadata.version(distributions[entry.include.partition('.')[0]][0])}",
            placement=placement.limited(entry.kinds)) for entry in placement.scope)
        self.excluded = (*ALWAYS_EXCLUDED, *sdk_packages(), *placement.exclude)

    def locate(self, module: str, origin: Path) -> tuple[str, Placement] | None:
        """The path a module's point ids carry and its placement rules; none for a module that gets no points."""
        if any(module == name or module.startswith(f"{name}.") for name in self.excluded):
            return None
        if placeable(origin, self.root):
            return origin.relative_to(self.root).as_posix(), self.placement
        library = next((library for library in self.libraries if library.owns(module)), None)
        return None if library is None else (f"{library.label}/{origin.relative_to(library.directory).as_posix()}",
                                             library.placement)


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


def dotted_name(expression: ast.expr) -> tuple[str, ...]:
    match expression:
        case ast.Name(id=name):
            return (name,)
        case ast.Attribute(value=owner, attr=name):
            return (*dotted_name(owner), name)
    return ()


def point_call(kind: PointKind, point: str, *arguments: ast.expr) -> ast.Call:
    target = ast.parse(f"{POINTS_MODULE}.{kind}", mode="eval").body
    return ast.Call(func=target, args=[ast.Constant(value=point), *arguments], keywords=[])


def handled_classes(handlers: list[ast.ExceptHandler]) -> tuple[ast.expr, ...]:
    """The exception classes a try statement's handlers name; a bare except names none."""
    return tuple(copy.deepcopy(klass) for handler in handlers
                 for klass in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])
                 if klass is not None)


def call_site(statement: ast.stmt, point: str, classes: tuple[ast.expr, ...]) -> ast.With:
    """A statement inside `with faultpoint.points.call(point, lambda: classes)`; the lambda defers the handlers'
    class expressions, which Python evaluates only when an exception reaches them."""
    candidates = ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                            body=ast.Tuple(elts=list(classes), ctx=ast.Load()))
    return ast.copy_location(ast.With(items=[ast.withitem(context_expr=point_call(PointKind.CALL, point, candidates))],
                                      body=[statement]), statement)


class PointPlacer(ast.NodeTransformer):
    """Places branch, check, loop, call and clock points in one module, as the placement rules allow; a call point
    is a statement with a call inside a try block whose handlers name exception classes."""

    def __init__(self, service: str, path: str, source: str, placement: Placement) -> None:
        self.service = service
        self.path = path
        self.source = source
        self.placement = placement
        self.clocks = [tuple(name.split(".")) for name in placement.clock]
        self.scopes: list[str] = []
        self.checks: list[str | None] = []
        self.handled: list[tuple[ast.expr, ...]] = []
        self.ordinals: Counter[str] = Counter()
        self.points: list[PointEntry] = []

    def place(self, kind: PointKind, node: ast.stmt | ast.expr, anchor: ast.AST | None) -> str:
        function = ".".join(self.scopes) or "<module>"
        identity = point_id(self.service, kind, f"{self.path}:{function}")
        if anchor is not None:
            digest = hashlib.sha256(ast.dump(anchor, annotate_fields=False).encode()).hexdigest()[:8]
            base = f"{identity}#{digest}"
            ordinal = self.ordinals[base]
            self.ordinals[base] += 1
            identity = base if ordinal == 0 else f"{base}.{ordinal}"
        code = (ast.get_source_segment(self.source, node) or "").splitlines()[0][:CODE_WIDTH]
        self.points.append(PointEntry(id=identity, kind=kind, file=self.path, line=node.lineno,
                                      function=function, code=code))
        return identity

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        self.scopes.append(node.name)
        self.handled.append(())
        self.generic_visit(node)
        self.handled.pop()
        self.scopes.pop()
        return node

    def visit_function[F: (ast.FunctionDef, ast.AsyncFunctionDef)](self, node: F) -> F:
        self.scopes.append(node.name)
        placed = self.placement.check and returns_bool(node)
        self.checks.append(self.place(PointKind.CHECK, node, None) if placed else None)
        self.handled.append(())
        self.generic_visit(node)
        self.handled.pop()
        self.checks.pop()
        self.scopes.pop()
        return node

    def visit_Try(self, node: ast.Try) -> ast.Try:
        self.handled.append(handled_classes(node.handlers))
        node.body = [self.visit(statement) for statement in node.body]
        self.handled.pop()
        node.handlers = [self.visit(handler) for handler in node.handlers]
        node.orelse = [self.visit(statement) for statement in node.orelse]
        node.finalbody = [self.visit(statement) for statement in node.finalbody]
        return node

    def call_point(self, node: ast.stmt) -> str | None:
        """The call point of a statement with a call whose exceptions the innermost try's handlers name."""
        classes = self.handled[-1] if self.handled else ()
        calls = self.placement.call and classes and any(isinstance(child, ast.Call) for child in ast.walk(node))
        return self.place(PointKind.CALL, node, node) if calls else None

    def visit_statement(self, node: ast.stmt) -> ast.stmt:
        point = self.call_point(node)
        self.generic_visit(node)
        return node if point is None else call_site(node, point, self.handled[-1])

    def visit_Expr(self, node: ast.Expr) -> ast.stmt:
        return self.visit_statement(node)

    def visit_Assign(self, node: ast.Assign) -> ast.stmt:
        return self.visit_statement(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.stmt:
        return self.visit_statement(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.stmt:
        return self.visit_statement(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self.visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self.visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        self.checks.append(None)
        self.generic_visit(node)
        self.checks.pop()
        return node

    def visit_Return(self, node: ast.Return) -> ast.stmt:
        point = self.call_point(node)
        self.generic_visit(node)
        check = self.checks[-1] if self.checks else None
        if check is not None and node.value is not None:
            node.value = point_call(PointKind.CHECK, check, node.value)
        return node if point is None else call_site(node, point, self.handled[-1])

    def visit_If(self, node: ast.If) -> ast.If:
        guards = self.placement.branch and any(
            isinstance(statement, ast.Raise) and statement.exc is not None for statement in node.body)
        point = self.place(PointKind.BRANCH, node, node.test) if guards else None
        self.generic_visit(node)
        if point is not None:
            node.test = point_call(PointKind.BRANCH, point, node.test)
        return node

    def visit_loop(self, node: ast.For | ast.AsyncFor | ast.While, anchor: ast.AST) -> ast.stmt:
        point = self.place(PointKind.LOOP, node, anchor) if self.placement.loop else None
        self.generic_visit(node)
        if point is not None:
            node.body.insert(0, ast.Expr(value=point_call(PointKind.LOOP, point)))
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
        name = dotted_name(node.func)
        reads_clock = any(name[-len(clock):] == clock for clock in self.clocks)
        point = self.place(PointKind.CLOCK, node, node) if reads_clock else None
        self.generic_visit(node)
        return node if point is None else point_call(PointKind.CLOCK, point, node)


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


def place_points(module: ast.Module, source: str, service: str, path: str,
                 placement: Placement) -> tuple[ast.Module, list[PointEntry]]:
    """A module's syntax tree, parsed from its source, with its points placed, and the points; `path` is what the
    scope locates it as."""
    placer = PointPlacer(service, path, source, placement)
    placer.visit(module)
    if placer.points:
        module.body.insert(import_position(module), ast.Import(names=[ast.alias(name=POINTS_MODULE)]))
    return ast.fix_missing_locations(module), placer.points


def source_files(base: Path) -> list[Path]:
    files: list[Path] = []
    for directory, directories, names in base.walk():
        # Pruning the listed directories in place keeps the walk out of excluded trees.
        directories[:] = sorted(name for name in directories if name not in EXCLUDED_DIRECTORIES)
        files.extend(directory / name for name in sorted(names) if name.endswith(".py"))
    return files


def scan_tree(root: Path, service: str, placement: Placement) -> Manifest:
    """The points the import hook places in the modules under a source root and in the included packages."""
    scope = Scope(root, placement)
    trees = [(scope.root, ()), *((library.directory, tuple(library.name.split("."))) for library in scope.libraries)]
    points: list[PointEntry] = []
    for base, package in trees:
        for path in source_files(base):
            located = scope.locate(".".join((*package, *module_parts(path.relative_to(base)))), path)
            if located is not None:
                source = importlib.util.decode_source(path.read_bytes())
                points.extend(place_points(ast.parse(source), source, service, *located)[1])
    return Manifest(service=service, language="python", points=tuple(points))
