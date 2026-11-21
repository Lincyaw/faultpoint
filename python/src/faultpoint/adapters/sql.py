import asyncio
import contextvars
import functools
import hashlib
import logging
import re
import time
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Annotated, Any, Final

import sqlglot
from pydantic import BaseModel, JsonValue, StringConstraints
from sqlglot import exp
from sqlglot.errors import ErrorLevel

from faultpoint.actions import (BoundaryError, Crash, Delay, Drop, Duplicate, Empty, StoreFail, StoreFailAfter,
                                StoreFailure)
from faultpoint.adapters.store import StoreKind, StoreOutcome, read_actions, write_actions
from faultpoint.observations import DetailKey, error_type
from faultpoint.rules import point_id
from faultpoint.runtime import Decision, Runtime

SQLGLOT_LOGGER: Final = "sqlglot"
STATEMENT_CACHE_SIZE: Final = 4096
DIGEST_LENGTH: Final = 8
STATEMENT_LOCATOR: Final = re.compile(rf"^[^ ]+#[0-9a-f]{{{DIGEST_LENGTH}}}$")
"""The shape of a statement point's locator, its tables and its hash, which no Redis command point has."""
CLASSIFYING: Final = contextvars.ContextVar("faultpoint_classifying", default=False)
WRITING_NODES: Final = (exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Into)
"""The nodes that make a query write: a data-modifying CTE, or SELECT INTO a new table."""
ERROR_CODE_ATTRIBUTES: Final = ("sqlstate", "sqlite_errorname")
SqlState = Annotated[str, StringConstraints(pattern=r"^[0-9A-Z]{5}$")]
STATEMENT_ACTIONS: Final[dict[str, object]] = {StoreKind.READ: read_actions(SqlState),
                                               StoreKind.WRITE: write_actions(SqlState)}
"""The actions of the statement points of every SQL plugin, whose failures name SQLSTATEs."""


def statement_points(options: dict[str, JsonValue]) -> Callable[[str], bool]:
    """Which points a SQL plugin serves, whatever its options: the statement points."""
    return lambda locator: STATEMENT_LOCATOR.fullmatch(locator) is not None


class ClassificationFilter(logging.Filter):
    """Drops what sqlglot logs while faultpoint classifies a statement, which the service never asked for."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not CLASSIFYING.get()


CLASSIFICATION_FILTER: Final = ClassificationFilter()


def quiet_classification() -> None:
    logging.getLogger(SQLGLOT_LOGGER).addFilter(CLASSIFICATION_FILTER)


def error_detail(error: Exception) -> dict[str, str]:
    """The error type, and the code the database returned with it: psycopg's SQLSTATE or sqlite3's error name,
    since DB-API names no common attribute."""
    codes = [code for name in ERROR_CODE_ATTRIBUTES if isinstance(code := getattr(error, name, None), str)]
    return {DetailKey.ERROR: error_type(error), **({DetailKey.CODE: codes[0]} if codes else {})}


@functools.lru_cache(maxsize=STATEMENT_CACHE_SIZE)
def statement_point(sql: str, dialect: str | None) -> tuple[StoreKind, str]:
    """The kind and locator of a statement or script: the tables it touches, not the names of its CTEs, and the
    hash of its shape without literals; it reads only when every statement is a query that writes nowhere in its
    tree."""
    token = CLASSIFYING.set(True)
    try:
        # The lenient level classifies a statement sqlglot only partly understands, which the database accepts.
        statements = [statement for statement in sqlglot.parse(sql, read=dialect, error_level=ErrorLevel.IGNORE)
                      if statement is not None]
        kind = StoreKind.READ if statements and all(
            isinstance(statement, exp.Query) and statement.find(*WRITING_NODES) is None
            for statement in statements) else StoreKind.WRITE
        tables = sorted({table.name for statement in statements for table in statement.find_all(exp.Table)
                         if table.name not in {cte.alias for cte in statement.find_all(exp.CTE)}})
        shape = ";".join(statement.transform(
            lambda node: exp.Placeholder() if isinstance(node, exp.Literal) else node).sql(dialect=dialect)
            for statement in statements)
    finally:
        CLASSIFYING.reset(token)
    return kind, f"{'+'.join(tables) or '-'}#{hashlib.sha256(shape.encode()).hexdigest()[:DIGEST_LENGTH]}"


class CursorStatement:
    """The statement a cursor ran last and the read it is fetching, whose rows are counted as fetched and
    observed once when the read ends."""

    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.action: BaseModel | None = None
        self.point: str | None = None
        self.decision: Decision | None = None
        self.rows = 0

    def start(self, kind: StoreKind, point: str, decision: Decision | None) -> None:
        self.end()
        self.action = None if decision is None else decision.action
        self.point = point if kind is StoreKind.READ else None
        self.decision = decision
        self.rows = 0

    @property
    def emptied(self) -> bool:
        return isinstance(self.action, Empty)

    @property
    def dropped(self) -> bool:
        return isinstance(self.action, Drop)

    def fetched(self, rows: int) -> None:
        """Count fetched rows; a fetch that yields none ends the read."""
        self.rows += rows
        if rows == 0:
            self.end()

    def end(self) -> None:
        if self.point is not None:
            self.runtime.observe(self.point, StoreOutcome.ROWS if self.rows else StoreOutcome.EMPTY, self.rows,
                                 self.decision)
            self.point = None


class Store:
    """The statements of one SQL driver as store points; injected failures raise the driver's own errors."""

    def __init__(self, runtime: Runtime, driver: ModuleType, dialect: str | None) -> None:
        self.runtime = runtime
        self.driver = driver
        self.dialect = dialect

    def failure(self, decision: Decision) -> Exception:
        """The error a failure rule raises, which the caller raises outside the SDK's own work."""
        with self.runtime.own:
            match decision.action:
                case StoreFailure(code=str() as code):
                    return self.coded_error(decision, code)
                case StoreFailure(error=BoundaryError.REFUSED):
                    return self.driver.OperationalError("connection refused")
            return self.driver.OperationalError("timed out")

    def coded_error(self, decision: Decision, code: str) -> Exception:
        """The driver's error with a code, which faultpoint cannot build for a DB-API driver, since DB-API defines
        no error code."""
        self.runtime.refuse(decision, f"the DB-API driver {self.driver.__name__} has no error faultpoint can build "
                                      f"with the code {code}")

    def decide(self, statement: CursorStatement, sql: str) -> tuple[StoreKind, str, Decision | None]:
        with self.runtime.own:
            statement.end()
            kind, locator = statement_point(sql, self.dialect)
            point = point_id(self.runtime.settings.service, kind, locator)
            return kind, point, self.runtime.decide(point)

    def finish(self, statement: CursorStatement, kind: StoreKind, point: str, decision: Decision | None,
               cursor: Any) -> None:
        """Record what the statement did: a write at once, a read when its fetching ends."""
        with self.runtime.own:
            statement.start(kind, point, decision)
            if kind is StoreKind.WRITE:
                rows = 1 if statement.dropped else max(cursor.rowcount, 0)
                self.runtime.observe(point, StoreOutcome.OK, rows, decision)

    def failed(self, point: str, decision: Decision | None, error: Exception) -> None:
        with self.runtime.own:
            self.runtime.observe(point, StoreOutcome.ERROR, 0.0, decision, error_detail(error))

    def completed(self, point: str, decision: Decision | None) -> Decision | None:
        """The decision of a statement that completed: the one made before it ran, or else a fail_after rule's,
        whose error is raised in place of the result."""
        if decision is None:
            decision = self.runtime.decide_completed(point)
        if decision is not None and isinstance(decision.action, StoreFailAfter):
            error = self.failure(decision)
            self.failed(point, decision, error)
            raise error
        return decision

    def run(self, statement: CursorStatement, sql: str, execute: Callable[[], Any], cursor: Any) -> Any:
        """Execute a statement at its point; the driver's result, or none for a dropped statement."""
        kind, point, decision = self.decide(statement, sql)
        try:
            result = self.perform(execute, decision)
        except Exception as error:
            self.failed(point, decision, error)
            raise
        self.finish(statement, kind, point, self.completed(point, decision), cursor)
        return result

    def perform(self, execute: Callable[[], Any], decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return execute()
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=StoreFail()):
                raise self.failure(decision)
            case Decision(action=Drop()):
                return None
            case Decision(action=Duplicate()):
                execute()
                return execute()
        return execute()

    async def run_async(self, statement: CursorStatement, sql: str, execute: Callable[[], Awaitable[Any]],
                        cursor: Any) -> Any:
        kind, point, decision = self.decide(statement, sql)
        try:
            result = await self.perform_async(execute, decision)
        except Exception as error:
            self.failed(point, decision, error)
            raise
        self.finish(statement, kind, point, self.completed(point, decision), cursor)
        return result

    async def perform_async(self, execute: Callable[[], Awaitable[Any]], decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                return await execute()
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=StoreFail()):
                raise self.failure(decision)
            case Decision(action=Drop()):
                return None
            case Decision(action=Duplicate()):
                await execute()
                return await execute()
        return await execute()
