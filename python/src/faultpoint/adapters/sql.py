import asyncio
import contextvars
import functools
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Any, Final

import sqlglot
from pydantic import BaseModel
from sqlglot import exp
from sqlglot.errors import ErrorLevel

from faultpoint.actions import BoundaryError, BoundaryFail, Crash, Delay, Drop, Duplicate, Empty, FailAfter, Failure
from faultpoint.adapters.store import StoreKind, StoreOutcome
from faultpoint.rules import point_id
from faultpoint.runtime import Decision, Runtime

SQLGLOT_LOGGER: Final = "sqlglot"
STATEMENT_CACHE_SIZE: Final = 4096
DIGEST_LENGTH: Final = 8
CLASSIFYING: Final = contextvars.ContextVar("faultpoint_classifying", default=False)


class ClassificationFilter(logging.Filter):
    """Drops what sqlglot logs while faultpoint classifies a statement, which the service never asked for."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not CLASSIFYING.get()


CLASSIFICATION_FILTER: Final = ClassificationFilter()


def quiet_classification() -> None:
    logging.getLogger(SQLGLOT_LOGGER).addFilter(CLASSIFICATION_FILTER)


@functools.lru_cache(maxsize=STATEMENT_CACHE_SIZE)
def statement_point(sql: str, dialect: str | None) -> tuple[StoreKind, str]:
    """The kind and locator of a statement or script: the tables it touches and the hash of its shape without
    literals; it reads only when every statement is a query."""
    token = CLASSIFYING.set(True)
    try:
        # The lenient level classifies a statement sqlglot only partly understands, which the database accepts.
        statements = [statement for statement in sqlglot.parse(sql, read=dialect, error_level=ErrorLevel.IGNORE)
                      if statement is not None]
        kind = StoreKind.READ if statements and all(isinstance(statement, exp.Query) for statement in statements) \
            else StoreKind.WRITE
        tables = sorted({table.name for statement in statements for table in statement.find_all(exp.Table)})
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

    def failure(self, failure: Failure) -> Exception:
        return self.driver.OperationalError(
            "connection refused" if failure.error is BoundaryError.REFUSED else "timed out")

    def decide(self, statement: CursorStatement, sql: str) -> tuple[StoreKind, str, Decision | None]:
        statement.end()
        kind, locator = statement_point(sql, self.dialect)
        point = point_id(self.runtime.settings.service, kind, locator)
        return kind, point, self.runtime.decide(point)

    def finish(self, statement: CursorStatement, kind: StoreKind, point: str, decision: Decision | None,
               cursor: Any) -> None:
        """Record what the statement did: a write at once, a read when its fetching ends."""
        statement.start(kind, point, decision)
        if kind is StoreKind.WRITE:
            rows = 1 if statement.dropped else max(cursor.rowcount, 0)
            self.runtime.observe(point, StoreOutcome.OK, rows, decision)

    def run(self, statement: CursorStatement, sql: str, execute: Callable[[], Any], cursor: Any) -> Any:
        """Execute a statement at its point; the driver's result, or none for a dropped statement."""
        kind, point, decision = self.decide(statement, sql)
        try:
            result = self.perform(execute, decision)
        except Exception:
            self.runtime.observe(point, StoreOutcome.ERROR, 0.0, decision)
            raise
        self.finish(statement, kind, point, decision, cursor)
        return result

    def perform(self, execute: Callable[[], Any], decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return execute()
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                raise self.failure(failure)
            case Decision(action=Drop()):
                return None
            case Decision(action=Duplicate()):
                execute()
                return execute()
            case Decision(action=FailAfter() as failure):
                execute()
                raise self.failure(failure)
        return execute()

    async def run_async(self, statement: CursorStatement, sql: str, execute: Callable[[], Awaitable[Any]],
                        cursor: Any) -> Any:
        kind, point, decision = self.decide(statement, sql)
        try:
            result = await self.perform_async(execute, decision)
        except Exception:
            self.runtime.observe(point, StoreOutcome.ERROR, 0.0, decision)
            raise
        self.finish(statement, kind, point, decision, cursor)
        return result

    async def perform_async(self, execute: Callable[[], Awaitable[Any]], decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                return await execute()
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                raise self.failure(failure)
            case Decision(action=Drop()):
                return None
            case Decision(action=Duplicate()):
                await execute()
                return await execute()
            case Decision(action=FailAfter() as failure):
                await execute()
                raise self.failure(failure)
        return await execute()
