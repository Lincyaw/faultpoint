import functools
import hashlib
import time
import weakref
from collections.abc import Callable
from enum import StrEnum
from types import ModuleType
from typing import Any, Final, Self

import sqlglot
import wrapt
from pydantic import BaseModel, JsonValue
from sqlglot import exp

from faultpoint.actions import BoundaryError, BoundaryFail, Crash, Delay, Drop, Duplicate, Empty, FailAfter, Failure
from faultpoint.rules import STRICT, point_id
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions

DEFAULT_DRIVERS: Final = ("sqlite3",)
STATEMENT_CACHE_SIZE: Final = 4096
DIGEST_LENGTH: Final = 8


class StoreKind(StrEnum):
    READ = "store_read"
    WRITE = "store_write"


class StoreOutcome(StrEnum):
    ROWS = "rows"
    EMPTY = "empty"
    OK = "ok"
    ERROR = "error"


class DbapiOptions(BaseModel):
    model_config = STRICT

    dialect: str | None = None
    """The sqlglot dialect statements are parsed in."""
    drivers: tuple[str, ...] = DEFAULT_DRIVERS
    """The DB-API modules whose connect function is patched."""


@functools.lru_cache(maxsize=STATEMENT_CACHE_SIZE)
def statement_point(sql: str, dialect: str | None) -> tuple[StoreKind, str]:
    """The kind and locator of a statement: the tables it touches and the hash of its shape without literals."""
    statement = sqlglot.parse_one(sql, read=dialect)
    kind = StoreKind.READ if isinstance(statement, exp.Query) else StoreKind.WRITE
    tables = sorted({table.name for table in statement.find_all(exp.Table)})
    shape = statement.transform(
        lambda node: exp.Placeholder() if isinstance(node, exp.Literal) else node).sql(dialect=dialect)
    return kind, f"{'+'.join(tables) or '-'}#{hashlib.sha256(shape.encode()).hexdigest()[:DIGEST_LENGTH]}"


class Store:
    """The statements of one DB-API driver as store points; injected failures raise the driver's own errors."""

    def __init__(self, runtime: Runtime, driver: ModuleType, dialect: str | None) -> None:
        self.runtime = runtime
        self.driver = driver
        self.dialect = dialect

    def failure(self, failure: Failure) -> Exception:
        return self.driver.OperationalError(
            "connection refused" if failure.error is BoundaryError.REFUSED else "timed out")

    def perform(self, method: Callable[..., Any], sql: str, args: tuple[Any, ...], kwargs: dict[str, Any],
                decision: Decision | None) -> Any:
        """Run a statement as its decision says: the driver's result, or none for a dropped statement."""
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return method(sql, *args, **kwargs)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                raise self.failure(failure)
            case Decision(action=Drop()):
                return None
            case Decision(action=Duplicate()):
                method(sql, *args, **kwargs)
                return method(sql, *args, **kwargs)
            case Decision(action=FailAfter() as failure):
                method(sql, *args, **kwargs)
                raise self.failure(failure)
        return method(sql, *args, **kwargs)


class Read:
    """The read statement a cursor is fetching, whose rows are counted as fetched and observed once when it ends."""

    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.point: str | None = None
        self.decision: Decision | None = None
        self.rows = 0

    def begin(self, point: str, decision: Decision | None) -> None:
        self.end()
        self.point = point
        self.decision = decision
        self.rows = 0

    def count(self, rows: int) -> None:
        self.rows += rows

    def end(self) -> None:
        if self.point is not None:
            self.runtime.observe(self.point, StoreOutcome.ROWS if self.rows else StoreOutcome.EMPTY, self.rows,
                                 self.decision)
            self.point = None


class Cursor(wrapt.ObjectProxy):
    """A DB-API cursor whose statements are store points; rows pass through as the application fetches them."""

    def __init__(self, cursor: Any, store: Store) -> None:
        super().__init__(cursor)
        # wrapt keeps attributes named _self_* on the proxy instead of the wrapped cursor.
        self._self_store = store
        self._self_read = Read(store.runtime)
        self._self_action: BaseModel | None = None
        weakref.finalize(self, self._self_read.end)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        return self.run_statement(self.__wrapped__.execute, sql, args, kwargs)

    def executemany(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        return self.run_statement(self.__wrapped__.executemany, sql, args, kwargs)

    def run_statement(self, method: Callable[..., Any], sql: str, args: tuple[Any, ...],
                      kwargs: dict[str, Any]) -> Any:
        """Run a statement at its point; a write is observed at once, a read when its fetching ends."""
        store, read = self._self_store, self._self_read
        read.end()
        kind, locator = statement_point(sql, store.dialect)
        point = point_id(store.runtime.settings.service, kind, locator)
        decision = store.runtime.decide(point)
        try:
            result = store.perform(method, sql, args, kwargs, decision)
        except Exception:
            store.runtime.observe(point, StoreOutcome.ERROR, 0.0, decision)
            raise
        self._self_action = None if decision is None else decision.action
        if kind is StoreKind.READ:
            read.begin(point, decision)
        else:
            store.runtime.observe(point, StoreOutcome.OK, max(self.rowcount, 0), decision)
        return self if result is self.__wrapped__ or isinstance(self._self_action, Drop) else result

    def fetchone(self) -> Any:
        row = None if isinstance(self._self_action, Empty) else self.__wrapped__.fetchone()
        self._self_read.count(0 if row is None else 1)
        if row is None:
            self._self_read.end()
        return row

    def fetchmany(self, *args: Any, **kwargs: Any) -> list[Any]:
        rows = [] if isinstance(self._self_action, Empty) else self.__wrapped__.fetchmany(*args, **kwargs)
        self._self_read.count(len(rows))
        if not rows:
            self._self_read.end()
        return rows

    def fetchall(self) -> list[Any]:
        rows = [] if isinstance(self._self_action, Empty) else self.__wrapped__.fetchall()
        self._self_read.count(len(rows))
        self._self_read.end()
        return rows

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Any:
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def close(self) -> None:
        self._self_read.end()
        self.__wrapped__.close()

    @property
    def rowcount(self) -> int:
        return 1 if isinstance(self._self_action, Drop) else self.__wrapped__.rowcount

    @property
    def lastrowid(self) -> Any:
        return None if isinstance(self._self_action, Drop) else self.__wrapped__.lastrowid


class Connection(wrapt.ObjectProxy):
    """A DB-API connection whose cursors are store points."""

    def __init__(self, connection: Any, store: Store) -> None:
        super().__init__(connection)
        self._self_store = store

    def cursor(self, *args: Any, **kwargs: Any) -> Cursor:
        return Cursor(self.__wrapped__.cursor(*args, **kwargs), self._self_store)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        return self.cursor().execute(sql, *args, **kwargs)

    def executemany(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        return self.cursor().executemany(sql, *args, **kwargs)

    def __enter__(self) -> Self:
        self.__wrapped__.__enter__()
        return self


def connect_with_points(store: Store, connect: Callable[..., Any], module: Any, args: tuple[Any, ...],
                        kwargs: dict[str, Any]) -> Connection:
    return Connection(connect(*args, **kwargs), store)


def patch_driver(runtime: Runtime, dialect: str | None, driver: ModuleType) -> None:
    wrapt.wrap_function_wrapper(driver, "connect",
                                functools.partial(connect_with_points, Store(runtime, driver, dialect)))


def install(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    dbapi = DbapiOptions.model_validate(options)
    for driver in dbapi.drivers:
        wrapt.register_post_import_hook(functools.partial(patch_driver, runtime, dbapi.dialect), driver)


PLUGIN: Final = Plugin(actions={StoreKind.READ: implemented_actions(BoundaryFail, Empty, Delay, Crash),
                                StoreKind.WRITE: implemented_actions(BoundaryFail, FailAfter, Drop, Duplicate,
                                                                     Delay, Crash)},
                       install=install)
