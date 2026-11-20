import functools
import weakref
from collections.abc import Callable
from types import ModuleType
from typing import Any, Final, Self

import wrapt
from pydantic import BaseModel, JsonValue

from faultpoint.adapters.sql import CursorStatement, Store, quiet_classification
from faultpoint.adapters.store import READ_ACTIONS, WRITE_ACTIONS, StoreKind
from faultpoint.rules import STRICT
from faultpoint.runtime import Plugin, Runtime

DEFAULT_DRIVERS: Final = ("sqlite3",)


class DbapiOptions(BaseModel):
    model_config = STRICT

    dialect: str | None = None
    """The sqlglot dialect statements are parsed in."""
    drivers: tuple[str, ...] = DEFAULT_DRIVERS
    """The DB-API modules whose connect function is patched."""


class Cursor(wrapt.ObjectProxy):
    """A DB-API cursor whose statements are store points; rows pass through as the application fetches them."""

    def __init__(self, cursor: Any, store: Store) -> None:
        super().__init__(cursor)
        # wrapt keeps attributes named _self_* on the proxy instead of the wrapped cursor.
        self._self_store = store
        self._self_statement = CursorStatement(store.runtime)
        weakref.finalize(self, self._self_statement.end)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        result = self._self_store.run(self._self_statement, sql,
                                      functools.partial(self.__wrapped__.execute, sql, *args, **kwargs), self)
        return self if result is self.__wrapped__ or self._self_statement.dropped else result

    def executemany(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        result = self._self_store.run(self._self_statement, sql,
                                      functools.partial(self.__wrapped__.executemany, sql, *args, **kwargs), self)
        return self if result is self.__wrapped__ or self._self_statement.dropped else result

    def fetchone(self) -> Any:
        row = None if self._self_statement.emptied else self.__wrapped__.fetchone()
        self._self_statement.fetched(0 if row is None else 1)
        return row

    def fetchmany(self, *args: Any, **kwargs: Any) -> list[Any]:
        rows = [] if self._self_statement.emptied else self.__wrapped__.fetchmany(*args, **kwargs)
        self._self_statement.fetched(len(rows))
        return rows

    def fetchall(self) -> list[Any]:
        rows = [] if self._self_statement.emptied else self.__wrapped__.fetchall()
        self._self_statement.fetched(len(rows))
        self._self_statement.end()
        return rows

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Any:
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def close(self) -> None:
        self._self_statement.end()
        self.__wrapped__.close()

    @property
    def rowcount(self) -> int:
        return 1 if self._self_statement.dropped else self.__wrapped__.rowcount

    @property
    def lastrowid(self) -> Any:
        return None if self._self_statement.dropped else self.__wrapped__.lastrowid


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
    quiet_classification()
    for driver in dbapi.drivers:
        wrapt.register_post_import_hook(functools.partial(patch_driver, runtime, dbapi.dialect), driver)


PLUGIN: Final = Plugin(actions={StoreKind.READ: READ_ACTIONS, StoreKind.WRITE: WRITE_ACTIONS}, install=install)
