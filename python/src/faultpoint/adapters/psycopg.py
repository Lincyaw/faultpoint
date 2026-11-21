import functools
import weakref
from types import ModuleType
from typing import Any, Final

import wrapt
from pydantic import BaseModel, JsonValue

from faultpoint.actions import INJECTED_MESSAGE
from faultpoint.adapters.sql import CursorStatement, Store, quiet_classification
from faultpoint.adapters.store import READ_ACTIONS, WRITE_ACTIONS, StoreKind
from faultpoint.rules import STRICT
from faultpoint.runtime import Decision, Plugin, Runtime

PSYCOPG_MODULE: Final = "psycopg"
DEFAULT_DIALECT: Final = "postgres"

type Arguments = tuple[Any, ...]
type Keywords = dict[str, Any]


class PsycopgOptions(BaseModel):
    model_config = STRICT

    dialect: str = DEFAULT_DIALECT
    """The sqlglot dialect statements are parsed in."""


def statement_text(args: Arguments, kwargs: Keywords, cursor: Any) -> str:
    """The text of the query a cursor method received; a psycopg.sql composition is rendered for its cursor."""
    query = args[0] if args else kwargs["query"]
    match query:
        case str():
            return query
        case bytes():
            return query.decode()
    return query.as_string(cursor)


class PsycopgStore(Store):
    """The statements of psycopg, whose errors carry the SQLSTATE PostgreSQL refused a statement with."""

    def coded_error(self, decision: Decision, code: str) -> Exception:
        """The error psycopg raises for a statement refused with a SQLSTATE: the class it looks up for the code,
        with the diagnostic of a server error."""
        errors, field = self.driver.errors, self.driver.pq.DiagnosticField
        try:
            error_class = errors.lookup(code)
        except KeyError:
            self.runtime.refuse(decision, f"psycopg has no error class for the SQLSTATE {code}")
        if error_class.sqlstate != code:
            self.runtime.refuse(decision, f"{code} is not a SQLSTATE: psycopg reports this error with the SQLSTATE "
                                          f"{error_class.sqlstate}")
        return error_class(INJECTED_MESSAGE, info={field.SEVERITY: b"ERROR", field.SQLSTATE: code.encode(),
                                                   field.MESSAGE_PRIMARY: INJECTED_MESSAGE.encode()})


class CursorPoints:
    """The statements of every psycopg cursor, sync or async and from any connection or pool, as store points."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.statements: weakref.WeakKeyDictionary[Any, CursorStatement] = weakref.WeakKeyDictionary()

    def statement(self, cursor: Any) -> CursorStatement:
        statement = self.statements.get(cursor)
        if statement is None:
            statement = self.statements[cursor] = CursorStatement(self.store.runtime)
            weakref.finalize(cursor, statement.end)
        return statement

    def execute(self, execute: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        self.store.run(self.statement(cursor), statement_text(args, kwargs, cursor),
                       functools.partial(execute, *args, **kwargs), cursor)
        return cursor

    def executemany(self, executemany: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        return self.store.run(self.statement(cursor), statement_text(args, kwargs, cursor),
                              functools.partial(executemany, *args, **kwargs), cursor)

    def fetchone(self, fetchone: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        statement = self.statement(cursor)
        row = None if statement.emptied else fetchone(*args, **kwargs)
        statement.fetched(0 if row is None else 1)
        return row

    def fetchmany(self, fetchmany: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> list[Any]:
        statement = self.statement(cursor)
        rows = [] if statement.emptied else fetchmany(*args, **kwargs)
        statement.fetched(len(rows))
        return rows

    def fetchall(self, fetchall: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> list[Any]:
        statement = self.statement(cursor)
        rows = [] if statement.emptied else fetchall(*args, **kwargs)
        statement.fetched(len(rows))
        statement.end()
        return rows

    def next_row(self, next_row: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        row = cursor.fetchone()
        if row is None:
            raise StopIteration
        return row

    async def execute_async(self, execute: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        await self.store.run_async(self.statement(cursor), statement_text(args, kwargs, cursor),
                                   functools.partial(execute, *args, **kwargs), cursor)
        return cursor

    async def executemany_async(self, executemany: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        return await self.store.run_async(self.statement(cursor), statement_text(args, kwargs, cursor),
                                          functools.partial(executemany, *args, **kwargs), cursor)

    async def fetchone_async(self, fetchone: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        statement = self.statement(cursor)
        row = None if statement.emptied else await fetchone(*args, **kwargs)
        statement.fetched(0 if row is None else 1)
        return row

    async def fetchmany_async(self, fetchmany: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> list[Any]:
        statement = self.statement(cursor)
        rows = [] if statement.emptied else await fetchmany(*args, **kwargs)
        statement.fetched(len(rows))
        return rows

    async def fetchall_async(self, fetchall: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> list[Any]:
        statement = self.statement(cursor)
        rows = [] if statement.emptied else await fetchall(*args, **kwargs)
        statement.fetched(len(rows))
        statement.end()
        return rows

    async def next_row_async(self, next_row: Any, cursor: Any, args: Arguments, kwargs: Keywords) -> Any:
        row = await cursor.fetchone()
        if row is None:
            raise StopAsyncIteration
        return row


def patch(runtime: Runtime, dialect: str, module: ModuleType) -> None:
    points = CursorPoints(PsycopgStore(runtime, module, dialect))
    for method, wrapper in (("execute", points.execute), ("executemany", points.executemany),
                            ("fetchone", points.fetchone), ("fetchmany", points.fetchmany),
                            ("fetchall", points.fetchall), ("__next__", points.next_row)):
        wrapt.wrap_function_wrapper(module, f"Cursor.{method}", wrapper)
    for method, wrapper in (("execute", points.execute_async), ("executemany", points.executemany_async),
                            ("fetchone", points.fetchone_async), ("fetchmany", points.fetchmany_async),
                            ("fetchall", points.fetchall_async), ("__anext__", points.next_row_async)):
        wrapt.wrap_function_wrapper(module, f"AsyncCursor.{method}", wrapper)


def install(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    psycopg = PsycopgOptions.model_validate(options)
    quiet_classification()
    wrapt.register_post_import_hook(functools.partial(patch, runtime, psycopg.dialect), PSYCOPG_MODULE)


PLUGIN: Final = Plugin(actions={StoreKind.READ: READ_ACTIONS, StoreKind.WRITE: WRITE_ACTIONS}, install=install)
