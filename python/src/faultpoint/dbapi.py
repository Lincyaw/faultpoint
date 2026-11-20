import functools
import hashlib
from collections.abc import Iterator, Sequence
from types import ModuleType, TracebackType
from typing import Any, Self

import sqlglot
from sqlglot import exp

from faultpoint.rules import Drop, Duplicate, Empty, Fail, FailAfter, PointKind, point_id
from faultpoint.runtime import RUNTIME


@functools.lru_cache(maxsize=4096)
def statement_point(sql: str, dialect: str | None) -> tuple[PointKind, str]:
    """The kind and locator of a statement: the tables it touches and the hash of its shape with
    literals removed."""
    statement = sqlglot.parse_one(sql, read=dialect)
    kind = PointKind.STORE_READ if isinstance(statement, exp.Query) else PointKind.STORE_WRITE
    tables = sorted({table.name for table in statement.find_all(exp.Table)})
    shape = statement.transform(
        lambda node: exp.Placeholder() if isinstance(node, exp.Literal) else node).sql(dialect=dialect)
    return kind, f"{'+'.join(tables) or '-'}#{hashlib.sha256(shape.encode()).hexdigest()[:8]}"


class Cursor:
    """A DB-API cursor whose statements are store_read and store_write points; result rows are
    buffered so that a read's outcome is known when it executes."""

    def __init__(self, cursor: Any, module: ModuleType, dialect: str | None) -> None:
        self.cursor = cursor
        self.module = module
        self.dialect = dialect
        self.rows: list[Any] = []
        self.dropped = False

    def execute(self, sql: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> Self:
        kind, locator = statement_point(sql, self.dialect)
        point = point_id(RUNTIME.settings.service, kind, locator)
        rule = RUNTIME.decide(point) if RUNTIME.enabled else None
        action = None if rule is None else rule.action
        if action is not None:
            RUNTIME.hold(action)
        self.rows, self.dropped = [], isinstance(action, Drop)
        if isinstance(action, Fail):
            RUNTIME.record(point, "error", 0.0, rule)
            raise self.module.OperationalError("faultpoint: injected store failure")
        if self.dropped:
            RUNTIME.record(point, "ok", 1.0, rule)
            return self
        try:
            self.cursor.execute(sql, parameters)
            if isinstance(action, Duplicate):
                self.cursor.execute(sql, parameters)
            self.rows = [] if self.cursor.description is None else self.cursor.fetchall()
        except Exception:
            RUNTIME.record(point, "error", 0.0, rule)
            raise
        if isinstance(action, FailAfter):
            RUNTIME.record(point, "error", 0.0, rule)
            raise self.module.OperationalError("faultpoint: store failed after the statement ran")
        if isinstance(action, Empty):
            self.rows = []
        if kind is PointKind.STORE_READ:
            RUNTIME.record(point, "rows" if self.rows else "empty", len(self.rows), rule)
        else:
            RUNTIME.record(point, "ok", max(self.cursor.rowcount, 0), rule)
        return self

    def fetchone(self) -> Any:
        return self.rows.pop(0) if self.rows else None

    def fetchmany(self, size: int = 1) -> list[Any]:
        taken, self.rows = self.rows[:size], self.rows[size:]
        return taken

    def fetchall(self) -> list[Any]:
        taken, self.rows = self.rows, []
        return taken

    def __iter__(self) -> Iterator[Any]:
        while self.rows:
            yield self.rows.pop(0)

    @property
    def rowcount(self) -> int:
        return 1 if self.dropped else self.cursor.rowcount

    @property
    def lastrowid(self) -> Any:
        return None if self.dropped else self.cursor.lastrowid

    @property
    def description(self) -> Any:
        return self.cursor.description

    def close(self) -> None:
        self.cursor.close()


class Connection:
    """A DB-API connection whose cursors are instrumented; `module` supplies the driver's own
    exception types for injected failures."""

    def __init__(self, connection: Any, module: ModuleType, dialect: str | None = None) -> None:
        self.connection = connection
        self.module = module
        self.dialect = dialect

    def cursor(self) -> Cursor:
        return Cursor(self.connection.cursor(), self.module, self.dialect)

    def execute(self, sql: str, parameters: Sequence[Any] | dict[str, Any] = ()) -> Cursor:
        return self.cursor().execute(sql, parameters)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Self:
        self.connection.__enter__()
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None,
                 trace: TracebackType | None) -> None:
        self.connection.__exit__(kind, error, trace)
