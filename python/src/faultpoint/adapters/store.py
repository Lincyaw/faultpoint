from enum import StrEnum
from typing import Any

from faultpoint.actions import Crash, Delay, Drop, Duplicate, Empty, StoreFail, StoreFailAfter
from faultpoint.runtime import implemented_actions


class StoreKind(StrEnum):
    READ = "store_read"
    WRITE = "store_write"


class MessageKind(StrEnum):
    PUBLISH = "publish"
    CONSUME = "consume"


class StoreOutcome(StrEnum):
    """The outcomes of store and message points; a read or a consume that yields nothing is empty."""

    ROWS = "rows"
    EMPTY = "empty"
    OK = "ok"
    ERROR = "error"


def read_actions(code: Any) -> object:
    """The actions of store_read points, whose failures name codes of this type."""
    return implemented_actions(StoreFail[code], Empty, Delay, Crash)


def write_actions(code: Any) -> object:
    """The actions of store_write and publish points, whose failures name codes of this type."""
    return implemented_actions(StoreFail[code], StoreFailAfter[code], Drop, Duplicate, Delay, Crash)


def consume_actions(code: Any) -> object:
    """The actions of consume points, whose failures name codes of this type."""
    return implemented_actions(StoreFail[code], StoreFailAfter[code], Duplicate, Empty, Delay, Crash)
