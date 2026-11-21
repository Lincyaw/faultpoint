from enum import StrEnum
from typing import Final

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


READ_ACTIONS: Final = implemented_actions(StoreFail, Empty, Delay, Crash)
WRITE_ACTIONS: Final = implemented_actions(StoreFail, StoreFailAfter, Drop, Duplicate, Delay, Crash)
"""The actions of store_write and publish points."""
CONSUME_ACTIONS: Final = implemented_actions(StoreFail, StoreFailAfter, Duplicate, Empty, Delay, Crash)
