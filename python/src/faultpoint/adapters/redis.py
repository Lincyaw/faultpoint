import asyncio
import contextlib
import copy
import functools
import importlib.resources
import re
import threading
import time
from collections.abc import Awaitable, Callable
from enum import StrEnum
from types import ModuleType
from typing import Annotated, Any, Final

import wrapt
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from faultpoint.actions import (INJECTED_MESSAGE, BoundaryError, Crash, Delay, Drop, Duplicate, Empty, StoreFail,
                                StoreFailAfter, StoreFailure, Wait)
from faultpoint.adapters.store import (MessageKind, StoreKind, StoreOutcome, consume_actions, read_actions,
                                       write_actions)
from faultpoint.observations import DetailKey, elapsed_ms, error_type
from faultpoint.rules import point_id
from faultpoint.runtime import Decision, Plugin, Runtime

REDIS_MODULE: Final = "redis"
REDIS_ASYNCIO_MODULE: Final = "redis.asyncio"
COMMANDS_FILE: Final = ("spec", "redis-commands.json")
"""spec/redis-commands.json inside the package: a link to the repository's file in a checkout, its content in a
wheel."""
KEY_POSITION: Final = r"^(after:\S+|numkeys:\d+)$"
AFTER: Final = "after"
STREAMS_KEY: Final = "after:STREAMS"
CONTAINERS: Final = (list, tuple, dict, set)
REPLY_CODE: Final = r"[A-Z][A-Z0-9_]*"
"""The code of an error reply, its first word in capitals."""
ERROR_CODE: Final = re.compile(rf"^{REPLY_CODE}(?= )")
ReplyCode = Annotated[str, StringConstraints(pattern=rf"^{REPLY_CODE}$")]

type Queued = tuple[tuple[Any, ...], dict[str, Any]]


class EmptyReply(StrEnum):
    """Which reply of a read or a consume counts as empty, as spec/redis-commands.json names it."""

    NIL = "nil"
    EMPTY_ARRAY = "empty_array"
    EMPTY_STRING = "empty_string"
    ZERO = "zero"
    ALL_NIL = "all_nil"
    NEVER = "never"


class Command(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: StoreKind | MessageKind
    key: int | Annotated[str, StringConstraints(pattern=KEY_POSITION)] | None
    """The key's index among the arguments after the command name, the argument after:TOKEN, the first key after
    the count at numkeys:N, or none."""
    empty: EmptyReply | None = None

    @property
    def reads_streams(self) -> bool:
        return self.key == STREAMS_KEY


class CommandTable(BaseModel):
    """spec/redis-commands.json."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    comment: str = Field(alias="$comment")
    key_identifier: re.Pattern[str]
    commands: dict[str, Command]


class RedisOptions(BaseModel):
    """A key_identifier that replaces the table's, and commands that extend or override its commands."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_identifier: re.Pattern[str] | None = None
    commands: dict[str, Command] = Field(default_factory=dict)


class Decided(BaseModel):
    """A command that is a point, with its table entry and the decision for this execution."""

    model_config = ConfigDict(frozen=True)

    command: Command
    point: str
    decision: Decision | None

    @property
    def action(self) -> BaseModel | None:
        return None if self.decision is None else self.decision.action


def argument_text(argument: Any) -> str:
    return argument.decode(errors="replace") if isinstance(argument, bytes) else str(argument)


def command_key(arguments: list[str], position: int | str | None) -> str | None:
    """The key of a command among the arguments after its name, as its table entry places it."""
    match position:
        case int():
            return arguments[position] if position < len(arguments) else None
        case str() if position.startswith(AFTER):
            token = position.partition(":")[2].upper()
            index = [argument.upper() for argument in arguments].index(token) + 1
            return arguments[index] if index < len(arguments) else None
        case str():
            count = int(position.partition(":")[2])
            return arguments[count + 1] if int(arguments[count]) > 0 else None
    return None


def is_empty(reply: Any, empty: EmptyReply | None) -> bool:
    """Whether a parsed reply is empty; the client parses a nil array into an empty list or map."""
    match empty:
        case EmptyReply.NIL:
            return reply is None or (isinstance(reply, CONTAINERS) and not reply)
        case EmptyReply.EMPTY_ARRAY:
            return isinstance(reply, CONTAINERS) and not reply
        case EmptyReply.EMPTY_STRING:
            return reply in ("", b"")
        case EmptyReply.ZERO:
            return reply == 0
        case EmptyReply.ALL_NIL:
            return isinstance(reply, CONTAINERS) and all(item is None for item in reply)
    return False


def empty_reply(client: Any, args: tuple[Any, ...], options: dict[str, Any], empty: EmptyReply | None) -> Any:
    """The empty reply a command gets without reaching Redis, parsed by the client's own callback for the command."""
    match empty:
        case EmptyReply.EMPTY_STRING:
            raw: Any = "" if client.get_encoder().decode_responses else b""
        case EmptyReply.ZERO:
            raw = 0
        case _:
            raw = None
    callback = client.response_callbacks.get(argument_text(args[0]))
    return raw if callback is None else callback(raw, **options)


def emptied(reply: Any, empty: EmptyReply | None) -> Any:
    """The empty reply of a read that reached Redis, of its reply's own container type or nils for all its items;
    a reply that is never empty stays."""
    match empty:
        case EmptyReply.ALL_NIL:
            return [None] * len(reply)
        case EmptyReply.EMPTY_ARRAY:
            return type(reply)()
    return reply


def stream_entries(reply: Any) -> list[list[Any]]:
    """The entry lists of an XREAD or XREADGROUP reply, in its RESP2 list or RESP3 map shape."""
    match reply:
        case dict():
            return [entries for lists in reply.values() for entries in lists]
    return [entries for _, entries in reply]


def delivered(command: Command, reply: Any) -> int:
    """The messages a consume delivered: the stream entries of a stream read, else one unless it is empty."""
    match command:
        case Command() if is_empty(reply, command.empty):
            return 0
        case Command(reads_streams=True):
            return sum(map(len, stream_entries(reply)))
    return 1


def delivered_twice(command: Command, reply: Any) -> Any:
    if not command.reads_streams:
        raise NotImplementedError("a duplicated consume delivers stream entries twice, and this command reads none")
    for entries in stream_entries(reply):
        entries.extend(list(entries))
    return reply


def detached(pipeline: Any, stack: list[Queued]) -> Any:
    """A copy of a pipeline holding its queued commands, which sends them on a connection of its own, without a
    WATCH the pipeline holds."""
    copied = copy.copy(pipeline)
    copied.command_stack = list(stack)
    copied.connection = None
    copied.watching = False
    return copied


def copies(decided: Decided | None) -> int:
    """How often a command is sent: never when dropped or emptied, twice when a write or publish is duplicated; a
    read emptied into an array, whose container type RESP3 decides, or into nils for each item it asks for, is sent
    and its reply replaced, which leaves Redis as it was."""
    match decided:
        case Decided(action=Drop()):
            return 0
        case Decided(action=Empty(), command=Command(empty=EmptyReply.NIL | EmptyReply.EMPTY_STRING | EmptyReply.ZERO)):
            return 0
        case Decided(action=Duplicate(), command=Command(kind=StoreKind.WRITE | MessageKind.PUBLISH)):
            return 2
    return 1


def delay_seconds(decisions: list[Decided | None]) -> float:
    """The seconds to wait before sending: the delays, and the waits of the fails that fail commands unsent."""
    waits = [decided.action.ms for decided in decisions
             if decided is not None and isinstance(decided.action, Delay | Wait) and decided.action.ms is not None]
    return sum(waits) / 1000


class CommandPoints:
    """The commands of every redis-py client and pipeline, sync or asyncio, that the command table lists, as
    points; a dropped command is acknowledged with True, and a duplicated consume delivers each entry twice."""

    def __init__(self, runtime: Runtime, key_identifier: re.Pattern[str], commands: dict[str, Command],
                 redis: ModuleType) -> None:
        self.runtime = runtime
        self.key_identifier = key_identifier
        self.commands = commands
        self.exceptions = redis.exceptions
        # Every parser of redis-py, sync or asyncio, RESP2, RESP3 or hiredis, turns an error reply into an error
        # with the parse_error they inherit.
        self.parser = redis.connection.DefaultParser
        self.unawaited: set[asyncio.Future[None]] = set()

    def resends(self, decisions: list[Decided | None]) -> bool:
        """Whether commands whose wait the client cut short are sent all the same: when delays alone made the
        wait, as the commands reach a slow server anyway; the wait of a fail sends nothing."""
        return not any(decided is not None and isinstance(decided.action, StoreFail) for decided in decisions)

    def wait(self, decisions: list[Decided | None], delay: float, waited: float, send: Callable[[], Any]) -> None:
        """Wait before sending; commands whose delay the client's socket timeout cut short are sent in the
        background, on a connection of their own, with their replies dropped."""
        if waited:
            time.sleep(waited)
        if waited < delay and self.resends(decisions):
            threading.Thread(target=self.drop_reply, args=(send,), name="faultpoint-unawaited", daemon=True).start()

    def drop_reply(self, send: Callable[[], Any]) -> None:
        """Send commands nobody waits for any longer and drop the reply, an error reply or a timeout included."""
        with contextlib.suppress(self.exceptions.RedisError):
            send()

    async def wait_async(self, decisions: list[Decided | None], delay: float, waited: float,
                         send: Callable[[], Awaitable[Any]]) -> None:
        """Wait before sending as wait does, also sending in the background when the caller cancels the wait."""
        try:
            if waited:
                await asyncio.sleep(waited)
        except asyncio.CancelledError:
            self.send_unawaited(decisions, send)
            raise
        if waited < delay:
            self.send_unawaited(decisions, send)

    def send_unawaited(self, decisions: list[Decided | None], send: Callable[[], Awaitable[Any]]) -> None:
        if self.resends(decisions):
            unawaited = asyncio.ensure_future(self.drop_reply_async(send))
            self.unawaited.add(unawaited)
            unawaited.add_done_callback(self.unawaited.discard)

    async def drop_reply_async(self, send: Callable[[], Awaitable[Any]]) -> None:
        with contextlib.suppress(self.exceptions.RedisError):
            await send()

    def decide(self, args: tuple[Any, ...]) -> Decided | None:
        """The point and decision of a command; none for a command that is not a point."""
        with self.runtime.own:
            words = argument_text(args[0]).split()
            name, arguments = words[0].upper(), [*words[1:], *(argument_text(argument) for argument in args[1:])]
            command = self.commands.get(name)
            if command is None:
                return None
            key = command_key(arguments, command.key)
            locator = name if key is None else f"{name} {self.key_identifier.sub('{}', key)}"
            point = point_id(self.runtime.settings.service, command.kind, locator)
            return Decided(command=command, point=point, decision=self.runtime.decide(point))

    def failure(self, decision: Decision) -> Exception:
        """The error a failure rule raises, which the caller raises outside the SDK's own work."""
        with self.runtime.own:
            match decision.action:
                case StoreFailure(code=str() as code):
                    return self.coded_error(decision, code)
                case StoreFailure(error=BoundaryError.REFUSED):
                    return self.exceptions.ConnectionError("Connection refused.")
            return self.exceptions.TimeoutError("Timeout reading from socket")

    def coded_error(self, decision: Decision, code: str) -> Exception:
        """The error redis-py raises for an error reply that starts with the code, from redis-py's own parsing of
        the reply."""
        try:
            error = self.parser.parse_error(f"{code} {INJECTED_MESSAGE}")
        except ValueError as reason:
            self.runtime.refuse(decision, f"redis-py builds the error of a {code} reply from the arguments Redis "
                                          f"sends with the code: {reason}")
        return error

    def error_detail(self, error: BaseException) -> dict[str, str]:
        """The error type, and the code of an error reply: the prefix redis-py parsed off, or else the leading
        word of a reply it kept whole."""
        with self.runtime.own:
            match error:
                case self.exceptions.RedisError(status_code=str() as code):
                    codes = [code]
                case self.exceptions.ResponseError():
                    codes = ERROR_CODE.findall(str(error))
                case _:
                    codes = []
            return {DetailKey.ERROR: error_type(error), **({DetailKey.CODE: codes[0]} if codes else {})}

    def prepare(self, decisions: list[Decided | None]) -> float:
        """Crash before anything is sent, and the seconds to wait before sending or failing."""
        for decided in decisions:
            match decided:
                case Decided(action=Crash(code=code)):
                    self.runtime.crash(code)
        return delay_seconds(decisions)

    def waited(self, client: Any, delay: float) -> float:
        """The seconds to wait before sending: the delay, no longer than the client's socket timeout, at which a
        client of a server that slow times out."""
        with self.runtime.own:
            timeout = client.connection_pool.connection_kwargs.get("socket_timeout")
            return delay if timeout is None else min(delay, timeout)

    def fail_unsent(self, decisions: list[Decided | None], started: float, delay: float, waited: float) -> None:
        """Fail before anything is sent, once the wait is over: as the client times out when its socket timeout
        cut the wait short, or as a rule fails one of the commands."""
        if waited < delay:
            timed_out = self.exceptions.TimeoutError("Timeout reading from socket")
            self.failed(decisions, timed_out, started)
            raise timed_out
        for decided in decisions:
            match decided:
                case Decided(decision=Decision(action=StoreFail()) as decision):
                    raised = self.failure(decision)
                    self.runtime.observe(decided.point, StoreOutcome.ERROR, 0.0, elapsed_ms(started), decision,
                                         self.error_detail(raised))
                    raise raised

    def failed(self, decisions: list[Decided | None], error: Exception, started: float) -> None:
        elapsed = elapsed_ms(started)
        for decided in decisions:
            if decided is not None:
                self.runtime.observe(decided.point, StoreOutcome.ERROR, 0.0, elapsed, decided.decision,
                                     self.error_detail(error))

    def settle(self, client: Any, queue: list[Queued], decisions: list[Decided | None], replies: list[Any],
               started: float) -> list[Any]:
        """Each command's reply out of the replies of what was sent, observed with the time since `started`, and a
        failure after the effect of a command that completed."""
        with self.runtime.own:
            elapsed = elapsed_ms(started)
            sent = iter(replies)
            settled = [self.reply(client, queued, decided, [next(sent) for _ in range(copies(decided))])
                       for queued, decided in zip(queue, decisions, strict=True)]
            completed = [self.completed(decided, reply) for decided, reply in zip(decisions, settled, strict=True)]
            for decided, reply in zip(completed, settled, strict=True):
                if decided is not None:
                    self.observe_reply(decided, reply, elapsed)
            failures = [decided.decision for decided in completed
                        if decided is not None and decided.decision is not None
                        and isinstance(decided.decision.action, StoreFailAfter)]
        if failures:
            raise self.failure(failures[0])
        return settled

    def completed(self, decided: Decided | None, reply: Any) -> Decided | None:
        """A command with the decision made before it was sent, or else, when its reply is no error, a fail_after
        rule's."""
        match decided, reply:
            case Decided(decision=None), _ if not isinstance(reply, Exception):
                return decided.model_copy(update={"decision": self.runtime.decide_completed(decided.point)})
        return decided

    def reply(self, client: Any, queued: Queued, decided: Decided | None, sent: list[Any]) -> Any:
        match decided, sent:
            case Decided(action=Drop()), []:
                reply = True
            case Decided(action=Empty()), []:
                reply = empty_reply(client, *queued, decided.command.empty)
            case Decided(action=Empty()), [*_, last]:
                reply = emptied(last, decided.command.empty)
            case Decided(action=Duplicate(), command=Command(kind=MessageKind.CONSUME)), [*_, last]:
                reply = delivered_twice(decided.command, last)
            case _:
                reply = sent[-1]
        return reply

    def observe_reply(self, decided: Decided, reply: Any, elapsed: float) -> None:
        """A read or a consume is empty or not; a consume's quantity is the messages it delivered."""
        command, point, decision = decided.command, decided.point, decided.decision
        match decision, reply:
            case Decision(action=StoreFailAfter()), _:
                self.runtime.observe(point, StoreOutcome.ERROR, 0.0, elapsed, decision,
                                     self.error_detail(self.failure(decision)))
            case _, Exception():
                self.runtime.observe(point, StoreOutcome.ERROR, 0.0, elapsed, decision, self.error_detail(reply))
            case _:
                self.observe_result(command, point, reply, decision, elapsed)

    def observe_result(self, command: Command, point: str, reply: Any, decision: Decision | None,
                       elapsed: float) -> None:
        match command.kind:
            case StoreKind.READ:
                self.runtime.observe(point, StoreOutcome.EMPTY if is_empty(reply, command.empty)
                                     else StoreOutcome.ROWS, 0.0, elapsed, decision)
            case MessageKind.CONSUME:
                messages = delivered(command, reply)
                self.runtime.observe(point, StoreOutcome.ROWS if messages else StoreOutcome.EMPTY, messages, elapsed,
                                     decision)
            case _:
                self.runtime.observe(point, StoreOutcome.OK, 0.0, elapsed, decision)

    def execute(self, execute_command: Callable[..., Any], client: Any, args: tuple[Any, ...],
                kwargs: dict[str, Any]) -> Any:
        started = time.monotonic()
        decisions = [self.decide(args)]
        delay = self.prepare(decisions)
        waited = self.waited(client, delay)
        self.wait(decisions, delay, waited, functools.partial(execute_command, *args, **kwargs))
        self.fail_unsent(decisions, started, delay, waited)
        try:
            replies = [execute_command(*args, **kwargs) for _ in range(copies(decisions[0]))]
        except Exception as error:
            self.failed(decisions, error, started)
            raise
        return self.settle(client, [(args, kwargs)], decisions, replies, started)[0]

    def execute_pipeline(self, execute: Any, pipeline: Any, args: tuple[Any, ...],
                         kwargs: dict[str, Any]) -> list[Any]:
        started = time.monotonic()
        stack: list[Queued] = list(pipeline.command_stack)
        decisions = [self.decide(queued_args) for queued_args, _ in stack]
        delay = self.prepare(decisions)
        waited = self.waited(pipeline, delay)
        self.wait(decisions, delay, waited, functools.partial(execute.__func__, detached(pipeline, stack)))
        try:
            self.fail_unsent(decisions, started, delay, waited)
        except self.exceptions.RedisError:
            # redis-py empties a pipeline whose execute failed, as this one did before sending.
            pipeline.reset()
            raise
        pipeline.command_stack[:] = [queued for queued, decided in zip(stack, decisions, strict=True)
                                     for _ in range(copies(decided))]
        try:
            replies = execute(*args, **kwargs)
        except Exception as error:
            self.failed(decisions, error, started)
            raise
        return self.settle(pipeline, stack, decisions, replies, started)

    async def execute_async(self, execute_command: Callable[..., Awaitable[Any]], client: Any,
                            args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        started = time.monotonic()
        decisions = [self.decide(args)]
        delay = self.prepare(decisions)
        waited = self.waited(client, delay)
        await self.wait_async(decisions, delay, waited, functools.partial(execute_command, *args, **kwargs))
        self.fail_unsent(decisions, started, delay, waited)
        try:
            replies = [await execute_command(*args, **kwargs) for _ in range(copies(decisions[0]))]
        except Exception as error:
            self.failed(decisions, error, started)
            raise
        return self.settle(client, [(args, kwargs)], decisions, replies, started)[0]

    async def execute_pipeline_async(self, execute: Any, pipeline: Any,
                                     args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[Any]:
        started = time.monotonic()
        stack: list[Queued] = list(pipeline.command_stack)
        decisions = [self.decide(queued_args) for queued_args, _ in stack]
        delay = self.prepare(decisions)
        waited = self.waited(pipeline, delay)
        try:
            await self.wait_async(decisions, delay, waited,
                                  functools.partial(execute.__func__, detached(pipeline, stack)))
            self.fail_unsent(decisions, started, delay, waited)
        except (self.exceptions.RedisError, asyncio.CancelledError):
            # redis-py empties a pipeline whose execute failed or was cancelled, as this one did before sending.
            await pipeline.reset()
            raise
        pipeline.command_stack[:] = [queued for queued, decided in zip(stack, decisions, strict=True)
                                     for _ in range(copies(decided))]
        try:
            replies = await execute(*args, **kwargs)
        except Exception as error:
            self.failed(decisions, error, started)
            raise
        return self.settle(pipeline, stack, decisions, replies, started)


def patch_asyncio(points: CommandPoints, module: ModuleType) -> None:
    wrapt.wrap_function_wrapper(module, "Redis.execute_command", points.execute_async)
    wrapt.wrap_function_wrapper(module, "client.Pipeline.execute", points.execute_pipeline_async)


def patch(runtime: Runtime, key_identifier: re.Pattern[str], commands: dict[str, Command], module: ModuleType) -> None:
    points = CommandPoints(runtime, key_identifier, commands, module)
    wrapt.wrap_function_wrapper(module, "Redis.execute_command", points.execute)
    wrapt.wrap_function_wrapper(module, "client.Pipeline.execute", points.execute_pipeline)
    wrapt.register_post_import_hook(functools.partial(patch_asyncio, points), REDIS_ASYNCIO_MODULE)


def configured_table(options: dict[str, JsonValue]) -> CommandTable:
    """The command table as the options extend it, its commands by upper-case name."""
    table = CommandTable.model_validate_json(
        importlib.resources.files("faultpoint").joinpath(*COMMANDS_FILE).read_bytes())
    extension = RedisOptions.model_validate(options)
    return table.model_copy(update={
        "key_identifier": table.key_identifier if extension.key_identifier is None else extension.key_identifier,
        "commands": {name.upper(): command for name, command in {**table.commands, **extension.commands}.items()}})


def command_points(options: dict[str, JsonValue]) -> Callable[[str], bool]:
    """Which points the plugin serves: those whose locator starts with a command of the table."""
    commands = configured_table(options).commands
    return lambda locator: locator.partition(" ")[0] in commands


def install(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    table = configured_table(options)
    wrapt.register_post_import_hook(functools.partial(patch, runtime, table.key_identifier, table.commands),
                                    REDIS_MODULE)


PLUGIN: Final = Plugin(actions={StoreKind.READ: read_actions(ReplyCode), StoreKind.WRITE: write_actions(ReplyCode),
                                MessageKind.PUBLISH: write_actions(ReplyCode),
                                MessageKind.CONSUME: consume_actions(ReplyCode)},
                       serves=command_points, install=install)
