import asyncio
import functools
import re
import time
from collections.abc import Awaitable, Callable, MutableMapping
from enum import StrEnum
from types import ModuleType
from typing import Any, Final

import wrapt
from pydantic import BaseModel, JsonValue

from faultpoint.actions import BoundaryFail, Crash, Delay, Duplicate, FailAfter
from faultpoint.rules import STRICT, point_id
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions

HTTPX_MODULE: Final = "httpx"
UVICORN_MODULE: Final = "uvicorn"
DEFAULT_FAILURE_STATUS: Final = 503
IDENTIFIER_SEGMENT: Final = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$")

type Message = MutableMapping[str, Any]
type Scope = MutableMapping[str, Any]
type Receive = Callable[[], Awaitable[Message]]
type Send = Callable[[Message], Awaitable[None]]
type Application = Callable[[Scope, Receive, Send], Awaitable[None]]


class RpcKind(StrEnum):
    CLIENT = "rpc_client"
    SERVER = "rpc_server"


class RpcOutcome(StrEnum):
    """The outcomes of an exchange that produced no response; a response's outcome is its status class."""

    TIMEOUT = "timeout"
    REFUSED = "refused"
    ERROR = "error"


class HttpOptions(BaseModel):
    model_config = STRICT

    identifier_segment: re.Pattern[str] = IDENTIFIER_SEGMENT
    """A path segment this matches is replaced by {} in the path template of a point."""


def path_template(path: str, identifier: re.Pattern[str]) -> str:
    return "/".join("{}" if identifier.match(segment) else segment for segment in path.split("/"))


def status_outcome(status: int) -> str:
    return f"{status // 100}xx"


def elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000


async def discard(message: Message) -> None:
    """A send that drops the response of an application whose effects took place."""


async def send_failure(send: Send, status: int | None) -> None:
    await send({"type": "http.response.start", "status": status or DEFAULT_FAILURE_STATUS,
                "headers": [(b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})


class ServerPoint:
    """The rpc_server point of every request an ASGI application serves, under the caller's request context."""

    def __init__(self, app: Application, runtime: Runtime, options: HttpOptions) -> None:
        self.app = app
        self.runtime = runtime
        self.options = options

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in scope["headers"]}
            with self.runtime.context.attach(headers):
                await self.serve(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def serve(self, scope: Scope, receive: Receive, send: Send) -> None:
        point = point_id(self.runtime.settings.service, RpcKind.SERVER,
                         f"{scope['method']} {path_template(scope['path'], self.options.identifier_segment)}")
        decision = self.runtime.decide(point)
        statuses: list[int] = []

        async def capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                statuses.append(message["status"])
            await send(message)

        started = time.monotonic()
        try:
            await self.respond(scope, receive, capture, decision)
        except BaseException:
            self.runtime.observe(point, RpcOutcome.ERROR, elapsed_ms(started), decision)
            raise
        self.runtime.observe(point, status_outcome(statuses[0]) if statuses else RpcOutcome.ERROR,
                             elapsed_ms(started), decision)

    async def respond(self, scope: Scope, receive: Receive, send: Send, decision: Decision | None) -> None:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                await self.app(scope, receive, send)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail(status=status)):
                await send_failure(send, status)
            case Decision(action=FailAfter(status=status)):
                await self.app(scope, receive, discard)
                await send_failure(send, status)
            case None:
                await self.app(scope, receive, send)


def serve_points(runtime: Runtime, options: HttpOptions, load: Callable[[], None], config: Any,
                 args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Wrap the application a uvicorn Config loaded."""
    load(*args, **kwargs)
    config.loaded_app = ServerPoint(config.loaded_app, runtime, options)


def install_asgi(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    """Wrap the application uvicorn serves, the one place every ASGI framework's requests pass through."""
    wrapper = functools.partial(serve_points, runtime, HttpOptions.model_validate(options))
    wrapt.register_post_import_hook(
        lambda module: wrapt.wrap_function_wrapper(module, "Config.load", wrapper), UVICORN_MODULE)


def patch_httpx(runtime: Runtime, options: HttpOptions, module: ModuleType) -> None:
    # Imported once the application imports httpx, so that a process without httpx never needs it.
    import faultpoint.adapters.httpx

    faultpoint.adapters.httpx.patch(module, runtime, options)


def install_httpx(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    wrapt.register_post_import_hook(
        functools.partial(patch_httpx, runtime, HttpOptions.model_validate(options)), HTTPX_MODULE)


HTTPX: Final = Plugin(actions={RpcKind.CLIENT: implemented_actions(BoundaryFail, FailAfter, Duplicate, Delay, Crash)},
                      install=install_httpx)
ASGI: Final = Plugin(actions={RpcKind.SERVER: implemented_actions(BoundaryFail, FailAfter, Delay, Crash)},
                     install=install_asgi)
