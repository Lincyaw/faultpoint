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

from faultpoint.actions import BoundaryError, BoundaryFail, Crash, Delay, Duplicate, FailAfter, Failure
from faultpoint.rules import STRICT, point_id
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions

HTTPX_MODULE: Final = "httpx"
HTTPX2_MODULE: Final = "httpx2"
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


class ClientPoint:
    """The rpc_client point of every request the transports of an httpx-compatible library send, which also
    carries the request context; the library module supplies its own response and exception types."""

    def __init__(self, runtime: Runtime, options: HttpOptions, library: ModuleType) -> None:
        self.runtime = runtime
        self.options = options
        self.library = library

    def decide(self, request: Any) -> tuple[str, Decision | None]:
        self.runtime.context.inject(request.headers)
        url = request.url
        peer = url.host if url.port is None else f"{url.host}:{url.port}"
        point = point_id(self.runtime.settings.service, RpcKind.CLIENT,
                         f"{request.method} {peer}{path_template(url.path, self.options.identifier_segment)}")
        return point, self.runtime.decide(point)

    def error_outcome(self, error: Exception) -> RpcOutcome:
        match error:
            case self.library.TimeoutException():
                return RpcOutcome.TIMEOUT
            case self.library.ConnectError():
                return RpcOutcome.REFUSED
        return RpcOutcome.ERROR

    def failed(self, failure: Failure, request: Any) -> Any:
        """The synthetic response of a failure with a status; a failure without one raises its boundary error."""
        if failure.status is None and failure.error is BoundaryError.REFUSED:
            raise self.library.ConnectError("[Errno 111] Connection refused", request=request)
        if failure.status is None:
            raise self.library.ReadTimeout("timed out", request=request)
        return self.library.Response(failure.status, request=request)

    def handle(self, send: Callable[..., Any], transport: Any, args: tuple[Any, ...],
               kwargs: dict[str, Any]) -> Any:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = self.exchange(send, request, decision)
        except Exception as error:
            self.runtime.observe(point, self.error_outcome(error), elapsed_ms(started), decision)
            raise
        self.runtime.observe(point, status_outcome(response.status_code), elapsed_ms(started), decision)
        return response

    def exchange(self, send: Callable[[Any], Any], request: Any, decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                return self.failed(failure, request)
            case Decision(action=Duplicate()):
                request.read()
                send(request).read()
                return send(request)
            case Decision(action=FailAfter() as failure):
                send(request).read()
                return self.failed(failure, request)
        return send(request)

    async def handle_async(self, send: Callable[..., Awaitable[Any]], transport: Any, args: tuple[Any, ...],
                           kwargs: dict[str, Any]) -> Any:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = await self.exchange_async(send, request, decision)
        except Exception as error:
            self.runtime.observe(point, self.error_outcome(error), elapsed_ms(started), decision)
            raise
        self.runtime.observe(point, status_outcome(response.status_code), elapsed_ms(started), decision)
        return response

    async def exchange_async(self, send: Callable[[Any], Awaitable[Any]], request: Any,
                             decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                return await send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                return self.failed(failure, request)
            case Decision(action=Duplicate()):
                await request.aread()
                await (await send(request)).aread()
                return await send(request)
            case Decision(action=FailAfter() as failure):
                await (await send(request)).aread()
                return self.failed(failure, request)
        return await send(request)


def patch_client(runtime: Runtime, options: HttpOptions, library: ModuleType) -> None:
    """Make the transports every client of the library sends through, by default, the rpc_client points."""
    point = ClientPoint(runtime, options, library)
    wrapt.wrap_function_wrapper(library, "HTTPTransport.handle_request", point.handle)
    wrapt.wrap_function_wrapper(library, "AsyncHTTPTransport.handle_async_request", point.handle_async)


def install_client(library: str, runtime: Runtime, options: dict[str, JsonValue]) -> None:
    wrapt.register_post_import_hook(
        functools.partial(patch_client, runtime, HttpOptions.model_validate(options)), library)


CLIENT_ACTIONS: Final = implemented_actions(BoundaryFail, FailAfter, Duplicate, Delay, Crash)
HTTPX: Final = Plugin(actions={RpcKind.CLIENT: CLIENT_ACTIONS}, install=functools.partial(install_client, HTTPX_MODULE))
HTTPX2: Final = Plugin(actions={RpcKind.CLIENT: CLIENT_ACTIONS},
                       install=functools.partial(install_client, HTTPX2_MODULE))
ASGI: Final = Plugin(actions={RpcKind.SERVER: implemented_actions(BoundaryFail, FailAfter, Delay, Crash)},
                     install=install_asgi)
