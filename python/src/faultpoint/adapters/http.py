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
from faultpoint.observations import DetailKey, elapsed_ms, error_type, flag
from faultpoint.rules import STRICT, point_id
from faultpoint.runtime import Decision, Plugin, Runtime, implemented_actions

HTTPX_MODULE: Final = "httpx"
HTTPX2_MODULE: Final = "httpx2"
UVICORN_MODULE: Final = "uvicorn"
DEFAULT_FAILURE_STATUS: Final = 503
COMPLETED_STATUSES: Final = range(200, 400)
"""The statuses of an exchange that completed, which a fail_after rule replaces."""
RESPONSE_START: Final = "http.response.start"
HTTP_DISCONNECT: Final = "http.disconnect"
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


async def send_failure(send: Send, status: int | None) -> None:
    await send({"type": RESPONSE_START, "status": status or DEFAULT_FAILURE_STATUS,
                "headers": [(b"content-length", b"0")]})
    await send({"type": "http.response.body", "body": b""})


async def ready_message(receive: Receive) -> Message | None:
    """The message a receive answers at once, without waiting for the client: a disconnect, or request body."""
    pending = asyncio.ensure_future(receive())
    done, _ = await asyncio.wait({pending}, timeout=0)
    pending.cancel()
    return pending.result() if pending in done else None


class ServerExchange:
    """One request's exchange with its client: the response status, and whether the client left before the
    response was sent, which a disconnect the application receives, a probe before the response, or a failed
    send tells; body the probe takes is handed to the application's next receive."""

    def __init__(self, receive: Receive, send: Send) -> None:
        self.inner_receive = receive
        self.inner_send = send
        self.status: int | None = None
        self.held: list[Message] = []
        self.abandoned = False

    async def receive(self) -> Message:
        message = self.held.pop() if self.held else await self.inner_receive()
        self.abandoned = self.abandoned or message["type"] == HTTP_DISCONNECT
        return message

    async def probe(self) -> None:
        """Look, before the response, whether the client left; request body the look takes is held."""
        ready = None if self.abandoned else await ready_message(self.inner_receive)
        if ready is not None and ready["type"] == HTTP_DISCONNECT:
            self.abandoned = True
        elif ready is not None:
            self.held.append(ready)

    async def send(self, message: Message) -> None:
        if message["type"] == RESPONSE_START:
            self.status = message["status"]
            await self.probe()
        try:
            await self.inner_send(message)
        except OSError:
            self.abandoned = True
            raise

    def detail(self) -> dict[str, str]:
        status = {} if self.status is None else {DetailKey.STATUS: str(self.status)}
        return {**status, DetailKey.ABANDONED: flag(self.abandoned)}


class CompletionGate:
    """The send of an application run with no rule decided before it: the start of a 2xx or 3xx response decides a
    fail_after rule, and a rule that fires holds back that response, start and body, for its failure."""

    def __init__(self, runtime: Runtime, point: str, send: Send) -> None:
        self.runtime = runtime
        self.point = point
        self.inner_send = send
        self.decision: Decision | None = None

    async def send(self, message: Message) -> None:
        if message["type"] == RESPONSE_START and message["status"] in COMPLETED_STATUSES:
            self.decision = self.runtime.decide_completed(self.point)
        if self.decision is None:
            await self.inner_send(message)


class ServerPoint:
    """The rpc_server point of every request an ASGI application serves, under the caller's request context."""

    def __init__(self, app: Application, runtime: Runtime, options: HttpOptions) -> None:
        self.app = app
        self.runtime = runtime
        self.options = options

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            with self.runtime.own:
                headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in scope["headers"]}
            with self.runtime.context.attach(headers):
                await self.serve(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def serve(self, scope: Scope, receive: Receive, send: Send) -> None:
        with self.runtime.own:
            point = point_id(self.runtime.settings.service, RpcKind.SERVER,
                             f"{scope['method']} {path_template(scope['path'], self.options.identifier_segment)}")
            decision = self.runtime.decide(point)
            exchange = ServerExchange(receive, send)
            started = time.monotonic()
        try:
            if decision is None:
                decision = await self.respond_undecided(scope, exchange, point)
            else:
                await self.respond(scope, exchange.receive, exchange.send, decision)
        except BaseException as error:
            with self.runtime.own:
                elapsed = elapsed_ms(started)
                self.runtime.observe(point, RpcOutcome.ERROR, elapsed, elapsed, decision,
                                     {**exchange.detail(), DetailKey.ERROR: error_type(error)})
            raise
        with self.runtime.own:
            elapsed = elapsed_ms(started)
            self.runtime.observe(point,
                                 RpcOutcome.ERROR if exchange.status is None else status_outcome(exchange.status),
                                 elapsed, elapsed, decision, exchange.detail())

    async def respond(self, scope: Scope, receive: Receive, send: Send, decision: Decision) -> None:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                await self.app(scope, receive, send)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail(status=status, ms=ms)):
                if ms is not None:
                    await asyncio.sleep(ms / 1000)
                await send_failure(send, status)

    async def respond_undecided(self, scope: Scope, exchange: ServerExchange, point: str) -> Decision | None:
        """Run the application for a request no rule was decided for before it ran; a fail_after rule its 2xx or
        3xx response decides replaces that response with the rule's failure."""
        gate = CompletionGate(self.runtime, point, exchange.send)
        await self.app(scope, exchange.receive, gate.send)
        match gate.decision:
            case Decision(action=FailAfter(status=status)):
                await send_failure(exchange.send, status)
        return gate.decision


def serve_points(runtime: Runtime, options: HttpOptions, load: Callable[[], None], config: Any,
                 args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Wrap the application a uvicorn Config loaded."""
    load(*args, **kwargs)
    config.loaded_app = ServerPoint(config.loaded_app, runtime, options)


async def flush_after_shutdown(runtime: Runtime, shutdown: Callable[..., Awaitable[None]], server: Any,
                               args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Write the observations once uvicorn has finished the requests it served, since uvicorn then ends the process
    with the signal it stopped on, which skips the exit handlers where that signal has its default disposition, as
    a gunicorn worker sets it."""
    await shutdown(*args, **kwargs)
    with runtime.own:
        if runtime.sink is not None:
            runtime.sink.flush()


def patch_uvicorn(runtime: Runtime, options: HttpOptions, module: ModuleType) -> None:
    wrapt.wrap_function_wrapper(module, "Config.load", functools.partial(serve_points, runtime, options))
    wrapt.wrap_function_wrapper(module, "Server.shutdown", functools.partial(flush_after_shutdown, runtime))


def install_asgi(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    """Wrap the application uvicorn serves, the one place every ASGI framework's requests pass through, and the
    shutdown after which uvicorn ends the process."""
    wrapt.register_post_import_hook(
        functools.partial(patch_uvicorn, runtime, HttpOptions.model_validate(options)), UVICORN_MODULE)


class ClientPoint:
    """The rpc_client point of every request the transports of an httpx-compatible library send, which also
    carries the request context; the library module supplies its own response and exception types."""

    def __init__(self, runtime: Runtime, options: HttpOptions, library: ModuleType) -> None:
        self.runtime = runtime
        self.options = options
        self.library = library

    def decide(self, request: Any) -> tuple[str, Decision | None]:
        with self.runtime.own:
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

    def sent(self, decision: Decision | None, error: Exception | None) -> dict[str, str]:
        """Whether the request was fully sent: never for an injected fail, always for a fail_after, and for a
        natural failure when it happened while the response was read."""
        match decision:
            case Decision(action=BoundaryFail()):
                return {DetailKey.SENT: flag(False)}
            case Decision(action=FailAfter()):
                return {DetailKey.SENT: flag(True)}
        reading = (self.library.ReadError, self.library.ReadTimeout, self.library.RemoteProtocolError)
        return {} if error is None else {DetailKey.SENT: flag(isinstance(error, reading))}

    def observe(self, point: str, started: float, decision: Decision | None, response: Any) -> None:
        with self.runtime.own:
            elapsed = elapsed_ms(started)
            self.runtime.observe(point, status_outcome(response.status_code), elapsed, elapsed, decision,
                                 {DetailKey.STATUS: str(response.status_code), **self.sent(decision, None)})

    def observe_error(self, point: str, started: float, decision: Decision | None, error: Exception) -> None:
        with self.runtime.own:
            elapsed = elapsed_ms(started)
            self.runtime.observe(point, self.error_outcome(error), elapsed, elapsed, decision,
                                 {DetailKey.ERROR: error_type(error), **self.sent(decision, error)})

    def completed(self, point: str, decision: Decision | None, response: Any) -> Decision | None:
        """The decision of an exchange that got a response: the one made before it was sent, or else, for a 2xx
        or 3xx, a fail_after rule's."""
        if decision is None and response.status_code in COMPLETED_STATUSES:
            return self.runtime.decide_completed(point)
        return decision

    def handle(self, send: Callable[..., Any], transport: Any, args: tuple[Any, ...],
               kwargs: dict[str, Any]) -> Any:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = self.exchange(send, request, decision)
            decision = self.completed(point, decision, response)
            match decision:
                case Decision(action=FailAfter() as failure):
                    response.read()
                    response = self.failed(failure, request)
        except Exception as error:
            self.observe_error(point, started, decision, error)
            raise
        self.observe(point, started, decision, response)
        return response

    def exchange(self, send: Callable[[Any], Any], request: Any, decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail(ms=ms) as failure):
                if ms is not None:
                    time.sleep(ms / 1000)
                return self.failed(failure, request)
            case Decision(action=Duplicate()):
                request.read()
                send(request).read()
                return send(request)
        return send(request)

    async def handle_async(self, send: Callable[..., Awaitable[Any]], transport: Any, args: tuple[Any, ...],
                           kwargs: dict[str, Any]) -> Any:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = await self.exchange_async(send, request, decision)
            decision = self.completed(point, decision, response)
            match decision:
                case Decision(action=FailAfter() as failure):
                    await response.aread()
                    response = self.failed(failure, request)
        except Exception as error:
            self.observe_error(point, started, decision, error)
            raise
        self.observe(point, started, decision, response)
        return response

    async def exchange_async(self, send: Callable[[Any], Awaitable[Any]], request: Any,
                             decision: Decision | None) -> Any:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                return await send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail(ms=ms) as failure):
                if ms is not None:
                    await asyncio.sleep(ms / 1000)
                return self.failed(failure, request)
            case Decision(action=Duplicate()):
                await request.aread()
                await (await send(request)).aread()
                return await send(request)
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
