import asyncio
import re
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

import httpx
from opentelemetry import context as otel_context

from faultpoint.context import PROPAGATOR
from faultpoint.rules import BoundaryError, Crash, Delay, Duplicate, Fail, FailAfter, PointKind, point_id
from faultpoint.runtime import RUNTIME

DEFAULT_FAILURE_STATUS: Final = 503
IDENTIFIER_SEGMENT: Final = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$")

type Scope = MutableMapping[str, Any]
type Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
type Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
type Application = Callable[[Scope, Receive, Send], Awaitable[None]]


def path_template(path: str) -> str:
    """A request path with identifier segments replaced, so that one route is one point."""
    return "/".join("{}" if IDENTIFIER_SEGMENT.match(segment) else segment
                    for segment in path.split("/"))


def status_outcome(status: int) -> str:
    return f"{status // 100}xx"


class FaultpointMiddleware:
    """The rpc_server point of every route of an ASGI application, which also restores the
    caller's trace context and baggage."""

    def __init__(self, app: Application) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not RUNTIME.enabled:
            await self.app(scope, receive, send)
            return
        carrier = {key.decode("latin-1"): value.decode("latin-1") for key, value in scope["headers"]}
        token = otel_context.attach(PROPAGATOR.extract(carrier))
        try:
            await self.serve(scope, receive, send)
        finally:
            otel_context.detach(token)

    async def serve(self, scope: Scope, receive: Receive, send: Send) -> None:
        point = point_id(RUNTIME.settings.service, PointKind.RPC_SERVER,
                         f"{scope['method']} {path_template(scope['path'])}")
        rule = RUNTIME.decide(point)
        action = None if rule is None else rule.action
        started = time.monotonic()
        statuses: list[int] = []

        async def capture(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                statuses.append(message["status"])
            await send(message)

        async def discard(message: MutableMapping[str, Any]) -> None:
            return None

        if isinstance(action, Delay):
            await asyncio.sleep(action.ms / 1000)
        if isinstance(action, Crash):
            RUNTIME.crash(action.code)
        try:
            if isinstance(action, Fail | FailAfter):
                if isinstance(action, FailAfter):
                    await self.app(scope, receive, discard)
                await capture({"type": "http.response.start",
                               "status": action.status or DEFAULT_FAILURE_STATUS,
                               "headers": [(b"content-length", b"0")]})
                await capture({"type": "http.response.body", "body": b""})
            else:
                await self.app(scope, receive, capture)
        except BaseException:
            RUNTIME.record(point, "error", (time.monotonic() - started) * 1000, rule)
            raise
        RUNTIME.record(point, status_outcome(statuses[0]), (time.monotonic() - started) * 1000,
                       rule)


def boundary_exception(error: BoundaryError | None, request: httpx.Request) -> httpx.TransportError:
    if error is BoundaryError.REFUSED:
        return httpx.ConnectError("faultpoint: connection refused", request=request)
    return httpx.ReadTimeout("faultpoint: read timed out", request=request)


def exception_outcome(error: Exception) -> str:
    if isinstance(error, httpx.TimeoutException):
        return BoundaryError.TIMEOUT
    if isinstance(error, httpx.ConnectError):
        return BoundaryError.REFUSED
    return "error"


class FaultpointTransport(httpx.AsyncBaseTransport):
    """The rpc_client point of every outgoing request of an httpx client, which also forwards
    the current trace context and baggage."""

    def __init__(self, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self.inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        PROPAGATOR.inject(request.headers)
        if not RUNTIME.enabled:
            return await self.inner.handle_async_request(request)
        peer = request.url.host if request.url.port is None else f"{request.url.host}:{request.url.port}"
        point = point_id(RUNTIME.settings.service, PointKind.RPC_CLIENT,
                         f"{request.method} {peer}{path_template(request.url.path)}")
        rule = RUNTIME.decide(point)
        action = None if rule is None else rule.action
        started = time.monotonic()
        if isinstance(action, Delay):
            await asyncio.sleep(action.ms / 1000)
        if isinstance(action, Crash):
            RUNTIME.crash(action.code)
        if isinstance(action, Fail) and action.status is not None:
            RUNTIME.record(point, status_outcome(action.status), 0.0, rule)
            return httpx.Response(action.status, request=request)
        if isinstance(action, Fail):
            error = boundary_exception(BoundaryError(action.error) if action.error else None, request)
            RUNTIME.record(point, exception_outcome(error), 0.0, rule)
            raise error
        await request.aread()
        try:
            response = await self.inner.handle_async_request(request)
            if isinstance(action, Duplicate | FailAfter):
                await response.aread()
                await response.aclose()
            if isinstance(action, Duplicate):
                response = await self.inner.handle_async_request(request)
        except httpx.TransportError as error:
            RUNTIME.record(point, exception_outcome(error), (time.monotonic() - started) * 1000, rule)
            raise
        if isinstance(action, FailAfter):
            if action.status is not None:
                RUNTIME.record(point, status_outcome(action.status), 0.0, rule)
                return httpx.Response(action.status, request=request)
            error = boundary_exception(action.error, request)
            RUNTIME.record(point, exception_outcome(error), (time.monotonic() - started) * 1000, rule)
            raise error
        RUNTIME.record(point, status_outcome(response.status_code),
                       (time.monotonic() - started) * 1000, rule)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()
