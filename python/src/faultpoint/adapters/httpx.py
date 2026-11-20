import asyncio
import time
from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import Any

import httpx
import wrapt

from faultpoint.actions import BoundaryError, BoundaryFail, Crash, Delay, Duplicate, FailAfter, Failure
from faultpoint.adapters.http import (HttpOptions, RpcKind, RpcOutcome, elapsed_ms, path_template,
                                      status_outcome)
from faultpoint.rules import point_id
from faultpoint.runtime import Decision, Runtime

type Send = Callable[[httpx.Request], httpx.Response]
type SendAsync = Callable[[httpx.Request], Awaitable[httpx.Response]]


def error_outcome(error: Exception) -> RpcOutcome:
    match error:
        case httpx.TimeoutException():
            return RpcOutcome.TIMEOUT
        case httpx.ConnectError():
            return RpcOutcome.REFUSED
    return RpcOutcome.ERROR


def failed(failure: Failure, request: httpx.Request) -> httpx.Response:
    """The synthetic response of a failure with a status; a failure without one raises its boundary error."""
    if failure.status is None and failure.error is BoundaryError.REFUSED:
        raise httpx.ConnectError("[Errno 111] Connection refused", request=request)
    if failure.status is None:
        raise httpx.ReadTimeout("timed out", request=request)
    return httpx.Response(failure.status, request=request)


class ClientPoint:
    """The rpc_client point of every request an httpx transport sends, which also carries the request context."""

    def __init__(self, runtime: Runtime, options: HttpOptions) -> None:
        self.runtime = runtime
        self.options = options

    def decide(self, request: httpx.Request) -> tuple[str, Decision | None]:
        self.runtime.context.inject(request.headers)
        url = request.url
        peer = url.host if url.port is None else f"{url.host}:{url.port}"
        point = point_id(self.runtime.settings.service, RpcKind.CLIENT,
                         f"{request.method} {peer}{path_template(url.path, self.options.identifier_segment)}")
        return point, self.runtime.decide(point)

    def handle(self, send: Send, transport: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> httpx.Response:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = self.exchange(send, request, decision)
        except Exception as error:
            self.runtime.observe(point, error_outcome(error), elapsed_ms(started), decision)
            raise
        self.runtime.observe(point, status_outcome(response.status_code), elapsed_ms(started), decision)
        return response

    def exchange(self, send: Send, request: httpx.Request, decision: Decision | None) -> httpx.Response:
        match decision:
            case Decision(action=Delay(ms=ms)):
                time.sleep(ms / 1000)
                return send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                return failed(failure, request)
            case Decision(action=Duplicate()):
                request.read()
                send(request).read()
                return send(request)
            case Decision(action=FailAfter() as failure):
                send(request).read()
                return failed(failure, request)
        return send(request)

    async def handle_async(self, send: SendAsync, transport: Any, args: tuple[Any, ...],
                           kwargs: dict[str, Any]) -> httpx.Response:
        (request,) = args
        point, decision = self.decide(request)
        started = time.monotonic()
        try:
            response = await self.exchange_async(send, request, decision)
        except Exception as error:
            self.runtime.observe(point, error_outcome(error), elapsed_ms(started), decision)
            raise
        self.runtime.observe(point, status_outcome(response.status_code), elapsed_ms(started), decision)
        return response

    async def exchange_async(self, send: SendAsync, request: httpx.Request,
                             decision: Decision | None) -> httpx.Response:
        match decision:
            case Decision(action=Delay(ms=ms)):
                await asyncio.sleep(ms / 1000)
                return await send(request)
            case Decision(action=Crash(code=code)):
                self.runtime.crash(code)
            case Decision(action=BoundaryFail() as failure):
                return failed(failure, request)
            case Decision(action=Duplicate()):
                await request.aread()
                await (await send(request)).aread()
                return await send(request)
            case Decision(action=FailAfter() as failure):
                await (await send(request)).aread()
                return failed(failure, request)
        return await send(request)


def patch(module: ModuleType, runtime: Runtime, options: HttpOptions) -> None:
    """Make the transports every httpx client sends through, by default, the rpc_client points."""
    point = ClientPoint(runtime, options)
    wrapt.wrap_function_wrapper(module, "HTTPTransport.handle_request", point.handle)
    wrapt.wrap_function_wrapper(module, "AsyncHTTPTransport.handle_async_request", point.handle_async)
