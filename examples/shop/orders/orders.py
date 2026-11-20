import os
import sqlite3
from typing import Final

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

INVENTORY_URL: Final = os.environ.get("INVENTORY_URL", "http://127.0.0.1:8082")
PRICING_URL: Final = os.environ.get("PRICING_URL", "http://127.0.0.1:8083")
LEDGER_URL: Final = os.environ.get("LEDGER_URL", "http://127.0.0.1:8084")
DATABASE: Final = os.environ.get("ORDERS_DATABASE", "orders.db")
RESERVE_ATTEMPTS: Final = 3
RESERVE_TIMEOUT_S: Final = 2.0


class OutOfStock(Exception):
    pass


class PaymentDeclined(Exception):
    pass


class DependencyFailed(Exception):
    pass


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, check_same_thread=False, isolation_level=None)
    connection.execute("CREATE TABLE IF NOT EXISTS orders (tenant TEXT, sku TEXT, quantity INTEGER, amount INTEGER)")
    return connection


DB: Final = connect()
CLIENT: Final = httpx.AsyncClient(timeout=RESERVE_TIMEOUT_S)


def retryable(status: int) -> bool:
    return status >= 500


async def reserve(sku: str, quantity: int) -> None:
    """Reserve stock, retrying a failed inventory call, since a reservation is the step most often interrupted."""
    attempt = 0
    while attempt < RESERVE_ATTEMPTS:
        attempt += 1
        try:
            response = await CLIENT.post(f"{INVENTORY_URL}/reserve", json={"sku": sku, "quantity": quantity})
        except httpx.TransportError:
            continue
        if response.status_code == 409:
            raise OutOfStock(sku)
        if not retryable(response.status_code):
            return
    raise DependencyFailed(f"inventory did not reserve {sku} after {RESERVE_ATTEMPTS} attempts")


async def price(sku: str, quantity: int) -> int:
    response = await CLIENT.get(f"{PRICING_URL}/price/{sku}")
    if response.status_code != 200:
        raise DependencyFailed(f"pricing answered {response.status_code}")
    return response.json()["unit"] * quantity


async def charge(tenant: str, amount: int) -> None:
    response = await CLIENT.post(f"{LEDGER_URL}/charge", json={"account": tenant, "amount": amount})
    if response.status_code == 402:
        raise PaymentDeclined(tenant)
    if response.status_code != 200:
        raise DependencyFailed(f"ledger answered {response.status_code}")


async def create_order(request: Request) -> JSONResponse:
    order = await request.json()
    try:
        await reserve(order["sku"], order["quantity"])
        amount = await price(order["sku"], order["quantity"])
        await charge(order["tenant"], amount)
    except OutOfStock as refused:
        return JSONResponse({"error": f"out of stock: {refused}"}, status_code=409)
    except PaymentDeclined as refused:
        return JSONResponse({"error": f"payment declined: {refused}"}, status_code=402)
    except DependencyFailed as failure:
        return JSONResponse({"error": str(failure)}, status_code=503)
    DB.execute("INSERT INTO orders VALUES (?, ?, ?, ?)", (order["tenant"], order["sku"], order["quantity"], amount))
    return JSONResponse({"amount": amount}, status_code=201)


app = Starlette(routes=[Route("/orders", create_order, methods=["POST"])])
