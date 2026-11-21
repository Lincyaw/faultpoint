import os
from typing import Final

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

CATALOG_URL: Final = os.environ["CATALOG_URL"]
CATALOG_TIMEOUT_S: Final = float(os.environ["CATALOG_TIMEOUT_S"])
LIST_PRICES: Final = {1: 1000, 2: 1200, 3: 1500}
"""The list price of every SKU number, which an estimate quotes."""
CLIENT: Final = httpx.AsyncClient(timeout=CATALOG_TIMEOUT_S)


class PriceUnavailable(Exception):
    pass


async def live_price(sku: str) -> int:
    response = await CLIENT.get(f"{CATALOG_URL}/prices/{sku}")
    if response.status_code != 200:
        raise PriceUnavailable(f"catalog answered {response.status_code}")
    return response.json()["price"]


def list_price(sku: str) -> int:
    return LIST_PRICES[int(sku.rsplit("-", 1)[1])]


async def create_quote(request: Request) -> JSONResponse:
    """The live price of a SKU; when the catalog cannot give one, an estimate at the list price, unless the quote
    guarantees its price."""
    quote = await request.json()
    try:
        price = await live_price(quote["sku"])
    except (PriceUnavailable, httpx.TransportError):
        if quote["guaranteed"]:
            return JSONResponse({"error": "no live price for a guaranteed quote"}, status_code=503)
        return JSONResponse({"price": list_price(quote["sku"]), "estimated": True})
    return JSONResponse({"price": price, "estimated": False})


app = Starlette(routes=[Route("/quotes", create_quote, methods=["POST"])])
