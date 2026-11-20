import http from "node:http";

const PORT = Number(process.env.PORT ?? "8080");
const ORDERS_URL = process.env.ORDERS_URL ?? "http://127.0.0.1:8081";
const MAXIMUM_QUANTITY = 10;

interface Checkout {
  tenant: string;
  sku: string;
  quantity: number;
}

class InvalidCheckout extends Error {}

function validQuantity(quantity: number): boolean {
  return Number.isInteger(quantity) && quantity > 0 && quantity <= MAXIMUM_QUANTITY;
}

function parseCheckout(text: string): Checkout {
  const checkout = JSON.parse(text) as Checkout;
  if (!validQuantity(checkout.quantity)) {
    throw new InvalidCheckout(`quantity ${checkout.quantity} is outside 1..${MAXIMUM_QUANTITY}`);
  }
  return checkout;
}

/** A failure of the order service is the gateway's bad gateway; a refusal passes through to the client. */
function clientStatus(ordersStatus: number): number {
  return ordersStatus >= 500 ? 502 : ordersStatus;
}

async function readBody(request: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

const server = http.createServer(async (request, response) => {
  if (request.method !== "POST" || request.url !== "/checkout") {
    response.writeHead(404).end();
    return;
  }
  try {
    const checkout = parseCheckout(await readBody(request));
    const reply = await fetch(`${ORDERS_URL}/orders`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(checkout),
    });
    const text = await reply.text();
    response.writeHead(clientStatus(reply.status), { "content-type": "application/json" }).end(text);
  } catch (error) {
    response.writeHead(error instanceof InvalidCheckout ? 400 : 502).end(String(error));
  }
});

server.listen(PORT, () => console.log(`gateway listening on ${PORT}`));
