import json
import os
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from shop.workload import FROZEN, SHOP, Workload

ROOT: Final = SHOP.parent.parent
RUNS: Final = ROOT / "runs" / "shop"
BUILD: Final = RUNS / "build"
MANIFESTS: Final = BUILD / "manifests"
BUILT_FROM: Final = BUILD / "sdk-commit"
FLUSH_SECONDS: Final = 0.5
REQUESTS_PER_TENANT: Final = 21
SCOPE_KEY: Final = "fp.scope"
IDENTIFIER_SEGMENT: Final = r"^(\d+|[a-z]-\d+)$"
"""Path segments that identify a record: numbers and the shop's SKUs, so that one route is one point."""
PORTS: Final = {"gateway": 27180, "orders": 27181, "inventory": 27182, "pricing": 27183, "ledger": 27184}
WORKLOAD_FILE: Final = "workload.json"
RULES_FILE: Final = "rules.json"
STATUSES_FILE: Final = "statuses.json"
NETWORK_NAMESPACE: Final = ("unshare", "--user", "--map-root-user", "--net", "--")
"""A fresh network namespace per repetition lets repetitions run side by side on the same ports, so that the client
points, whose ids carry the peer's address, keep one id."""


class Service(BaseModel):
    model_config = FROZEN

    name: str
    port: int
    command: list[str]
    directory: Path
    route_plugins: tuple[str, ...]
    """The plugins that turn request paths into point ids, which take the shop's identifier segments."""
    environment: dict[str, str] = {}


class Statuses(BaseModel):
    """How many of each tenant's checkouts received each response status."""

    model_config = FROZEN

    tenants: dict[str, dict[int, int]]


def run(command: list[str], directory: Path, environment: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=directory, check=True, env={**os.environ, **(environment or {})})


def java_agent(sdk: Path) -> Path:
    return sdk / "java" / "target" / "faultpoint-agent-0.1.0.jar"


def sdk_commit(sdk: Path) -> str:
    """The commit of an SDK checkout, which must not differ from it."""
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=sdk, check=True, capture_output=True,
                            text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "python", "go", "typescript", "java", "rust"],
                           cwd=sdk, check=True, capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError(f"the SDKs in {sdk} differ from commit {commit}:\n{dirty}")
    return commit


def verified_build(sdk: Path) -> str:
    """The commit of an SDK checkout whose build the services use, which the last build must have been made from."""
    commit = sdk_commit(sdk)
    built = BUILT_FROM.read_text().strip()
    if built != commit:
        raise RuntimeError(f"the services were built from {built}, not from {commit} in {sdk}")
    return commit


def build(sdk: Path) -> str:
    """Build the SDKs of a snapshot and every service, and return its commit; the Go and Rust services are built from
    instrumented copies, the others attach at start."""
    commit = sdk_commit(sdk)
    BUILD.mkdir(parents=True, exist_ok=True)
    # npm ci installs from the lock files and never rewrites them, so the pinned SDK stays at its commit.
    run(["npm", "ci", "--silent"], sdk / "typescript")
    run(["npx", "tsc", "-p", "tsconfig.json"], sdk / "typescript")
    run(["mvn", "-q", "-B", "package", "-DskipTests"], sdk / "java")
    run(["npm", "ci", "--silent"], SHOP / "gateway")
    run(["npx", "tsc", "-p", "tsconfig.json"], SHOP / "gateway")
    run(["uv", "sync", "-q"], SHOP / "orders")
    # Python plugins are found through the faultpoint.plugins entry points, which only an installed package exposes.
    run(["uv", "pip", "install", "-q", "--python", str(SHOP / "orders" / ".venv"), "-e", str(sdk / "python")],
        SHOP / "orders")
    run(["mvn", "-q", "-B", "package", "dependency:copy-dependencies", "-DoutputDirectory=target/lib"], SHOP / "ledger")
    go_copy = BUILD / "inventory"
    shutil.rmtree(go_copy, ignore_errors=True)
    run(["go", "build", "-o", str(BUILD / "fprewrite"), "."], sdk / "go" / "rewrite")
    run([str(BUILD / "fprewrite"), "instrument", "-service", "inventory", "-source", str(SHOP / "inventory"),
         "-target", str(go_copy), "-sdk", str(sdk / "go")], SHOP)
    run(["go", "build", "-o", str(BUILD / "inventory-bin"), "."], go_copy)
    rust_copy = BUILD / "pricing"
    shutil.rmtree(rust_copy, ignore_errors=True)
    run(["cargo", "build", "-q", "-p", "faultpoint-rewrite"], sdk / "rust")
    run([str(sdk / "rust" / "target" / "debug" / "faultpoint-rewrite"), "--service", "pricing", "--source",
         str(SHOP / "pricing"), "--target", str(rust_copy), "--sdk", str(sdk / "rust" / "faultpoint")], SHOP)
    run(["cargo", "build", "-q", "--release"], rust_copy)
    collect_manifests(sdk)
    BUILT_FROM.write_text(commit)
    return commit


def collect_manifests(sdk: Path) -> None:
    """The in-process points of every service, from the copies the rewriters wrote and from offline scans."""
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    run(["node", str(sdk / "typescript" / "dist" / "scan.js"), "--service", "gateway", "--root", "dist"], SHOP / "gateway")
    run(["java", "-jar", str(java_agent(sdk)), "scan", "--service", "ledger", "--packages", "shop", "--classes",
         str(SHOP / "ledger" / "target" / "classes")], SHOP / "ledger")
    run(["uv", "run", "--extra", "tools", "faultpoint", "scan", str(SHOP / "orders"), "--service", "orders",
         "--output", str(MANIFESTS / "orders.json")], sdk / "python")
    for service, manifest in (("gateway", SHOP / "gateway" / "dist"), ("inventory", BUILD / "inventory"),
                              ("pricing", BUILD / "pricing"), ("ledger", SHOP / "ledger" / "target" / "classes")):
        shutil.copy(manifest / "faultpoint-manifest.json", MANIFESTS / f"{service}.json")


def services(directory: Path, sdk: Path, workload: Workload) -> list[Service]:
    urls = {f"{name.upper()}_URL": f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
    # The Python SDK attaches at start through the sitecustomize of its bootstrap directory.
    orders_attachment = {"PYTHONPATH": str(sdk / "python" / "src" / "faultpoint" / "bootstrap"),
                         "FAULTPOINT_SOURCE_ROOT": str(SHOP / "orders")}
    return [
        Service(name="gateway", port=PORTS["gateway"], command=["node", "dist/server.js"], directory=SHOP / "gateway",
                route_plugins=("http",), environment={
                    "NODE_OPTIONS": f"--import {sdk / 'typescript' / 'dist' / 'register.js'}",
                    "FAULTPOINT_SOURCE_ROOT": str(SHOP / "gateway" / "dist"), **urls}),
        Service(name="orders", port=PORTS["orders"],
                command=[str(SHOP / "orders" / ".venv" / "bin" / "uvicorn"), "orders:app", "--port",
                         str(PORTS["orders"]), "--log-level", "warning"],
                directory=SHOP / "orders", route_plugins=("asgi", "httpx"),
                environment={**orders_attachment, "ORDERS_DATABASE": str(directory / "orders.db"),
                             "RESERVE_TIMEOUT_S": str(workload.reserve_timeout_s), **urls}),
        Service(name="inventory", port=PORTS["inventory"], command=[str(BUILD / "inventory-bin")], directory=directory,
                route_plugins=("http",), environment={"INVENTORY_DATABASE": str(directory / "inventory.db")}),
        Service(name="pricing", port=PORTS["pricing"],
                command=[str(BUILD / "pricing" / "target" / "release" / "pricing")], directory=directory,
                route_plugins=("tower",)),
        Service(name="ledger", port=PORTS["ledger"],
                command=["java", f"-javaagent:{java_agent(sdk)}", "-cp",
                         f"{SHOP / 'ledger' / 'target' / 'classes'}:{SHOP / 'ledger' / 'target' / 'lib' / '*'}",
                         "shop.Ledger"],
                directory=directory, route_plugins=("servlet",),
                environment={"FAULTPOINT_PACKAGES": "shop", "LEDGER_DATABASE": str(directory / "ledger.db")}),
    ]


def seed(directory: Path, workload: Workload) -> None:
    with sqlite3.connect(directory / "inventory.db") as inventory:
        inventory.execute("CREATE TABLE stock (sku TEXT PRIMARY KEY, available INTEGER)")
        inventory.executemany("INSERT INTO stock VALUES (?, ?)", [
            (sku, workload.stock_per_sku) for tenant in workload.tenant_names() for sku in workload.skus(tenant)])
    with sqlite3.connect(directory / "ledger.db") as ledger:
        ledger.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER)")
        ledger.executemany("INSERT INTO accounts VALUES (?, ?)",
                           [(tenant, workload.balance) for tenant in workload.tenant_names()])


def start(directory: Path, service: Service) -> subprocess.Popen[bytes]:
    config = directory / f"{service.name}.config.json"
    config.write_text(json.dumps({"options": {
        "jsonl": {"flush_seconds": FLUSH_SECONDS},
        **{plugin: {"identifier_segment": IDENTIFIER_SEGMENT} for plugin in service.route_plugins}}}))
    environment = {**os.environ, **service.environment, "PORT": str(service.port),
                   "FAULTPOINT_SERVICE": service.name, "FAULTPOINT_RULES": str(directory / RULES_FILE),
                   "FAULTPOINT_REPORT": str(directory / f"{service.name}.jsonl"), "FAULTPOINT_CONFIG": str(config)}
    with (directory / f"{service.name}.log").open("wb") as log:
        return subprocess.Popen(service.command, cwd=service.directory, env=environment, stdout=log,
                                stderr=subprocess.STDOUT)


def wait_for_port(port: int, process: subprocess.Popen[bytes], deadline_s: float = 60) -> None:
    started = time.monotonic()
    while time.monotonic() - started < deadline_s:
        if process.poll() is not None:
            raise RuntimeError(f"a service on port {port} exited with {process.returncode}")
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"no service listens on port {port}")


def checkout(tenant: str, sku: str, quantity: int) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{PORTS['gateway']}/checkout", method="POST",
        data=json.dumps({"tenant": tenant, "sku": sku, "quantity": quantity}).encode(),
        headers={"content-type": "application/json", "baggage": f"{SCOPE_KEY}={tenant}",
                 "traceparent": f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as refused:
        return refused.code


def load(workload: Workload) -> Statuses:
    """The same sequence of checkouts in every repetition, the tenants interleaved."""
    statuses: dict[str, dict[int, int]] = {tenant: {} for tenant in workload.tenant_names()}
    for index in range(REQUESTS_PER_TENANT):
        for tenant in workload.tenant_names():
            sku = workload.skus(tenant)[index % len(workload.sku_numbers)]
            status = checkout(tenant, sku, workload.quantities[index % len(workload.quantities)])
            statuses[tenant][status] = statuses[tenant].get(status, 0) + 1
    return Statuses(tenants=statuses)


def serve_and_load(directory: Path, sdk: Path) -> Statuses:
    """Start the services on a repetition directory, send its workload's checkouts and stop them; this runs inside the
    repetition's own network namespace."""
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    workload = Workload.model_validate_json((directory / WORKLOAD_FILE).read_text())
    seed(directory, workload)
    shop = services(directory, sdk, workload)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        for service in shop:
            processes.append(start(directory, service))
        for service, process in zip(shop, processes, strict=True):
            wait_for_port(service.port, process)
        statuses = load(workload)
        time.sleep(3 * FLUSH_SECONDS)
    finally:
        for process in processes:
            process.send_signal(signal.SIGTERM)
        for process in processes:
            process.wait(timeout=30)
    return statuses


def repetition(directory: Path, workload: Workload, rules: dict[str, Any], sdk: Path) -> Statuses:
    """One run of the whole shop under a rule set, with fresh databases; its observations stay in its directory."""
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    (directory / WORKLOAD_FILE).write_text(workload.model_dump_json())
    (directory / RULES_FILE).write_text(json.dumps(rules))
    subprocess.run([*NETWORK_NAMESPACE, sys.executable, "-m", "shop.deployment", str(directory), str(sdk)],
                   check=True)
    return Statuses.model_validate_json((directory / STATUSES_FILE).read_text())


if __name__ == "__main__":
    (Path(sys.argv[1]) / STATUSES_FILE).write_text(serve_and_load(Path(sys.argv[1]), Path(sys.argv[2])).model_dump_json())
