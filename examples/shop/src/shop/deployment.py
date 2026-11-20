import json
import os
import re
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
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, JsonValue

from shop.upstream import (HOST_FROM_NAMESPACE, UPSTREAM_FILE, Upstream, remove_containers, start_agent,
                           start_upstream, stop_agent)
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
REDIS_KEY_IDENTIFIER: Final = r"\b[a-z]-\d+\b"
"""The SKU inside a cache key, so that price:<sku> is one point."""
LIBRARY_KINDS: Final = ["branch", "call", "check", "loop"]
ORDERS_LIBRARIES: Final = [{"include": "redis.asyncio", "kinds": LIBRARY_KINDS}]
INVENTORY_LIBRARIES: Final = [{"include": "github.com/jackc/pgx/v5/pgxpool", "kinds": LIBRARY_KINDS},
                              {"include": "github.com/jackc/puddle/v2", "kinds": LIBRARY_KINDS}]
ORDERS_PLUGINS: Final = ["points", "import-hook", "httpx", "asgi", "dbapi", "redis"]
PORTS: Final = {"gateway": 27180, "orders": 27181, "inventory": 27182, "pricing": 27183, "ledger": 27184}
WORKLOAD_FILE: Final = "workload.json"
RULES_FILE: Final = "rules.json"
STATUSES_FILE: Final = "statuses.json"
REFUSAL_FILE: Final = "refusal.txt"
NETWORK_NAMESPACE: Final = ("unshare", "--user", "--map-root-user", "--net", "--")
"""A fresh network namespace per repetition lets repetitions run side by side on the same ports, so that the client
points, whose ids carry the peer's address, keep one id."""
HOST_ROUTE_DEADLINE_S: Final = 10
REFUSAL: Final = re.compile(r"faultpoint: rule \S+: [^\n]*")
"""How every SDK says it stops because a rule names an action the plugins serving its point do not all implement."""
LOAD_DEADLINE_S: Final = 120
"""The longest a repetition sends checkouts, so that a fault that hangs a service every tenant shares ends its
repetition too; a control sends all of them in about ten seconds."""


class Service(BaseModel):
    model_config = FROZEN

    name: str
    port: int
    command: list[str]
    directory: Path
    config: dict[str, JsonValue]
    """The service's FAULTPOINT_CONFIG without the observation output, which every service shares."""
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
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "python", "go", "typescript", "java", "rust", "ebpf"],
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


def write_config(path: Path, config: dict[str, JsonValue]) -> Path:
    path.write_text(json.dumps(config))
    return path


def build(sdk: Path) -> str:
    """Build the SDKs of a snapshot, the kernel agent and every service, and return its commit; the Go and Rust
    services are built from instrumented copies, the others attach at start."""
    commit = sdk_commit(sdk)
    BUILD.mkdir(parents=True, exist_ok=True)
    # npm ci installs from the lock files and never rewrites them, so the pinned SDK stays at its commit.
    run(["npm", "ci", "--silent"], sdk / "typescript")
    run(["npm", "run", "--silent", "build"], sdk / "typescript")
    run(["mvn", "-q", "-B", "package", "-DskipTests"], sdk / "java")
    run(["go", "build", "-o", "fpebpf", "."], sdk / "ebpf", {"CGO_ENABLED": "0"})
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
         "-target", str(go_copy), "-sdk", str(sdk / "go"), "-config",
         str(write_config(BUILD / "inventory.build.json", {"placement": {"scope": INVENTORY_LIBRARIES}}))], SHOP)
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
    redis_version = subprocess.run([str(SHOP / "orders" / ".venv" / "bin" / "python"), "-c",
                                    "import importlib.metadata; print(importlib.metadata.version('redis'))"],
                                   check=True, capture_output=True, text=True).stdout.strip()
    # The scan locates the libraries in scope among its own installed packages, so it needs orders' redis-py.
    run(["uv", "run", "--extra", "tools", "--with", f"redis=={redis_version}", "faultpoint", "scan", str(SHOP / "orders"),
         "--service", "orders", "--config", str(write_config(BUILD / "orders.scan.json", orders_config())),
         "--output", str(MANIFESTS / "orders.json")], sdk / "python")
    for service, manifest in (("gateway", SHOP / "gateway" / "dist"), ("inventory", BUILD / "inventory"),
                              ("pricing", BUILD / "pricing"), ("ledger", SHOP / "ledger" / "target" / "classes")):
        shutil.copy(manifest / "faultpoint-manifest.json", MANIFESTS / f"{service}.json")


def orders_config() -> dict[str, JsonValue]:
    return {"plugins": ORDERS_PLUGINS, "placement": {"scope": ORDERS_LIBRARIES},
            "options": {"asgi": {"identifier_segment": IDENTIFIER_SEGMENT},
                        "httpx": {"identifier_segment": IDENTIFIER_SEGMENT},
                        "redis": {"key_identifier": REDIS_KEY_IDENTIFIER}}}


def services(directory: Path, sdk: Path, workload: Workload, upstream: Upstream) -> list[Service]:
    urls = {f"{name.upper()}_URL": f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
    # The Python SDK attaches at start through the sitecustomize of its bootstrap directory.
    orders_attachment = {"PYTHONPATH": str(sdk / "python" / "src" / "faultpoint" / "bootstrap"),
                         "FAULTPOINT_SOURCE_ROOT": str(SHOP / "orders")}
    routes = {"identifier_segment": IDENTIFIER_SEGMENT}
    return [
        Service(name="gateway", port=PORTS["gateway"], command=["node", "dist/server.js"], directory=SHOP / "gateway",
                config={"options": {"http": routes}}, environment={
                    "NODE_OPTIONS": f"--import {sdk / 'typescript' / 'dist' / 'register.js'}",
                    "FAULTPOINT_SOURCE_ROOT": str(SHOP / "gateway" / "dist"), **urls}),
        Service(name="orders", port=PORTS["orders"],
                command=[str(SHOP / "orders" / ".venv" / "bin" / "uvicorn"), "orders:app", "--port",
                         str(PORTS["orders"]), "--log-level", "warning"],
                directory=SHOP / "orders", config=orders_config(),
                environment={**orders_attachment, "ORDERS_DATABASE": str(directory / "orders.db"),
                             "RESERVE_TIMEOUT_S": str(workload.reserve_timeout_s),
                             "PRICE_CACHE_TTL_S": str(workload.price_cache_ttl_s),
                             "REDIS_URL": upstream.environment()["REDIS_URL"], **urls}),
        Service(name="inventory", port=PORTS["inventory"], command=[str(BUILD / "inventory-bin")], directory=directory,
                config={"options": {"http": routes}},
                environment={"INVENTORY_DATABASE": upstream.environment()["INVENTORY_DATABASE"]}),
        Service(name="pricing", port=PORTS["pricing"],
                command=[str(BUILD / "pricing" / "target" / "release" / "pricing")], directory=directory,
                config={"options": {"tower": routes}}),
        Service(name="ledger", port=PORTS["ledger"],
                command=["java", f"-javaagent:{java_agent(sdk)}", "-cp",
                         f"{SHOP / 'ledger' / 'target' / 'classes'}:{SHOP / 'ledger' / 'target' / 'lib' / '*'}",
                         "shop.Ledger"],
                directory=directory, config={"options": {"servlet": routes}},
                environment={"FAULTPOINT_PACKAGES": "shop", "LEDGER_DATABASE": str(directory / "ledger.db")}),
    ]


def seed_ledger(directory: Path, workload: Workload) -> None:
    with sqlite3.connect(directory / "ledger.db") as ledger:
        ledger.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER)")
        ledger.executemany("INSERT INTO accounts VALUES (?, ?)",
                           [(tenant, workload.balance) for tenant in workload.tenant_names()])


def start(directory: Path, service: Service) -> subprocess.Popen[bytes]:
    options = service.config.get("options", {})
    config = write_config(directory / f"{service.name}.config.json", {
        **service.config, "options": {**options, "jsonl": {"flush_seconds": FLUSH_SECONDS}}})
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


def wait_for_host_route() -> None:
    """Wait until slirp4netns has given the namespace its route to the host."""
    started = time.monotonic()
    while "default" not in subprocess.run(["ip", "route"], check=True, capture_output=True, text=True).stdout:
        if time.monotonic() - started > HOST_ROUTE_DEADLINE_S:
            raise TimeoutError(f"no route to {HOST_FROM_NAMESPACE} in the repetition's network namespace")
        time.sleep(0.05)


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
    """The same sequence of checkouts in every repetition, the tenants interleaved, sent for at most
    LOAD_DEADLINE_S."""
    statuses: dict[str, dict[int, int]] = {tenant: {} for tenant in workload.tenant_names()}
    checkouts = [(tenant, workload.skus(tenant)[index % len(workload.sku_numbers)],
                  workload.quantities[index % len(workload.quantities)])
                 for index in range(REQUESTS_PER_TENANT) for tenant in workload.tenant_names()]
    started = time.monotonic()
    for tenant, sku, quantity in checkouts:
        if time.monotonic() - started > LOAD_DEADLINE_S:
            break
        status = checkout(tenant, sku, quantity)
        statuses[tenant][status] = statuses[tenant].get(status, 0) + 1
    return Statuses(tenants=statuses)


def serve_and_load(directory: Path, sdk: Path) -> Statuses:
    """Start the services on a repetition directory, send its workload's checkouts and stop them; this runs inside the
    repetition's own network namespace, which reaches the upstream containers through slirp4netns."""
    wait_for_host_route()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    workload = Workload.model_validate_json((directory / WORKLOAD_FILE).read_text())
    upstream = Upstream.model_validate_json((directory / UPSTREAM_FILE).read_text())
    seed_ledger(directory, workload)
    shop = services(directory, sdk, workload, upstream)
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


def wait_for_namespace(pid: int) -> None:
    """Wait until a child runs in a network namespace of its own, which slirp4netns then joins."""
    started = time.monotonic()
    while os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net"):
        if time.monotonic() - started > HOST_ROUTE_DEADLINE_S:
            raise TimeoutError(f"process {pid} did not enter a network namespace of its own")
        time.sleep(0.01)


def namespaced_run(directory: Path, sdk: Path) -> None:
    """Run serve_and_load in a fresh user and network namespace that slirp4netns connects to the host."""
    child = subprocess.Popen([*NETWORK_NAMESPACE, sys.executable, "-m", "shop.deployment", str(directory), str(sdk)])
    wait_for_namespace(child.pid)
    with (directory / "slirp4netns.log").open("wb") as log:
        slirp = subprocess.Popen(["slirp4netns", "--configure", "--mtu=65520", str(child.pid), "tap0"], stdout=log,
                                 stderr=subprocess.STDOUT)
    try:
        if child.wait() != 0:
            raise subprocess.CalledProcessError(child.returncode, child.args)
    finally:
        slirp.terminate()
        slirp.wait(timeout=30)


def refusal(directory: Path) -> str | None:
    """What a service said when it stopped at a rule it cannot apply, none when no service did."""
    found = [match.group(0) for log in sorted(directory.glob("*.log"))
             if (match := REFUSAL.search(log.read_text(errors="replace")))]
    return found[0] if found else None


def repetition(directory: Path, workload: Workload, rules: dict[str, Any], sdk: Path) -> Statuses:
    """One run of the whole shop under a rule set, with fresh databases, a fresh cache and the kernel agent watching
    the upstream containers; its observations stay in its directory."""
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    (directory / WORKLOAD_FILE).write_text(workload.model_dump_json())
    (directory / RULES_FILE).write_text(json.dumps(rules))
    prefix = f"fp-{sha256(str(directory).encode()).hexdigest()[:12]}"
    remove_containers(prefix)
    try:
        upstream = start_upstream(prefix, workload)
        (directory / UPSTREAM_FILE).write_text(upstream.model_dump_json())
        agent = start_agent(directory, directory / RULES_FILE, upstream, sdk, prefix, FLUSH_SECONDS)
        namespaced_run(directory, sdk)
        stop_agent(agent, directory)
    finally:
        remove_containers(prefix)
    return Statuses.model_validate_json((directory / STATUSES_FILE).read_text())


if __name__ == "__main__":
    (Path(sys.argv[1]) / STATUSES_FILE).write_text(serve_and_load(Path(sys.argv[1]), Path(sys.argv[2])).model_dump_json())
