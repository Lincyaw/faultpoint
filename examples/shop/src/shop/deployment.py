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
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from faultsearch.counterfactual import SCOPE_KEY, Statuses
from faultsearch.recording import (INSTRUMENTATION_FILE, REFUSAL_FILE, RULES_FILE, SEED_FILE, STATUSES_FILE,
                                   WORKLOAD_FILE)
from faultsearch_local.systems import System
from pydantic import BaseModel, JsonValue

from shop.upstream import (HOST_FROM_NAMESPACE, PACKET_POINTS, UNSCOPED_TARGETS, UPSTREAM_FILE, UPSTREAM_SERVICES,
                           AgentObservation, Upstream, remove_containers, scan_hooks, start_agent, start_upstream,
                           stop_agent)
from shop.workload import FROZEN, SCENARIOS, SHOP, Workload

ROOT: Final = SHOP.parent.parent
RUNS: Final = ROOT / "runs" / "shop"
BUILD: Final = RUNS / "build"
MANIFESTS: Final = BUILD / "manifests"
HOOKS_DIRECTORY: Final = "hooks"
"""Where in a system's build the kernel agent's hook catalog of the upstream images lies."""
BUILT_FROM: Final = BUILD / "sdk-commit"
FLUSH_SECONDS: Final = 0.5
REQUESTS_PER_TENANT: Final = 21
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
LEDGER_CLASS_PATH: Final = f"{SHOP / 'ledger' / 'target' / 'classes'}:{SHOP / 'ledger' / 'target' / 'lib' / '*'}"
"""The class path ledger runs with, which its scan reads too, so that the scan lists the calls into its libraries."""
RESPONSES_FILE: Final = "responses.json"
FAULTPOINT_VARIABLES: Final = "FAULTPOINT_"
"""The prefix of the environment variables every SDK reads, none of which a service without faultpoint gets."""
NETWORK_NAMESPACE: Final = ("unshare", "--user", "--map-root-user", "--net", "--")
"""A fresh network namespace per repetition lets repetitions run side by side on the same ports, so that the client
points, whose ids carry the peer's address, keep one id."""
HOST_ROUTE_DEADLINE_S: Final = 10
REFUSAL: Final = re.compile(r"faultpoint: rule \S+: [^\n]*")
"""How every SDK says it stops because a rule names an action the plugins serving its point do not all implement."""
STOP_EXIT_CODE: Final = 70
"""The exit code with which faultpoint stops a process whose rule set it cannot apply, whatever it says before."""
REFUSAL_LINES: Final = 3
"""The last lines of a service's log that record why it stopped at start, when it says so in no form REFUSAL knows."""
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
    attachment: dict[str, str] = {}
    """The environment that attaches the service's SDK at start, besides the FAULTPOINT_ variables every service with
    faultpoint gets; a compiled service has the SDK built in, which those variables alone enable."""


class Response(BaseModel):
    """What one request of a tenant received."""

    model_config = FROZEN

    tenant: str
    status: int
    body: str


class Responses(BaseModel):
    """Every response of a repetition, in the order the requests were sent."""

    model_config = FROZEN

    responses: tuple[Response, ...]


class Instrumentation(BaseModel):
    """Whether services load their SDK, and what the optional kernel agent observes."""

    model_config = FROZEN

    attached: bool = True
    agent: AgentObservation | None = AgentObservation()


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


def built_commit(sdk: Path, built_from: Path) -> str:
    """The commit of an SDK checkout whose build a system's services use, which the file where its last build wrote
    its commit must name."""
    commit = sdk_commit(sdk)
    built = built_from.read_text().strip()
    if built != commit:
        raise RuntimeError(f"the services were built from {built}, not from {commit} in {sdk}")
    return commit


def verified_build(sdk: Path) -> str:
    return built_commit(sdk, BUILT_FROM)


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
    scan_hooks(sdk, BUILD / HOOKS_DIRECTORY)
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
         str(SHOP / "ledger" / "target" / "classes"), "--classpath", LEDGER_CLASS_PATH], SHOP / "ledger")
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


def services(directory: Path, sdk: Path, build: Path, workload: Workload, upstream: Upstream) -> list[Service]:
    urls = {f"{name.upper()}_URL": f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
    routes = {"identifier_segment": IDENTIFIER_SEGMENT}
    return [
        Service(name="gateway", port=PORTS["gateway"], command=["node", "dist/server.js"], directory=SHOP / "gateway",
                config={"options": {"http": routes}}, environment=urls, attachment={
                    "NODE_OPTIONS": f"--import {sdk / 'typescript' / 'dist' / 'register.js'}",
                    "FAULTPOINT_SOURCE_ROOT": str(SHOP / "gateway" / "dist")}),
        Service(name="orders", port=PORTS["orders"],
                command=[str(SHOP / "orders" / ".venv" / "bin" / "uvicorn"), "orders:app", "--port",
                         str(PORTS["orders"]), "--log-level", "warning"],
                directory=SHOP / "orders", config=orders_config(),
                environment={"ORDERS_DATABASE": str(directory / "orders.db"),
                             "RESERVE_TIMEOUT_S": str(workload.reserve_timeout_s),
                             "PRICE_CACHE_TTL_S": str(workload.price_cache_ttl_s),
                             "REDIS_URL": upstream.redis_url, **urls},
                # The Python SDK attaches at start through the sitecustomize of its bootstrap directory; orders' own
                # directory lets a rule name an exception class of the orders module, which the SDK imports.
                attachment={"PYTHONPATH": os.pathsep.join([str(sdk / "python" / "src" / "faultpoint" / "bootstrap"),
                                                           str(SHOP / "orders")]),
                            "FAULTPOINT_SOURCE_ROOT": str(SHOP / "orders")}),
        Service(name="inventory", port=PORTS["inventory"], command=[str(build / "inventory-bin")], directory=directory,
                config={"options": {"http": routes}}, environment={"INVENTORY_DATABASE": upstream.database}),
        Service(name="pricing", port=PORTS["pricing"],
                command=[str(build / "pricing" / "target" / "release" / "pricing")], directory=directory,
                config={"options": {"tower": routes}}),
        Service(name="ledger", port=PORTS["ledger"], command=["java", "-cp", LEDGER_CLASS_PATH, "shop.Ledger"],
                directory=directory, config={"options": {"servlet": routes}},
                environment={"LEDGER_DATABASE": str(directory / "ledger.db")},
                attachment={"JAVA_TOOL_OPTIONS": f"-javaagent:{java_agent(sdk)}", "FAULTPOINT_PACKAGES": "shop"}),
    ]


def seed_ledger(directory: Path, workload: Workload) -> None:
    with sqlite3.connect(directory / "ledger.db") as ledger:
        ledger.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER)")
        ledger.executemany("INSERT INTO accounts VALUES (?, ?)",
                           [(tenant, workload.balance) for tenant in workload.tenant_names()])


def detached_environment(service: Service) -> dict[str, str]:
    """A service's environment without faultpoint: no SDK attached and no FAULTPOINT_ variable, inherited or not."""
    return {**{name: value for name, value in os.environ.items() if not name.startswith(FAULTPOINT_VARIABLES)},
            **service.environment, "PORT": str(service.port)}


def attached_environment(directory: Path, service: Service) -> dict[str, str]:
    """A service's environment with its SDK attached, reading the repetition's rules and writing its observations to
    the repetition's directory."""
    options = service.config.get("options", {})
    config = write_config(directory / f"{service.name}.config.json", {
        **service.config, "options": {**options, "jsonl": {"flush_seconds": FLUSH_SECONDS}}})
    return {**detached_environment(service), **service.attachment, "FAULTPOINT_SERVICE": service.name,
            "FAULTPOINT_RULES": str(directory / RULES_FILE),
            "FAULTPOINT_REPORT": str(directory / f"{service.name}.jsonl"), "FAULTPOINT_CONFIG": str(config),
            "FAULTPOINT_SEED": (directory / SEED_FILE).read_text()}


def service_environment(directory: Path, service: Service, instrumentation: Instrumentation) -> dict[str, str]:
    return attached_environment(directory, service) if instrumentation.attached else detached_environment(service)


def start(directory: Path, service: Service, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    with (directory / f"{service.name}.log").open("wb") as log:
        return subprocess.Popen(service.command, cwd=service.directory, env=environment, stdout=log,
                                stderr=subprocess.STDOUT)


def wait_for_port(directory: Path, service: Service, process: subprocess.Popen[bytes], deadline_s: float = 60) -> None:
    """Wait until a service listens; one that stops first with faultpoint's stop code refused the rule set, which the
    repetition's directory records with the end of the service's log."""
    started = time.monotonic()
    while time.monotonic() - started < deadline_s:
        if process.poll() is not None:
            if process.returncode == STOP_EXIT_CODE:
                lines = [line for line in (directory / f"{service.name}.log").read_text(errors="replace").splitlines()
                         if line.strip()]
                (directory / REFUSAL_FILE).write_text(f"{service.name} stopped at start: "
                                                      + " | ".join(lines[-REFUSAL_LINES:]))
            raise RuntimeError(f"a service on port {service.port} exited with {process.returncode}")
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", service.port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"no service listens on port {service.port}")


def wait_for_host_route() -> None:
    """Wait until slirp4netns has given the namespace its route to the host."""
    started = time.monotonic()
    while "default" not in subprocess.run(["ip", "route"], check=True, capture_output=True, text=True).stdout:
        if time.monotonic() - started > HOST_ROUTE_DEADLINE_S:
            raise TimeoutError(f"no route to {HOST_FROM_NAMESPACE} in the repetition's network namespace")
        time.sleep(0.05)


def answered(tenant: str, request: urllib.request.Request) -> Response:
    """The response a tenant's request receives, whatever its status."""
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return Response(tenant=tenant, status=response.status, body=response.read().decode(errors="replace"))
    except urllib.error.HTTPError as refused:
        return Response(tenant=tenant, status=refused.code, body=refused.read().decode(errors="replace"))


def tenant_request(url: str, tenant: str, body: dict[str, JsonValue]) -> urllib.request.Request:
    """A tenant's JSON request, in the tenant's scope and in a trace of its own."""
    return urllib.request.Request(url, method="POST", data=json.dumps(body).encode(), headers={
        "content-type": "application/json", "baggage": f"{SCOPE_KEY}={tenant}",
        "traceparent": f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"})


def load(workload: Workload) -> list[Response]:
    """The same sequence of checkouts in every repetition, the tenants interleaved, sent for at most
    LOAD_DEADLINE_S."""
    checkouts = [(tenant, workload.skus(tenant)[index % len(workload.sku_numbers)],
                  workload.quantities[index % len(workload.quantities)])
                 for index in range(REQUESTS_PER_TENANT) for tenant in workload.tenant_names()]
    started = time.monotonic()
    responses: list[Response] = []
    for tenant, sku, quantity in checkouts:
        if time.monotonic() - started > LOAD_DEADLINE_S:
            break
        responses.append(answered(tenant, tenant_request(f"http://127.0.0.1:{PORTS['gateway']}/checkout", tenant,
                                                         {"tenant": tenant, "sku": sku, "quantity": quantity})))
    return responses


def record_responses(directory: Path, tenants: list[str], responses: list[Response]) -> None:
    """Keep a repetition's responses and how many of each tenant's received each status."""
    (directory / RESPONSES_FILE).write_text(Responses(responses=tuple(responses)).model_dump_json())
    counts = Statuses(tenants={tenant: dict(Counter(response.status for response in responses
                                                    if response.tenant == tenant)) for tenant in tenants})
    (directory / STATUSES_FILE).write_text(counts.model_dump_json())


def serve_and_load(directory: Path, sdk: Path, build: Path) -> None:
    """Start a build's services on a repetition directory, send its workload's checkouts, stop them and keep the
    responses; this runs inside the repetition's own network namespace, which reaches the upstream containers through
    slirp4netns."""
    wait_for_host_route()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    workload = Workload.model_validate_json((directory / WORKLOAD_FILE).read_text())
    upstream = Upstream.model_validate_json((directory / UPSTREAM_FILE).read_text())
    instrumentation = Instrumentation.model_validate_json((directory / INSTRUMENTATION_FILE).read_text())
    seed_ledger(directory, workload)
    shop = services(directory, sdk, build, workload, upstream)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        for service in shop:
            processes.append(start(directory, service, service_environment(directory, service, instrumentation)))
        for service, process in zip(shop, processes, strict=True):
            wait_for_port(directory, service, process)
        responses = load(workload)
        time.sleep(3 * FLUSH_SECONDS)
    finally:
        for process in processes:
            process.send_signal(signal.SIGTERM)
        for process in processes:
            process.wait(timeout=30)
    record_responses(directory, workload.tenant_names(), responses)


def wait_for_namespace(pid: int) -> None:
    """Wait until a child runs in a network namespace of its own, which slirp4netns then joins."""
    started = time.monotonic()
    while os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net"):
        if time.monotonic() - started > HOST_ROUTE_DEADLINE_S:
            raise TimeoutError(f"process {pid} did not enter a network namespace of its own")
        time.sleep(0.01)


def namespaced_run(directory: Path, sdk: Path, module: str, build: Path) -> None:
    """Run a system's deployment module, which serves the build's services and loads them on the repetition's
    directory, in a fresh user and network namespace that slirp4netns connects to the host."""
    child = subprocess.Popen([*NETWORK_NAMESPACE, sys.executable, "-m", module, str(directory), str(sdk), str(build)])
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
    """What a service said when it stopped at a rule it cannot apply, or the end of the log of one that stopped at
    start with faultpoint's stop code; none when no service did."""
    found = [match.group(0) for log in sorted(directory.glob("*.log"))
             if (match := REFUSAL.search(log.read_text(errors="replace")))]
    if found:
        return found[0]
    return (directory / REFUSAL_FILE).read_text() if (directory / REFUSAL_FILE).exists() else None


def isolated_repetition(directory: Path, workload: BaseModel, rules: dict[str, Any], sdk: Path,
                        instrumentation: Instrumentation, seed: int, sql: str, redis_commands: list[str], module: str,
                        build: Path) -> Statuses:
    """One run of a build of a system's services under a rule set and a seed for its rules' draws, with a fresh
    database and cache seeded as given and, with faultpoint, the kernel agent watching the upstream containers,
    attaching what it selects of the build's hook catalog; the system's deployment module serves and loads it in a
    namespace of its own, and its observations stay in its directory."""
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    (directory / WORKLOAD_FILE).write_text(workload.model_dump_json())
    (directory / RULES_FILE).write_text(json.dumps(rules))
    (directory / INSTRUMENTATION_FILE).write_text(instrumentation.model_dump_json())
    (directory / SEED_FILE).write_text(str(seed))
    prefix = f"fp-{sha256(str(directory).encode()).hexdigest()[:12]}"
    remove_containers(prefix)
    try:
        upstream = start_upstream(prefix, sql, redis_commands)
        (directory / UPSTREAM_FILE).write_text(upstream.model_dump_json())
        agent = start_agent(directory, directory / RULES_FILE, upstream, sdk, prefix, FLUSH_SECONDS,
                            instrumentation.agent, build / HOOKS_DIRECTORY) \
            if instrumentation.attached and instrumentation.agent is not None else None
        namespaced_run(directory, sdk, module, build)
        if agent is not None:
            stop_agent(agent, directory)
    finally:
        remove_containers(prefix)
    return Statuses.model_validate_json((directory / STATUSES_FILE).read_text())


def stock_sql(workload: Workload) -> str:
    """Inventory's stock: every SKU of every tenant with the workload's stock."""
    stock = ", ".join(f"('{sku}', {workload.stock_per_sku})"
                      for tenant in workload.tenant_names() for sku in workload.skus(tenant))
    return f"CREATE TABLE stock (sku TEXT PRIMARY KEY, available INTEGER); INSERT INTO stock VALUES {stock};"


def repetition(directory: Path, workload: dict[str, JsonValue], rules: dict[str, Any], sdk: Path,
               instrumentation: dict[str, JsonValue], seed: int) -> Statuses:
    """One run of the whole shop under a rule set, with inventory's stock in PostgreSQL and an empty price cache."""
    shop = Workload.model_validate(workload)
    return isolated_repetition(directory, shop, rules, sdk, Instrumentation.model_validate(instrumentation), seed,
                               stock_sql(shop), [], "shop.deployment", BUILD)


SYSTEM: Final = System(name="shop", scenarios=SCENARIOS, manifests=MANIFESTS, entry_service="gateway", ports=PORTS,
                       upstream=UPSTREAM_SERVICES, targets=UNSCOPED_TARGETS, configured=PACKET_POINTS,
                       instrumentation=Instrumentation().model_dump(mode="json"), build=build,
                       verified_build=verified_build, repetition=repetition, refusal=refusal)


if __name__ == "__main__":
    serve_and_load(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
