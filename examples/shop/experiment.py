import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

SHOP: Final = Path(__file__).resolve().parent
ROOT: Final = SHOP.parent.parent
RUNS: Final = ROOT / "runs" / "shop"
BUILD: Final = RUNS / "build"
FLUSH_SECONDS: Final = 0.5
TENANTS: Final = ("a", "b")
REQUESTS_PER_TENANT: Final = 21
STOCK_PER_SKU: Final = 12
BALANCE: Final = 100_000
SCOPE_KEY: Final = "fp.scope"
IDENTIFIER_SEGMENT: Final = r"^(\d+|[a-z]-\d+)$"
"""Path segments that identify a record: numbers and the shop's SKUs, so that one route is one point."""
MANIFESTS: Final = BUILD / "manifests"
PORTS: Final = {"gateway": 27180, "orders": 27181, "inventory": 27182, "pricing": 27183, "ledger": 27184}


@dataclass(frozen=True)
class Service:
    name: str
    port: int
    command: list[str]
    directory: Path
    route_plugins: tuple[str, ...]
    """The plugins that turn request paths into point ids, which take the shop's identifier segments."""
    environment: dict[str, str] = field(default_factory=dict)


def run(command: list[str], directory: Path, environment: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=directory, check=True, env={**os.environ, **(environment or {})})


def java_agent(sdk: Path) -> Path:
    return sdk / "java" / "target" / "faultpoint-agent-0.1.0.jar"


def build(sdk: Path) -> None:
    """Build the SDKs of a snapshot and every service; the Go and Rust services are built from instrumented copies,
    the others attach at start."""
    BUILD.mkdir(parents=True, exist_ok=True)
    run(["npm", "install", "--silent"], sdk / "typescript")
    run(["npx", "tsc", "-p", "tsconfig.json"], sdk / "typescript")
    run(["mvn", "-q", "-B", "package", "-DskipTests"], sdk / "java")
    run(["npm", "install", "--silent"], SHOP / "gateway")
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


def services(directory: Path, sdk: Path) -> list[Service]:
    urls = {f"{name.upper()}_URL": f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
    # The Python SDK attaches at start through the sitecustomize of its bootstrap directory.
    orders_attachment = {"PYTHONPATH": str(sdk / "python" / "src" / "faultpoint" / "bootstrap"),
                         "FAULTPOINT_SOURCE_ROOT": str(SHOP / "orders")}
    return [
        Service("gateway", PORTS["gateway"], ["node", "dist/server.js"], SHOP / "gateway", ("http",), {
            "NODE_OPTIONS": f"--import {sdk / 'typescript' / 'dist' / 'register.js'}",
            "FAULTPOINT_SOURCE_ROOT": str(SHOP / "gateway" / "dist"), **urls}),
        Service("orders", PORTS["orders"], [str(SHOP / "orders" / ".venv" / "bin" / "uvicorn"), "orders:app", "--port",
                                            str(PORTS["orders"]), "--log-level", "warning"], SHOP / "orders",
                ("asgi", "httpx"), {**orders_attachment, "ORDERS_DATABASE": str(directory / "orders.db"), **urls}),
        Service("inventory", PORTS["inventory"], [str(BUILD / "inventory-bin")], directory, ("http",),
                {"INVENTORY_DATABASE": str(directory / "inventory.db")}),
        Service("pricing", PORTS["pricing"], [str(BUILD / "pricing" / "target" / "release" / "pricing")], directory,
                ("tower",)),
        Service("ledger", PORTS["ledger"], ["java", f"-javaagent:{java_agent(sdk)}", "-cp",
                                 f"{SHOP / 'ledger' / 'target' / 'classes'}:{SHOP / 'ledger' / 'target' / 'lib' / '*'}",
                                 "shop.Ledger"], directory, ("servlet",),
                {"FAULTPOINT_PACKAGES": "shop", "LEDGER_DATABASE": str(directory / "ledger.db")}),
    ]


def skus(tenant: str) -> list[str]:
    return [f"{tenant}-1", f"{tenant}-2", f"{tenant}-7"]


def seed(directory: Path) -> None:
    with sqlite3.connect(directory / "inventory.db") as inventory:
        inventory.execute("CREATE TABLE stock (sku TEXT PRIMARY KEY, available INTEGER)")
        inventory.executemany("INSERT INTO stock VALUES (?, ?)",
                              [(sku, STOCK_PER_SKU) for tenant in TENANTS for sku in skus(tenant)])
    with sqlite3.connect(directory / "ledger.db") as ledger:
        ledger.execute("CREATE TABLE accounts (id TEXT PRIMARY KEY, balance INTEGER)")
        ledger.executemany("INSERT INTO accounts VALUES (?, ?)", [(tenant, BALANCE) for tenant in TENANTS])


def listening(port: int) -> bool:
    with socket.socket() as probe:
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_for_port(port: int, process: subprocess.Popen[bytes], deadline_s: float = 60) -> None:
    started = time.monotonic()
    while time.monotonic() - started < deadline_s:
        if process.poll() is not None:
            raise RuntimeError(f"a service on port {port} exited with {process.returncode}")
        if listening(port):
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


def load() -> dict[str, dict[int, int]]:
    """The same sequence of checkouts in every repetition, the tenants interleaved."""
    statuses: dict[str, dict[int, int]] = {tenant: {} for tenant in TENANTS}
    for index in range(REQUESTS_PER_TENANT):
        for tenant in TENANTS:
            status = checkout(tenant, skus(tenant)[index % 3], 1 + index % 2)
            statuses[tenant][status] = statuses[tenant].get(status, 0) + 1
    return statuses


def repetition(label: str, rules: dict, sdk: Path) -> dict[str, dict[int, int]]:
    """One run of the whole shop under a rule set, with fresh databases; its observations stay in its directory."""
    directory = RUNS / label
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    seed(directory)
    (directory / "rules.json").write_text(json.dumps(rules))
    occupied = [port for port in PORTS.values() if listening(port)]
    if occupied:
        raise RuntimeError(f"ports {occupied} are taken by another process")
    processes = []
    try:
        for service in services(directory, sdk):
            config = directory / f"{service.name}.config.json"
            config.write_text(json.dumps({"options": {
                "jsonl": {"flush_seconds": FLUSH_SECONDS},
                **{plugin: {"identifier_segment": IDENTIFIER_SEGMENT} for plugin in service.route_plugins}}}))
            environment = {**os.environ, **service.environment, "PORT": str(service.port),
                           "FAULTPOINT_SERVICE": service.name, "FAULTPOINT_RULES": str(directory / "rules.json"),
                           "FAULTPOINT_REPORT": str(directory / f"{service.name}.jsonl"),
                           "FAULTPOINT_CONFIG": str(config)}
            log = (directory / f"{service.name}.log").open("wb")
            process = subprocess.Popen(service.command, cwd=service.directory, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT)
            processes.append(process)
            wait_for_port(service.port, process)
        statuses = load()
        time.sleep(3 * FLUSH_SECONDS)
    finally:
        for process in processes:
            process.send_signal(signal.SIGTERM)
        for process in processes:
            process.wait(timeout=30)
    return statuses


def known_points(control: str) -> dict[str, str]:
    """Every point id with the text it is recognised by: the manifests' code for placed points, and the id itself
    for the boundary points the control run observed."""
    points = {record["point"]: record["point"] for path in (RUNS / control).glob("*.jsonl")
              for record in map(json.loads, path.read_text().splitlines())}
    for manifest in MANIFESTS.glob("*.json"):
        points.update({point["id"]: f"{point['id']} {point['code']}" for point in json.loads(manifest.read_text())["points"]})
    return points


def find_point(control: str, service: str, kind: str, contains: str) -> str:
    """The one point of a service and kind whose id or code contains a text."""
    found = sorted(point for point, text in known_points(control).items()
                   if point.startswith(f"{service}:{kind}:") and contains in text)
    if len(found) != 1:
        raise LookupError(f"{service}:{kind} with {contains!r} matches {found}")
    return found[0]


TREATMENTS: Final = {
    "inventory-read-empty": ("inventory", "store_read", "stock", {"kind": "empty"}),
    "reserve-fail-after": ("orders", "rpc_client", "/reserve", {"kind": "fail_after", "error": "timeout"}),
    "pricing-unavailable": ("pricing", "rpc_server", "/price", {"kind": "fail", "status": 503}),
    "ledger-declines": ("ledger", "branch", "InsufficientFunds", {"kind": "fail"}),
    "pricing-discount": ("pricing", "check", "discounted", {"kind": "negate"}),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=(
        "Build the five shop services with faultpoint attached, run control and treatment repetitions under the "
        "same load, and compare them with faultpoint diff."))
    parser.add_argument("--sdk-root", type=Path, required=True,
                        help="A checkout of one commit of this repository, e.g. a git worktree, whose SDKs are used.")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("treatments", nargs="*", default=list(TREATMENTS))
    arguments = parser.parse_args()
    sdk = arguments.sdk_root.resolve()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=sdk, check=True, capture_output=True,
                            text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "python", "go", "typescript", "java", "rust"],
                           cwd=sdk, check=True, capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError(f"the SDKs in {sdk} differ from commit {commit}:\n{dirty}")
    print(f"SDK commit {commit} from {sdk}", flush=True)
    if not arguments.skip_build:
        build(sdk)
    controls = [f"control-{index}" for index in range(arguments.repetitions)]
    for label in controls:
        print(label, repetition(label, {"experiment": label, "rules": []}, sdk), flush=True)
    for name in arguments.treatments:
        service, kind, contains, action = TREATMENTS[name]
        point = find_point(controls[0], service, kind, contains)
        labels = [f"{name}-{index}" for index in range(arguments.repetitions)]
        for label in labels:
            rules = {"experiment": label, "rules": [{"id": name, "point": point, "action": action,
                                                     "scope": {SCOPE_KEY: "a"}}]}
            print(label, repetition(label, rules, sdk), flush=True)
        reports = sorted(str(path) for label in controls + labels for path in (RUNS / label).glob("*.jsonl"))
        print(f"\n== {name}: {action} at {point}, scope a", flush=True)
        run(["uv", "run", "--extra", "tools", "faultpoint", "diff", *reports,
             *[f"--control={label}@a" for label in controls], *[f"--treatment={label}@a" for label in labels]],
            sdk / "python")


if __name__ == "__main__":
    main()
