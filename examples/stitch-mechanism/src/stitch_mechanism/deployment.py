import os
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from string import ascii_lowercase
from typing import Any, Final

from pydantic import BaseModel, Field, JsonValue, PositiveInt
from shop.deployment import (FLUSH_SECONDS, HOOKS_DIRECTORY, IDENTIFIER_SEGMENT, INSTRUMENTATION_FILE, LOAD_DEADLINE_S,
                             REDIS_KEY_IDENTIFIER, WORKLOAD_FILE, Instrumentation, Response, Service, Statuses, System,
                             answered, built_commit, isolated_repetition, record_responses, run, sdk_commit,
                             service_environment, start, tenant_request, wait_for_host_route, wait_for_port,
                             write_config)
from shop.upstream import UPSTREAM_FILE, Upstream, scan_hooks
from shop.workload import FROZEN

MECHANISM: Final = Path(__file__).resolve().parents[2]
SCENARIOS: Final = MECHANISM / "scenarios.json"
RUNS: Final = MECHANISM.parent.parent / "runs" / "stitch-mechanism"
PORTS: Final = {"quote": 27280, "catalog": 27281}
QUOTE_PLUGINS: Final = ["points", "import-hook", "httpx", "asgi"]
QUOTE_CATALOG_TIMEOUT_S: Final = 2.0
CATALOG_POOL_SIZE: Final = 1
CATALOG_DB_BUDGET_MS: Final = 400
"""The database work a catalog request may take, waiting for a connection included: several times one uncached
computation on a loaded host, and a fraction of the wait behind a flash sale's queue at the connection."""
LIST_PRICES: Final = {1: 1000, 2: 1200, 3: 1500}
DISCOUNT_RULES_PER_SKU: Final = 150000
"""The discount rules the catalog scans to price a SKU it has not cached, which make that work take tens of ms."""
DISCOUNT_MODULUS: Final = 90
ACTIVE_RULE_MODULUS: Final = 7
CACHE_TTL_S: Final = 600


class Workload(BaseModel):
    """The quotes every tenant sends and the prices the cache holds when a repetition starts."""

    model_config = FROZEN

    tenants: int = Field(ge=1, le=len(ascii_lowercase))
    quotes_per_tenant: PositiveInt
    sku_numbers: tuple[PositiveInt, ...] = Field(min_length=1)
    """Every tenant quotes <tenant>-<number> for each number in turn."""
    cached_sku_numbers: tuple[PositiveInt, ...]
    """The SKU numbers whose prices the cache holds at the start; the others are new products the catalog computes."""
    concurrency: PositiveInt
    """How many quotes are in flight at once."""
    guaranteed: bool
    """Whether the quotes guarantee their price, so that quote cannot answer with an estimate."""

    def tenant_names(self) -> list[str]:
        return list(ascii_lowercase[:self.tenants])

    def skus(self, tenant: str) -> list[str]:
        return [f"{tenant}-{number}" for number in self.sku_numbers]


class Build(BaseModel):
    """A build of the constructed system in a directory of its own, catalog's rewrite registering the exported error
    variables of the packages it names, with its manifests and its hook catalog."""

    model_config = FROZEN

    name: str
    directory: Path
    error_packages: tuple[str, ...]

    @property
    def manifests(self) -> Path:
        return self.directory / "manifests"

    @property
    def built_from(self) -> Path:
        return self.directory / "sdk-commit"


def quote_config() -> dict[str, JsonValue]:
    return {"plugins": QUOTE_PLUGINS, "options": {"asgi": {"identifier_segment": IDENTIFIER_SEGMENT},
                                                  "httpx": {"identifier_segment": IDENTIFIER_SEGMENT}}}


def build(sdk: Path, variant: Build) -> str:
    """Build the kernel agent, quote's environment with the Python SDK and catalog from an instrumented copy, and
    return the SDK's commit."""
    commit = sdk_commit(sdk)
    directory = variant.directory
    directory.mkdir(parents=True, exist_ok=True)
    run(["go", "build", "-o", "fpebpf", "."], sdk / "ebpf", {"CGO_ENABLED": "0"})
    scan_hooks(sdk, directory / HOOKS_DIRECTORY)
    run(["uv", "sync", "-q"], MECHANISM / "quote")
    # Python plugins are found through the faultpoint.plugins entry points, which only an installed package exposes.
    run(["uv", "pip", "install", "-q", "--python", str(MECHANISM / "quote" / ".venv"), "-e", str(sdk / "python")],
        MECHANISM / "quote")
    go_copy = directory / "catalog"
    shutil.rmtree(go_copy, ignore_errors=True)
    placement = {"scope": [], "error_packages": list(variant.error_packages)}
    run(["go", "build", "-o", str(directory / "fprewrite"), "."], sdk / "go" / "rewrite")
    run([str(directory / "fprewrite"), "instrument", "-service", "catalog", "-source", str(MECHANISM / "catalog"),
         "-target", str(go_copy), "-sdk", str(sdk / "go"), "-config",
         str(write_config(directory / "catalog.build.json", {"placement": placement}))], MECHANISM)
    run(["go", "build", "-o", str(directory / "catalog-bin"), "."], go_copy)
    variant.manifests.mkdir(parents=True, exist_ok=True)
    run(["uv", "run", "--extra", "tools", "faultpoint", "scan", str(MECHANISM / "quote"), "--service", "quote",
         "--config", str(write_config(directory / "quote.scan.json", quote_config())),
         "--output", str(variant.manifests / "quote.json")], sdk / "python")
    shutil.copy(go_copy / "faultpoint-manifest.json", variant.manifests / "catalog.json")
    variant.built_from.write_text(commit)
    return commit


def verified_build(sdk: Path, variant: Build) -> str:
    return built_commit(sdk, variant.built_from)


def services(sdk: Path, build: Path, upstream: Upstream) -> list[Service]:
    routes = {"identifier_segment": IDENTIFIER_SEGMENT}
    return [
        Service(name="quote", port=PORTS["quote"],
                command=[str(MECHANISM / "quote" / ".venv" / "bin" / "uvicorn"), "quote:app", "--port",
                         str(PORTS["quote"]), "--log-level", "warning"],
                directory=MECHANISM / "quote", config=quote_config(), environment={
                    "CATALOG_URL": f"http://127.0.0.1:{PORTS['catalog']}",
                    "CATALOG_TIMEOUT_S": str(QUOTE_CATALOG_TIMEOUT_S)},
                # The Python SDK attaches at start through the sitecustomize of its bootstrap directory; quote's own
                # directory lets a rule name an exception class of the quote module.
                attachment={"PYTHONPATH": os.pathsep.join([str(sdk / "python" / "src" / "faultpoint" / "bootstrap"),
                                                           str(MECHANISM / "quote")]),
                            "FAULTPOINT_SOURCE_ROOT": str(MECHANISM / "quote")}),
        Service(name="catalog", port=PORTS["catalog"], command=[str(build / "catalog-bin")], directory=build,
                config={"options": {"http": routes, "redis": {"key_identifier": REDIS_KEY_IDENTIFIER}}},
                environment={"CATALOG_DATABASE": f"{upstream.database} pool_max_conns={CATALOG_POOL_SIZE}",
                             "REDIS_URL": upstream.redis_url, "CATALOG_DB_BUDGET_MS": str(CATALOG_DB_BUDGET_MS)}),
    ]


def largest_discount() -> int:
    """The largest discount of a SKU's active rules, which the seed's rules give every SKU."""
    return max(rule % DISCOUNT_MODULUS for rule in range(1, DISCOUNT_RULES_PER_SKU + 1)
               if rule % ACTIVE_RULE_MODULUS == 0)


def price_sql(workload: Workload) -> str:
    """Every SKU's list price and its discount rules, of which every seventh is active."""
    prices = ", ".join(f"('{tenant}-{number}', {LIST_PRICES[number]})"
                       for tenant in workload.tenant_names() for number in workload.sku_numbers)
    return (f"CREATE TABLE prices (sku TEXT PRIMARY KEY, list_price BIGINT); INSERT INTO prices VALUES {prices}; "
            "CREATE TABLE discount_rules (sku TEXT, discount BIGINT, active BOOLEAN); "
            f"INSERT INTO discount_rules SELECT sku, rule % {DISCOUNT_MODULUS}, rule % {ACTIVE_RULE_MODULUS} = 0 "
            f"FROM prices, generate_series(1, {DISCOUNT_RULES_PER_SKU}) AS rule; ANALYZE;")


def cache_commands(workload: Workload) -> list[str]:
    """The prices of the cached SKU numbers, as the catalog would have written them."""
    return [f"SET price:{tenant}-{number} {LIST_PRICES[number] - largest_discount()} EX {CACHE_TTL_S}"
            for tenant in workload.tenant_names() for number in workload.cached_sku_numbers]


def load(workload: Workload) -> list[Response]:
    """The same sequence of quotes in every repetition, the tenants interleaved and the workload's number of them in
    flight at once, in the order they were sent; a quote due after LOAD_DEADLINE_S is not sent."""
    quotes = [(tenant, workload.skus(tenant)[index % len(workload.sku_numbers)])
              for index in range(workload.quotes_per_tenant) for tenant in workload.tenant_names()]
    started = time.monotonic()

    def quoted(quote: tuple[str, str]) -> Response | None:
        tenant, sku = quote
        if time.monotonic() - started > LOAD_DEADLINE_S:
            return None
        return answered(tenant, tenant_request(f"http://127.0.0.1:{PORTS['quote']}/quotes", tenant,
                                               {"tenant": tenant, "sku": sku, "guaranteed": workload.guaranteed}))

    with ThreadPoolExecutor(workload.concurrency) as pool:
        return [response for response in pool.map(quoted, quotes) if response is not None]


def serve_and_load(directory: Path, sdk: Path, build: Path) -> None:
    """Start quote and a build's catalog on a repetition directory, send its workload's quotes, stop them and keep
    the responses, inside the repetition's own network namespace."""
    wait_for_host_route()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    workload = Workload.model_validate_json((directory / WORKLOAD_FILE).read_text())
    upstream = Upstream.model_validate_json((directory / UPSTREAM_FILE).read_text())
    instrumentation = Instrumentation.model_validate_json((directory / INSTRUMENTATION_FILE).read_text())
    mechanism = services(sdk, build, upstream)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        for service in mechanism:
            processes.append(start(directory, service, service_environment(directory, service, instrumentation)))
        for service, process in zip(mechanism, processes, strict=True):
            wait_for_port(directory, service, process)
        responses = load(workload)
        time.sleep(3 * FLUSH_SECONDS)
    finally:
        for process in processes:
            process.send_signal(signal.SIGTERM)
        for process in processes:
            process.wait(timeout=30)
    record_responses(directory, workload.tenant_names(), responses)


def repetition(directory: Path, workload: dict[str, JsonValue], rules: dict[str, Any], sdk: Path,
               instrumentation: Instrumentation, seed: int, variant: Build) -> Statuses:
    """One run of quote and a build's catalog under a rule set, with the prices and discount rules in PostgreSQL and
    the cached SKUs' prices in Redis."""
    mechanism = Workload.model_validate(workload)
    return isolated_repetition(directory, mechanism, rules, sdk, instrumentation, seed, price_sql(mechanism),
                               cache_commands(mechanism), "stitch_mechanism.deployment", variant.directory)


def system(variant: Build) -> System:
    """The constructed system as the search explores one of its builds."""
    return System(name=variant.name, scenarios=SCENARIOS, manifests=variant.manifests, entry_service="quote",
                  ports=PORTS, build=partial(build, variant=variant),
                  verified_build=partial(verified_build, variant=variant),
                  repetition=partial(repetition, variant=variant))


PLAIN: Final = Build(name="stitch-mechanism", directory=RUNS / "build", error_packages=())
"""Catalog registers no error variable of another package, so a deadline's error is named by its type."""
CONTEXT_SENTINELS: Final = Build(name="stitch-mechanism-context-sentinels", directory=RUNS / "build-context-sentinels",
                                 error_packages=("context",))
"""Catalog registers the error variables of the context package, so a deadline's error is named
context.DeadlineExceeded."""
SYSTEMS: Final = (system(PLAIN), system(CONTEXT_SENTINELS))


if __name__ == "__main__":
    serve_and_load(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
