import argparse
import json
from pathlib import Path
from typing import Final

from shop.deployment import MANIFESTS, RUNS, SCOPE_KEY, build, repetition, run, verified_build
from shop.upstream import UPSTREAM_SERVICES
from shop.workload import Scenarios

TREATED_TENANT: Final = "a"
UNSCOPED: Final = ""


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
    "redis-lookup-miss": ("redis", "call", "lookupKey", {"kind": "fail", "error": "NULL"}),
    "postgres-client-eof": ("postgres", "call", "pq_getbyte", {"kind": "fail", "error": "EOF"}),
}
"""Faults at points of the shop's services, injected in tenant a, and at points the kernel agent places in an upstream
component, which no rule can scope and so reach every tenant."""


def main() -> None:
    parser = argparse.ArgumentParser(description=(
        "Build the five shop services with faultpoint attached, run control and treatment repetitions under the "
        "same load, and compare them with faultpoint diff. Run it in the shop's project: "
        "uv run --project examples/shop examples/shop/experiment.py --sdk-root ..."))
    parser.add_argument("--sdk-root", type=Path, required=True,
                        help="A checkout of one commit of this repository, e.g. a git worktree, whose SDKs are used.")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--scenario", default="limited-stock", help="The workload, a scenario of scenarios.json.")
    parser.add_argument("treatments", nargs="*", default=list(TREATMENTS))
    arguments = parser.parse_args()
    sdk = arguments.sdk_root.resolve()
    commit = verified_build(sdk) if arguments.skip_build else build(sdk)
    print(f"SDK commit {commit} from {sdk}", flush=True)
    workload = Scenarios.read().workload(arguments.scenario)
    controls = [f"control-{index}" for index in range(arguments.repetitions)]
    for label in controls:
        print(label, repetition(RUNS / label, workload, {"experiment": label, "rules": []}, sdk), flush=True)
    for name in arguments.treatments:
        service, kind, contains, action = TREATMENTS[name]
        point = find_point(controls[0], service, kind, contains)
        scoped = service not in UPSTREAM_SERVICES
        labels = [f"{name}-{index}" for index in range(arguments.repetitions)]
        for label in labels:
            rule = {"id": name, "point": point, "action": action} | (
                {"scope": {SCOPE_KEY: TREATED_TENANT}} if scoped else {})
            print(label, repetition(RUNS / label, workload, {"experiment": label, "rules": [rule]}, sdk), flush=True)
        reports = sorted(str(path) for label in controls + labels for path in (RUNS / label).glob("*.jsonl"))
        for scope in [TREATED_TENANT] if scoped else [TREATED_TENANT, UNSCOPED]:
            print(f"\n== {name}: {action} at {point}, compared in scope {scope!r}", flush=True)
            run(["uv", "run", "--extra", "tools", "faultpoint", "diff", *reports,
                 *[f"--control={label}@{scope}" for label in controls],
                 *[f"--treatment={label}@{scope}" for label in labels]], sdk / "python")


if __name__ == "__main__":
    main()
