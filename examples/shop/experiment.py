import argparse
import json
import subprocess
from pathlib import Path
from typing import Final

from pydantic import BaseModel, JsonValue, TypeAdapter

from shop.deployment import (MANIFESTS, RESPONSES_FILE, RUNS, SCOPE_KEY, Instrumentation, Responses, build, refusal,
                             repetition, run, verified_build)
from shop.upstream import PACKET_POINTS, AgentObservation
from shop.workload import FROZEN, Scenarios

TREATED_TENANT: Final = "a"
UNSCOPED: Final = ""
SHOWN_DIFFERENCES: Final = 3
"""The differing responses a transparency check prints of each scenario."""


class PointRule(BaseModel):
    """A rule of a treatment: the action at the one point of a service and kind whose id is, or whose id or code
    contains, a text; in a tenant's scope, or outside any scope when tenant is none."""

    model_config = FROZEN

    service: str
    kind: str
    contains: str
    action: dict[str, JsonValue]
    tenant: str | None = TREATED_TENANT
    trigger: dict[str, JsonValue] = {}


Treatments = TypeAdapter(dict[str, list[PointRule]])


def known_points(control: str) -> dict[str, str]:
    """Every point id with the text it is recognised by: the manifests' code for placed points, and the id itself
    for the boundary points the control run observed and for the packet points the deployment configures."""
    points = {record["point"]: record["point"] for path in (RUNS / control).glob("*.jsonl")
              for record in map(json.loads, path.read_text().splitlines())} | {point: point for point in PACKET_POINTS}
    for manifest in MANIFESTS.glob("*.json"):
        points.update({point["id"]: f"{point['id']} {point['code']}" for point in json.loads(manifest.read_text())["points"]})
    return points


def find_point(control: str, service: str, kind: str, contains: str) -> str:
    """The point of a service and kind whose id is a text, or else the one whose id or code contains it."""
    found = sorted(point for point, text in known_points(control).items()
                   if point.startswith(f"{service}:{kind}:") and contains in text)
    if contains in found:
        return contains
    if len(found) != 1:
        raise LookupError(f"{service}:{kind} with {contains!r} matches {found}")
    return found[0]


TREATMENTS: Final = {
    "inventory-read-empty": [PointRule(service="inventory", kind="store_read", contains="stock",
                                       action={"kind": "empty"})],
    "reserve-fail-after": [PointRule(service="orders", kind="rpc_client", contains="/reserve",
                                     action={"kind": "fail_after", "error": "timeout"})],
    "pricing-unavailable": [PointRule(service="pricing", kind="rpc_server", contains="/price",
                                      action={"kind": "fail", "status": 503})],
    "ledger-declines": [PointRule(service="ledger", kind="branch", contains="InsufficientFunds",
                                  action={"kind": "fail"})],
    "pricing-discount": [PointRule(service="pricing", kind="check", contains="discounted", action={"kind": "negate"})],
    "redis-lookup-miss": [PointRule(service="redis", kind="call", contains="lookupKey",
                                    action={"kind": "fail", "error": "NULL"}, tenant=None)],
    "postgres-client-eof": [PointRule(service="postgres", kind="call", contains="pq_getbyte",
                                      action={"kind": "fail", "error": "EOF"}, tenant=None)],
}
"""Faults at points of the shop's services, injected in tenant a, and at points the kernel agent places in an upstream
component, which no rule can scope and so reach every tenant."""


def rule_of(name: str, index: int, point_rule: PointRule, control: str) -> dict[str, JsonValue]:
    point = find_point(control, point_rule.service, point_rule.kind, point_rule.contains)
    return ({"id": f"{name}-{index}", "point": point, "action": point_rule.action}
            | ({"scope": {SCOPE_KEY: point_rule.tenant}} if point_rule.tenant is not None else {})
            | ({"trigger": point_rule.trigger} if point_rule.trigger else {}))


def compare_transparency(sdk: Path, instrumentation: Instrumentation) -> None:
    """Run every scenario once without faultpoint and once with it and no rule, and show whether the users received
    the same responses, status and body, in the same order."""
    scenarios = Scenarios.read()
    runs = {"detached": Instrumentation(attached=False), "attached": instrumentation}
    for scenario in scenarios.scenarios:
        workload = scenarios.workload(scenario.name).model_dump(mode="json")
        received = {}
        for mode, chosen in runs.items():
            label = f"transparency-{scenario.name}-{mode}"
            print(label, repetition(RUNS / label, workload, {"experiment": label, "rules": []}, sdk, chosen),
                  flush=True)
            received[mode] = Responses.model_validate_json((RUNS / label / RESPONSES_FILE).read_text()).responses
        # Both send the same sequence, so a run that answered fewer requests within the load's deadline differs.
        pairs = list(zip(received["detached"], received["attached"]))
        differing = [(index, detached, attached) for index, (detached, attached) in enumerate(pairs)
                     if detached != attached]
        print(f"== {scenario.name}: {len(pairs) - len(differing)} of {len(received['detached'])} responses without "
              f"faultpoint and {len(received['attached'])} with it the same", flush=True)
        for index, detached, attached in differing[:SHOWN_DIFFERENCES]:
            print(f"   #{index} without {detached.status} {detached.body[:120]!r}, "
                  f"with {attached.status} {attached.body[:120]!r}", flush=True)


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
    parser.add_argument("--treatments-file", type=Path,
                        help="Further treatments, by name, as JSON lists of rules of the PointRule form.")
    parser.add_argument("--all-syscalls", action="store_true",
                        help="Let the kernel agent report the natural results of every syscall, not of a chosen few.")
    parser.add_argument("--hooks", type=Path, help=(
        "A JSON file of the records of the build's hook catalog the kernel agent attaches, per upstream service, in "
        "the shape of its hooks options."))
    parser.add_argument("--controls-only", action="store_true", help="Run the control repetitions and no treatment.")
    parser.add_argument("--transparency", action="store_true", help=(
        "Instead, run every scenario once without faultpoint, no SDK, FAULTPOINT_ variable or kernel agent, and once "
        "with it and no rule, and compare the responses."))
    parser.add_argument("treatments", nargs="*", default=list(TREATMENTS))
    arguments = parser.parse_args()
    treatments = TREATMENTS | (Treatments.validate_json(arguments.treatments_file.read_bytes())
                               if arguments.treatments_file else {})
    instrumentation = Instrumentation(agent=AgentObservation(
        **({"syscalls": None} if arguments.all_syscalls else {}),
        **({"hooks": json.loads(arguments.hooks.read_text())} if arguments.hooks else {})))
    sdk = arguments.sdk_root.resolve()
    commit = verified_build(sdk) if arguments.skip_build else build(sdk)
    print(f"SDK commit {commit} from {sdk}", flush=True)
    if arguments.transparency:
        compare_transparency(sdk, instrumentation)
        return
    workload = Scenarios.read().workload(arguments.scenario).model_dump(mode="json")
    controls = [f"control-{index}" for index in range(arguments.repetitions)]
    for label in controls:
        print(label, repetition(RUNS / label, workload, {"experiment": label, "rules": []}, sdk, instrumentation),
              flush=True)
    for name in [] if arguments.controls_only else arguments.treatments:
        rules = [rule_of(name, index, point_rule, controls[0]) for index, point_rule in enumerate(treatments[name])]
        labels = [f"{name}-{index}" for index in range(arguments.repetitions)]
        refused = False
        for label in labels:
            try:
                print(label, repetition(RUNS / label, workload, {"experiment": label, "rules": rules}, sdk,
                                        instrumentation), flush=True)
            except subprocess.CalledProcessError:
                refused = True
                print(label, "refused:", refusal(RUNS / label), flush=True)
        if refused:
            continue
        reports = sorted(str(path) for label in controls + labels for path in (RUNS / label).glob("*.jsonl"))
        tenants = {point_rule.tenant for point_rule in treatments[name]}
        # A rule outside any scope reaches every tenant, so tenant a stands for them beside the unscoped records.
        scopes = sorted({UNSCOPED, TREATED_TENANT} if None in tenants else tenants)
        for scope in scopes:
            print(f"\n== {name}: {json.dumps(rules)}, compared in scope {scope!r}", flush=True)
            run(["uv", "run", "--extra", "tools", "faultpoint", "diff", *reports,
                 *[f"--control={label}@{scope}" for label in controls],
                 *[f"--treatment={label}@{scope}" for label in labels]], sdk / "python")


if __name__ == "__main__":
    main()
