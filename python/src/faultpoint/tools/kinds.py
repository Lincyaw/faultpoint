import importlib.resources
import re
from collections.abc import Iterable
from typing import Any, Final, Self

from jsonschema import Draft202012Validator
from pydantic import BaseModel

from faultpoint.actions import ONE_FAILURE
from faultpoint.placement import Manifest
from faultpoint.rules import STRICT, Rule, RuleSet

KINDS_FILE: Final = ("spec", "kinds.json")
"""spec/kinds.json inside the package: a link to the repository's file in a checkout, its content in a wheel."""


class KindSpec(BaseModel):
    """One kind of the kind table: its actions and outcomes, and the constraints on its rules."""

    model_config = STRICT

    actions: tuple[str, ...]
    outcomes: tuple[str, ...]
    status: bool = False
    code: bool = False
    """Whether fail may name the code the client library reports, such as a SQLSTATE or a Redis error prefix."""
    errors: tuple[str, ...] | None = None
    scope: bool = True
    error_pattern: re.Pattern[str] | None = None
    error_required: bool = False
    details: tuple[str, ...] = ()
    """The keys an observation of this kind may carry in its detail."""


class KindTable(BaseModel):
    """spec/kinds.json: the JSON Schema of every action's parameters, and every kind."""

    model_config = STRICT

    actions: dict[str, dict[str, Any]]
    kinds: dict[str, KindSpec]

    @classmethod
    def installed(cls) -> Self:
        return cls.model_validate_json(importlib.resources.files("faultpoint").joinpath(*KINDS_FILE).read_bytes())

    def violations(self, ruleset: RuleSet) -> list[str]:
        return [f"rule {rule.id}: {problem}" for rule in ruleset.rules for problem in self.rule_violations(rule)]

    def rule_violations(self, rule: Rule) -> list[str]:
        spec = self.kinds.get(rule.kind)
        action = rule.action.kind
        if spec is None:
            return [f"the kind {rule.kind} is not in the kind table"]
        if action not in spec.actions:
            return [f"a {rule.kind} point does not execute {action}"]
        schema = self.actions[action]
        parameters = rule.action.model_dump(exclude={"kind"})
        error = parameters.get("error")
        problems = [issue.message for issue in Draft202012Validator(schema).iter_errors(parameters)]
        if "status" in parameters and not spec.status:
            problems.append(f"a {rule.kind} point responds with no status")
        if "code" in parameters and not spec.code:
            problems.append(f"a {rule.kind} point fails with no client library code")
        if "code" in parameters and error is not None:
            problems.append(ONE_FAILURE)
        if error is not None and spec.errors is not None and error not in spec.errors:
            problems.append(f"a {rule.kind} point fails with one of {list(spec.errors)}, not {error}")
        if isinstance(error, str) and spec.error_pattern is not None and not spec.error_pattern.match(error):
            problems.append(f"a {rule.kind} point fails with an error matching {spec.error_pattern.pattern}")
        if spec.error_required and "error" in schema.get("properties", {}) and error is None:
            problems.append(f"a {rule.kind} point needs an error for {action}")
        if rule.scope and not spec.scope:
            problems.append(f"a {rule.kind} point sees no request baggage, so its rule has no scope")
        return problems


def manifest_violations(ruleset: RuleSet, manifests: Iterable[Manifest]) -> list[str]:
    """The rules whose point is narrower than its kind in a manifest and that ask for another action, those that
    name an error the manifest's build does not register, and those missing from the manifests of their service
    that list points of their kind; a boundary point, which no manifest lists, is never missing."""
    points = {point.id: (point, manifest.errors) for manifest in manifests for point in manifest.points}
    listed = {(manifest.service, point.kind) for manifest in manifests for point in manifest.points}
    violations = []
    for rule in ruleset.rules:
        point, errors = points.get(rule.point, (None, ()))
        error = rule.action.model_dump().get("error")
        if point is None and (rule.service, rule.kind) in listed:
            violations.append(f"rule {rule.id}: {rule.point} is in no manifest of {rule.service}")
        if point is not None and point.actions is not None and rule.action.kind not in point.actions:
            violations.append(f"rule {rule.id}: {rule.point} implements only {', '.join(point.actions)}")
        if errors and error is not None and error not in errors:
            violations.append(f"rule {rule.id}: {rule.point} fails only with the errors its build registers, "
                              f"not {error}")
    return violations
