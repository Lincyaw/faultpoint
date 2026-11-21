import importlib.resources
import re
from typing import Any, Final, Self

from jsonschema import Draft202012Validator
from pydantic import BaseModel

from faultpoint.rules import STRICT, Rule, RuleSet

KINDS_FILE: Final = ("spec", "kinds.json")
"""spec/kinds.json inside the package: a link to the repository's file in a checkout, its content in a wheel."""


class KindSpec(BaseModel):
    """One kind of the kind table: its actions and outcomes, and the constraints on its rules."""

    model_config = STRICT

    actions: tuple[str, ...]
    outcomes: tuple[str, ...]
    status: bool = False
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
        if error is not None and spec.errors is not None and error not in spec.errors:
            problems.append(f"a {rule.kind} point fails with one of {list(spec.errors)}, not {error}")
        if isinstance(error, str) and spec.error_pattern is not None and not spec.error_pattern.match(error):
            problems.append(f"a {rule.kind} point fails with an error matching {spec.error_pattern.pattern}")
        if spec.error_required and "error" in schema.get("properties", {}) and error is None:
            problems.append(f"a {rule.kind} point needs an error for {action}")
        if rule.scope and not spec.scope:
            problems.append(f"a {rule.kind} point sees no request baggage, so its rule has no scope")
        return problems
