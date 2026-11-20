import os
from pathlib import Path
from typing import Final, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

STRICT: Final = ConfigDict(frozen=True, extra="forbid")
POINT_ID_PATTERN: Final = r"^[^:]+:[^:]+:.+$"


def point_id(service: str, kind: str, locator: str) -> str:
    if ":" in service:
        raise ValueError(f"a service name cannot contain ':': {service}")
    return f"{service}:{kind}:{locator}"


class Action(BaseModel):
    """An action kind and the free parameters the plugin that executes it interprets."""

    model_config = ConfigDict(frozen=True, extra="allow")

    kind: str = Field(min_length=1)


class Trigger(BaseModel):
    model_config = STRICT

    skip: int = Field(default=0, ge=0)
    limit: int | None = Field(default=None, ge=1)
    probability: float = Field(default=1.0, gt=0, le=1)


class Rule(BaseModel):
    model_config = STRICT

    id: str = Field(min_length=1)
    point: str = Field(pattern=POINT_ID_PATTERN)
    action: Action
    scope: dict[str, str] = Field(default_factory=dict)
    """Baggage entries a request must carry for the rule to apply."""
    trigger: Trigger = Field(default_factory=Trigger)

    @property
    def service(self) -> str:
        return self.point.split(":", 2)[0]

    @property
    def kind(self) -> str:
        return self.point.split(":", 2)[1]


class RuleSet(BaseModel):
    model_config = STRICT

    experiment: str = Field(min_length=1)
    rules: tuple[Rule, ...] = ()

    @model_validator(mode="after")
    def validate_identities(self) -> Self:
        identities = [rule.id for rule in self.rules]
        if len(identities) != len(set(identities)):
            raise ValueError("rule ids repeat")
        return self


class RuleSource(Protocol):
    def poll(self) -> RuleSet | None:
        """The rule set when it is new since the previous poll; the first poll always returns one."""
        ...


class FileRuleSource:
    """A rule set file, which a controller replaces atomically by renaming a new file over it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.version: tuple[int, int] | None = None

    def poll(self) -> RuleSet | None:
        with self.path.open("rb") as stream:
            status = os.fstat(stream.fileno())
            version = (status.st_ino, status.st_mtime_ns)
            changed = version != self.version
            self.version = version
            return RuleSet.model_validate_json(stream.read()) if changed else None
