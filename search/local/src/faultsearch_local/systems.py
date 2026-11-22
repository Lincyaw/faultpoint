from collections.abc import Callable
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Final

from faultsearch.counterfactual import Statuses, Workload
from pydantic import BaseModel, ConfigDict, JsonValue

SYSTEMS_GROUP: Final = "faultsearch.systems"
"""The entry point group a system registers itself in, so that the local executor runs it without importing it."""


class System(BaseModel):
    """A system the local executor runs: its scenarios and manifests, the service whose responses the user sees, the
    port each service listens on and the upstream components it uses, how to build it, how to run one repetition of it
    under a rule set with a seed into a run directory, and how to tell that a service refused a rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    scenarios: Path
    manifests: Path
    entry_service: str
    ports: dict[str, int]
    upstream: frozenset[str]
    """The services of the upstream components in point ids."""
    targets: dict[str, str]
    """What a fault no rule can scope acts on, by the service of its point: the whole of a container."""
    configured: tuple[str, ...]
    """The points the deployment configures rather than a control shows, such as the upstream components' packets."""
    instrumentation: dict[str, JsonValue]
    """How the system's repetitions are instrumented unless an experiment says otherwise, as its deployment reads it."""
    build: Callable[[Path], str]
    verified_build: Callable[[Path], str]
    repetition: Callable[[Path, Workload, dict[str, Any], Path, dict[str, JsonValue], int], Statuses]
    refusal: Callable[[Path], str | None]


def installed_systems() -> dict[str, System]:
    """Every system an installed package registers, by name."""
    systems = {}
    for entry in entry_points(group=SYSTEMS_GROUP):
        system = entry.load()
        if not isinstance(system, System):
            raise TypeError(f"the {SYSTEMS_GROUP} entry point {entry.name} is not a System")
        systems[system.name] = system
    return systems
