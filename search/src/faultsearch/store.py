from pathlib import Path
from typing import Final

from pydantic import BaseModel

SEARCH_RUNS: Final = Path(__file__).resolve().parents[3] / "runs" / "search"
REPETITIONS: Final = "repetitions"
CONTROLS: Final = "controls"
TREATMENTS: Final = "treatments"
LEAKS: Final = "leaks"
INPUTS: Final = "inputs"
SCENARIOS_INPUT: Final = "scenarios.json"
ACTIONS_INPUT: Final = "actions.json"
EFFECTS_INPUT: Final = "effects.json"
RUN_SETTINGS: Final = "run-settings.json"
ALLOCATION_SETTINGS: Final = "allocation-settings.json"
CATALOG: Final = "catalog.json"
VALIDATIONS: Final = "validations.json"
HEADROOM: Final = "headroom.json"
MAPPING_FEEDBACK: Final = "mapping-feedback.json"
REPORT: Final = "report.json"


def allocation_file(strategy: str) -> str:
    return f"allocation-{strategy}.json"


def edges_file(strategy: str) -> str:
    return f"edges-{strategy}.json"


def chains_file(strategy: str) -> str:
    return f"chains-{strategy}.json"


class Store:
    """The directory of one experiment, where every input, run and result is kept as JSON to resume and audit it."""

    def __init__(self, experiment: str) -> None:
        self.root = SEARCH_RUNS / experiment

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def has(self, *parts: str) -> bool:
        return self.path(*parts).exists()

    def save(self, model: BaseModel, *parts: str) -> None:
        path = self.path(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        # A record is written whole or not at all, so that an interrupted run resumes from complete records only.
        staging = path.with_name(f"{path.name}.partial")
        staging.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        staging.replace(path)

    def load[M: BaseModel](self, model: type[M], *parts: str) -> M:
        return model.model_validate_json(self.path(*parts).read_text(encoding="utf-8"))

    def record_input[M: BaseModel](self, model: M, *parts: str) -> M:
        """Keep an input the first time; a resumed run must use the same, so that its records stay comparable."""
        if not self.has(*parts):
            self.save(model, *parts)
        recorded = self.load(type(model), *parts)
        if recorded != model:
            raise ValueError(f"{self.path(*parts)} records another input than this run's: {recorded} != {model}")
        return recorded

    def repetition(self, label: str) -> Path:
        return self.path(REPETITIONS, label)
