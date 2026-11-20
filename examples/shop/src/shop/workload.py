from pathlib import Path
from string import ascii_lowercase
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, PositiveInt

SHOP: Final = Path(__file__).resolve().parents[2]
SCENARIOS: Final = SHOP / "scenarios.json"
FROZEN: Final = ConfigDict(frozen=True, extra="forbid")


class Workload(BaseModel):
    """The data a repetition starts from and the checkouts every tenant sends."""

    model_config = FROZEN

    tenants: int = Field(ge=1, le=len(ascii_lowercase))
    stock_per_sku: int = Field(ge=0)
    balance: int = Field(ge=0)
    """The balance of every tenant's account."""
    sku_numbers: tuple[PositiveInt, ...] = Field(min_length=1)
    """The SKU mix: every tenant sells <tenant>-<number> for each number, which pricing reads."""
    quantities: tuple[PositiveInt, ...] = Field(min_length=1)
    """The quantity pattern, cycled over a tenant's checkouts."""
    reserve_timeout_s: float = Field(gt=0)
    """The timeout of the orders service's client, which retries the inventory call."""

    def tenant_names(self) -> list[str]:
        return list(ascii_lowercase[:self.tenants])

    def skus(self, tenant: str) -> list[str]:
        return [f"{tenant}-{number}" for number in self.sku_numbers]

    def with_changes(self, changes: dict[str, JsonValue]) -> Self:
        return self.model_validate({**self.model_dump(), **changes})


class Scenario(BaseModel):
    """A business situation that changes the baseline workload, as an existing test of the shop would."""

    model_config = FROZEN

    name: str = Field(pattern=r"^[a-z0-9-]+$")
    reason: str
    changes: dict[str, JsonValue]


class Scenarios(BaseModel):
    model_config = FROZEN

    baseline: Workload
    scenarios: tuple[Scenario, ...]

    @classmethod
    def read(cls, path: Path = SCENARIOS) -> Self:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def named(self, name: str) -> Scenario:
        return {scenario.name: scenario for scenario in self.scenarios}[name]

    def workload(self, name: str) -> Workload:
        return self.baseline.with_changes(self.named(name).changes)
