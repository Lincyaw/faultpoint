from pathlib import Path
from typing import Final, Self

from pydantic import BaseModel, Field, JsonValue, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from faultpoint.observations import JSONL_OPTIONS
from faultpoint.rules import STRICT

DEFAULT_PLUGINS: Final = ("points", "import-hook", "httpx", "asgi", "dbapi")


class Settings(BaseSettings):
    """The FAULTPOINT_ environment variables of a process in which faultpoint is enabled."""

    model_config = SettingsConfigDict(env_prefix="FAULTPOINT_", frozen=True)

    service: str = Field(min_length=1)
    rules: Path | None = None
    report: Path | None = None
    source_root: Path = Field(default_factory=Path.cwd)
    scope_key: str = "fp.scope"
    seed: int = 0
    config: Path | None = None


class Config(BaseModel):
    """The plugins a process enables and the sections each plugin reads and validates itself."""

    model_config = STRICT

    plugins: tuple[str, ...] = DEFAULT_PLUGINS
    options: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    """Options keyed by the name of the enabled plugin or default component that reads them."""
    placement: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_option_names(self) -> Self:
        unknown = sorted(set(self.options) - {*self.plugins, JSONL_OPTIONS})
        if unknown:
            raise ValueError(f"options are given to {unknown}, which name no enabled plugin or component")
        return self

    @classmethod
    def read(cls, path: Path | None) -> Self:
        return cls() if path is None else cls.model_validate_json(path.read_bytes())
