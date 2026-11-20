from pydantic import BaseModel

from faultpoint.rules import STRICT, PointKind


class PointEntry(BaseModel):
    """One fault point a rewriter placed."""

    model_config = STRICT

    id: str
    kind: PointKind
    file: str
    line: int
    function: str
    code: str
    """The first line of the instrumented source."""


class Manifest(BaseModel):
    model_config = STRICT

    service: str
    language: str
    points: tuple[PointEntry, ...]
