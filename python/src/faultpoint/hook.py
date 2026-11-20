import importlib.abc
import importlib.util
import sys
from collections.abc import Sequence
from importlib.machinery import ModuleSpec, PathFinder, SourceFileLoader
from pathlib import Path
from types import CodeType, ModuleType
from typing import Final

from pydantic import JsonValue

from faultpoint.placement import Placement, Scope, place_points
from faultpoint.runtime import Plugin, Runtime


class PlacingLoader(SourceFileLoader):
    """Loads a module with its points placed, bypassing the bytecode cache so that placed code is never cached."""

    def __init__(self, fullname: str, path: str, service: str, relative: str, placement: Placement) -> None:
        super().__init__(fullname, path)
        self.service = service
        self.relative = relative
        self.placement = placement

    def get_code(self, fullname: str) -> CodeType:
        path = self.get_filename(fullname)
        source = importlib.util.decode_source(self.get_data(path))
        module, _ = place_points(source, self.service, self.relative, self.placement)
        return compile(module, path, "exec", dont_inherit=True)


class PlacingFinder(importlib.abc.MetaPathFinder):
    """Finds modules as the path finder it precedes does, and places points in the pure-Python modules the scope
    locates."""

    def __init__(self, scope: Scope, service: str) -> None:
        self.scope = scope
        self.service = service

    def find_spec(self, fullname: str, path: Sequence[str] | None,
                  target: ModuleType | None = None) -> ModuleSpec | None:
        spec = PathFinder.find_spec(fullname, path, target)
        match spec:
            case ModuleSpec(origin=str() as origin, loader=SourceFileLoader()):
                located = self.scope.locate(fullname, Path(origin).resolve())
                if located is not None:
                    spec.loader = PlacingLoader(fullname, origin, self.service, *located)
        return spec


def install(runtime: Runtime, options: dict[str, JsonValue]) -> None:
    scope = Scope(runtime.settings.source_root, Placement.model_validate(runtime.config.placement))
    sys.meta_path.insert(sys.meta_path.index(PathFinder), PlacingFinder(scope, runtime.settings.service))


PLUGIN: Final = Plugin(install=install)
