import importlib.abc
import importlib.util
import sys
from collections.abc import Sequence
from importlib.machinery import ModuleSpec, PathFinder, SourceFileLoader
from pathlib import Path
from types import CodeType, ModuleType
from typing import Final

from faultpoint.placement import Placement, place_points, placeable
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
    """Finds modules as the path finder it precedes does, and places points in those under the source root."""

    def __init__(self, root: Path, service: str, placement: Placement) -> None:
        self.root = root
        self.service = service
        self.placement = placement

    def find_spec(self, fullname: str, path: Sequence[str] | None,
                  target: ModuleType | None = None) -> ModuleSpec | None:
        spec = PathFinder.find_spec(fullname, path, target)
        match spec:
            case ModuleSpec(origin=str() as origin, loader=SourceFileLoader()) if placeable(
                    Path(origin).resolve(), self.root):
                spec.loader = PlacingLoader(fullname, origin, self.service,
                                            Path(origin).resolve().relative_to(self.root).as_posix(),
                                            self.placement)
        return spec


def install(runtime: Runtime) -> None:
    finder = PlacingFinder(runtime.settings.source_root.resolve(), runtime.settings.service,
                           Placement.model_validate(runtime.config.placement))
    sys.meta_path.insert(sys.meta_path.index(PathFinder), finder)


PLUGIN: Final = Plugin(install=install)
