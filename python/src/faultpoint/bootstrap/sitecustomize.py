import importlib.util
import os
import sys
from importlib.machinery import PathFinder
from pathlib import Path

BOOTSTRAP_DIRECTORY = Path(__file__).resolve().parent
ENABLING_VARIABLES = ("FAULTPOINT_RULES", "FAULTPOINT_REPORT")

# This directory on PYTHONPATH shadows any other sitecustomize, which still runs first.
shadowed = PathFinder.find_spec(
    "sitecustomize", [entry for entry in sys.path if Path(entry or ".").resolve() != BOOTSTRAP_DIRECTORY])
if shadowed is not None and shadowed.loader is not None:
    shadowed.loader.exec_module(importlib.util.module_from_spec(shadowed))

if any(os.environ.get(name) for name in ENABLING_VARIABLES):
    import faultpoint.runtime

    faultpoint.runtime.start()
