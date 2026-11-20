import atexit
import os
import random
import socket
import sys
import threading
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from faultpoint.context import current_scope, current_trace_id, scope_matches
from faultpoint.observations import Tally, append_records
from faultpoint.rules import Action, Crash, Delay, Rule, RuleSet

WATCH_INTERVAL_S: Final = 0.5
INVALID_RULES_EXIT: Final = 70


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FAULTPOINT_")

    service: str = ""
    rules: Path | None = None
    report: Path | None = None
    scope_key: str = "fp.scope"
    flush_seconds: float = Field(default=2.0, gt=0)
    seed: int = 0


class Runtime:
    """The rules a process obeys and the observations it has not yet written."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = settings.rules is not None or settings.report is not None
        if self.enabled and not settings.service:
            raise ValueError("FAULTPOINT_SERVICE is required when faultpoint is enabled")
        self.process = f"{socket.gethostname()}:{os.getpid()}"
        self.lock = threading.Lock()
        self.experiment = ""
        self.rules: dict[str, tuple[Rule, ...]] = {}
        self.matches: Counter[str] = Counter()
        self.injections: Counter[str] = Counter()
        self.randoms: dict[str, random.Random] = {}
        self.tally = Tally()
        self.window_start = time.time()
        self.rules_mtime: float | None = None
        if settings.rules is not None:
            self.load_rules(settings.rules)
        if self.enabled:
            threading.Thread(target=self.watch, name="faultpoint", daemon=True).start()
            atexit.register(self.flush)

    def load_rules(self, path: Path) -> None:
        mtime = path.stat().st_mtime
        ruleset = RuleSet.model_validate_json(path.read_bytes())
        self.flush()
        by_point: dict[str, list[Rule]] = {}
        for rule in ruleset.rules:
            by_point.setdefault(rule.point, []).append(rule)
        with self.lock:
            self.experiment = ruleset.experiment
            self.rules = {point: tuple(rules) for point, rules in by_point.items()}
            self.matches = Counter()
            self.injections = Counter()
            self.randoms = {rule.id: random.Random(f"{self.settings.seed}:{rule.id}")
                            for rule in ruleset.rules}
            self.rules_mtime = mtime

    def watch(self) -> None:
        last_flush = time.monotonic()
        while True:
            time.sleep(WATCH_INTERVAL_S)
            # An unusable rule file ends the process so that no experiment runs under rules it did not ask for.
            try:
                rules = self.settings.rules
                if rules is not None and rules.stat().st_mtime != self.rules_mtime:
                    self.load_rules(rules)
                if time.monotonic() - last_flush >= self.settings.flush_seconds:
                    self.flush()
                    last_flush = time.monotonic()
            except Exception:
                traceback.print_exc()
                print("faultpoint: stopping the process", file=sys.stderr, flush=True)
                os._exit(INVALID_RULES_EXIT)

    def decide(self, point: str) -> Rule | None:
        """The first rule of a point whose scope matches the current request and whose trigger
        fires for this execution."""
        for rule in self.rules.get(point, ()):
            if not scope_matches(rule.scope):
                continue
            with self.lock:
                seen = self.matches[rule.id]
                self.matches[rule.id] = seen + 1
                if seen < rule.trigger.skip:
                    continue
                if rule.trigger.limit is not None and self.injections[rule.id] >= rule.trigger.limit:
                    continue
                if self.randoms[rule.id].random() >= rule.trigger.probability:
                    continue
                self.injections[rule.id] += 1
            return rule
        return None

    def record(self, point: str, outcome: str, total: float, rule: Rule | None) -> None:
        if self.settings.report is None:
            return
        scope = current_scope(self.settings.scope_key)
        trace_id = current_trace_id()
        with self.lock:
            self.tally.add(point, outcome, scope, None if rule is None else rule.id, total,
                           trace_id)

    def hold(self, action: Action) -> None:
        """Perform the actions every point shares, blocking the current thread."""
        if isinstance(action, Delay):
            time.sleep(action.ms / 1000)
        if isinstance(action, Crash):
            self.crash(action.code)

    def crash(self, code: int) -> None:
        self.flush()
        os._exit(code)

    def flush(self) -> None:
        report = self.settings.report
        if report is None:
            return
        end = time.time()
        with self.lock:
            records = self.tally.drain(self.experiment, self.settings.service, self.process,
                                       self.window_start, end)
            self.window_start = end
        append_records(report, records)


RUNTIME: Final = Runtime(Settings())
