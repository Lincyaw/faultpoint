import os
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from typing import Final

from faultpoint.tools.kinds import KindTable
from faultsearch.catalog import FROZEN
from faultsearch.counterfactual import Statuses
from faultsearch.execution import RunRequest
from faultsearch.facts import SearchRun
from pydantic import BaseModel, Field, JsonValue

from faultsearch_local.facts_file import FactLog, RunOrigin
from faultsearch_local.store import Store
from faultsearch_local.systems import REFUSAL_FILE, STATUSES_FILE, System

LOAD_POLL_S: Final = 2.0
"""How often a repetition held back by the host's load checks it again."""

type Running = list[tuple[str, Future[Statuses]]]
"""Repetitions submitted, by label."""


class RunSettings(BaseModel):
    """How an experiment's repetitions run: the SDK checkout and the commit its services are built from, the
    repetitions of every request, the comparison's thresholds, how many run side by side, whether faults share
    repetitions, the system and its instrumentation."""

    model_config = FROZEN

    sdk: Path
    commit: str
    repetitions: int = Field(ge=2)
    alpha: float
    min_mean_increase: float
    workers: int = Field(ge=1)
    pack_tenants: bool = True
    """Whether faults share repetitions in different tenants; off when upstream components are observed, since no
    tenant scope separates their observations."""
    system: str = "shop"
    """The system the experiment explores, by name."""
    instrumentation: dict[str, JsonValue]
    """What of faultpoint runs and what the kernel agent observes, the same in every repetition, as the system's
    deployment reads it."""


def repetition_seed(label: str) -> int:
    """The FAULTPOINT_SEED of a repetition, from its label, so that the repetitions of one group draw their rules'
    chances anew and a repetition run again draws the same."""
    return int(sha256(label.encode()).hexdigest()[:15], 16)


class LocalExecutor:
    """Runs requests as repetitions of a registered system in local containers, side by side, and writes every
    request's search runs to the experiment's fact log as soon as its repetitions end; a repetition whose search run
    the log holds is not run again, and one whose directory ran to its end is only written."""

    def __init__(self, store: Store, settings: RunSettings, system: System, log: FactLog, max_load: float) -> None:
        self.store = store
        self.settings = settings
        self.system = system
        self.log = log
        self.origin = RunOrigin(store, system.name, settings.commit)
        self.max_load = max_load
        """The host's 1-minute load above which no new repetition starts while others still run."""
        self.kinds = KindTable.installed()

    def wait_for_load(self, started: list[Future[Statuses]]) -> None:
        """Wait, while a repetition still runs, until the host's load falls under the limit, so that a loaded host
        does not slow the repetitions whose timing the faults depend on."""
        while any(not future.done() for future in started) and os.getloadavg()[0] > self.max_load:
            time.sleep(LOAD_POLL_S)

    def ended(self, label: str) -> bool:
        directory = self.store.repetition(label)
        return (directory / STATUSES_FILE).exists() or (directory / REFUSAL_FILE).exists()

    def repetition(self, request: RunRequest, label: str) -> Statuses:
        """One repetition; a service refusing a rule ends it, which is recorded so that the fault counts as never
        exercised instead of stopping the experiment."""
        directory = self.store.repetition(label)
        try:
            return self.system.repetition(directory, request.workload.workload,
                                          request.ruleset(label).model_dump(mode="json"), self.settings.sdk,
                                          self.settings.instrumentation, repetition_seed(label))
        except subprocess.CalledProcessError:
            reason = self.system.refusal(directory)
            if reason is None:
                raise
            (directory / REFUSAL_FILE).write_text(reason)
            return Statuses(tenants={})

    def pending(self, request: RunRequest) -> list[str]:
        """The request's repetitions the log does not hold and that never ran to their end."""
        return [label for label in request.labels()
                if (self.store.root.name, label) not in self.log.runs and not self.ended(label)]

    def start(self, pool: ThreadPoolExecutor, request: RunRequest, labels: list[str],
              started: list[Future[Statuses]]) -> Running:
        """Submit repetitions, each once the host's load allows, adding them to those started."""
        running = []
        for label in labels:
            self.wait_for_load(started)
            future = pool.submit(self.repetition, request, label)
            started.append(future)
            running.append((label, future))
        return running

    def settle(self, request: RunRequest, running: Running) -> None:
        """Once a request's repetitions ended, write the search runs of those the log does not hold."""
        for label, future in running:
            print(label, future.result().tenants, flush=True)
        for index, label in enumerate(request.labels()):
            if (self.store.root.name, label) not in self.log.runs:
                self.log.append(self.origin.search_run(label, self.log.next_sequence(), request.workload,
                                                       request.group, index, request.purpose, request.phases,
                                                       request.requests))

    def run(self, requests: list[RunRequest]) -> list[SearchRun]:
        """The requests' search runs; a rule the kind table refuses stops the run before any repetition starts."""
        pending = [self.pending(request) for request in requests]
        for request, labels in zip(requests, pending, strict=True):
            for label in labels:
                violations = self.kinds.violations(request.ruleset(label))
                if violations:
                    raise ValueError(f"{label}: {violations}")
        unsettled: list[tuple[RunRequest, Running]] = []
        started: list[Future[Statuses]] = []
        with ThreadPoolExecutor(self.settings.workers) as pool:
            for request, labels in zip(requests, pending, strict=True):
                unsettled.append((request, self.start(pool, request, labels, started)))
                ended = [all(future.done() for _, future in running) for _, running in unsettled]
                for (waiting, running), done in zip(unsettled, ended, strict=True):
                    if done:
                        self.settle(waiting, running)
                unsettled = [entry for entry, done in zip(unsettled, ended, strict=True) if not done]
            for waiting, running in unsettled:
                self.settle(waiting, running)
        return [self.log.runs[(self.store.root.name, label)] for request in requests for label in request.labels()]
