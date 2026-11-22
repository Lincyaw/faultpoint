from collections import defaultdict

from faultpoint.tools.analysis import compare
from faultpoint.tools.analysis import Selection as Repetition
from pydantic import BaseModel

from faultsearch.catalog import FROZEN
from faultsearch.chains import Chain, Stitching
from faultsearch.counterfactual import UNSCOPED, EffectKey, merge_scope_effects, tenant_names
from faultsearch.edges import holds
from faultsearch.execution import PlannedRequest
from faultsearch.facts import (CONTROL_GROUP, Facts, GitRevision, PathIdentity, PointInventory, Purpose,
                               RepetitionCount, SearchRun)
from faultsearch.validation import HopCheck, RunVerdict


class NaturalPlanning(BaseModel):
    model_config = FROZEN

    path: PathIdentity
    revision: GitRevision
    repetitions: RepetitionCount


class NaturalPlan(BaseModel):
    model_config = FROZEN

    revision: GitRevision
    sdk_build: str
    planned: PlannedRequest


class NaturalJudgement(BaseModel):
    """A path checked without injection at one rewritten revision, with its actual control and run identities."""

    model_config = FROZEN

    path: PathIdentity
    revision: GitRevision
    controls: tuple[str, ...]
    runs: tuple[str, ...]
    judgement: RunVerdict
    hops: tuple[HopCheck, ...]


def natural_judgements(facts: Facts, stitching: Stitching, inventory: PointInventory, alpha: float,
                       min_mean_increase: float, min_count_increase: float) -> tuple[NaturalJudgement, ...]:
    chains = {PathIdentity.from_chain(chain, inventory.identity): chain
              for chain in (*stitching.top, *stitching.top_cross_layer)}
    recorded = {run.identity: run for run in facts.facts if isinstance(run, SearchRun)}
    standing = {run.identity: run for run in facts.standing_runs()}
    groups: dict[tuple[str, str, str], list[SearchRun]] = defaultdict(list)
    for run in standing.values():
        if run.purpose == Purpose.NATURAL:
            groups[(run.source, run.workload.name, run.group)].append(run)
    judgements = []
    for members in sorted(groups.values(), key=lambda runs: max(run.sequence for run in runs)):
        first = members[0]
        target = first.natural
        if target is None:
            raise ValueError("a natural run has no path")
        if target.path not in chains:
            continue
        controls = [recorded[identity] for identity in sorted(target.controls)]
        supported = all(control.identity in standing for control in controls)
        if supported and inventory.revision is None:
            raise ValueError("natural verification requires the recorded healthy revision")
        if supported and any(control.group != CONTROL_GROUP or control.rules or control.purpose == Purpose.NATURAL
                             or control.refusal is not None for control in controls):
            raise ValueError("natural controls must be standing healthy runs")
        if supported and any((control.system, control.revision, control.sdk_build, control.deployment)
                             != (inventory.system, inventory.revision, inventory.sdk_build, inventory.deployment)
                             for control in controls):
            raise ValueError("natural controls must match their path inventory's healthy revision and SDK deployment")
        if supported and any((run.system, run.sdk_build, run.workload.workload)
               != (first.system, first.sdk_build, first.workload.workload) for run in (*controls, *members)):
            raise ValueError("natural comparisons require the same system, SDK and workload parameters")
        complete = (supported and {run.index for run in members} == set(range(target.repetitions))
                    and all(run.refusal is None for run in members))
        hops = natural_hops(chains[target.path], controls, members, alpha, min_mean_increase,
                            min_count_increase) if complete else ()
        verdict = (RunVerdict.CONFIRMED if all(hop.confirmed for hop in hops) else RunVerdict.REFUTED
                   ) if complete else RunVerdict.NEEDS_RUN
        judgements.append(NaturalJudgement(
            path=target.path, revision=target.revision, controls=tuple(control.identity for control in controls),
            runs=tuple(run.identity for run in sorted(members, key=lambda run: run.index)),
            judgement=verdict, hops=hops))
    return tuple(judgements)


def natural_hops(chain: Chain, controls: list[SearchRun], runs: list[SearchRun], alpha: float,
                  min_mean_increase: float, min_count_increase: float) -> tuple[HopCheck, ...]:
    tenant = tenant_names(runs[0].workload.workload)[0]
    records = [record for run in (*controls, *runs) for record in run.records()]
    comparisons = {}
    for scope in (UNSCOPED, tenant):
        comparison = compare(records,
            [Repetition(experiment=run.label, scope=scope) for run in controls],
            [Repetition(experiment=run.label, scope=scope) for run in runs], alpha, min_mean_increase)
        comparisons[scope] = comparison.effects
    effects = merge_scope_effects(comparisons[tenant], comparisons[UNSCOPED])
    observed = {EffectKey.of(effect).key: effect for effect in effects if holds(effect, min_count_increase)}
    hops = []
    for index, hop in enumerate(chain.hops):
        effect = observed.get(hop.effect.key)
        hops.append(HopCheck(hop=index, effect=hop.effect, confirmed=effect is not None, observed=effect))
    return tuple(hops)
