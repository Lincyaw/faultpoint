import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from faultpoint.config import Config
from faultpoint.observations import ObservationRecord, read_records
from faultpoint.placement import MANIFEST_FILE, Manifest, Placement, scan_tree
from faultpoint.rules import RuleSet
from faultpoint.tools.analysis import Selection, compare
from faultpoint.tools.candidates import executed_candidates
from faultpoint.tools.kinds import KindTable

app = typer.Typer(no_args_is_help=True, help="Fault points that inject and observe faults.")
# Point ids are printed verbatim: rich would turn ":loop:" into an emoji and "[...]" into markup.
CONSOLE = Console(emoji=False, markup=False, highlight=False)


@app.command()
def schema(directory: Annotated[Path, typer.Argument(help="Where the JSON Schemas are written.")]) -> None:
    """Write the JSON Schemas of rule sets, observation records and manifests, which every
    language's SDK follows."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, model in (("rules", RuleSet), ("observation", ObservationRecord), ("manifest", Manifest)):
        (directory / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2) + "\n", encoding="utf-8")


@app.command()
def check(rules: Annotated[Path, typer.Argument(help="A rule set file.")]) -> None:
    """Validate a rule set against the kind table before a controller installs it."""
    ruleset = RuleSet.model_validate_json(rules.read_bytes())
    violations = KindTable.installed().violations(ruleset)
    for violation in violations:
        typer.echo(violation, err=True)
    if violations:
        raise typer.Exit(1)
    typer.echo(f"{ruleset.experiment}: {len(ruleset.rules)} rules")


@app.command()
def scan(root: Annotated[Path, typer.Argument(help="The source root, as FAULTPOINT_SOURCE_ROOT.")],
         service: Annotated[str, typer.Option(envvar="FAULTPOINT_SERVICE", help="The service of the points.")],
         config: Annotated[Path | None, typer.Option(envvar="FAULTPOINT_CONFIG",
                                                     help="The configuration whose placement applies.")] = None,
         output: Annotated[Path, typer.Option(help="Where the manifest is written.")] = Path(MANIFEST_FILE)) -> None:
    """List the points the import hook places under a source root, without running the service."""
    manifest = scan_tree(root, service, Placement.model_validate(Config.read(config).placement))
    output.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    typer.echo(f"{len(manifest.points)} points written to {output}")


@app.command()
def candidates(reports: Annotated[list[Path], typer.Argument(help="Observation files of a run without rules.")],
               manifest: Annotated[list[Path], typer.Option(help="A manifest scan wrote.")],
               as_json: Annotated[bool, typer.Option("--json", help="Print the candidates as JSON.")] = False) -> None:
    """List the placed points a run without rules executed, the candidates for injection, most executed first."""
    found = executed_candidates([Manifest.model_validate_json(path.read_bytes()) for path in manifest],
                                read_records(reports))
    if as_json:
        typer.echo(json.dumps([candidate.model_dump(mode="json") for candidate in found], indent=2))
        return
    table = Table("executions", "point", "outcomes", "code", title=f"{len(found)} candidates")
    for candidate in found:
        table.add_row(str(candidate.executions), candidate.point.id,
                      " ".join(f"{outcome}={count}" for outcome, count in candidate.outcomes.items()),
                      candidate.point.code)
    CONSOLE.print(table)


@app.command()
def diff(reports: Annotated[list[Path], typer.Argument(help="Observation files of every process.")],
         control: Annotated[list[str], typer.Option(help="A control repetition, EXPERIMENT@SCOPE.")],
         treatment: Annotated[list[str], typer.Option(help="A treatment repetition, EXPERIMENT@SCOPE.")],
         alpha: Annotated[float, typer.Option(help="Significance of an increase.")] = 0.1,
         min_mean_increase: Annotated[float, typer.Option(
             help="The smallest relative increase of a mean that counts, 0.2 meaning 20%.")] = 0.2,
         as_json: Annotated[bool, typer.Option("--json", help="Print the comparison as JSON.")] = False) -> None:
    """Compare treatment repetitions with control repetitions: the outcomes the injection added
    or increased."""
    comparison = compare(read_records(reports), [Selection.parse(text) for text in control],
                         [Selection.parse(text) for text in treatment], alpha, min_mean_increase)
    if as_json:
        typer.echo(comparison.model_dump_json(indent=2))
        return
    injections = Table("rule", "point", "outcome", "injected per repetition", title="Injections")
    for injection in comparison.injections:
        injections.add_row(injection.rule, injection.point, injection.outcome,
                           " ".join(map(str, injection.counts)))
    CONSOLE.print(injections)
    effects = Table("point", "outcome", "metric", "verdict", "control", "treatment", "p",
                    title="Effects")
    for effect in comparison.effects:
        effects.add_row(effect.point, effect.outcome, effect.metric, effect.verdict,
                        " ".join(f"{value:g}" for value in effect.control),
                        " ".join(f"{value:g}" for value in effect.treatment),
                        "" if effect.p_value is None else f"{effect.p_value:.3g}")
    CONSOLE.print(effects)
