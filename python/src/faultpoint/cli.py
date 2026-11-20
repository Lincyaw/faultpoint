import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from faultpoint.analysis import Selection, compare
from faultpoint.manifest import Manifest
from faultpoint.observations import ObservationRecord, read_records
from faultpoint.rewrite import rewrite_tree
from faultpoint.rules import RuleSet

app = typer.Typer(no_args_is_help=True, help="Fault points that inject and observe faults.")


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
    """Validate a rule set before a controller installs it."""
    ruleset = RuleSet.model_validate_json(rules.read_bytes())
    typer.echo(f"{ruleset.experiment}: {len(ruleset.rules)} rules")


@app.command()
def rewrite(source: Annotated[Path, typer.Argument(help="The source tree.")],
            target: Annotated[Path, typer.Argument(help="Where the instrumented copy is written.")],
            service: Annotated[str, typer.Option(help="The service the points belong to.")]) -> None:
    """Copy a Python source tree and place branch, check, loop and clock points in the copy."""
    manifest = rewrite_tree(source, target, service)
    typer.echo(f"{len(manifest.points)} points placed in {target}")


@app.command()
def diff(reports: Annotated[list[Path], typer.Argument(help="Observation files of every process.")],
         control: Annotated[list[str], typer.Option(help="A control repetition, EXPERIMENT@SCOPE.")],
         treatment: Annotated[list[str], typer.Option(help="A treatment repetition, EXPERIMENT@SCOPE.")],
         alpha: Annotated[float, typer.Option(help="Significance of an increase.")] = 0.1,
         as_json: Annotated[bool, typer.Option("--json", help="Print the comparison as JSON.")] = False) -> None:
    """Compare treatment repetitions with control repetitions: the outcomes the injection added
    or increased."""
    comparison = compare(read_records(reports), [Selection.parse(text) for text in control],
                         [Selection.parse(text) for text in treatment], alpha)
    if as_json:
        typer.echo(comparison.model_dump_json(indent=2))
        return
    console = Console()
    injections = Table("rule", "point", "outcome", "injected per repetition", title="Injections")
    for injection in comparison.injections:
        injections.add_row(injection.rule, injection.point, injection.outcome,
                           " ".join(map(str, injection.counts)))
    console.print(injections)
    effects = Table("point", "outcome", "metric", "verdict", "control", "treatment", "p",
                    title="Effects")
    for effect in comparison.effects:
        effects.add_row(effect.point, effect.outcome, effect.metric, effect.verdict,
                        " ".join(f"{value:g}" for value in effect.control),
                        " ".join(f"{value:g}" for value in effect.treatment),
                        "" if effect.p_value is None else f"{effect.p_value:.3g}")
    console.print(effects)
