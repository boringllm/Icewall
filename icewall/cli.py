"""Icewall command-line interface."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from icewall import __version__
from icewall.config import IcewallConfig
from icewall.engine import Engine
from icewall.report import to_markdown, to_sarif
from icewall.schemas import ScanResult, Severity

app = typer.Typer(add_completion=False, help="Icewall — LLM-driven multi-agent vulnerability scanner.")
console = Console(stderr=True)

_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _write_stdout(text: str) -> None:
    """Write a report to stdout as UTF-8 regardless of the console codepage
    (Windows consoles default to cp1252 and choke on arrows/emoji)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")


def _resolve_config(config_path: Optional[str], dry_run: bool) -> IcewallConfig:
    if dry_run:
        console.print("[yellow]Dry run: using offline mock provider (no API calls).[/]")
        return IcewallConfig.default()
    if config_path:
        return IcewallConfig.load(config_path)
    default_file = Path("icewall.yaml")
    if default_file.exists():
        console.print(f"[dim]Using config: {default_file}[/]")
        return IcewallConfig.load(default_file)
    console.print(
        "[yellow]No config found (icewall.yaml). Falling back to offline mock provider.[/]\n"
        "[dim]Run 'icewall init-config' to create one with real models.[/]"
    )
    return IcewallConfig.default()


class _ProgressReporter:
    """Drives a determinate overall progress bar with a live cost readout.

    The total grows as each pipeline stage announces its task count
    (`stage_tasks`); the bar advances on every `task_done`. Stage milestone
    events update the label. Cost is shown live and updates as LLM calls land."""

    STAGE_LABEL = {
        "triage": "Triaging attack surface",
        "trace": "Tracing source->sink paths",
        "analyze": "Analyzing candidate paths",
        "validate": "Validating findings",
        "remediate": "Proposing remediations",
    }
    MILESTONES = {
        "graph_start": "Building code graph",
        "graph_done": "Graph: {files} files, {symbols} symbols, {call_edges} edges",
        "triage_start": "Triaging {candidates} candidate symbols",
        "triage_done": "Entry points: {entry_points}",
        "trace_done": "Traced {candidate_paths} source->sink paths",
        "analyze_done": "Raw findings: {findings}",
        "validate_done": "Confirmed: {confirmed}",
        "remediate_done": "Remediation proposals: {count}",
    }

    def __init__(self) -> None:
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TaskProgressColumn,
            TextColumn,
        )

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.fields[cost]}"),
            console=console,
            transient=True,
        )
        self.task = self.progress.add_task("Starting", total=None, cost="$0.0000")
        self.total = 0
        self.completed = 0
        self.stage = ""

    def __enter__(self):
        self.progress.__enter__()
        return self

    def __exit__(self, *exc):
        self.progress.__exit__(*exc)

    def __call__(self, event: str, kw: dict) -> None:
        if event in self.MILESTONES:
            try:
                text = self.MILESTONES[event].format(**kw)
            except (KeyError, IndexError):
                text = event
            console.log(text)
            if not event.endswith("_start"):
                self.progress.update(self.task, description=text)
        elif event == "stage_tasks":
            self.total += int(kw.get("total", 0))
            self.stage = self.STAGE_LABEL.get(kw.get("stage", ""), kw.get("stage", ""))
            self.progress.update(
                self.task, total=self.total, description=self.stage
            )
        elif event == "task_done":
            self.completed += 1
            cost = kw.get("cost", 0.0)
            self.progress.update(
                self.task,
                completed=self.completed,
                description=self.stage,
                cost=f"${cost:.4f}",
            )


def _make_reporter():
    reporter = _ProgressReporter()
    return reporter, reporter


def _summary_table(result: ScanResult) -> Table:
    table = Table(title="Icewall - confirmed findings")
    table.add_column("Sev", style="bold")
    table.add_column("Conf")
    table.add_column("Class")
    table.add_column("Location")
    table.add_column("Entry")
    sev_color = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    for f in result.findings:
        table.add_row(
            f"[{sev_color.get(f.severity,'white')}]{f.severity.value}[/]",
            str(f.confidence),
            f.vuln_class.value,
            f.location.as_ref(),
            f.entry_point or "-",
        )
    return table


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to the repository or file to scan."),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to icewall.yaml."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown | sarif | json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file."),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", help="Drop findings below this severity (info|low|medium|high|critical)."
    ),
    intensity: Optional[str] = typer.Option(
        None, "--intensity", help="Recall/cost preset: fast | balanced | thorough | exhaustive."
    ),
    workshop_dir: Optional[str] = typer.Option(
        None, "--workshop-dir", help="Root folder for per-session workshops (default: .icewall)."
    ),
    no_workshop: bool = typer.Option(
        False, "--no-workshop", help="Disable the per-session workshop folder."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Use the offline mock provider."),
) -> None:
    """Scan a repository for vulnerabilities and emit a report."""
    if not Path(target).exists():
        console.print(f"[red]Target not found: {target}[/]")
        raise typer.Exit(2)

    cfg = _resolve_config(config, dry_run)
    if intensity:
        from icewall.config import INTENSITY_IDS, apply_intensity

        if intensity not in INTENSITY_IDS:
            console.print(f"[red]Invalid --intensity: {intensity} (choose {', '.join(INTENSITY_IDS)})[/]")
            raise typer.Exit(2)
        apply_intensity(cfg, intensity)
        console.print(f"[dim]Intensity: {intensity}[/]")
    if workshop_dir:
        cfg.workshop.root = workshop_dir
    if no_workshop:
        cfg.workshop.enabled = False
    progress, reporter = _make_reporter()

    with progress:
        engine = Engine(cfg, on_event=reporter)
        result = engine.scan(target)

    if min_severity:
        try:
            floor = _SEV_RANK[Severity(min_severity)]
            result.findings = [f for f in result.findings if _SEV_RANK[f.severity] >= floor]
        except (ValueError, KeyError):
            console.print(f"[red]Invalid --min-severity: {min_severity}[/]")
            raise typer.Exit(2)

    console.print(_summary_table(result))
    st = result.stats
    cost_str = "free (mock)" if st.estimated_cost_usd == 0 else f"~${st.estimated_cost_usd:.4f}"
    console.print(
        f"[bold]Estimated cost: {cost_str}[/]  "
        f"[dim]| {st.llm_calls} LLM calls | "
        f"{st.input_tokens + st.output_tokens:,} tokens | {st.duration_seconds}s[/]"
    )
    if len(st.cost_by_model) > 1 or (st.cost_by_model and st.estimated_cost_usd > 0):
        ct = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
        ct.add_column("Model", style="dim")
        ct.add_column("Calls", justify="right", style="dim")
        ct.add_column("Tokens", justify="right", style="dim")
        ct.add_column("Cost", justify="right", style="cyan")
        for model, row in sorted(st.cost_by_model.items(), key=lambda kv: -kv[1]["cost_usd"]):
            ct.add_row(
                model,
                str(row["calls"]),
                f"{row['input_tokens'] + row['output_tokens']:,}",
                f"${row['cost_usd']:.4f}",
            )
        console.print(ct)

    if fmt == "markdown":
        rendered = to_markdown(result)
    elif fmt == "sarif":
        rendered = to_sarif(result)
    elif fmt == "json":
        rendered = result.model_dump_json(indent=2)
    else:
        console.print(f"[red]Unknown format: {fmt}[/]")
        raise typer.Exit(2)

    if result.workshop_dir:
        console.print(
            f"[green]Workshop:[/] {result.workshop_dir}  "
            f"[dim](reports in artifacts/, agent memory in memory/master.md)[/]"
        )

    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/]")
    else:
        # Report to stdout so it can be piped; progress/summary went to stderr.
        _write_stdout(rendered)

    # Non-zero exit if any high/critical confirmed — useful in CI.
    if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings):
        raise typer.Exit(1)


@app.command("graph")
def graph_cmd(
    target: str = typer.Argument(..., help="Repository path."),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Build and inspect the code graph without running any LLM agents."""
    from icewall.graph import build_graph

    cfg = _resolve_config(config, dry_run=True)
    g = build_graph(target, cfg.scan)
    console.print(g.stats())
    table = Table(title="Symbols")
    table.add_column("Kind")
    table.add_column("Location")
    table.add_column("Qualname")
    table.add_column("Calls")
    for s in sorted(g.all_symbols(), key=lambda x: (x.file, x.start_line)):
        table.add_row(s.kind, s.ref(), s.qualname, ", ".join(sorted(set(s.calls)))[:60])
    console.print(table)


@app.command("init-config")
def init_config(
    path: str = typer.Argument("icewall.yaml", help="Where to write the sample config."),
) -> None:
    """Write a sample icewall.yaml wiring Anthropic + an OpenAI-compatible endpoint."""
    if Path(path).exists():
        console.print(f"[red]Refusing to overwrite existing {path}[/]")
        raise typer.Exit(2)
    Path(path).write_text(_SAMPLE_CONFIG, encoding="utf-8")
    console.print(f"[green]Wrote sample config to {path}[/]")
    console.print("[dim]Edit provider/model tiers, then: icewall scan <path> -c " + path + "[/]")


@app.command("skills")
def skills_cmd(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    role: Optional[str] = typer.Option(None, "--role", "-r", help="Filter to one agent role."),
) -> None:
    """List the skills that will be loaded into each agent at spawn time."""
    from icewall.config import AgentRole
    from icewall.skills import SkillRegistry

    cfg = _resolve_config(config, dry_run=True)
    registry = SkillRegistry.discover(cfg.skills)

    roles = [AgentRole(role)] if role else list(AgentRole)
    table = Table(title="Icewall agent skills")
    table.add_column("Agent", style="bold")
    table.add_column("Skill")
    table.add_column("Prio")
    table.add_column("Description")
    any_rows = False
    for r in roles:
        explicit = cfg.agents.get(r).skills if r in cfg.agents else []
        for s in registry.for_role(r.value, explicit or None):
            table.add_row(r.value, s.name, str(s.priority), s.description or "-")
            any_rows = True
    if not any_rows:
        console.print("[yellow]No skills discovered.[/]")
        return
    console.print(table)
    disabled = [s.name for s in registry.skills if not s.enabled]
    if disabled:
        console.print(f"[dim]Disabled: {', '.join(disabled)}[/]")


@app.command("ui")
def ui_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8765, "--port", "-p", help="Port to serve on."),
    workshop_root: str = typer.Option(".icewall", "--workshop-dir", help="Workshop root the dashboard reads sessions from."),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open the UI in a browser."),
) -> None:
    """Launch the Icewall web UI (settings + presets, live scan view, dashboards)."""
    try:
        from icewall.ui import run
    except ImportError:
        console.print(
            "[red]The UI needs extra packages. Install them with:[/]\n"
            "  pip install \"icewall[ui]\"   (or: pip install fastapi uvicorn)"
        )
        raise typer.Exit(2)

    url = f"http://{host}:{port}/"
    console.print(f"[green]Icewall UI on[/] [bold]{url}[/]  [dim](Ctrl-C to stop)[/]")
    if open_browser:
        import threading
        import webbrowser

        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    run(host=host, port=port, workshop_root=workshop_root)


@app.command()
def version() -> None:
    """Print the Icewall version."""
    print(f"icewall {__version__}")


_SAMPLE_CONFIG = """\
# Icewall configuration — one provider per agent, so each agent can have its own
# API key and model tier. Fill in the api_key lines (or swap each for
# `api_key_env: NAME` to read the key from an environment variable — preferred).
# This file may hold plaintext keys; keep it out of version control.

providers:
  triage_provider:
    type: anthropic
    api_key: "PASTE_TRIAGE_AGENT_KEY_HERE"       # or: api_key_env: ANTHROPIC_API_KEY
  tracer_provider:
    type: anthropic
    api_key: "PASTE_TRACER_AGENT_KEY_HERE"
  analyzer_provider:
    type: anthropic
    api_key: "PASTE_ANALYZER_AGENT_KEY_HERE"
  validator_provider:
    type: anthropic
    api_key: "PASTE_VALIDATOR_AGENT_KEY_HERE"
  remediator_provider:
    type: anthropic
    api_key: "PASTE_REMEDIATOR_AGENT_KEY_HERE"
  # Share one key across all agents by pointing each agent at this instead:
  # shared:
  #   type: anthropic
  #   api_key_env: ANTHROPIC_API_KEY
  # Any OpenAI-compatible endpoint (local model, gateway, vLLM, ...):
  # local:
  #   type: openai
  #   base_url: https://localhost:8000/v1
  #   api_key: "PASTE_LOCAL_KEY_HERE"
  #   verify_ssl: false     # skip TLS cert check (self-signed / MITM) — insecure

# Model tiers (USD per 1M tokens in/out): haiku $1/$5, sonnet $3/$15, opus $5/$25
agents:
  triage:
    provider: triage_provider
    model: claude-haiku-4-5
    max_tokens: 2048
  tracer:
    provider: tracer_provider
    model: claude-haiku-4-5
    max_tokens: 3072
  analyzer:
    provider: analyzer_provider
    model: claude-sonnet-5
    max_tokens: 4096
    thinking_tokens: 2048
    # `params` forwards ANY generation parameter to the model's API (merged into
    # the request body). Use provider-appropriate names — Anthropic vs OpenAI
    # differ. Anthropic example: top_p / top_k / stop_sequences / metadata.
    # OpenAI example: top_p / seed / stop / frequency_penalty / reasoning_effort /
    # response_format. e.g.:
    # params:
    #   top_p: 0.9
    #   stop_sequences: ["END", "STOP"]
  validator:
    provider: validator_provider
    model: claude-opus-4-8
    max_tokens: 4096
    thinking_tokens: 4096
  remediator:
    provider: remediator_provider
    model: claude-sonnet-5
    max_tokens: 4096
  # Compresses oversized context on demand (dynamic context management). Use a
  # cheap, fast model — it only summarizes. Omit this agent to fall back to a
  # deterministic header-only digest (no model calls).
  summarizer:
    provider: triage_provider
    model: claude-haiku-4-5
    max_tokens: 1536
  orchestrator:
    provider: analyzer_provider
    model: claude-sonnet-5

concurrency:
  neural_workers: 8
  symbolic_workers: 8
  max_context_requests: 4

# Per-session working folder: each scan gets <root>/<timestamp>-<target>/ holding
# the reports (artifacts/), run metadata (session.json), and agent memory (memory/).
workshop:
  enabled: true
  root: .icewall
  keep_last: 0        # keep only the N newest sessions (0 = keep all)

# Dynamic context management: when an agent's assembled context exceeds
# max_context_tokens, the summarizer compresses the non-anchor blocks toward
# summarize_to_tokens, keeping the entry point and sink verbatim.
context:
  enabled: true
  max_context_tokens: 6000
  summarize_to_tokens: 2000

# Session memory: agents write master.md + per-topic sub-notes as they finish;
# later stages recall relevant notes by file/vuln-class instead of re-deriving.
memory:
  enabled: true
  share_across_stages: true

# Per-task LLM exchange capture (prompt, reasoning, answer, tokens) powering the
# UI's task drill-down. Saved to each session's artifacts/traces.jsonl.
trace:
  enabled: true
  max_chars: 16000     # cap per captured field

budget:
  max_total_tokens: 2000000
  max_llm_calls: 2000
  min_suspicion: 0.3

scan:
  languages: [python, javascript, typescript]
  max_file_bytes: 400000

skills:
  include_bundled: true   # load bundled expertise; attaches to agents by role
  dirs: []                # add your own skill directories
  disabled: []            # turn off bundled skills by name
  # Pin skills to an agent explicitly via agents.<role>.skills: [name, ...]

# Custom per-model prices (USD per 1M tokens) for accurate cost estimates on
# endpoint/custom models not in the built-in table. Set your provider's rates.
# pricing:
#   my-model:
#     input: 0.60
#     output: 2.50
"""


if __name__ == "__main__":
    app()
