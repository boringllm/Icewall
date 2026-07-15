<p align="center">
  <img src="image/icewall.png" alt="Icewall" width="420" />
</p>

# Icewall

**LLM-driven, multi-agent vulnerability scanner for large repositories.**

Icewall builds a code graph of a repo, uses a team of specialized LLM agents to
trace untrusted input to dangerous sinks across files, independently validates
each finding to cut false positives, and proposes (never applies) remediations.
It runs fully offline out of the box via a heuristic mock provider, and scales to
real models with per-agent tiering across Anthropic and any OpenAI-compatible
endpoint.

---

## Why it's built this way

Icewall's design follows the 2025–2026 state of the art in LLM-based security:

- **Agentic + interprocedural beats single-shot.** Real vulns emerge from
  sequences of calls, so tracing the source→sink path is the core task
  (JitVul, *arXiv:2503.03586*).
- **A code graph is the backbone for large repos**, not brute-force context
  (RepoGraph, CGM). tree-sitter parses build-free — no compilation needed
  (cf. RepoAudit).
- **A separate validator agent is the precision pillar.** Independent
  feasibility + guard-recognition cut false positives dramatically
  (QASecClaw: −88.6% FPs; LLM4PFA/AdaTaint).
- **Iterative context expansion.** Tracer subagents pull in only the functions
  they need, graph-backed (the Vulnhuntr move, made cheaper).
- **Propose-only remediation.** AI patches can introduce new bugs
  (*arXiv:2507.02976*), so Icewall outputs diffs for human review.

## Architecture

```
Ingest → tree-sitter code graph → pre-filter (taint signals)
      → TRIAGE (cheap model) → entry points
      → TRACER subagents (threaded) → source→sink paths       ┐ dynamic
                ↑ request more context ── orchestrator ────────┘ parent↔child
      → ANALYZER (strong model, one prompt per CWE) → raw findings
      → VALIDATOR (strong model) → confirm / reject / adjust
      → REMEDIATOR → patch proposals
      → SARIF + Markdown + JSON report
```

| Agent | Role | Typical tier |
|---|---|---|
| Triage | classify attack surface | fast (Haiku) |
| Tracer | walk graph source→sink, request context | fast–mid |
| Analyzer | per-CWE verdict + confidence | strong (Sonnet + thinking) |
| Validator | feasibility, guards, dedup | strongest (Opus + thinking) |
| Remediator | propose fix diff | strong (Sonnet) |
| Summarizer | compress oversized context on demand | fast (Haiku) |

Concurrency uses two bounded thread pools — **neural** (LLM calls, rate/cost
bounded) and **symbolic** (graph work) — with a thread-safe deduping finding
store and a per-run token/call budget the orchestrator enforces.

## Install

```bash
pip install -e .            # core (tree-sitter + mock provider, no keys needed)
pip install -e ".[all]"     # + anthropic and openai SDKs
```

Requires Python ≥ 3.11.

## Quick start

```bash
# Offline — no API keys. Uses the heuristic mock provider.
icewall scan examples/vulnerable_app --dry-run

# Inspect the code graph only (no LLM calls)
icewall graph examples/vulnerable_app

# Real models: create and edit a config, then scan
icewall init-config icewall.yaml
export ANTHROPIC_API_KEY=...           # (PowerShell: $env:ANTHROPIC_API_KEY=...)
icewall scan ./my-repo -c icewall.yaml -f markdown -o report.md
```

Output formats: `markdown` (default), `sarif` (CI / GitHub code scanning),
`json`. Progress and the summary table go to **stderr**; the report goes to
**stdout** (or `--output FILE`), so you can pipe it. Exit code is `1` when any
high/critical finding is confirmed — handy in CI.

Useful flags: `--min-severity {info,low,medium,high,critical}`, `--dry-run`.

## Web UI

Prefer a UI to the CLI? Launch the local web app:

```bash
pip install -e ".[ui]"      # fastapi + uvicorn
icewall ui                  # serves http://127.0.0.1:8765 and opens a browser
```

It's a thin layer over the same engine and gives you:

- **Settings + presets** — an editable configuration form (provider, per-agent
  models/tiers, budget, concurrency, context, memory, workshop, custom pricing).
  Each agent has a full **provider-aware generation-parameter editor** — OpenAI
  and Anthropic expose different knobs (`top_p`, `seed`, `stop`,
  `frequency_penalty`, `reasoning_effort`, … vs `top_p`, `top_k`,
  `stop_sequences`, …), with a raw-JSON escape hatch for anything else
  (`response_format`, `tools`, `metadata`). Anything set here is forwarded
  verbatim to the model's API (config key `agents.<role>.params`).
  Save any configuration as a named **preset** and load it for future scans.
  Already have an `icewall.yaml`? Import it as a ready-to-use preset — either
  `python run.py --import icewall.yaml` (or `icewall.yaml` path in the Presets
  tab's *Import* box). Selecting a preset on the Scan form runs it as-is; the
  form's default is the offline **mock** provider, so no real API calls happen
  until you pick a real preset (or fill the form in).
- **Scan intensity** — a one-click recall/cost dial on the Scan form:
  **Fast** (high-suspicion entry points, shallow tracing) → **Balanced** (default) →
  **Thorough** (more entry points, deeper tracing) → **Exhaustive** (every function
  triaged — bypasses the source/sink pre-filter — with the deepest tracing).
  Higher intensity investigates more paths (fewer misses) at higher cost; pick
  **Custom** to drive the individual knobs in Configuration. Also on the CLI:
  `icewall scan <path> --intensity thorough`.
- **Live scan view** — a progress bar, a card per agent showing what it's doing
  right now (triaging / tracing / analyzing / validating / summarizing) with live
  task counts and **live per-agent cost**, a running **cost / token / call**
  readout, the **code graph** rendered interactively (sinks and sources
  highlighted), and a streaming event log. Click an agent to see its full
  transcript, then click any task to drill into the actual **LLM exchange** —
  the system prompt, the user input, the model's reasoning/thinking (when
  exposed), the answer, and token counts.
- **Session dashboard** — every scan is listed; open one for a **cost-per-agent**
  breakdown, the findings table, the saved code graph, agent memory, and download
  links for the markdown / SARIF / JSON artifacts.

Live updates stream over Server-Sent Events from the engine's event bus, so the UI
reflects exactly what the pipeline is doing. Flags: `--port`, `--host`,
`--workshop-dir`, `--no-open`.

The UI runs **fully offline** — the graph library is vendored locally, no CDN. The
provider settings include a **Verify SSL certificate** toggle (uncheck to skip TLS
verification for self-signed / MITM-proxied endpoints — insecure, config key
`providers.<name>.verify_ssl: false`). Captured LLM exchanges are saved to the
session's `artifacts/traces.jsonl`; disable capture with `trace.enabled: false`.

## Configuration (`icewall.yaml`)

Per-agent model tiering is the point: spend cheap tokens on high-volume triage
and tracing, strong models on analysis/validation/remediation. Providers can mix
Anthropic and any OpenAI-compatible `base_url` (local models, gateways, vLLM).
`icewall init-config` writes a documented starting point (the repo also ships a
ready-to-edit [`icewall.yaml`](icewall.yaml)). Key sections: `providers`,
`agents` (role → provider/model/max_tokens/thinking_tokens/skills), `concurrency`,
`budget`, `scan`, `skills`.

**Per-agent API keys.** The shipped config gives each agent its own provider
block so you can paste a different key (and model) per agent. Each provider takes
either an inline `api_key:` or, preferably, `api_key_env:` naming an environment
variable. Sharing one key? Point every agent at a single provider. Inline keys
are plaintext — `icewall.yaml` is git-ignored by default; still prefer env vars
for anything committed.

## Cost & progress

Every scan reports an **estimated cost** priced per model from current Anthropic
list prices (`icewall/cost.py`), with a per-model breakdown (calls, tokens, $).
The CLI shows a live **progress bar** with a running cost readout as the pipeline
advances through its stages, and the cost also lands in the markdown/JSON reports.
Mock/dry-run scans are free. Costs are estimates from token usage, not billing.

For models not in the built-in table (custom or endpoint models), set exact rates
in the config's `pricing` section so estimates are accurate:

```yaml
pricing:
  my-model:
    input: 0.60     # USD per 1M input tokens
    output: 2.50    # USD per 1M output tokens
```

Custom rates override the built-in table by exact model id; unlisted models fall
back to a conservative default.

## Workshop (per-session results)

Every scan opens its own **workshop** folder so runs never clobber each other:

```
.icewall/<UTC-timestamp>-<target>/
  session.json          run metadata: target, config, stats, cost, status
  artifacts/            report.md, report.sarif, report.json (always written)
  memory/
    master.md           auto-maintained index of everything the agents learned
    notes/<slug>.md     one sub-note per fact (attack surface, paths, verdicts)
```

Reports are saved here automatically — `--output` is only for an extra copy. The
CLI prints the session path when the scan finishes.

```yaml
workshop:
  enabled: true
  root: .icewall
  keep_last: 0    # keep only the N newest sessions (0 = keep all)
```

Flags: `--workshop-dir DIR`, `--no-workshop`.

## Dynamic context management

Long traces and deep source→sink paths can outgrow the model window. When an
agent's assembled context passes `max_context_tokens`, the **summarizer** compresses
the non-anchor blocks toward `summarize_to_tokens`, keeping the entry point and
sink **verbatim** so the trace stays intact. Every compression is recorded to
session memory, so nothing is silently dropped. If no summarizer agent is
configured, a deterministic header-only digest is used (no extra model calls).

```yaml
context:
  enabled: true
  max_context_tokens: 6000
  summarize_to_tokens: 2000
```

## Session memory

Agents write notes **as they finish** — triage records the attack surface, the
tracer records each source→sink path, the analyzer records candidates, the
validator records verdicts — building `master.md` plus per-topic sub-notes. Later
stages **recall** relevant notes by file / vulnerability class (e.g. the validator
sees what the tracer already established for that sink) instead of re-deriving them.

This is deterministic relevance recall, **not** an extra LLM deciding what to load:
the code graph already serves targeted context on demand, so memory's job is
cross-stage fact sharing and an auditable trail (and the substrate for future
incremental re-scans), without paying per-decision model calls.

```yaml
memory:
  enabled: true
  share_across_stages: true   # feed recalled notes into the validator
```

## Agent skills

Each agent loads **skills** — detailed markdown knowledge modules — into its
system prompt when it spawns, so you can specialize or extend an agent without
touching Python. Bundled skills live in
[`icewall/skills/library/`](icewall/skills/library): attack-surface triage,
taint-propagation rules for the tracer, per-CWE analyzer deep-dives (SQLi,
command injection, XSS, SSRF, path traversal, deserialization), a skeptical
false-positive checklist for the validator, and secure-remediation patterns.

A skill is a markdown file with YAML frontmatter:

```markdown
---
name: sql-injection-analysis
description: Deep guidance for confirming or dismissing SQL injection.
roles: [analyzer, validator]   # or [all]; inferred from a role-named folder
priority: 8                    # higher loads first
---
Confirm SQL injection only when attacker-controlled data is composed into a
query as *code* rather than passed as a *bound parameter*. ...
```

- **Targeting:** a skill attaches to a role via its `roles` frontmatter, or
  automatically if it sits in a role-named subfolder (`.../analyzer/foo.md`).
- **Your own skills:** point `skills.dirs` in `icewall.yaml` at a directory; a
  same-named skill there overrides a bundled one.
- **Pinning:** set `skills: [name, ...]` on an agent to load exactly those
  (instead of auto-by-role). Disable any bundled skill via `skills.disabled`.

Inspect what each agent will load:

```bash
icewall skills                 # table of role -> skills
icewall skills --role analyzer
```

## The code graph

The code graph is Icewall's map of the repository, and every LLM decision is
anchored to it. tree-sitter parses each file **without compiling or installing
anything**, extracting one **symbol** per function / method / class and three
kinds of edge between them:

| Edge | Meaning | Example |
|---|---|---|
| **call** | one symbol invokes another | `ping()` → `run_report()` |
| **import** | a file pulls in a definition from another module | `app.py` → `run_report` (from `utils`) |
| **inherit** | a class extends another class | `AdminHandler` → `Handler` |

That graph is what lets the agents follow a tainted value *across files* — through
a call, an import, or an inherited method — instead of guessing from a single
snippet. (The heterogeneous call/import/inherit schema follows the graph design
of *LocAgent*, arXiv:2503.09089.)

### Inspect it directly (no LLM, no keys)

```bash
icewall graph examples/vulnerable_app
```

```
{'files': 3, 'symbols': 11, 'functions': 11,
 'call_edges': 2, 'inherit_edges': 0, 'import_edges': 2}
                                    Symbols
+-----------------------------------------------------------------------------+
| Kind     | Location     | Qualname                | Calls                   |
|----------+--------------+-------------------------+-------------------------|
| function | app.py:19    | ping                    | get, run_report         |
| function | app.py:26    | search                  | cursor, execute, ...    |
| function | app.py:42    | download                | get, join, send_file    |
| function | app.py:50    | calc                    | eval, get, str          |
| function | utils.py:5   | run_report              | system                  |
| function | utils.py:11  | safe_lookup             | cursor, execute, ...    |
| function | server.js:14 | anonymous@14            | String, eval, send      |
| ...      |              |                         |                         |
+-----------------------------------------------------------------------------+
```

The two `import_edges` here are `app.py`'s `from utils import run_report,
safe_lookup` — each resolved to the actual definition in `utils.py`, not merely
guessed by name.

### A worked example: a cross-file command injection

Read the `Calls` column as edges. Two symbols in the table above form a path
that no single-file view would catch:

```
app.py:19  ping()              # Flask handler: reads request.args.get(...)   ← SOURCE
   └─ calls run_report()       # edge resolved across files
utils.py:5 run_report()        # calls os.system(cmd)                          ← SINK
```

A user-controlled value enters in `app.py` but reaches `os.system` in
`utils.py`. Here's how the graph drives the pipeline over that path:

1. **Pre-filter** flags `ping` as taint-relevant (it reads `request.args`, a
   *source*) and `run_report` as taint-relevant (it calls `os.system`, a
   *sink*). These signals come from `icewall/detectors/patterns.py`.
2. **Triage** confirms `ping` is real attack surface (an HTTP entry point).
3. **Tracer** starts at `ping`, walks the **call edge** to `run_report`, and —
   because the sink lives in another file — asks the orchestrator for that
   function's source via the graph (`neighborhood()`), assembling the full
   `ping → run_report → os.system` path.
4. **Analyzer** issues a per-CWE verdict (command injection) with confidence.
5. **Validator** independently checks feasibility and guards, then confirms or
   rejects — the false-positive pillar.

The graph is what makes step 3 possible without dumping the whole repo into the
model: the tracer pulls in **only** the one function it needs, following an edge.

### Import edges — precise cross-file resolution

Call edges alone link a name to *every* symbol declared with that name (cheap,
but over-approximate). **Import edges** add precision: Icewall parses each file's
`import` / `from … import` (Python) and `import … from '…'` (JS/TS) statements,
resolves the module string to the actual file in the repo, and records an edge
from the importing file to the definitions it pulls in.

```python
from icewall.graph import build_graph
g = build_graph("examples/vulnerable_app")

g.imported_symbols("app.py")      # → [run_report, safe_lookup]  (the real defs in utils.py)
g.importing_files(run_report.id)  # → ['app.py']                 (reverse edge)
g.imports("app.py")[0].target_file # → 'utils.py'                (module resolved to a file)
```

External modules (stdlib `os`, third-party `flask`) don't resolve to a repo file,
so they produce no edge — the graph stays focused on *your* code. Relative imports
(`from .helpers import x`, `import './utils.js'`) are resolved against the
importing file's directory, including `__init__.py` / `index.js` package entry
points.

### Inherit edges — following taint through class hierarchies

**Inherit edges** connect a subclass to the class it extends, so taint that flows
through an inherited or overridden method is no longer invisible:

```python
# base.py:   class Handler:      def handle(self, x): ...
# app.py:    class AdminHandler(Handler):  ...        (imports Handler)

g.bases(admin.id)         # → [Handler]        (Python bases, resolved across files)
g.subclasses(handler.id)  # → [AdminHandler]   (reverse edge)
```

They're extracted for Python (`class Foo(Base)`) and JS/TS (`class Foo extends
Base`) alike; TypeScript `implements` clauses are deliberately **not** treated as
inheritance. Crucially, `neighborhood()` now follows inherit edges by default, so
when the tracer inspects a subclass or an overriding method, the base class it
extends is pulled into context automatically.

### How the graph is rendered in the UI

During a scan the same graph is streamed to the browser (`graph_data` events) and
drawn with a locally-vendored Cytoscape.js — **no CDN, works fully offline**.
`icewall/graph/view.py` turns the `CodeGraph` into nodes/edges and colors them:

- 🔴 **sink** — the symbol contains a dangerous call (`os.system`, `eval`,
  `cursor.execute`, …)
- 🟢 **source** — the symbol reads untrusted input (`request.args`, `req.query`, …)
- 🔵 **function** — everything else

Edges carry a `kind` (`call` or `inherit`) so the two symbol-to-symbol relations
are distinguishable; import edges (which point from a file, not a symbol) are
summarized in the payload's `import_edges` count. Large repos are capped to the
most-connected, most taint-relevant symbols (`cap`, default 300) so the view
stays legible, and the saved `graph.json` in each session lets you re-open the
exact graph later from the session dashboard.

### Can the graph cause a missed vulnerability?

Yes, in principle — that's why scan **intensity** exists, and why the graph
carries import and inherit edges. Two graph limits matter:

- **Name-based edge resolution is over-approximate but can also under-connect.**
  A call made purely through a dynamic dispatch (a value looked up at runtime,
  reflection, a callback stored in a dict) may leave no static edge, so the
  tracer won't follow it. **Import edges** shrink this gap for cross-file calls
  by tying a name to the specific module it came from, and **inherit edges**
  recover taint that flows through an inherited/overridden method.
- **The source/sink pre-filter can skip a function** whose sink Icewall doesn't
  recognize as a pattern (a custom wrapper around a dangerous call).

**Exhaustive** intensity addresses the second directly: it bypasses the pre-filter
so *every* function is triaged, at higher cost. The over-approximate edges are
deliberate — they guide the LLM toward candidate paths, and the analyzer/validator
confirm real reachability rather than trusting the edge blindly.

## Languages

Python, JavaScript, TypeScript (incl. TSX) via tree-sitter. Adding a language is
a `LanguageSpec` in `icewall/graph/languages.py` — declaring its function, class,
call, and import node types, plus how it spells inheritance (`superclass_field`
for Python, `heritage_nodes` for the `extends`-style grammars).

## External scanners

**v1 requires no external tools** — the engine is LLM + tree-sitter only. An
optional `Sensor` interface (`icewall/sensors/`) is the documented seam where
Semgrep (v1.1) and others will *seed* candidates to focus LLM effort; it is
additive and never a hard dependency.

## Development

```bash
pip install pytest
python -m pytest tests/ -q     # 75 offline tests, no API keys
```

## Project layout

```
icewall/
  providers/     anthropic, openai-compat, mock, base interface
  graph/         tree-sitter parsing, code graph, builder, queries
  agents/        triage, tracer, analyzer, validator, remediator, summarizer
  orchestration/ thread pools, budget, context broker + manager, finding store
  detectors/     taint source/sink/sanitizer patterns
  skills/        markdown expertise loaded into agents at spawn (+ library/)
  sensors/       optional external-scanner seam (Semgrep stub, v1.1)
  report/        SARIF + markdown
  ui/            FastAPI app + static SPA (settings/presets, live view, dashboard)
  workshop.py    per-session working folder (artifacts + memory)
  memory.py      session memory: master.md index + relevance recall
  engine.py      the orchestrator pipeline
  cli.py         typer CLI (scan, graph, skills, ui, init-config, …)
examples/vulnerable_app/   deliberately-vulnerable sample repo
tests/
```

## Caveats

- Name-based *call* resolution is over-approximate (guides context; the LLM
  confirms reachability). *Import* edges are resolved more precisely — the module
  string is mapped to the actual repo file — but there's still no full
  cross-module type resolution, so a name imported through a package re-export or
  a dynamically-built path may not resolve.
- Remediations are **proposals for human review**, never auto-applied.
- The mock provider is a crude pattern-matcher for offline/dev/testing — real
  precision comes from configuring real models.
