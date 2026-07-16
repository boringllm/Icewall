"""Icewall orchestrator engine.

Runs the full multi-agent pipeline over a repository:

  1. build the code graph (tree-sitter, build-free)
  2. pre-filter candidate symbols by cheap taint signals
  3. LLM triage -> entry points (attack surface) with suspicion
  4. tracer subagents follow the graph source->sink, expanding context
     dynamically via the parent<->child protocol
  5. analyzer subagents render a per-class verdict on each candidate path
  6. validator independently confirms/rejects (false-positive pillar)
  7. remediator proposes fixes for confirmed findings

Stages run concurrently on the neural pool; graph work on the symbolic pool.
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from icewall.agents import (
    AnalyzerAgent,
    RemediatorAgent,
    SummarizerAgent,
    TracerAgent,
    TriageAgent,
    ValidatorAgent,
)
from icewall.config import AgentRole, IcewallConfig
from icewall.detectors.patterns import find_sinks, has_source
from icewall.graph import CodeGraph, Symbol, build_graph
from icewall.orchestration import (
    BudgetExceeded,
    BudgetTracker,
    ContextBroker,
    ContextManager,
    FindingStore,
    TraceRecorder,
    WorkerPools,
)
from icewall.providers import build_provider
from icewall.report import to_markdown, to_sarif
from icewall.skills import SkillRegistry
from icewall.workshop import Workshop
from icewall.schemas import (
    CWE_MAP,
    CallChainStep,
    ChainRole,
    CodeLocation,
    Finding,
    Remediation,
    ScanResult,
    ScanStats,
    Severity,
    Verdict,
    VulnClass,
    severity_for,
)

EventCB = Optional[Callable[[str, dict], None]]


@dataclass
class CandidatePath:
    entry: Symbol
    sink_symbol: Symbol
    sink_kind: str
    vuln_class: VulnClass
    chain: list[str]
    code: str
    sink_line: int
    context_ids: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, config: IcewallConfig, on_event: EventCB = None) -> None:
        self.cfg = config
        self.on_event = on_event or (lambda *_: None)
        self.budget = BudgetTracker(
            config.budget.max_total_tokens,
            config.budget.max_llm_calls,
            pricing_overrides=config.price_overrides(),
        )
        self._emit_lock = threading.Lock()
        self._trace_lock = threading.Lock()
        # Captures each LLM exchange, tagged to the task it ran under, for the
        # UI's per-task drill-down. Streamed live and persisted to the workshop.
        self.recorder = TraceRecorder(
            self._on_trace,
            enabled=config.trace.enabled,
            max_chars=config.trace.max_chars,
        )
        self.agents = self._build_agents()
        # Optional knowledge base (Vul-RAG): retrieved per finding and fed to the
        # validator. None when disabled or empty, so validation is unchanged then.
        self.knowledge = self._build_knowledge()

    def _build_knowledge(self):
        kc = self.cfg.knowledge
        if not kc.enabled:
            return None
        try:
            from icewall.knowledge import KnowledgeStore, build_embedder

            store = KnowledgeStore(kc, embedder=build_embedder(kc.embedding))
            return store if store.items else None
        except Exception:
            return None

    def _build_agents(self) -> dict:
        self.skill_registry = SkillRegistry.discover(self.cfg.skills)

        def make(agent_cls, role):
            provider = build_provider(self.cfg.provider_for(role))
            acfg = self.cfg.agent(role)
            skills = self.skill_registry.for_role(role.value, acfg.skills or None)
            return agent_cls(provider, acfg, self.budget, skills=skills, recorder=self.recorder)

        agents = {
            AgentRole.TRIAGE: make(TriageAgent, AgentRole.TRIAGE),
            AgentRole.TRACER: make(TracerAgent, AgentRole.TRACER),
            AgentRole.ANALYZER: make(AnalyzerAgent, AgentRole.ANALYZER),
            AgentRole.VALIDATOR: make(ValidatorAgent, AgentRole.VALIDATOR),
            AgentRole.REMEDIATOR: make(RemediatorAgent, AgentRole.REMEDIATOR),
        }
        # The summarizer is optional: only built if a config wires it, so
        # existing configs (without a summarizer agent) still load. When absent,
        # the ContextManager uses its deterministic header-only fallback.
        if AgentRole.SUMMARIZER in self.cfg.agents:
            agents[AgentRole.SUMMARIZER] = make(SummarizerAgent, AgentRole.SUMMARIZER)
        return agents

    def _emit(self, event: str, **kw) -> None:
        # Serialized: work-unit events fire from concurrent worker threads.
        with self._emit_lock:
            self.on_event(event, kw)

    def _agent(
        self, role: str, phase: str, label: str, subject: str = "", outcome: str = ""
    ) -> None:
        """Emit a live agent-activity event for the UI: who is doing what (and,
        on 'end', what they concluded), with a running total cost plus this
        role's own running cost so per-agent spend updates live.

        Also maintains the trace recorder's per-thread task stack so every LLM
        exchange made during this unit is tagged with `task_id`."""
        if phase == "start":
            task_id = uuid.uuid4().hex[:12]
            self.recorder.push_task(task_id, role, label)
        else:
            cur = self.recorder.current()
            task_id = cur[0] if cur else None
        self._emit(
            "agent",
            role=role,
            phase=phase,
            label=label,
            subject=subject,
            outcome=outcome,
            task_id=task_id,
            cost=self.budget.estimated_cost(),
            tokens=self.budget.total_tokens,
            calls=self.budget.calls,
            role_cost=self.budget.cost_for_role(role),
        )
        if phase == "end":
            self.recorder.pop_task()

    def _on_trace(self, rec: dict) -> None:
        """Stream one captured LLM exchange to the UI and persist it."""
        self._emit("agent_trace", **rec)
        ws = getattr(self, "workshop", None)
        if ws is not None and ws.dir is not None:
            import json as _json

            with self._trace_lock:
                with (ws.dir / "artifacts" / "traces.jsonl").open("a", encoding="utf-8") as fh:
                    fh.write(_json.dumps(rec) + "\n")

    def _build_context_manager(self) -> ContextManager:
        summarizer = None
        if AgentRole.SUMMARIZER in self.agents:
            agent = self.agents[AgentRole.SUMMARIZER]

            def summarizer(blocks, topic):  # noqa: E306
                return agent.summarize(blocks, topic)

        cc = self.cfg.context

        def emit_agent(phase, label, outcome=""):
            self._agent("summarizer", phase, label, outcome=outcome)

        return ContextManager(
            enabled=cc.enabled,
            max_tokens=cc.max_context_tokens,
            target_tokens=cc.summarize_to_tokens,
            summarizer=summarizer,
            memory=self.memory,
            emit_agent=emit_agent,
        )

    def _completed(self, futures, stage: str):
        """Drive a stage's futures to completion, emitting progress + live cost.

        Emits `stage_tasks` (with the total) before draining and `task_done`
        (with running cost/tokens) after each future, so the CLI can render an
        overall progress bar and a live cost readout."""
        futures = list(futures)
        self._emit("stage_tasks", stage=stage, total=len(futures))
        for fut in as_completed(futures):
            result = fut.result()
            self._emit(
                "task_done",
                stage=stage,
                cost=self.budget.estimated_cost(),
                tokens=self.budget.total_tokens,
            )
            yield result

    # --- public entrypoint ---------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        t0 = time.time()
        stats = ScanStats()

        # Open the per-session workshop: results, artifacts, and memory land here.
        self.workshop = Workshop(
            self.cfg.workshop.root,
            target,
            enabled=self.cfg.workshop.enabled,
            keep_last=self.cfg.workshop.keep_last,
        )
        self.workshop.open(self.cfg.summary())
        self.memory = self.workshop.memory if self.cfg.memory.enabled else None
        self.ctx = self._build_context_manager()

        self._emit("workshop_open", session=self.workshop.session_id,
                   dir=str(self.workshop.dir) if self.workshop.dir else "")

        self._emit("graph_start", target=target)
        graph = build_graph(target, self.cfg.scan)
        gstats = graph.stats()
        stats.files_scanned = gstats["files"]
        stats.symbols = gstats["symbols"]
        self._emit("graph_done", **gstats)

        self.broker = ContextBroker(graph)
        self.graph = graph

        # Serialize the graph for the live visualization and persist it.
        try:
            from icewall.graph.view import graph_view

            gview = graph_view(graph)
            self._emit("graph_data", **gview)
            if self.workshop.dir:
                import json as _json

                self.workshop.write_artifact("graph.json", _json.dumps(gview))
        except Exception:
            pass

        pools = WorkerPools.from_config(self.cfg.concurrency)
        try:
            entry_points = self._triage_stage(graph, pools)
            stats.entry_points = len(entry_points)
            self._emit("triage_done", entry_points=len(entry_points))

            paths = self._trace_stage(entry_points, pools)
            stats.candidate_paths = len(paths)
            self._emit("trace_done", candidate_paths=len(paths))

            store = FindingStore()
            self._analyze_stage(paths, store, pools)
            stats.findings_raw = len(store)
            self._emit("analyze_done", findings=len(store))

            confirmed = self._validate_stage(store, pools)
            stats.findings_confirmed = len(confirmed)
            self._emit("validate_done", confirmed=len(confirmed))

            self._remediate_stage(confirmed, pools)
            self._emit("remediate_done", count=len(confirmed))
        finally:
            pools.shutdown()

        bsnap = self.budget.snapshot()
        stats.input_tokens = bsnap["input_tokens"]
        stats.output_tokens = bsnap["output_tokens"]
        stats.llm_calls = bsnap["llm_calls"]
        stats.estimated_cost_usd = self.budget.estimated_cost()
        stats.cost_by_model = self.budget.cost_by_model()
        stats.cost_by_role = self.budget.cost_by_role()
        stats.duration_seconds = round(time.time() - t0, 2)

        confirmed.sort(key=lambda f: (-f.confidence, f.location.file, f.location.start_line))
        result = ScanResult(
            target=target,
            findings=confirmed,
            stats=stats,
            config_summary=self.cfg.summary(),
            workshop_dir=str(self.workshop.dir) if self.workshop.dir else None,
        )
        self._persist_artifacts(result)
        self.workshop.finalize(result)
        self._emit("workshop_done", dir=result.workshop_dir or "")
        return result

    def _persist_artifacts(self, result: ScanResult) -> None:
        """Write the run's reports into the workshop's artifacts/ folder."""
        if not self.workshop.dir:
            return
        try:
            self.workshop.write_artifact("report.md", to_markdown(result))
            self.workshop.write_artifact("report.sarif", to_sarif(result))
            self.workshop.write_artifact("report.json", result.model_dump_json(indent=2))
        except Exception:  # never let artifact IO fail a completed scan
            pass

    # --- stage 3: triage -----------------------------------------------------

    def _candidate_symbols(self, graph: CodeGraph) -> list[Symbol]:
        """Which functions go to LLM triage. By default a cheap deterministic
        pre-filter keeps only functions touching a source or a sink. With
        `scan.analyze_all_functions` (Exhaustive intensity) every function is
        triaged so novel/unpatterned sinks aren't missed — higher recall, cost."""
        funcs = graph.functions()
        if self.cfg.scan.analyze_all_functions:
            return list(funcs)
        return [s for s in funcs if has_source(s.code) or find_sinks(s.code)]

    def _triage_stage(self, graph: CodeGraph, pools: WorkerPools) -> list[Symbol]:
        candidates = self._candidate_symbols(graph)
        self._emit("triage_start", candidates=len(candidates))
        by_id = {s.id: s for s in candidates}

        # Batch candidates to keep triage calls efficient.
        batch_size = 8
        batches = [candidates[i : i + batch_size] for i in range(0, len(candidates), batch_size)]
        agent: TriageAgent = self.agents[AgentRole.TRIAGE]

        entry_ids: dict[str, float] = {}
        futures = []
        for batch in batches:
            packed = [
                {"symbol_id": s.id, "name": s.qualname, "file": s.file, "code": s.snippet()}
                for s in batch
            ]
            futures.append(pools.neural.submit(self._safe_triage, agent, packed))
        for eps in self._completed(futures, "triage"):
            for ep in eps:
                sid = ep.get("symbol_id")
                susp = float(ep.get("suspicion", 0.0))
                if sid in by_id and susp >= self.cfg.budget.min_suspicion:
                    entry_ids[sid] = max(entry_ids.get(sid, 0.0), susp)

        # Highest-suspicion first.
        ordered = sorted(entry_ids.items(), key=lambda kv: -kv[1])
        entries = [by_id[sid] for sid, _ in ordered]
        if self.memory and entries:
            self.memory.note(
                title="Attack surface",
                body="Entry points selected for tracing (highest suspicion first):\n"
                + "\n".join(
                    f"- {by_id[sid].qualname} ({by_id[sid].file}) suspicion={susp:.2f}"
                    for sid, susp in ordered
                ),
                role="triage",
                tags=["attack-surface"],
            )
        return entries

    def _safe_triage(self, agent: TriageAgent, packed: list[dict]) -> list[dict]:
        label = f"Triaging {len(packed)} symbols"
        self._agent("triage", "start", label)
        try:
            eps = agent.triage(packed)
        except BudgetExceeded:
            self._agent("triage", "end", label, outcome="budget exceeded")
            return []
        floor = self.cfg.budget.min_suspicion
        n = sum(1 for e in eps if float(e.get("suspicion", 0.0)) >= floor)
        self._agent("triage", "end", label, outcome=f"{n} suspicious of {len(packed)}")
        return eps

    # --- stage 4: trace ------------------------------------------------------

    def _trace_stage(self, entry_points: list[Symbol], pools: WorkerPools) -> list[CandidatePath]:
        futures = [pools.neural.submit(self._trace_entry, ep) for ep in entry_points]
        paths: list[CandidatePath] = []
        for path in self._completed(futures, "trace"):
            if path is not None:
                paths.append(path)
        return paths

    def _trace_entry(self, entry: Symbol) -> Optional[CandidatePath]:
        agent: TracerAgent = self.agents[AgentRole.TRACER]
        neighborhood = self.broker.neighborhood(entry.id, depth=2)
        entry_pack = self.broker.pack(entry)
        gathered: dict[str, dict] = {}
        label = f"Tracing {entry.qualname}"
        self._agent("tracer", "start", label, subject=entry.file)
        outcome = "no sink reached"
        try:
            for _ in range(self.cfg.concurrency.max_context_requests + 1):
                # Dynamic context management: as `gathered` grows across hops,
                # keep the entry point verbatim and compress the accumulated
                # context so the tracer prompt stays within budget.
                ctx_blocks = self.ctx.fit(
                    [entry_pack],
                    list(gathered.values()),
                    topic=f"trace {entry.qualname}",
                )[1:]
                result = agent.trace(entry_pack, neighborhood, ctx_blocks)
                need = result.get("need_context") or []
                if result.get("reached_sink"):
                    path = self._build_path(entry, result, neighborhood, gathered)
                    if path is not None:
                        self._note_path(path)
                        outcome = f"reached {path.vuln_class.value} sink: {' → '.join(path.chain)}"
                    return path
                if not need:
                    return None
                # Dynamic parent<->child: resolve requested context from the graph.
                new = self.broker.resolve(need)
                added = False
                for block in new:
                    if block["symbol_id"] not in gathered:
                        gathered[block["symbol_id"]] = block
                        added = True
                    if added and len(need):
                        outcome = f"requested context: {', '.join(need[:4])}"
                if not added:
                    return None
        except BudgetExceeded:
            outcome = "budget exceeded"
            return None
        finally:
            self._agent("tracer", "end", label, subject=entry.file, outcome=outcome)
        return None

    def _build_path(
        self, entry: Symbol, trace: dict, neighborhood: list[dict], gathered: dict
    ) -> Optional[CandidatePath]:
        sink = trace.get("sink") or {}
        sink_id = sink.get("symbol_id")
        sink_symbol = self.graph.get(sink_id) if sink_id else None
        if sink_symbol is None:
            sink_symbol = entry
        try:
            vuln_class = VulnClass(sink.get("vuln_class"))
        except (ValueError, TypeError):
            found = find_sinks(sink_symbol.code)
            if not found:
                return None
            vuln_class = found[0][0]

        sink_kind = sink.get("kind") or (find_sinks(sink_symbol.code) or [(vuln_class, "")])[0][1]
        sink_line = self._locate_sink_line(sink_symbol, sink_kind)

        # Assemble the path code: entry + relevant context, deduped by symbol.
        blocks = {entry.id: self.broker.pack(entry)}
        for b in neighborhood:
            blocks.setdefault(b["symbol_id"], b)
        for b in gathered.values():
            blocks.setdefault(b["symbol_id"], b)
        # Ensure sink symbol code present.
        blocks.setdefault(sink_symbol.id, self.broker.pack(sink_symbol))
        # Dynamic context management: keep entry + sink verbatim, compress the
        # rest so a long source->sink path doesn't overflow the analyzer prompt.
        anchor_ids = {entry.id, sink_symbol.id}
        anchors = [blocks[i] for i in anchor_ids if i in blocks]
        middle = [b for i, b in blocks.items() if i not in anchor_ids]
        fitted = self.ctx.fit(anchors, middle, topic=f"analyze {entry.qualname}")
        code = "\n\n# ---\n".join(
            f"# {b['file']}:{b['line']} {b['name']}\n{b['code']}" for b in fitted
        )
        return CandidatePath(
            entry=entry,
            sink_symbol=sink_symbol,
            sink_kind=sink_kind,
            vuln_class=vuln_class,
            chain=trace.get("chain") or [entry.name],
            code=code,
            sink_line=sink_line,
            context_ids=list(blocks.keys()),
        )

    # --- session memory helpers ---------------------------------------------

    def _note_path(self, path: CandidatePath) -> None:
        if not self.memory:
            return
        self.memory.note(
            title=f"Traced {path.vuln_class.value} path from {path.entry.qualname}",
            body=(
                f"Chain: {' -> '.join(path.chain)}\n"
                f"Sink: `{path.sink_kind}` at {path.sink_symbol.file}:{path.sink_line}"
            ),
            role="tracer",
            tags=["taint-path", path.vuln_class.value],
            file=path.sink_symbol.file,
            vuln_class=path.vuln_class.value,
        )

    def _note_finding(self, finding: Finding) -> None:
        if not self.memory:
            return
        self.memory.note(
            title=f"{finding.vuln_class.value} candidate: {finding.title}",
            body=(
                f"{finding.description}\n\n"
                f"Confidence {finding.confidence}/10 at "
                f"{finding.location.as_ref()} (entry: {finding.entry_point})."
            ),
            role="analyzer",
            tags=["finding", finding.vuln_class.value],
            file=finding.location.file,
            vuln_class=finding.vuln_class.value,
        )

    def _note_verdict(self, finding: Finding) -> None:
        if not self.memory or finding.verdict is None:
            return
        self.memory.note(
            title=f"Validator {finding.verdict.value}: {finding.title}",
            body=(finding.validation_notes or "")
            + f"\n\nAdjusted confidence: {finding.confidence}/10.",
            role="validator",
            tags=["verdict", finding.verdict.value, finding.vuln_class.value],
            file=finding.location.file,
            vuln_class=finding.vuln_class.value,
        )

    @staticmethod
    def _locate_sink_line(sym: Symbol, sink_kind: str) -> int:
        needle = (sink_kind or "").split("(")[0].strip()
        if needle:
            for i, line in enumerate(sym.code.splitlines()):
                if needle in line:
                    return sym.start_line + i
        return sym.start_line

    # --- stage 5: analyze ----------------------------------------------------

    def _analyze_stage(self, paths: list[CandidatePath], store: FindingStore, pools: WorkerPools) -> None:
        futures = [pools.neural.submit(self._analyze_path, p) for p in paths]
        for finding in self._completed(futures, "analyze"):
            if finding is not None:
                store.add(finding)

    def _analyze_path(self, path: CandidatePath) -> Optional[Finding]:
        agent: AnalyzerAgent = self.agents[AgentRole.ANALYZER]
        label = f"Analyzing {path.vuln_class.value} at {path.sink_symbol.qualname}"
        self._agent("analyzer", "start", label, subject=path.sink_symbol.file)
        subj = path.sink_symbol.file
        try:
            result = agent.analyze(
                vuln_class=path.vuln_class.value,
                symbol=path.sink_symbol.qualname,
                file=path.sink_symbol.file,
                sink_line=path.sink_line,
                code=path.code,
                chain=path.chain,
            )
        except BudgetExceeded:
            self._agent("analyzer", "end", label, subject=subj, outcome="budget exceeded")
            return None
        if not result.get("is_vulnerable"):
            self._agent("analyzer", "end", label, subject=subj, outcome="not vulnerable")
            return None
        confidence = int(result.get("confidence", 0))
        try:
            vc = VulnClass(result.get("vuln_class", path.vuln_class.value))
        except ValueError:
            vc = path.vuln_class
        chain_steps = self._chain_steps(path)
        finding = Finding(
            id=uuid.uuid4().hex[:12],
            vuln_class=vc,
            title=result.get("title") or f"{vc.value} in {path.sink_symbol.qualname}",
            description=result.get("description", ""),
            severity=severity_for(vc, confidence),
            confidence=confidence,
            location=CodeLocation(
                file=path.sink_symbol.file,
                start_line=path.sink_line,
                end_line=path.sink_line,
            ),
            entry_point=path.entry.qualname,
            sink=result.get("sink") or path.sink_kind,
            cwe=result.get("cwe") or CWE_MAP.get(vc),
            call_chain=chain_steps,
        )
        self._agent(
            "analyzer", "end", label, subject=subj,
            outcome=f"vulnerable (conf {confidence}): {finding.title}",
        )
        self._note_finding(finding)
        return finding

    def _chain_steps(self, path: CandidatePath) -> list[CallChainStep]:
        steps: list[CallChainStep] = []
        n = len(path.chain)
        for i, name in enumerate(path.chain):
            role = ChainRole.SOURCE if i == 0 else (ChainRole.SINK if i == n - 1 else ChainRole.PROPAGATOR)
            steps.append(CallChainStep(symbol=name, role=role))
        return steps

    # --- stage 6: validate ---------------------------------------------------

    def _validate_stage(self, store: FindingStore, pools: WorkerPools) -> list[Finding]:
        raw = store.all()
        futures = [pools.neural.submit(self._validate_finding, f) for f in raw]
        confirmed: list[Finding] = []
        for f in self._completed(futures, "validate"):
            if f is not None:
                confirmed.append(f)
        return confirmed

    def _validate_finding(self, finding: Finding) -> Optional[Finding]:
        agent: ValidatorAgent = self.agents[AgentRole.VALIDATOR]
        code = self._code_for(finding)
        payload = {
            "vuln_class": finding.vuln_class.value,
            "confidence": finding.confidence,
            "sink": finding.title,
            "file": finding.location.file,
            "line": finding.location.start_line,
            "description": finding.description,
        }
        # Cross-stage memory: surface what the tracer/analyzer already learned
        # about this file+class so the validator needn't re-derive it. Relevance
        # recall (deterministic), not an LLM deciding what to load.
        if self.memory and self.cfg.memory.share_across_stages:
            prior = self.memory.recall(
                file=finding.location.file,
                vuln_class=finding.vuln_class.value,
                limit=5,
            )
            if prior:
                payload["prior_notes"] = [
                    {"title": n.title, "role": n.role, "body": n.body} for n in prior
                ]
        # Knowledge-level RAG: retrieve CVE-derived items for this class and feed
        # them to the validator, which checks "cause present AND fix absent".
        knowledge_block = None
        if self.knowledge is not None:
            items = self.knowledge.retrieve(
                finding.vuln_class.value,
                [code, finding.description or "", finding.title],
            )
            if items:
                knowledge_block = [
                    {
                        "cause": it.abstract_cause or it.detailed_cause,
                        "fix": it.fixing_solution,
                        "source": it.source,
                    }
                    for it in items
                ]
                finding.knowledge_refs = [it.source for it in items]
        label = f"Validating {finding.title}"
        subj = finding.location.file
        self._agent("validator", "start", label, subject=subj)
        try:
            result = agent.validate(
                payload, code, [s.symbol for s in finding.call_chain], knowledge=knowledge_block
            )
        except BudgetExceeded:
            self._agent("validator", "end", label, subject=subj, outcome="budget exceeded (kept)")
            return finding  # fail-open: keep unvalidated rather than lose it
        verdict = result.get("verdict", "uncertain")
        finding.validated = True
        finding.verdict = Verdict(verdict) if verdict in Verdict._value2member_map_ else Verdict.UNCERTAIN
        finding.validation_notes = result.get("notes")
        adj = result.get("adjusted_confidence")
        if isinstance(adj, int):
            finding.confidence = adj
            finding.severity = severity_for(finding.vuln_class, adj)
        self._agent(
            "validator", "end", label, subject=subj,
            outcome=f"{finding.verdict.value} (conf {finding.confidence})",
        )
        self._note_verdict(finding)
        if finding.verdict == Verdict.REJECTED:
            return None
        return finding

    def _code_for(self, finding: Finding) -> str:
        for sym in self.graph.file_symbols(finding.location.file):
            if sym.start_line <= finding.location.start_line <= sym.end_line:
                return sym.code
        return ""

    # --- stage 7: remediate --------------------------------------------------

    def _remediate_stage(self, findings: list[Finding], pools: WorkerPools) -> None:
        futures = [pools.neural.submit(self._remediate_finding, f) for f in findings]
        for _ in self._completed(futures, "remediate"):
            pass

    def _remediate_finding(self, finding: Finding) -> None:
        agent: RemediatorAgent = self.agents[AgentRole.REMEDIATOR]
        code = self._code_for(finding)
        payload = {
            "vuln_class": finding.vuln_class.value,
            "file": finding.location.file,
            "line": finding.location.start_line,
            "sink": finding.sink or finding.title,
            "description": finding.description,
        }
        label = f"Proposing fix for {finding.title}"
        subj = finding.location.file
        self._agent("remediator", "start", label, subject=subj)
        try:
            result = agent.remediate(payload, code)
        except BudgetExceeded:
            self._agent("remediator", "end", label, subject=subj, outcome="budget exceeded")
            return
        if result:
            finding.remediation = Remediation(
                summary=result.get("summary", ""),
                diff=result.get("diff"),
                rationale=result.get("rationale", ""),
                confidence=int(result.get("confidence", 0)),
            )
        self._agent(
            "remediator", "end", label, subject=subj,
            outcome=(result.get("summary", "proposed fix") if result else "no fix"),
        )
