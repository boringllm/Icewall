"""End-to-end and unit tests for Icewall, all runnable offline via the mock
provider (no API keys)."""
from __future__ import annotations

import json
import os

import pytest

from icewall.config import AgentRole, IcewallConfig
from icewall.engine import Engine
from icewall.graph import build_graph
from icewall.providers.base import extract_json
from icewall.report import to_markdown, to_sarif
from icewall.schemas import ScanResult, Severity, VulnClass

SAMPLE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable_app")
)


@pytest.fixture(autouse=True, scope="session")
def _isolate_workshop(tmp_path_factory):
    """Run scans from a temp CWD so per-session .icewall/ folders don't litter
    the repo. SAMPLE is absolute, so scanning still resolves correctly."""
    d = tmp_path_factory.mktemp("icewall_cwd")
    old = os.getcwd()
    os.chdir(d)
    yield
    os.chdir(old)


# --- providers / json ---------------------------------------------------------

def test_extract_json_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced_with_prose():
    text = 'Here is the result:\n```json\n{"is_vulnerable": true, "confidence": 8}\n```\nDone.'
    assert extract_json(text) == {"is_vulnerable": True, "confidence": 8}


def test_extract_json_nested_braces():
    text = 'noise {"sink": {"kind": "os.system("}, "ok": true} tail'
    assert extract_json(text) == {"sink": {"kind": "os.system("}, "ok": True}


def test_extract_json_garbage_returns_empty():
    assert extract_json("not json at all") == {}


# --- graph --------------------------------------------------------------------

def test_graph_builds_symbols():
    g = build_graph(SAMPLE)
    s = g.stats()
    assert s["files"] == 3
    assert s["functions"] >= 10


def test_graph_interprocedural_edge():
    g = build_graph(SAMPLE)
    ping = g.find("ping")[0]
    callees = {c.name for c in g.callees(ping.id)}
    assert "run_report" in callees
    rr = g.find("run_report")[0]
    assert "ping" in {c.name for c in g.callers(rr.id)}


def test_graph_no_phantom_duplicate_symbols():
    # The JS grammar's nested `function` node must not create duplicates.
    g = build_graph(SAMPLE)
    starts = [(s.file, s.start_byte) for s in g.all_symbols()]
    assert len(starts) == len(set(starts))


# --- engine end-to-end (mock provider) ---------------------------------------

@pytest.fixture(scope="module")
def result() -> ScanResult:
    eng = Engine(IcewallConfig.default())
    return eng.scan(SAMPLE)


def test_finds_interprocedural_command_injection(result):
    ci = [f for f in result.findings if f.vuln_class == VulnClass.COMMAND_INJECTION]
    assert ci, "expected command injection finding"
    f = ci[0]
    # Entry is the route; sink is one hop away in utils.run_report.
    assert f.entry_point == "ping"
    assert f.location.file.endswith("utils.py")
    assert [s.symbol for s in f.call_chain] == ["ping", "run_report"]


def test_finds_sql_injection_and_rce(result):
    classes = {f.vuln_class for f in result.findings}
    assert VulnClass.SQLI in classes
    assert VulnClass.RCE in classes


def test_safe_parameterized_query_not_flagged(result):
    # /user -> safe_lookup uses a parameterized query; must not be a SQLi finding.
    for f in result.findings:
        if f.vuln_class == VulnClass.SQLI:
            assert "safe_lookup" not in (f.entry_point or "")
            assert f.entry_point != "user"


def test_all_findings_validated(result):
    for f in result.findings:
        assert f.validated
        assert f.verdict is not None
        assert f.verdict.value != "rejected"  # rejected ones are dropped


def test_confirmed_have_remediation_proposals(result):
    for f in result.findings:
        assert f.remediation is not None
        assert f.remediation.diff  # proposal only, never applied


def test_stats_populated(result):
    st = result.stats
    assert st.llm_calls > 0
    assert st.symbols > 0
    assert st.findings_confirmed == len(result.findings)


# --- reporting ----------------------------------------------------------------

def test_sarif_is_valid_json(result):
    doc = json.loads(to_sarif(result))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Icewall"


def test_markdown_mentions_findings(result):
    md = to_markdown(result)
    assert "Icewall Security Report" in md
    assert "CWE-" in md
    assert "proposal for review, not applied" in md


def test_json_roundtrips(result):
    data = result.model_dump_json()
    back = ScanResult.model_validate_json(data)
    assert len(back.findings) == len(result.findings)


# --- budget -------------------------------------------------------------------

def test_cost_priced_per_model():
    from icewall.config import AgentRole
    from icewall.cost import cost_of

    # 1M input + 1M output on opus 4.8 = $5 + $25 = $30.
    assert cost_of("claude-opus-4-8", 1_000_000, 1_000_000) == 30.0
    assert cost_of("claude-haiku-4-5", 1_000_000, 1_000_000) == 6.0
    assert cost_of("mock-1", 1_000_000, 1_000_000) == 0.0

    # Tiered config (mock provider, real model names) prices per model.
    cfg = IcewallConfig.default()
    cfg.agents[AgentRole.VALIDATOR].model = "claude-opus-4-8"
    cfg.agents[AgentRole.TRIAGE].model = "claude-haiku-4-5"
    res = Engine(cfg).scan(SAMPLE)
    assert res.stats.estimated_cost_usd > 0
    assert "claude-opus-4-8" in res.stats.cost_by_model
    # Total equals the sum of per-model costs.
    total = round(sum(m["cost_usd"] for m in res.stats.cost_by_model.values()), 4)
    assert abs(total - res.stats.estimated_cost_usd) < 0.001


def test_mock_run_is_free(result):
    assert result.stats.estimated_cost_usd == 0.0


def test_custom_price_override():
    from icewall.config import AgentRole, ModelPrice
    from icewall.cost import cost_of

    ov = {"kimi-x": (0.6, 2.5)}
    # Override beats both the built-in table and the default fallback.
    assert cost_of("kimi-x", 1_000_000, 1_000_000, ov) == 3.1  # 0.6 + 2.5
    # Unknown model without override still falls back to default ($1/$5).
    assert cost_of("kimi-x", 1_000_000, 1_000_000) == 6.0

    # Flows through config -> engine -> stats.
    cfg = IcewallConfig.default()
    cfg.agents[AgentRole.ANALYZER].model = "custom-x"
    cfg.pricing["custom-x"] = ModelPrice(input=2.0, output=8.0)
    assert cfg.price_overrides() == {"custom-x": (2.0, 8.0)}
    res = Engine(cfg).scan(SAMPLE)
    row = res.stats.cost_by_model["custom-x"]
    expected = round(row["input_tokens"] / 1e6 * 2.0 + row["output_tokens"] / 1e6 * 8.0, 4)
    assert abs(row["cost_usd"] - expected) < 0.0001


def test_pricing_yaml_short_keys(tmp_path):
    # YAML `input:`/`output:` keys map onto the ModelPrice fields.
    import yaml

    from icewall.config import ModelPrice

    data = yaml.safe_load("input: 0.6\noutput: 2.5\n")
    mp = ModelPrice.model_validate(data)
    assert mp.input_per_mtok == 0.6 and mp.output_per_mtok == 2.5


def test_progress_events_emitted():
    events = []
    Engine(IcewallConfig.default(), on_event=lambda e, kw: events.append((e, kw))).scan(SAMPLE)
    names = [e for e, _ in events]
    assert "stage_tasks" in names
    assert "task_done" in names
    # task_done carries a running cost readout for the live progress bar.
    done = [kw for e, kw in events if e == "task_done"]
    assert all("cost" in kw for kw in done)


def test_inline_api_key_resolution():
    # Inline api_key is used without an env var; missing both raises clearly.
    import os

    from icewall.config import ProviderConfig, ProviderType
    from icewall.providers.factory import build_provider

    os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        build_provider(ProviderConfig(type=ProviderType.ANTHROPIC))
    except RuntimeError as e:
        assert "api_key" in str(e) or "key" in str(e).lower()
    else:
        raise AssertionError("expected a missing-key error")


# --- workshop / memory / context management ----------------------------------

def test_workshop_created_with_artifacts_and_session(tmp_path):
    cfg = IcewallConfig.default()
    cfg.workshop.root = str(tmp_path / "ws")
    res = Engine(cfg).scan(SAMPLE)

    assert res.workshop_dir is not None
    wdir = os.path.abspath(res.workshop_dir)
    assert os.path.isdir(wdir)
    # Reports are persisted into the session folder automatically.
    for name in ("report.md", "report.sarif", "report.json"):
        assert os.path.isfile(os.path.join(wdir, "artifacts", name))
    # session.json records final status + cost.
    with open(os.path.join(wdir, "session.json"), encoding="utf-8") as fh:
        session = json.load(fh)
    assert session["status"] == "complete"
    assert session["findings_confirmed"] == len(res.findings)
    assert "estimated_cost_usd" in session


def test_each_scan_gets_its_own_session_folder(tmp_path):
    cfg = IcewallConfig.default()
    cfg.workshop.root = str(tmp_path / "ws")
    a = Engine(cfg).scan(SAMPLE).workshop_dir
    b = Engine(cfg).scan(SAMPLE).workshop_dir
    assert a != b
    assert len({a, b}) == 2


def test_memory_master_and_subnotes_written(tmp_path):
    cfg = IcewallConfig.default()
    cfg.workshop.root = str(tmp_path / "ws")
    res = Engine(cfg).scan(SAMPLE)

    mem_dir = os.path.join(os.path.abspath(res.workshop_dir), "memory")
    master = os.path.join(mem_dir, "master.md")
    assert os.path.isfile(master)
    text = open(master, encoding="utf-8").read()
    assert "master index" in text
    # Agents wrote role-tagged sub-notes.
    for role in ("triage", "analyzer", "validator"):
        assert role in text
    notes = os.listdir(os.path.join(mem_dir, "notes"))
    assert len(notes) >= 3


def test_workshop_disabled_is_noop(tmp_path):
    cfg = IcewallConfig.default()
    cfg.workshop.enabled = False
    cfg.workshop.root = str(tmp_path / "ws")
    res = Engine(cfg).scan(SAMPLE)
    assert res.workshop_dir is None
    assert not (tmp_path / "ws").exists()
    # Findings are unaffected by the workshop being off.
    assert res.findings


def test_workshop_keep_last_prunes_old_sessions(tmp_path):
    cfg = IcewallConfig.default()
    cfg.workshop.root = str(tmp_path / "ws")
    cfg.workshop.keep_last = 1
    Engine(cfg).scan(SAMPLE)
    last = Engine(cfg).scan(SAMPLE).workshop_dir
    remaining = os.listdir(tmp_path / "ws")
    assert len(remaining) == 1
    assert os.path.basename(os.path.abspath(last)) in remaining


def test_session_memory_recall_by_relevance():
    from icewall.memory import SessionMemory

    mem = SessionMemory(None)  # in-memory only
    mem.note("A", "sql body", role="analyzer", file="app.py", vuln_class="sql_injection")
    mem.note("B", "xss body", role="analyzer", file="web.js", vuln_class="xss")
    mem.note("C", "sql note 2", role="tracer", file="app.py", vuln_class="sql_injection")

    hits = mem.recall(file="app.py", vuln_class="sql_injection")
    titles = {n.title for n in hits}
    assert titles == {"A", "C"}
    # Most-recent first.
    assert hits[0].title == "C"
    assert mem.recall(role="analyzer", file="web.js")[0].title == "B"


def test_context_manager_summarizes_overflow_without_agent():
    from icewall.orchestration import ContextManager, estimate_tokens

    cm = ContextManager(max_tokens=50, target_tokens=20, summarizer=None)
    anchor = {"symbol_id": "e", "name": "entry", "file": "a.py", "line": 1,
              "code": "def entry(x):\n    return sink(x)"}
    blocks = [
        {"symbol_id": f"s{i}", "name": f"f{i}", "file": "a.py", "line": i,
         "code": "def f(x):\n    " + "y = x + 1\n    " * 40 + "return y"}
        for i in range(6)
    ]
    fitted = cm.fit([anchor], blocks, topic="t")
    # Anchor is preserved verbatim; overflow is compressed into a digest block.
    assert fitted[0] is anchor
    assert any(b.get("summarized") for b in fitted)
    # The result is smaller than the raw input.
    raw = sum(estimate_tokens(b["code"]) for b in [anchor] + blocks)
    got = sum(estimate_tokens(b["code"]) for b in fitted)
    assert got < raw


def test_context_manager_records_summary_to_memory():
    from icewall.memory import SessionMemory
    from icewall.orchestration import ContextManager

    mem = SessionMemory(None)
    cm = ContextManager(max_tokens=10, target_tokens=5, summarizer=None, memory=mem)
    blocks = [
        {"symbol_id": f"s{i}", "name": f"f{i}", "file": "a.py", "line": i,
         "code": "x = 1\n" * 30}
        for i in range(4)
    ]
    cm.fit([], blocks, topic="mytopic")
    notes = mem.recall(tags=["context-summary"])
    assert notes and "mytopic" in notes[0].title


def test_summarizer_agent_compresses_via_context_manager():
    # The wired-up SummarizerAgent (mock) is what the ContextManager calls when
    # context overflows; its taint-aware digest replaces the raw bodies.
    from icewall.config import AgentRole
    from icewall.orchestration import ContextManager

    eng = Engine(IcewallConfig.default())
    agent = eng.agents[AgentRole.SUMMARIZER]
    cm = ContextManager(
        max_tokens=20, target_tokens=5,
        summarizer=lambda blocks, topic: agent.summarize(blocks, topic),
    )
    blocks = [
        {"symbol_id": "s1", "name": "handler", "file": "app.py", "line": 1,
         "code": "def handler(req):\n    cmd = req.args['c']\n    os.system(cmd)\n"
                 + "    pass\n" * 30},
    ]
    fitted = cm.fit([], blocks, topic="t")
    digest = next(b for b in fitted if b.get("summarized"))
    # The mock summarizer reports the taint signal it detected.
    assert "Taint-relevant digest" in digest["code"]
    assert "os.system" in digest["code"]


def test_summarizer_role_in_default_config():
    cfg = IcewallConfig.default()
    assert AgentRole.SUMMARIZER in cfg.agents
    eng = Engine(cfg)
    assert AgentRole.SUMMARIZER in eng.agents


def test_config_without_summarizer_still_loads(tmp_path):
    # Backward compat: a config predating the summarizer role must still run.
    cfg = IcewallConfig.default()
    del cfg.agents[AgentRole.SUMMARIZER]
    cfg.workshop.root = str(tmp_path / "ws")
    eng = Engine(cfg)
    assert AgentRole.SUMMARIZER not in eng.agents
    res = eng.scan(SAMPLE)  # ContextManager falls back to heuristic digest
    assert res.findings


def test_verify_ssl_config_and_cache_key():
    from icewall.config import ProviderConfig, ProviderType
    from icewall.providers.factory import _cache_key

    # Defaults to secure; togglable per provider.
    assert ProviderConfig(type=ProviderType.OPENAI).verify_ssl is True
    insecure = ProviderConfig(type=ProviderType.OPENAI, verify_ssl=False)
    assert insecure.verify_ssl is False
    # verify_ssl participates in the provider cache key (different clients).
    secure = ProviderConfig(type=ProviderType.OPENAI, base_url="http://x")
    insecure2 = ProviderConfig(type=ProviderType.OPENAI, base_url="http://x", verify_ssl=False)
    assert _cache_key(secure) != _cache_key(insecure2)


def test_llm_exchange_recorder_captures_calls():
    from icewall.config import AgentRole
    from icewall.orchestration import TraceRecorder

    seen = []
    rec = TraceRecorder(seen.append)
    cfg = IcewallConfig.default()
    eng = Engine(cfg)
    eng.recorder = rec
    for a in eng.agents.values():
        a.recorder = rec
    res = eng.scan(SAMPLE)
    assert seen, "expected captured LLM exchanges"
    # Every record has the exchange fields and is tagged to a task.
    r0 = seen[0]
    assert r0["system"] and r0["user"] and r0["response"]
    assert r0["task_id"] and r0["role"]


def test_agent_params_forwarded_to_provider():
    # Arbitrary generation params on the agent config reach provider.complete().
    from icewall.agents.base import BaseAgent
    from icewall.config import AgentModelConfig, AgentRole
    from icewall.orchestration import BudgetTracker
    from icewall.providers.base import LLMProvider, LLMResponse

    seen = {}

    class Fake(LLMProvider):
        def complete(self, *, system, messages, model, max_tokens=4096,
                     temperature=0.0, thinking_tokens=0, params=None):
            seen["params"] = params
            return LLMResponse(text='{"ok": true}', input_tokens=1, output_tokens=1, model=model)

    class A(BaseAgent):
        role = AgentRole.TRIAGE
        SYSTEM = "x"

    cfg = AgentModelConfig(
        provider="p", model="m",
        params={"top_p": 0.9, "reasoning_effort": "high", "stop": ["\n\n"]},
    )
    A(Fake(), cfg, BudgetTracker(10**9, 10**6)).call({"a": 1})
    assert seen["params"] == {"top_p": 0.9, "reasoning_effort": "high", "stop": ["\n\n"]}


def test_agent_params_round_trip_and_scan():
    # A config carrying custom params validates and scans (mock ignores them).
    from icewall.config import AgentRole

    cfg = IcewallConfig.default()
    cfg.agents[AgentRole.ANALYZER].params = {"top_p": 0.8, "stop_sequences": ["Q:"]}
    dumped = cfg.model_dump()
    assert dumped["agents"][AgentRole.ANALYZER]["params"]["top_p"] == 0.8
    res = Engine(cfg).scan(SAMPLE)
    assert res.findings  # params don't disrupt the mock pipeline


def test_intensity_presets_set_recall_knobs():
    from icewall.config import INTENSITY_IDS, apply_intensity

    assert INTENSITY_IDS == ["fast", "balanced", "thorough", "exhaustive"]
    fast = apply_intensity(IcewallConfig.default(), "fast")
    exhaustive = apply_intensity(IcewallConfig.default(), "exhaustive")
    assert fast.budget.min_suspicion > exhaustive.budget.min_suspicion
    assert fast.concurrency.max_context_requests < exhaustive.concurrency.max_context_requests
    assert exhaustive.scan.analyze_all_functions is True
    # Unknown/custom leaves the config untouched.
    c = IcewallConfig.default()
    c.budget.min_suspicion = 0.42
    apply_intensity(c, "custom")
    assert c.budget.min_suspicion == 0.42


def test_analyze_all_functions_triages_every_function():
    g = build_graph(SAMPLE)
    eng = Engine(IcewallConfig.default())
    filtered = eng._candidate_symbols(g)
    eng.cfg.scan.analyze_all_functions = True
    every = eng._candidate_symbols(g)
    # Exhaustive triages the full function set (a superset of the pattern-filtered).
    assert len(every) == len(g.functions())
    assert set(s.id for s in filtered) <= set(s.id for s in every)


def test_budget_halts_pipeline():
    cfg = IcewallConfig.default()
    cfg.budget.max_llm_calls = 2  # exhaust almost immediately
    eng = Engine(cfg)
    res = eng.scan(SAMPLE)
    # With a 2-call ceiling the run must stop early: few/no confirmed findings.
    assert res.stats.llm_calls <= 4
    assert res.stats.findings_confirmed <= 2
