"""Tests for the web UI backend (FastAPI), all offline via the mock provider.

Uses the in-process TestClient — no browser, no network. The frontend (static
JS/HTML) is exercised manually; these lock down the API contract the UI relies on.
"""
from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from icewall.ui.server import create_app  # noqa: E402

SAMPLE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable_app")
)


@pytest.fixture()
def client(tmp_path):
    app = create_app(workshop_root=str(tmp_path / "ws"), kb_root=str(tmp_path / "kb"))
    return TestClient(app)


def _run_scan_to_completion(client, body):
    job = client.post("/api/scan", json=body).json()
    events = []
    with client.stream("GET", f"/api/scan/{job['id']}/events") as resp:
        for line in resp.iter_lines():
            if line and line.startswith("data: "):
                ev = json.loads(line[6:])
                events.append(ev)
                if ev["event"] == "stream_end":
                    break
    return job, events


# --- meta --------------------------------------------------------------------

def test_health(client):
    h = client.get("/api/health").json()
    assert h["ok"] and h["version"]


def test_config_template_and_validate(client):
    tmpl = client.get("/api/config/template").json()
    assert "agents" in tmpl and "providers" in tmpl
    ok = client.post("/api/config/validate", json={"config": tmpl}).json()
    assert ok["ok"] is True
    bad = client.post("/api/config/validate", json={"config": {"providers": {}}}).json()
    assert bad["ok"] is False


# --- presets -----------------------------------------------------------------

def test_presets_crud(client):
    cfg = client.get("/api/config/template").json()
    # create
    r = client.put("/api/presets/My Preset", json={"description": "d", "config": cfg})
    assert r.status_code == 200
    name = r.json()["name"]  # sanitized
    # list + get
    assert any(p["name"] == name for p in client.get("/api/presets").json())
    got = client.get(f"/api/presets/{name}").json()
    assert got["config"]["agents"]
    # invalid config is rejected
    bad = client.put("/api/presets/bad", json={"config": {"nope": 1}})
    assert bad.status_code == 400
    # delete
    assert client.delete(f"/api/presets/{name}").json()["deleted"] is True
    assert client.get(f"/api/presets/{name}").status_code == 404


def test_preset_carries_provider_timeout_and_retries(client):
    # The config form now exposes provider timeout/max_retries/extra_headers;
    # a preset must round-trip them so they aren't silently dropped.
    cfg = client.get("/api/config/template").json()
    cfg["providers"]["ui"] = {
        "type": "openai", "base_url": "https://x/v1",
        "timeout": 45, "max_retries": 2, "extra_headers": {"X-Gw": "k"},
    }
    for a in cfg["agents"].values():
        a["provider"] = "ui"
    client.put("/api/presets/prov", json={"config": cfg})
    p = client.get("/api/presets/prov").json()["config"]["providers"]["ui"]
    assert p["timeout"] == 45 and p["max_retries"] == 2 and p["extra_headers"] == {"X-Gw": "k"}


def test_import_config_file_as_preset(client, tmp_path):
    import yaml

    # A config like the user's icewall.yaml (openai-compatible endpoint + key).
    cfg = {
        "providers": {"glm": {"type": "openai", "base_url": "https://openrouter.ai/api/v1", "api_key": "sk-test"}},
        "agents": {r: {"provider": "glm", "model": "z-ai/glm-5.2"} for r in
                   ["triage", "tracer", "analyzer", "validator", "remediator"]},
    }
    cfg_path = tmp_path / "icewall.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    r = client.post("/api/presets/import", json={"path": str(cfg_path)})
    assert r.status_code == 200
    name = r.json()["name"]
    # It shows up as a preset and carries the endpoint + model through.
    got = client.get(f"/api/presets/{name}").json()
    assert got["config"]["providers"]["glm"]["base_url"] == "https://openrouter.ai/api/v1"
    assert got["config"]["agents"]["analyzer"]["model"] == "z-ai/glm-5.2"


def test_import_missing_file_404(client):
    assert client.post("/api/presets/import", json={"path": "nope.yaml"}).status_code == 404


def test_preset_roundtrips_into_scan(client):
    cfg = client.get("/api/config/template").json()
    client.put("/api/presets/run1", json={"config": cfg})
    job, events = _run_scan_to_completion(client, {"target": SAMPLE, "preset": "run1"})
    assert any(e["event"] == "scan_complete" for e in events)


# --- scanning ----------------------------------------------------------------

def test_scan_streams_agents_graph_and_completion(client):
    job, events = _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})
    names = {e["event"] for e in events}
    assert {"scan_started", "graph_data", "agent", "scan_complete"} <= names

    # Live agent activity spans every role.
    roles = {e["role"] for e in events if e["event"] == "agent"}
    assert {"triage", "tracer", "analyzer", "validator", "remediator"} <= roles

    # Graph payload is usable by the visualization.
    gd = next(e for e in events if e["event"] == "graph_data")
    assert gd["nodes"] and "id" in gd["nodes"][0]

    done = next(e for e in events if e["event"] == "scan_complete")
    assert done["findings"] > 0
    assert set(done["cost_by_role"]) >= {"triage", "analyzer", "validator"}


def test_agent_events_carry_live_cost_and_outcomes(client):
    _, events = _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})
    agent = [e for e in events if e["event"] == "agent"]
    # Per-agent running cost is on every event (drives live per-agent spend).
    assert all("role_cost" in e for e in agent)
    # 'end' events report what the agent concluded (the transcript payload).
    ends = [e for e in agent if e["phase"] == "end"]
    assert ends and all("outcome" in e for e in ends)
    verdicts = [e["outcome"] for e in ends if e["role"] == "validator"]
    assert any("confirmed" in o for o in verdicts)


def test_artifact_downloads_as_attachment(client):
    _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})
    sid = client.get("/api/sessions").json()[0]["id"]
    r = client.get(f"/api/sessions/{sid}/artifact/report.md")
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
    # Inline view still available via ?download=false.
    r2 = client.get(f"/api/sessions/{sid}/artifact/report.md?download=false")
    assert "attachment" not in r2.headers.get("content-disposition", "")


def test_intensities_endpoint(client):
    data = client.get("/api/config/intensities").json()
    ids = [l["id"] for l in data["levels"]]
    assert ids == ["fast", "balanced", "thorough", "exhaustive"]
    assert data["default"] == "balanced"
    assert all("description" in l for l in data["levels"])


def test_scan_honors_intensity(client):
    # Exhaustive intensity applies to a dry-run scan and completes.
    _, events = _run_scan_to_completion(
        client, {"target": SAMPLE, "dry_run": True, "intensity": "exhaustive"}
    )
    assert any(e["event"] == "scan_complete" for e in events)
    assert any(e["event"] == "agent" for e in events)


def test_scan_bad_target_400(client):
    r = client.post("/api/scan", json={"target": "does/not/exist", "dry_run": True})
    assert r.status_code == 400


# --- knowledge base (Vul-RAG) ------------------------------------------------

def test_kb_seed_stats_items_and_clear(client):
    empty = client.get("/api/kb/stats").json()
    assert empty["count"] == 0 and empty["has_embedding"] is False

    seeded = client.post("/api/kb/seed", json={}).json()
    assert seeded["added"] >= 5

    stats = client.get("/api/kb/stats").json()
    assert stats["count"] == seeded["added"]
    assert "command_injection" in stats["by_class"]

    items = client.get("/api/kb/items", params={"vuln_class": "command_injection"}).json()
    assert items and all(i["vuln_class"] == "command_injection" for i in items)
    assert "embedding" not in items[0]  # trimmed from the payload

    assert client.delete("/api/kb").json()["cleared"] == seeded["added"]
    assert client.get("/api/kb/stats").json()["count"] == 0


def test_kb_build_requires_cves(client):
    r = client.post("/api/kb/build", json={"cves": [], "distiller": {"type": "mock"}, "distiller_model": "m"})
    assert r.status_code == 400


def test_kb_import_validation(client):
    base = {"distiller": {"type": "mock"}, "distiller_model": "m"}
    assert client.post("/api/kb/import", json={"source": "nope", **base}).status_code == 400
    assert client.post("/api/kb/import", json={"source": "cvefixes", **base}).status_code == 400  # no db


def test_kb_import_cvefixes_builds_items(client, tmp_path):
    import sqlite3

    db = tmp_path / "CVEfixes.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE cve(cve_id TEXT, description TEXT);"
        "CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);"
        "CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);"
        "CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);"
        "INSERT INTO cve VALUES('CVE-1','sqli');"
        "INSERT INTO fixes VALUES('CVE-1','h1','u');"
        "INSERT INTO file_change VALUES('f1','h1','Python');"
        "INSERT INTO method_change VALUES('f1','search',1,'execute(\"SELECT \"+v)');"
        "INSERT INTO method_change VALUES('f1','search',0,'execute(\"SELECT ?\", v)');"
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-89');"
    )
    conn.commit()
    conn.close()

    job = client.post("/api/kb/import", json={
        "source": "cvefixes", "db_path": str(db),
        "distiller": {"type": "mock"}, "distiller_model": "mock-1", "limit": 5,
    }).json()
    # Drain the shared build-event stream to completion.
    with client.stream("GET", f"/api/kb/build/{job['id']}/events") as resp:
        for line in resp.iter_lines():
            if line and line.startswith("data: ") and json.loads(line[6:])["event"] == "stream_end":
                break
    stats = client.get("/api/kb/stats").json()
    assert stats["count"] == 1 and "sql_injection" in stats["by_class"]


def _drain(client, job_id):
    summary = None
    with client.stream("GET", f"/api/kb/build/{job_id}/events") as resp:
        for line in resp.iter_lines():
            if not (line and line.startswith("data: ")):
                continue
            ev = json.loads(line[6:])
            if ev["event"] == "build_complete":
                summary = ev
            if ev["event"] == "stream_end":
                break
    return summary


def _make_cvefixes_db(path):
    import sqlite3

    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE cve(cve_id TEXT, description TEXT);"
        "CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);"
        "CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);"
        "CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);"
        "INSERT INTO cve VALUES('CVE-1','sqli');"
        "INSERT INTO fixes VALUES('CVE-1','h1','u');"
        "INSERT INTO file_change VALUES('f1','h1','Python');"
        "INSERT INTO method_change VALUES('f1','search',1,'execute(\"SELECT \"+v)');"
        "INSERT INTO method_change VALUES('f1','search',0,'execute(\"SELECT ?\", v)');"
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-89');"
    )
    conn.commit()
    conn.close()


def test_kb_test_llm_probes_distiller(client):
    # Mock provider answers a tiny completion => ok with a latency reading.
    r = client.post("/api/kb/test-llm", json={
        "distiller": {"type": "mock"}, "distiller_model": "mock-1"}).json()
    assert r["ok"] is True and "latency_ms" in r
    # Missing model is a client error.
    assert client.post("/api/kb/test-llm", json={
        "distiller": {"type": "mock"}, "distiller_model": ""}).status_code == 400


def test_kb_test_embedding_reports_bm25_without_model(client):
    r = client.post("/api/kb/test-embedding", json={"embedding": None}).json()
    assert r["ok"] is True and r["mode"] == "bm25"
    r2 = client.post("/api/kb/test-embedding", json={"embedding": {"model": ""}}).json()
    assert r2["mode"] == "bm25"


def test_kb_import_skip_existing_dedups_on_reimport(client, tmp_path):
    db = tmp_path / "CVEfixes.db"
    _make_cvefixes_db(str(db))
    body = {
        "source": "cvefixes", "db_path": str(db),
        "distiller": {"type": "mock"}, "distiller_model": "mock-1", "limit": 5,
    }
    first = _drain(client, client.post("/api/kb/import", json=body).json()["id"])
    assert first["added"] == 1 and first.get("skipped", 0) == 0

    # Re-import the same dataset: the one pair is already in the KB -> skipped.
    second = _drain(client, client.post("/api/kb/import", json=body).json()["id"])
    assert second["added"] == 0 and second["skipped"] == 1
    assert client.get("/api/kb/stats").json()["count"] == 1


def test_kb_search_and_delete_item(client):
    client.post("/api/kb/seed", json={})  # BM25 base, several classes
    all_items = client.get("/api/kb/items").json()
    assert all_items

    # BM25 search returns ranked matches with scores.
    res = client.post("/api/kb/search", json={
        "query": "sql database query from user input", "mode": "bm25"}).json()
    assert res["mode"] == "bm25" and res["results"]
    assert "score" in res["results"][0] and "id" in res["results"][0]

    # Delete one item by id.
    victim = all_items[0]["id"]
    assert client.delete(f"/api/kb/items/{victim}").json()["deleted"] == 1
    remaining = {i["id"] for i in client.get("/api/kb/items").json()}
    assert victim not in remaining

    # Bulk delete by id list.
    ids = list(remaining)[:2]
    assert client.post("/api/kb/items/delete", json={"ids": ids}).json()["deleted"] == len(ids)
    assert client.post("/api/kb/items/delete", json={"ids": []}).status_code == 400


def test_kb_search_embedding_mode_errors_without_model(client):
    client.post("/api/kb/seed", json={})  # seeded without embeddings
    r = client.post("/api/kb/search", json={"query": "x", "mode": "embedding"})
    assert r.status_code == 400  # no embedding model / no embedded items
    assert client.post("/api/kb/search", json={"query": "x", "mode": "nope"}).status_code == 400


def test_kb_endpoint_presets_crud(client):
    assert client.get("/api/kb/endpoint-presets").json() == []
    body = {
        "distiller": {"type": "openai", "base_url": "https://x/v1", "timeout": 60, "max_retries": 1},
        "distiller_model": "cheap-1",
        "embedding": {"model": "emb-1", "base_url": "https://y/v1"},
    }
    name = client.put("/api/kb/endpoint-presets/My Endpoints", json=body).json()["name"]
    assert name == "My-Endpoints"  # sanitized
    assert any(p["name"] == name for p in client.get("/api/kb/endpoint-presets").json())

    got = client.get(f"/api/kb/endpoint-presets/{name}").json()
    assert got["distiller"]["timeout"] == 60 and got["distiller_model"] == "cheap-1"
    assert got["embedding"]["model"] == "emb-1"

    # An invalid provider config is rejected before it is stored.
    assert client.put("/api/kb/endpoint-presets/bad", json={"distiller": {"type": "nope"}}).status_code == 400

    assert client.delete(f"/api/kb/endpoint-presets/{name}").json()["deleted"] is True
    assert client.get(f"/api/kb/endpoint-presets/{name}").status_code == 404


def test_scan_with_knowledge_toggle_attaches_refs(client):
    client.post("/api/kb/seed", json={})  # BM25 knowledge base
    _, events = _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True, "knowledge": True})
    assert any(e["event"] == "scan_complete" for e in events)

    sid = client.get("/api/sessions").json()[0]["id"]
    findings = client.get(f"/api/sessions/{sid}").json()["findings"]
    refs = [f.get("knowledge_refs") for f in findings if f.get("knowledge_refs")]
    assert refs, "expected at least one finding to cite retrieved knowledge"


def test_scan_without_toggle_has_no_refs(client):
    client.post("/api/kb/seed", json={})
    _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})  # no knowledge flag
    sid = client.get("/api/sessions").json()[0]["id"]
    findings = client.get(f"/api/sessions/{sid}").json()["findings"]
    assert all(not f.get("knowledge_refs") for f in findings)


def test_scan_reconnect_replays_events(client):
    # A late subscriber still receives the full event history (buffer replay).
    job = client.post("/api/scan", json={"target": SAMPLE, "dry_run": True}).json()
    # First drain finishes the job.
    _run_scan_to_completion_by_id(client, job["id"])
    # A brand-new stream replays from the start.
    events = _run_scan_to_completion_by_id(client, job["id"])
    assert any(e["event"] == "scan_complete" for e in events)


def _run_scan_to_completion_by_id(client, job_id):
    events = []
    with client.stream("GET", f"/api/scan/{job_id}/events") as resp:
        for line in resp.iter_lines():
            if line and line.startswith("data: "):
                ev = json.loads(line[6:])
                events.append(ev)
                if ev["event"] == "stream_end":
                    break
    return events


# --- sessions dashboard ------------------------------------------------------

def test_session_dashboard_after_scan(client):
    _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})

    sessions = client.get("/api/sessions").json()
    assert sessions and sessions[0]["status"] == "complete"
    sid = sessions[0]["id"]

    detail = client.get(f"/api/sessions/{sid}").json()
    assert detail["findings"]
    # Per-agent cost is what the dashboard's cost chart renders.
    cbr = detail["stats"]["cost_by_role"]
    assert set(cbr) >= {"triage", "analyzer", "validator"}
    assert all("cost_usd" in v and "calls" in v for v in cbr.values())

    # Saved graph + memory + artifacts are reachable.
    assert client.get(f"/api/sessions/{sid}/graph").json()["nodes"]
    assert "master index" in client.get(f"/api/sessions/{sid}/memory").json()["master"]
    assert "report.md" in detail["artifacts"]
    md = client.get(f"/api/sessions/{sid}/artifact/report.md")
    assert md.status_code == 200 and "Icewall" in md.text


def test_session_not_found(client):
    assert client.get("/api/sessions/nope").status_code == 404


def test_index_served(client):
    html = client.get("/")
    assert html.status_code == 200 and "Icewall" in html.text


def test_cytoscape_vendored_offline(client):
    # The graph library is served locally, so the graph works with no network.
    r = client.get("/static/vendor/cytoscape.min.js")
    assert r.status_code == 200 and len(r.content) > 100_000
    # The page references the local copy, not a CDN.
    assert "/static/vendor/cytoscape.min.js" in client.get("/").text
    assert "cdnjs" not in client.get("/").text


def test_llm_exchanges_captured_and_linked_to_tasks(client):
    job, events = _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})
    traces = [e for e in events if e["event"] == "agent_trace"]
    assert traces, "expected captured LLM exchanges"
    t = traces[0]
    # Each exchange carries the full input/output for the drill-down.
    assert t["system"] and t["user"] and t["response"]
    assert "input_tokens" in t and "output_tokens" in t and "reasoning" in t
    # Exchanges are tagged to the task (agent start) they ran under.
    starts = {e["task_id"] for e in events if e.get("event") == "agent" and e.get("phase") == "start"}
    assert t["task_id"] in starts


def test_traces_persisted_and_served(client):
    _run_scan_to_completion(client, {"target": SAMPLE, "dry_run": True})
    sid = client.get("/api/sessions").json()[0]["id"]
    tr = client.get(f"/api/sessions/{sid}/traces").json()
    assert tr and all("response" in r for r in tr)


def test_trace_disabled_produces_no_exchanges(client, tmp_path):
    cfg = client.get("/api/config/template").json()
    cfg["trace"] = {"enabled": False}
    _, events = _run_scan_to_completion(client, {"target": SAMPLE, "config": cfg})
    assert not [e for e in events if e["event"] == "agent_trace"]
