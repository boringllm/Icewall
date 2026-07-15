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
    app = create_app(workshop_root=str(tmp_path / "ws"))
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
