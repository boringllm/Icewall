"""FastAPI app for the Icewall UI.

Routes:
  GET  /                          the single-page app
  GET  /api/health                liveness + version
  GET  /api/config/template       a starting config dict for the settings form
  POST /api/config/validate       validate a config dict -> {ok, errors, summary}
  GET  /api/presets               list saved presets
  GET  /api/presets/{name}        one preset (name, description, config)
  PUT  /api/presets/{name}        create/update a preset (validated)
  DEL  /api/presets/{name}        delete a preset
  POST /api/scan                  start a scan -> {job}
  GET  /api/scan                  list scan jobs
  GET  /api/scan/{id}             job snapshot
  GET  /api/scan/{id}/events      SSE stream of live scan events
  GET  /api/sessions              list workshop sessions (dashboard index)
  GET  /api/sessions/{id}         session detail (metadata, findings, cost/agent)
  GET  /api/sessions/{id}/graph   saved code-graph view
  GET  /api/sessions/{id}/memory  master.md + note list
  GET  /api/sessions/{id}/artifact/{name}   raw artifact (md/sarif/json)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from icewall import __version__
from icewall.config import INTENSITY_LEVELS, IcewallConfig, apply_intensity
from icewall.ui.presets import PresetStore
from icewall.ui.runner import ScanManager

STATIC_DIR = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    target: str
    preset: Optional[str] = None
    config: Optional[dict] = None
    dry_run: bool = False
    # Named intensity (fast/balanced/thorough/exhaustive) overriding the recall
    # knobs on whatever base config is resolved. "custom"/None leaves it alone.
    intensity: Optional[str] = None


class PresetBody(BaseModel):
    description: str = ""
    config: dict


class ValidateBody(BaseModel):
    config: dict


class ImportBody(BaseModel):
    path: str
    name: Optional[str] = None


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


def create_app(workshop_root: str = ".icewall", presets_root: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="Icewall UI", version=__version__)
    manager = ScanManager()
    presets = PresetStore(presets_root or f"{workshop_root}/presets")
    root = Path(workshop_root)

    # --- meta / config -------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": __version__, "workshop_root": str(root)}

    @app.get("/api/config/template")
    def config_template() -> dict:
        # Mock-backed default: runs with no keys; the form switches provider type.
        return IcewallConfig.default().model_dump(mode="json")

    @app.get("/api/config/intensities")
    def config_intensities() -> dict:
        return {"levels": INTENSITY_LEVELS, "default": "balanced"}

    @app.post("/api/config/validate")
    def config_validate(body: ValidateBody) -> dict:
        try:
            cfg = IcewallConfig.model_validate(body.config)
            return {"ok": True, "summary": cfg.summary()}
        except Exception as exc:
            return {"ok": False, "errors": str(exc)}

    # --- presets -------------------------------------------------------------

    @app.get("/api/presets")
    def list_presets() -> list[dict]:
        return presets.list()

    @app.post("/api/presets/import")
    def import_preset(body: ImportBody) -> dict:
        try:
            return presets.import_file(body.path, body.name)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            raise HTTPException(400, f"could not import: {exc}")

    @app.get("/api/presets/{name}")
    def get_preset(name: str) -> dict:
        data = presets.get(name)
        if data is None:
            raise HTTPException(404, f"no preset '{name}'")
        return data

    @app.put("/api/presets/{name}")
    def put_preset(name: str, body: PresetBody) -> dict:
        try:
            return presets.save(name, body.config, body.description)
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/api/presets/{name}")
    def delete_preset(name: str) -> dict:
        return {"deleted": presets.delete(name)}

    # --- scans ---------------------------------------------------------------

    def _resolve_config(req: ScanRequest) -> IcewallConfig:
        if req.dry_run:
            cfg = IcewallConfig.default()
        elif req.config is not None:
            cfg = IcewallConfig.model_validate(req.config)
        elif req.preset:
            cfg = presets.config_for(req.preset)
        else:
            cfg = IcewallConfig.default()
        # Intensity overrides the recall knobs on the resolved base config, so it
        # applies uniformly to dry-run, preset, and form-config scans.
        if req.intensity:
            apply_intensity(cfg, req.intensity)
        # UI scans always land in the dashboard's workshop root.
        cfg.workshop.enabled = True
        cfg.workshop.root = str(root)
        return cfg

    @app.post("/api/scan")
    def start_scan(req: ScanRequest) -> dict:
        if not Path(req.target).exists():
            raise HTTPException(400, f"target not found: {req.target}")
        try:
            cfg = _resolve_config(req)
        except Exception as exc:
            raise HTTPException(400, f"bad config: {exc}")
        job = manager.start(req.target, cfg, label=req.target)
        return job.snapshot()

    @app.get("/api/scan")
    def list_scans() -> list[dict]:
        return manager.list()

    @app.get("/api/scan/{job_id}")
    def get_scan(job_id: str) -> dict:
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        return job.snapshot()

    @app.get("/api/scan/{job_id}/events")
    def scan_events(job_id: str) -> StreamingResponse:
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")

        def gen():
            for event in job.stream():
                yield _sse(event)
            yield _sse({"event": "stream_end", "job": job_id})

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # --- sessions (dashboard) ------------------------------------------------

    def _session_dir(sid: str) -> Path:
        d = root / sid
        if not d.is_dir() or ".." in sid or "/" in sid or "\\" in sid:
            raise HTTPException(404, "no such session")
        return d

    @app.get("/api/sessions")
    def list_sessions() -> list[dict]:
        out = []
        if not root.is_dir():
            return out
        for d in sorted(root.iterdir(), reverse=True):
            sj = d / "session.json"
            if not (d.is_dir() and sj.exists()):
                continue
            try:
                meta = json.loads(sj.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            out.append(
                {
                    "id": d.name,
                    "target": meta.get("target"),
                    "status": meta.get("status"),
                    "findings": meta.get("findings_confirmed"),
                    "cost": meta.get("estimated_cost_usd"),
                    "started": meta.get("started"),
                    "finished": meta.get("finished"),
                }
            )
        return out

    @app.get("/api/sessions/{sid}")
    def session_detail(sid: str) -> dict:
        d = _session_dir(sid)
        meta = json.loads((d / "session.json").read_text(encoding="utf-8"))
        report = d / "artifacts" / "report.json"
        findings: list = []
        stats: dict = {}
        if report.exists():
            data = json.loads(report.read_text(encoding="utf-8"))
            findings = data.get("findings", [])
            stats = data.get("stats", {})
        return {
            "id": sid,
            "meta": meta,
            "stats": stats,
            "findings": findings,
            "has_graph": (d / "artifacts" / "graph.json").exists(),
            "artifacts": [p.name for p in (d / "artifacts").glob("*")]
            if (d / "artifacts").is_dir()
            else [],
        }

    @app.get("/api/sessions/{sid}/graph")
    def session_graph(sid: str) -> dict:
        d = _session_dir(sid)
        gp = d / "artifacts" / "graph.json"
        if not gp.exists():
            raise HTTPException(404, "no graph for this session")
        return json.loads(gp.read_text(encoding="utf-8"))

    @app.get("/api/sessions/{sid}/traces")
    def session_traces(sid: str) -> list[dict]:
        d = _session_dir(sid)
        tp = d / "artifacts" / "traces.jsonl"
        if not tp.exists():
            return []
        out = []
        for line in tp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    @app.get("/api/sessions/{sid}/memory")
    def session_memory(sid: str) -> dict:
        d = _session_dir(sid)
        mem = d / "memory"
        master = mem / "master.md"
        notes = []
        if (mem / "notes").is_dir():
            notes = sorted(p.name for p in (mem / "notes").glob("*.md"))
        return {
            "master": master.read_text(encoding="utf-8") if master.exists() else "",
            "notes": notes,
        }

    @app.get("/api/sessions/{sid}/artifact/{name}")
    def session_artifact(sid: str, name: str, download: bool = True):
        d = _session_dir(sid)
        if "/" in name or "\\" in name or ".." in name:
            raise HTTPException(400, "bad name")
        # memory notes live under memory/notes; everything else under artifacts/
        p = (d / "memory" / "notes" / name) if name.endswith(".md") and (
            d / "memory" / "notes" / name
        ).exists() else (d / "artifacts" / name)
        if not p.exists():
            raise HTTPException(404, "no such artifact")
        if download:
            # Content-Disposition: attachment -> the browser saves the file
            # instead of rendering it inline.
            return FileResponse(
                p, filename=f"{sid}-{name}", media_type="application/octet-stream"
            )
        return PlainTextResponse(p.read_text(encoding="utf-8"))

    # --- static SPA ----------------------------------------------------------

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def run(host: str = "127.0.0.1", port: int = 8765, workshop_root: str = ".icewall") -> None:
    import uvicorn

    uvicorn.run(create_app(workshop_root=workshop_root), host=host, port=port, log_level="warning")
