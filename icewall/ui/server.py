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
  GET  /api/kb/stats              knowledge-base item counts + retrieval mode
  GET  /api/kb/items              list knowledge items (optional ?vuln_class=)
  POST /api/kb/seed               seed the KB from bundled skills (no network)
  POST /api/kb/build              start a CVE build -> {job}
  GET  /api/kb/build/{id}/events  SSE stream of build progress
  POST /api/kb/search             rank items by query (bm25|embedding) for curation
  DEL  /api/kb/items/{item_id}    delete one knowledge item
  POST /api/kb/items/delete       delete knowledge items by id (bulk)
  DEL  /api/kb                    clear all knowledge items
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from icewall import __version__
from icewall.config import (
    INTENSITY_LEVELS,
    EmbeddingConfig,
    IcewallConfig,
    KnowledgeConfig,
    apply_intensity,
)
from icewall.ui.kb_runner import BuildManager
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
    # Activate knowledge-base (Vul-RAG) augmentation of the validator.
    knowledge: bool = False


class KbBuildRequest(BaseModel):
    cves: list[str]
    distiller: dict  # a ProviderConfig dict (type/base_url/api_key/...)
    distiller_model: str
    embedding: Optional[dict] = None  # an EmbeddingConfig dict; None => BM25
    top_k: int = 6
    min_score: float = 0.0
    fetch_verify_ssl: bool = True
    github_token_env: Optional[str] = None
    # Skip pairs already in the knowledge base (dedup) before distilling.
    skip_existing: bool = True


class KbSeedRequest(BaseModel):
    embedding: Optional[dict] = None


class KbImportRequest(BaseModel):
    source: str  # "cvefixes" | "osv"
    db_path: Optional[str] = None          # cvefixes
    ecosystems: Optional[list[str]] = None  # osv
    languages: Optional[list[str]] = None
    cwe_filter: bool = True
    limit: int = 500
    distiller: dict
    distiller_model: str
    embedding: Optional[dict] = None
    # Verify TLS when fetching patches from GitHub (OSV path only).
    fetch_verify_ssl: bool = True
    # Skip pairs already in the knowledge base (dedup) before distilling.
    skip_existing: bool = True


class KbSearchRequest(BaseModel):
    query: str
    mode: str = "auto"  # auto | bm25 | embedding
    vuln_class: Optional[str] = None
    limit: int = 20


class KbDeleteRequest(BaseModel):
    ids: list[str]


class KbTestLlmRequest(BaseModel):
    distiller: dict  # a ProviderConfig dict
    distiller_model: str


class KbTestEmbeddingRequest(BaseModel):
    embedding: Optional[dict] = None  # an EmbeddingConfig dict


class KbEndpointPresetBody(BaseModel):
    """A saved distiller + embedding endpoint set for the Build KB view."""
    distiller: dict            # a ProviderConfig dict
    distiller_model: str = ""
    embedding: Optional[dict] = None  # an EmbeddingConfig dict (or None => BM25)


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


def create_app(
    workshop_root: str = ".icewall",
    presets_root: Optional[str] = None,
    kb_root: str = "kb",
) -> FastAPI:
    app = FastAPI(title="Icewall UI", version=__version__)
    manager = ScanManager()
    builds = BuildManager()
    presets = PresetStore(presets_root or f"{workshop_root}/presets")
    root = Path(workshop_root)
    kb_dir = Path(kb_root)

    # --- knowledge base helpers ---------------------------------------------

    def _kb_config(embedding: Optional[dict] = None, **over) -> KnowledgeConfig:
        emb = EmbeddingConfig(**embedding) if embedding else _saved_embedding()
        return KnowledgeConfig(enabled=True, root=str(kb_dir), embedding=emb, **over)

    def _saved_embedding() -> EmbeddingConfig:
        # Retrieval must embed queries with the same model the items were built
        # with, so the build persists its embedding config next to the store.
        p = kb_dir / "embedding.json"
        if p.exists():
            try:
                return EmbeddingConfig.model_validate(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                pass
        return EmbeddingConfig()

    def _persist_embedding(embedding: Optional[dict]) -> None:
        kb_dir.mkdir(parents=True, exist_ok=True)
        (kb_dir / "embedding.json").write_text(
            json.dumps(embedding or {}), encoding="utf-8"
        )

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
        # Knowledge-base toggle: point the scan at the shared KB and the embedding
        # config it was built with (falls back to BM25 when none was persisted).
        if req.knowledge:
            cfg.knowledge.enabled = True
            cfg.knowledge.root = str(kb_dir)
            cfg.knowledge.embedding = _saved_embedding()
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

    # --- knowledge base (Vul-RAG) --------------------------------------------

    @app.get("/api/kb/stats")
    def kb_stats() -> dict:
        from icewall.knowledge import KnowledgeStore

        stats = KnowledgeStore(_kb_config()).stats()
        stats["has_embedding"] = (kb_dir / "embedding.json").exists() and bool(
            _saved_embedding().model
        )
        return stats

    @app.get("/api/kb/items")
    def kb_items(vuln_class: Optional[str] = None, limit: int = 200) -> list[dict]:
        from icewall.knowledge import KnowledgeStore

        store = KnowledgeStore(_kb_config())
        out = []
        for it in store.items:
            if vuln_class and it.vuln_class != vuln_class:
                continue
            d = it.to_dict()
            d.pop("embedding", None)  # keep the payload small
            out.append(d)
            if len(out) >= limit:
                break
        return out

    @app.post("/api/kb/seed")
    def kb_seed(body: KbSeedRequest) -> dict:
        from icewall.knowledge import build_embedder
        from icewall.knowledge.builder import KnowledgeBuilder

        kc = _kb_config(embedding=body.embedding)
        if body.embedding is not None:
            _persist_embedding(body.embedding)
        builder = KnowledgeBuilder(kc, embedder=build_embedder(kc.embedding))
        return builder.seed_from_skills()

    @app.delete("/api/kb")
    def kb_clear() -> dict:
        from icewall.knowledge import KnowledgeStore

        store = KnowledgeStore(_kb_config())
        n = len(store.items)
        store.clear()
        return {"cleared": n}

    def _item_summary(it) -> dict:
        return {
            "id": it.id,
            "vuln_class": it.vuln_class,
            "cwe": it.cwe,
            "source": it.source,
            "abstract_cause": it.abstract_cause,
            "fixing_solution": (it.fixing_solution or "")[:240],
            "embedded": bool(it.embedding),
        }

    @app.post("/api/kb/search")
    def kb_search(body: KbSearchRequest) -> dict:
        """Rank items by a query (BM25 or the embedding model) so the UI can
        preview matches before deleting them."""
        from icewall.knowledge import KnowledgeStore, build_embedder

        if body.mode not in ("auto", "bm25", "embedding"):
            raise HTTPException(400, "mode must be auto, bm25, or embedding")
        kc = _kb_config()
        # An embedder is only needed for semantic search; BM25 needs none.
        embedder = build_embedder(kc.embedding) if body.mode in ("auto", "embedding") else None
        store = KnowledgeStore(kc, embedder=embedder)
        try:
            used, results = store.search(
                body.query, mode=body.mode, vuln_class=body.vuln_class, limit=body.limit
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {
            "mode": used,
            "results": [{**_item_summary(it), "score": round(score, 4)} for it, score in results],
        }

    @app.delete("/api/kb/items/{item_id}")
    def kb_delete_item(item_id: str) -> dict:
        from icewall.knowledge import KnowledgeStore

        return {"deleted": KnowledgeStore(_kb_config()).remove([item_id])}

    @app.post("/api/kb/items/delete")
    def kb_delete_items(body: KbDeleteRequest) -> dict:
        from icewall.knowledge import KnowledgeStore

        if not body.ids:
            raise HTTPException(400, "no ids provided")
        return {"deleted": KnowledgeStore(_kb_config()).remove(body.ids)}

    # --- endpoint presets (distiller + embedding for the Build KB view) ------

    ep_presets_dir = kb_dir / "endpoint_presets"

    def _ep_path(name: str) -> tuple[Path, str]:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", (name or "").strip()).strip("-")
        if not slug:
            raise HTTPException(400, "preset name must contain letters or digits")
        return ep_presets_dir / f"{slug}.json", slug

    @app.get("/api/kb/endpoint-presets")
    def kb_ep_presets() -> list[dict]:
        out = []
        if ep_presets_dir.exists():
            for p in sorted(ep_presets_dir.glob("*.json")):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                out.append({"name": d.get("name", p.stem)})
        return out

    @app.get("/api/kb/endpoint-presets/{name}")
    def kb_ep_preset_get(name: str) -> dict:
        path, _ = _ep_path(name)
        if not path.exists():
            raise HTTPException(404, "no such endpoint preset")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.put("/api/kb/endpoint-presets/{name}")
    def kb_ep_preset_put(name: str, body: KbEndpointPresetBody) -> dict:
        from icewall.config import ProviderConfig

        # Validate before persisting so a stored preset always loads back.
        try:
            ProviderConfig.model_validate(body.distiller)
            if body.embedding:
                EmbeddingConfig.model_validate(body.embedding)
        except Exception as exc:
            raise HTTPException(400, f"invalid endpoint config: {exc}")
        path, slug = _ep_path(name)
        ep_presets_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "name": slug,
                "distiller": body.distiller,
                "distiller_model": body.distiller_model,
                "embedding": body.embedding,
            }, indent=2),
            encoding="utf-8",
        )
        return {"name": slug}

    @app.delete("/api/kb/endpoint-presets/{name}")
    def kb_ep_preset_del(name: str) -> dict:
        path, _ = _ep_path(name)
        if path.exists():
            path.unlink()
            return {"deleted": True}
        return {"deleted": False}

    @app.post("/api/kb/build")
    def kb_build(body: KbBuildRequest) -> dict:
        cves = [c.strip() for c in body.cves if c.strip()]
        if not cves:
            raise HTTPException(400, "no CVE ids provided")
        if not body.distiller_model:
            raise HTTPException(400, "distiller_model is required")
        _persist_embedding(body.embedding)
        kc = _kb_config(
            embedding=body.embedding,
            top_k=body.top_k,
            min_score=body.min_score,
            fetch_verify_ssl=body.fetch_verify_ssl,
            github_token_env=body.github_token_env,
        )
        job = builds.start(
            kc, cves, body.distiller, body.distiller_model, skip_existing=body.skip_existing
        )
        return job.snapshot()

    @app.post("/api/kb/import")
    def kb_import(body: KbImportRequest) -> dict:
        if body.source not in ("cvefixes", "osv"):
            raise HTTPException(400, "source must be 'cvefixes' or 'osv'")
        if not body.distiller_model:
            raise HTTPException(400, "distiller_model is required")
        if body.source == "cvefixes" and not body.db_path:
            raise HTTPException(400, "cvefixes import needs db_path")
        _persist_embedding(body.embedding)
        kc = _kb_config(
            embedding=body.embedding,
            fetch_verify_ssl=body.fetch_verify_ssl,
        )
        spec = {
            "source": body.source,
            "db": body.db_path,
            "ecosystems": body.ecosystems,
            "languages": body.languages,
            "cwe_filter": body.cwe_filter,
            "limit": body.limit,
            "skip_existing": body.skip_existing,
        }
        job = builds.start_import(kc, spec, body.distiller, body.distiller_model)
        return job.snapshot()

    @app.post("/api/kb/test-llm")
    def kb_test_llm(body: KbTestLlmRequest) -> dict:
        """Probe the distiller endpoint with one tiny completion. Bounds the call
        so a wrong host/key/model fails fast instead of hanging the UI."""
        import time as _time

        from icewall.config import ProviderConfig
        from icewall.providers import build_provider
        from icewall.providers.base import LLMMessage

        if not body.distiller_model:
            raise HTTPException(400, "distiller_model is required")
        pc = dict(body.distiller)
        # Force a short, non-retrying probe regardless of the configured values.
        pc["timeout"] = min(float(pc.get("timeout") or 20), 20)
        pc["max_retries"] = 0
        try:
            provider = build_provider(ProviderConfig.model_validate(pc))
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        t0 = _time.time()
        try:
            resp = provider.complete(
                system="Reply with the single word: ok",
                messages=[LLMMessage(role="user", content="ping")],
                model=body.distiller_model,
                max_tokens=16,
                temperature=0.0,
            )
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300],
                    "latency_ms": round((_time.time() - t0) * 1000)}
        return {
            "ok": True,
            "latency_ms": round((_time.time() - t0) * 1000),
            "model": resp.model or body.distiller_model,
            "sample": (resp.text or "").strip()[:80],
        }

    @app.post("/api/kb/test-embedding")
    def kb_test_embedding(body: KbTestEmbeddingRequest) -> dict:
        """Probe the embedding endpoint with one tiny vector request. With no
        model configured, retrieval uses the local BM25 fallback (nothing to test)."""
        import time as _time

        from icewall.knowledge.embed import OpenAIEmbedder

        emb = body.embedding or {}
        if not emb.get("model"):
            return {"ok": True, "mode": "bm25",
                    "note": "No embedding model — retrieval uses the local BM25 fallback."}
        cfg = EmbeddingConfig(**emb)
        cfg.timeout = min(cfg.timeout, 20)
        cfg.max_retries = 0
        try:
            embedder = OpenAIEmbedder(cfg)
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
        t0 = _time.time()
        try:
            vecs = embedder.embed(["ping"])
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300],
                    "latency_ms": round((_time.time() - t0) * 1000)}
        dims = len(vecs[0]) if vecs and vecs[0] else 0
        return {"ok": True, "mode": "embeddings", "dimensions": dims,
                "model": cfg.model, "latency_ms": round((_time.time() - t0) * 1000)}

    @app.get("/api/kb/build/{job_id}")
    def kb_build_status(job_id: str) -> dict:
        job = builds.get(job_id)
        if job is None:
            raise HTTPException(404, "no such build")
        return job.snapshot()

    @app.get("/api/kb/build/{job_id}/events")
    def kb_build_events(job_id: str) -> StreamingResponse:
        job = builds.get(job_id)
        if job is None:
            raise HTTPException(404, "no such build")

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
