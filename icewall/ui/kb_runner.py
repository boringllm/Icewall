"""Background knowledge-base jobs for the UI: CVE builds and dataset imports.

Both run on a worker thread and buffer progress events so the SSE endpoint can
replay them to a late/refreshing subscriber. The build/import config (distiller
endpoint, embedding endpoint, CVE ids or dataset params) comes straight from the
UI, so the browser drives it without touching icewall.yaml.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Iterator, Optional

from icewall.config import KnowledgeConfig


class _KbJob:
    """Shared event/stream plumbing for build and import jobs."""

    def __init__(self, kcfg: KnowledgeConfig, provider_cfg: dict, model: str) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kcfg = kcfg
        self.provider_cfg = provider_cfg  # a ProviderConfig dict for the distiller
        self.model = model
        self.created = time.time()
        self.status = "pending"  # pending | running | done | error
        self.error: Optional[str] = None
        self.summary: Optional[dict] = None
        self._events: list[dict] = []
        self._cond = threading.Condition(threading.Lock())
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._guarded_run, name=f"kb-{self.id}", daemon=True)
        self._thread.start()

    def _guarded_run(self) -> None:
        with self._cond:
            self.status = "running"
        try:
            self._run()
        except Exception as exc:  # surface to the UI, don't crash the server
            self.error = f"{type(exc).__name__}: {exc}"
            self._finish("error", "build_error", {"job": self.id, "message": self.error})

    def _run(self) -> None:  # overridden
        raise NotImplementedError

    def _builder(self, on_progress):
        from icewall.config import ProviderConfig
        from icewall.knowledge import build_embedder
        from icewall.knowledge.builder import KnowledgeBuilder
        from icewall.providers import build_provider

        # Bound the distiller's requests so one slow/hung endpoint call can't
        # stall the whole import (the SDK default is 10 min / 2 retries).
        pc = dict(self.provider_cfg)
        pc.setdefault("timeout", 120)
        pc.setdefault("max_retries", 1)
        provider = build_provider(ProviderConfig.model_validate(pc))
        return KnowledgeBuilder(
            self.kcfg,
            provider=provider,
            model=self.model,
            embedder=build_embedder(self.kcfg.embedding),
            on_progress=on_progress,
        )

    # --- event plumbing ------------------------------------------------------

    def _on_progress(self, event: str, kw: dict) -> None:
        self._append(event, kw)

    def _append(self, event: str, kw: dict) -> None:
        with self._cond:
            self._events.append({"event": event, **kw})
            self._cond.notify_all()

    def _finish(self, status: str, event: str, kw: dict) -> None:
        with self._cond:
            self._events.append({"event": event, **kw})
            self.status = status
            self._cond.notify_all()

    def stream(self) -> Iterator[dict]:
        idx = 0
        while True:
            with self._cond:
                while idx >= len(self._events) and self.status in ("pending", "running"):
                    self._cond.wait(timeout=1.0)
                batch = self._events[idx:]
                idx += len(batch)
                done = self.status in ("done", "error") and idx >= len(self._events)
            for e in batch:
                yield e
            if done:
                break

    def snapshot(self) -> dict:
        with self._cond:
            return {
                "id": self.id,
                "status": self.status,
                "error": self.error,
                "events": len(self._events),
                "created": self.created,
                "summary": self.summary,
            }


class BuildJob(_KbJob):
    def __init__(self, kcfg, provider_cfg, model, cve_ids: list[str], skip_existing: bool = True) -> None:
        super().__init__(kcfg, provider_cfg, model)
        self.cve_ids = cve_ids
        self.skip_existing = skip_existing

    def _run(self) -> None:
        self._append("build_started", {"job": self.id, "cves": len(self.cve_ids)})
        self.summary = self._builder(self._on_progress).build_from_cves(
            self.cve_ids, skip_existing=self.skip_existing
        )
        self._finish("done", "build_complete", {"job": self.id, **self.summary})


class ImportJob(_KbJob):
    def __init__(self, kcfg, provider_cfg, model, spec: dict) -> None:
        super().__init__(kcfg, provider_cfg, model)
        self.spec = spec  # {source, db, ecosystems, languages, cwe_filter, limit, skip_existing}

    def _run(self) -> None:
        self._append("build_started", {"job": self.id, "source": self.spec.get("source")})
        source = self._build_source()
        # `limit` bounds NEW items (duplicates are skipped without consuming it),
        # so it is enforced in the builder while the source streams uncapped.
        limit = int(self.spec.get("limit", 500))
        self.summary = self._builder(self._on_progress).build_from_pairs(
            source.iter_pairs(), skip_existing=self.spec.get("skip_existing", True), limit=limit
        )
        self._finish("done", "build_complete", {"job": self.id, **self.summary})

    def _build_source(self):
        from icewall.knowledge.cvefixes import INJECTION_CWES

        spec = self.spec
        cwe_ids = INJECTION_CWES if spec.get("cwe_filter", True) else None
        langs = spec.get("languages") or ["python", "javascript", "typescript"]
        if spec.get("source") == "cvefixes":
            from icewall.knowledge.cvefixes import CvefixesSource, resolve_or_prepare

            db = spec.get("db") or self.kcfg.cvefixes_db
            if not db:
                raise ValueError("cvefixes import needs a db path or dataset folder")
            # Point at the dataset folder and we do the rest: find the .sql.gz and
            # convert it to SQLite if no .db exists yet (streams prepare_* events).
            db = resolve_or_prepare(db, on_progress=self._on_progress)
            return CvefixesSource(
                db, languages=langs, cwe_ids=cwe_ids,  # uncapped; builder bounds new items
                on_progress=self._on_progress,  # index-build + scan progress
            )
        if spec.get("source") == "osv":
            import os

            from icewall.knowledge.fetch import CveFetcher
            from icewall.knowledge.osv_bulk import OsvBulkSource

            token = os.environ.get(self.kcfg.github_token_env) if self.kcfg.github_token_env else None
            fetcher = CveFetcher(verify_ssl=self.kcfg.fetch_verify_ssl, github_token=token)
            return OsvBulkSource(
                spec.get("ecosystems") or ["PyPI", "npm"],
                cwe_ids=cwe_ids, fetcher=fetcher,  # uncapped; builder bounds new items
                cache_dir=f"{self.kcfg.root}/_osv_cache",
            )
        raise ValueError(f"unknown import source: {spec.get('source')}")


class BuildManager:
    def __init__(self) -> None:
        self._jobs: dict[str, _KbJob] = {}
        self._lock = threading.Lock()

    def _register(self, job: _KbJob) -> _KbJob:
        with self._lock:
            self._jobs[job.id] = job
        job.start()
        return job

    def start(self, kcfg, cve_ids, provider_cfg, model, skip_existing: bool = True) -> BuildJob:
        return self._register(BuildJob(kcfg, provider_cfg, model, cve_ids, skip_existing))

    def start_import(self, kcfg, spec, provider_cfg, model) -> ImportJob:
        return self._register(ImportJob(kcfg, provider_cfg, model, spec))

    def get(self, job_id: str) -> Optional[_KbJob]:
        with self._lock:
            return self._jobs.get(job_id)
