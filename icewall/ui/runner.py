"""Background scan jobs for the UI.

A `ScanJob` runs one scan on a worker thread. The engine's `on_event` callback
appends events to a growing, lock-guarded list; the SSE endpoint replays the
buffer to a late subscriber and then streams new events until the job reaches a
terminal state. This makes the live view robust to reconnects and lets several
tabs watch the same scan.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Iterator, Optional

from icewall.config import IcewallConfig
from icewall.engine import Engine


class ScanJob:
    def __init__(self, target: str, config: IcewallConfig, label: str = "") -> None:
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.config = config
        self.label = label or target
        self.created = time.time()
        self.status = "pending"  # pending | running | done | error
        self.result = None
        self.error: Optional[str] = None
        self.workshop_dir: Optional[str] = None
        self._events: list[dict] = []
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._thread: Optional[threading.Thread] = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"scan-{self.id}", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        with self._cond:
            self.status = "running"
        self._append("scan_started", {"target": self.target, "job": self.id})
        try:
            engine = Engine(self.config, on_event=self._on_event)
            result = engine.scan(self.target)
            self.result = result
            self.workshop_dir = result.workshop_dir
            self._finish(
                "done",
                "scan_complete",
                {
                    "job": self.id,
                    "workshop_dir": result.workshop_dir,
                    "findings": len(result.findings),
                    "cost": result.stats.estimated_cost_usd,
                    "duration": result.stats.duration_seconds,
                    "cost_by_role": result.stats.cost_by_role,
                },
            )
        except Exception as exc:  # surface failures to the UI, don't crash server
            self.error = f"{type(exc).__name__}: {exc}"
            self._finish("error", "scan_error", {"job": self.id, "message": self.error})

    # --- event plumbing ------------------------------------------------------

    def _on_event(self, event: str, kw: dict) -> None:
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
        """Yield every event from the start, then live ones, until terminal."""
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
        with self._lock:
            return {
                "id": self.id,
                "target": self.target,
                "label": self.label,
                "status": self.status,
                "error": self.error,
                "workshop_dir": self.workshop_dir,
                "events": len(self._events),
                "created": self.created,
            }


class ScanManager:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def start(self, target: str, config: IcewallConfig, label: str = "") -> ScanJob:
        job = ScanJob(target, config, label=label)
        with self._lock:
            self._jobs[job.id] = job
        job.start()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.snapshot() for j in sorted(jobs, key=lambda j: -j.created)]
