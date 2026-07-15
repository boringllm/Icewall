"""Workshop — the per-session working directory.

Every `scan` opens a fresh session folder so results and artifacts never clobber
a previous run:

    <root>/<session-id>/
        session.json      run metadata: target, config summary, stats, cost
        artifacts/        report.md, report.sarif, report.json
        memory/           master.md + notes/  (see icewall.memory)

The session id is `<UTC-timestamp>-<target-slug>`, so folders sort chronologically.
A disabled workshop (`workshop.enabled: false`) yields a no-op instance whose
memory lives in RAM only and whose artifact writes are skipped.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from icewall.memory import SessionMemory

_SLUG_RE = re.compile(r"[^A-Za-z0-9]+")


def _target_slug(target: str) -> str:
    name = Path(target).name or Path(target).anchor or "scan"
    slug = _SLUG_RE.sub("-", name).strip("-").lower()
    return slug or "scan"


class Workshop:
    def __init__(
        self,
        root: str | Path,
        target: str,
        *,
        enabled: bool = True,
        keep_last: int = 0,
        session_id: Optional[str] = None,
    ) -> None:
        self.enabled = enabled
        self.keep_last = keep_last
        self.target = target
        self.root = Path(root)
        # Microsecond precision keeps back-to-back sessions unique and still
        # name-sortable by creation time (used by keep_last pruning).
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        self.session_id = session_id or f"{ts}-{_target_slug(target)}"
        if enabled:
            self.dir: Optional[Path] = Path(root) / self.session_id
            (self.dir / "artifacts").mkdir(parents=True, exist_ok=True)
            self.memory = SessionMemory(self.dir / "memory")
        else:
            self.dir = None
            self.memory = SessionMemory(None)

    # --- paths ---------------------------------------------------------------

    @property
    def artifacts_dir(self) -> Optional[Path]:
        return (self.dir / "artifacts") if self.dir else None

    def artifact_path(self, name: str) -> Optional[Path]:
        return (self.dir / "artifacts" / name) if self.dir else None

    def write_artifact(self, name: str, text: str) -> Optional[Path]:
        if not self.dir:
            return None
        path = self.dir / "artifacts" / name
        path.write_text(text, encoding="utf-8")
        return path

    # --- session lifecycle ---------------------------------------------------

    def open(self, config_summary: dict) -> None:
        self._write_session(
            {
                "session_id": self.session_id,
                "target": self.target,
                "status": "running",
                "started": datetime.now(timezone.utc).isoformat(),
                "config": config_summary,
            }
        )

    def finalize(self, result) -> None:
        """Persist final session.json with stats/cost and prune old sessions."""
        if not self.dir:
            return
        stats = result.stats
        self._write_session(
            {
                "session_id": self.session_id,
                "target": self.target,
                "status": "complete",
                "finished": datetime.now(timezone.utc).isoformat(),
                "config": result.config_summary,
                "stats": stats.model_dump(),
                "findings_confirmed": len(result.findings),
                "estimated_cost_usd": stats.estimated_cost_usd,
                "memory_notes": len(self.memory.all()),
            }
        )
        self._prune()

    def _write_session(self, data: dict) -> None:
        if self.dir:
            (self.dir / "session.json").write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )

    def _prune(self) -> None:
        """Keep only the `keep_last` most recent session folders (0 = keep all)."""
        if not self.dir or self.keep_last <= 0:
            return
        sessions = sorted(
            (p for p in self.root.iterdir() if p.is_dir()),
            key=lambda p: p.name,
        )
        for old in sessions[: -self.keep_last]:
            if old.resolve() == self.dir.resolve():
                continue
            _rmtree(old)


def _rmtree(path: Path) -> None:
    import shutil

    try:
        shutil.rmtree(path)
    except OSError:
        pass
