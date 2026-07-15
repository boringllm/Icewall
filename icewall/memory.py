"""Session memory — a deterministic, thread-safe knowledge store for one scan.

Agents write notes as they finish (``note``); the store maintains a human-readable
``master.md`` index plus one ``notes/<slug>.md`` sub-note per fact. Later stages
recall relevant notes (``recall``) by role, file, or vulnerability class instead
of paying an LLM to decide what to load — the code graph already serves targeted
context, so memory's job is cross-stage/cross-session *fact sharing*, not context
retrieval.

If constructed without a `root` the store keeps notes in memory only (recall still
works); with a `root` it also persists master.md + sub-notes into the workshop,
so a session doubles as an audit trail and the substrate for incremental re-scans.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return slug or "note"


@dataclass
class MemoryNote:
    slug: str
    title: str
    body: str
    role: str = ""
    tags: list[str] = field(default_factory=list)
    file: Optional[str] = None
    vuln_class: Optional[str] = None
    ts: str = ""

    def matches(
        self,
        *,
        role: Optional[str] = None,
        file: Optional[str] = None,
        vuln_class: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> bool:
        if role is not None and self.role != role:
            return False
        if file is not None and self.file != file:
            return False
        if vuln_class is not None and self.vuln_class != vuln_class:
            return False
        if tags:
            if not set(tags) & set(self.tags):
                return False
        return True

    def render(self) -> str:
        meta = []
        if self.role:
            meta.append(f"role: {self.role}")
        if self.file:
            meta.append(f"file: {self.file}")
        if self.vuln_class:
            meta.append(f"vuln_class: {self.vuln_class}")
        if self.tags:
            meta.append(f"tags: {', '.join(self.tags)}")
        header = f"# {self.title}\n\n"
        if meta:
            header += "> " + " | ".join(meta) + "\n\n"
        header += f"_recorded {self.ts}_\n\n"
        return header + self.body.rstrip() + "\n"


class SessionMemory:
    """Thread-safe. Many agent threads write; later stages read by relevance."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._notes: list[MemoryNote] = []
        self._slugs: set[str] = set()
        self.root = Path(root) if root else None
        if self.root:
            (self.root / "notes").mkdir(parents=True, exist_ok=True)

    @property
    def master_path(self) -> Optional[Path]:
        return (self.root / "master.md") if self.root else None

    def _unique_slug(self, base: str) -> str:
        slug = base
        i = 2
        while slug in self._slugs:
            slug = f"{base}-{i}"
            i += 1
        self._slugs.add(slug)
        return slug

    def note(
        self,
        title: str,
        body: str,
        *,
        role: str = "",
        tags: Optional[list[str]] = None,
        file: Optional[str] = None,
        vuln_class: Optional[str] = None,
    ) -> MemoryNote:
        """Record one fact. Writes notes/<slug>.md and refreshes master.md."""
        with self._lock:
            slug = self._unique_slug(_slugify(title))
            note = MemoryNote(
                slug=slug,
                title=title,
                body=body,
                role=role,
                tags=list(tags or []),
                file=file,
                vuln_class=vuln_class,
                ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            )
            self._notes.append(note)
            if self.root:
                (self.root / "notes" / f"{slug}.md").write_text(
                    note.render(), encoding="utf-8"
                )
                self._write_master_locked()
            return note

    def recall(
        self,
        *,
        role: Optional[str] = None,
        file: Optional[str] = None,
        vuln_class: Optional[str] = None,
        tags: Optional[list[str]] = None,
        limit: int = 10,
    ) -> list[MemoryNote]:
        """Return notes relevant to a stage/finding, most recent first."""
        with self._lock:
            hits = [
                n
                for n in self._notes
                if n.matches(role=role, file=file, vuln_class=vuln_class, tags=tags)
            ]
        return list(reversed(hits))[:limit]

    def all(self) -> list[MemoryNote]:
        with self._lock:
            return list(self._notes)

    def _write_master_locked(self) -> None:
        if not self.root:
            return
        lines = [
            "# Icewall session memory — master index",
            "",
            "Auto-maintained by agents as they finish. Each entry links to a "
            "sub-note under `notes/`.",
            "",
            f"_{len(self._notes)} notes_",
            "",
        ]
        by_role: dict[str, list[MemoryNote]] = {}
        for n in self._notes:
            by_role.setdefault(n.role or "general", []).append(n)
        for role in sorted(by_role):
            lines.append(f"## {role}")
            lines.append("")
            for n in by_role[role]:
                meta = []
                if n.file:
                    meta.append(n.file)
                if n.vuln_class:
                    meta.append(n.vuln_class)
                suffix = f" — {', '.join(meta)}" if meta else ""
                lines.append(f"- [{n.title}](notes/{n.slug}.md){suffix}")
            lines.append("")
        self.master_path.write_text("\n".join(lines), encoding="utf-8")
