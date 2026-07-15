"""Thread-safe finding store with dedup. Many analyzer threads write here; the
same class+sink-line collapses to one finding, keeping the higher-confidence."""
from __future__ import annotations

import threading

from icewall.schemas import Finding


class FindingStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[tuple, Finding] = {}

    def add(self, finding: Finding) -> bool:
        """Insert or merge. Returns True if this became the stored finding."""
        key = finding.dedup_key()
        with self._lock:
            existing = self._by_key.get(key)
            if existing is None or finding.confidence > existing.confidence:
                self._by_key[key] = finding
                return True
            return False

    def all(self) -> list[Finding]:
        with self._lock:
            return list(self._by_key.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_key)
