"""The knowledge base: a persistent set of `KnowledgeItem`s plus retrieval.

Storage is a single JSONL file (`<root>/items.jsonl`) with a sidecar
`<root>/index.json` for bookkeeping. Retrieval filters by vulnerability class,
then ranks by functional similarity using embeddings (cosine) when an embedder
and stored vectors are available, otherwise a local BM25 fallback. Multiple
query parts are fused with Reciprocal Rank Fusion (RRF), following Vul-RAG.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from icewall.config import KnowledgeConfig
from icewall.knowledge.bm25 import BM25
from icewall.knowledge.embed import Embedder, cosine
from icewall.knowledge.schema import KnowledgeItem

_RRF_K = 60  # standard RRF damping constant


class KnowledgeStore:
    def __init__(self, cfg: KnowledgeConfig, embedder: Optional[Embedder] = None) -> None:
        self.cfg = cfg
        self.embedder = embedder
        self.root = Path(cfg.root)
        self.items: list[KnowledgeItem] = []
        self._by_class: dict[str, list[KnowledgeItem]] = {}
        self.load()

    # --- persistence ---------------------------------------------------------

    @property
    def items_path(self) -> Path:
        return self.root / "items.jsonl"

    @property
    def index_path(self) -> Path:
        return self.root / "index.json"

    def load(self) -> None:
        self.items = []
        if self.items_path.exists():
            for line in self.items_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.items.append(KnowledgeItem.from_dict(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
        self._reindex()

    def _reindex(self) -> None:
        self._by_class = {}
        for it in self.items:
            self._by_class.setdefault(it.vuln_class, []).append(it)

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.items_path.open("w", encoding="utf-8") as fh:
            for it in self.items:
                fh.write(json.dumps(it.to_dict()) + "\n")
        self.index_path.write_text(
            json.dumps(
                {
                    "count": len(self.items),
                    "by_class": {k: len(v) for k, v in self._by_class.items()},
                    "embedded": sum(1 for it in self.items if it.embedding),
                    "embedding_model": self.cfg.embedding.model,
                    "updated": time.time(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def add(self, items: list[KnowledgeItem]) -> int:
        """Add items, replacing any with a colliding id (idempotent re-builds)."""
        by_id = {it.id: it for it in self.items}
        for it in items:
            by_id[it.id] = it
        self.items = list(by_id.values())
        self._reindex()
        return len(items)

    def remove(self, ids: list[str]) -> int:
        """Delete items by id and persist. Returns how many were removed."""
        drop = set(ids)
        before = len(self.items)
        self.items = [it for it in self.items if it.id not in drop]
        removed = before - len(self.items)
        if removed:
            self._reindex()
            self.save()
        return removed

    def clear(self) -> None:
        self.items = []
        self._reindex()
        for p in (self.items_path, self.index_path):
            if p.exists():
                p.unlink()

    # --- search (for curation / delete) --------------------------------------

    def search(
        self, query: str, mode: str = "auto", vuln_class: Optional[str] = None, limit: int = 20
    ) -> tuple[str, list[tuple[KnowledgeItem, float]]]:
        """Rank items against a single free-text query, returning (mode_used,
        [(item, score), …]) best-first. Used by the UI's find-and-delete tool.

        `mode`: "bm25" (lexical), "embedding" (semantic — requires an embedder
        and embedded items), or "auto" (embeddings when available, else BM25).
        `vuln_class` restricts the pool to one class; None searches all items.
        """
        query = (query or "").strip()
        pool = self._by_class.get(vuln_class, []) if vuln_class else self.items
        if not query or not pool:
            return (mode if mode != "auto" else "bm25"), []

        want_emb = mode == "embedding" or (mode == "auto" and self._use_embeddings(pool))
        if want_emb:
            if self.embedder is None:
                raise ValueError("no embedding model configured — build/import with an embedding endpoint, or search by BM25")
            embedded = [it for it in pool if it.embedding]
            if not embedded:
                raise ValueError("no items have embeddings — rebuild with an embedding endpoint, or search by BM25")
            try:
                qv = self.embedder.embed([query])[0]
            except Exception as exc:
                raise ValueError(f"embedding the query failed: {exc}")
            scored = [(it, cosine(qv, it.embedding)) for it in embedded]
            used = "embedding"
        else:
            bm = BM25([it.knowledge_text() for it in pool])
            scored = list(zip(pool, bm.scores(query)))
            used = "bm25"

        scored.sort(key=lambda t: (-t[1], t[0].id))
        return used, scored[:limit]

    # --- stats ---------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "count": len(self.items),
            "by_class": {k: len(v) for k, v in sorted(self._by_class.items())},
            "embedded": sum(1 for it in self.items if it.embedding),
            "embedding_model": self.cfg.embedding.model or None,
            "root": str(self.root),
        }

    # --- retrieval -----------------------------------------------------------

    def _use_embeddings(self, pool: list[KnowledgeItem]) -> bool:
        return self.embedder is not None and all(it.embedding for it in pool) and bool(pool)

    def retrieve(self, vuln_class: str, queries: list[str]) -> list[KnowledgeItem]:
        """Top-k items for `vuln_class` ranked by similarity to the query parts.

        `queries` are the candidate's functional signals (e.g. sink code, the
        analyzer's behavior description). Returns [] when the class has no items.
        """
        pool = self._by_class.get(vuln_class, [])
        queries = [q for q in queries if q and q.strip()]
        if not pool or not queries:
            return []

        rankings: list[list[int]] = []  # per query: pool indices, best first
        if self._use_embeddings(pool):
            try:
                qvecs = self.embedder.embed(queries)
            except Exception:
                qvecs = []
            for qv in qvecs:
                scored = [(i, cosine(qv, it.embedding)) for i, it in enumerate(pool)]
                rankings.append(self._rank(scored))
        if not rankings:
            # BM25 fallback (also the path when embeddings are unavailable).
            bm = BM25([it.knowledge_text() for it in pool])
            for q in queries:
                scored = list(enumerate(bm.scores(q)))
                rankings.append(self._rank(scored))

        fused = self._rrf(rankings)
        return [pool[i] for i in fused[: self.cfg.top_k]]

    def _rank(self, scored: list[tuple[int, float]]) -> list[int]:
        """Indices sorted by score desc, dropping those below min_score."""
        keep = [(i, s) for i, s in scored if s >= self.cfg.min_score]
        keep.sort(key=lambda t: (-t[1], t[0]))
        return [i for i, _ in keep]

    @staticmethod
    def _rrf(rankings: list[list[int]]) -> list[int]:
        acc: dict[int, float] = {}
        for ranking in rankings:
            for rank, idx in enumerate(ranking):
                acc[idx] = acc.get(idx, 0.0) + 1.0 / (_RRF_K + rank + 1)
        return [i for i, _ in sorted(acc.items(), key=lambda t: (-t[1], t[0]))]
