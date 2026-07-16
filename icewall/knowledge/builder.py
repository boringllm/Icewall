"""Build the knowledge base.

`build_from_cves` runs the full pipeline for a list of CVE ids: fetch the fix
commits, distill each {vulnerable, patched} pair into a `KnowledgeItem`, embed
the items (if an embedding endpoint is configured), and persist them. Progress
is reported through a callback so the UI can stream it. `seed_from_skills` gives
a non-empty base with no corpus, by converting Icewall's per-CWE skills.
"""
from __future__ import annotations

from typing import Callable, Optional

from icewall.config import KnowledgeConfig
from icewall.knowledge.distill import Distiller
from icewall.knowledge.embed import Embedder, build_embedder
from icewall.knowledge.fetch import CveFetcher
from icewall.knowledge.schema import KnowledgeItem, new_item_id, pair_item_id
from icewall.knowledge.store import KnowledgeStore
from icewall.providers.base import LLMProvider

Progress = Callable[[str, dict], None]

# Which class a bundled analyzer skill seeds knowledge for.
_SKILL_CLASS = {
    "sql-injection": "sql_injection",
    "command-injection": "command_injection",
    "xss": "xss",
    "ssrf": "ssrf",
    "path-traversal": "path_traversal",
    "deserialization": "insecure_deserialization",
}


class KnowledgeBuilder:
    def __init__(
        self,
        cfg: KnowledgeConfig,
        provider: Optional[LLMProvider] = None,
        model: str = "",
        fetcher: Optional[CveFetcher] = None,
        embedder: Optional[Embedder] = None,
        on_progress: Optional[Progress] = None,
    ) -> None:
        self.cfg = cfg
        self.store = KnowledgeStore(cfg, embedder=embedder)
        self.distiller = Distiller(provider, model) if provider else None
        self.fetcher = fetcher
        self.embedder = embedder
        self._emit = on_progress or (lambda *_: None)

    # --- CVE pipeline --------------------------------------------------------

    def build_from_cves(self, cve_ids: list[str], skip_existing: bool = True) -> dict:
        if self.distiller is None:
            raise ValueError("a distiller provider/model is required to build from CVEs")
        fetcher = self.fetcher or CveFetcher(
            verify_ssl=self.cfg.fetch_verify_ssl, github_token=self._github_token()
        )
        cve_ids = [c.strip() for c in cve_ids if c.strip()]
        self._emit("kb_build_start", {"cves": len(cve_ids)})
        existing = self._existing_ids() if skip_existing else set()
        new_items: list[KnowledgeItem] = []
        errors: list[str] = []
        skipped = 0

        for i, cve in enumerate(cve_ids):
            self._emit("cve_fetch", {"cve": cve, "index": i, "total": len(cve_ids)})
            try:
                pairs = fetcher.fetch(cve)
            except Exception as exc:
                errors.append(f"{cve}: fetch failed ({type(exc).__name__}: {exc})")
                self._emit("cve_error", {"cve": cve, "message": str(exc)})
                continue
            made = 0
            for pair in pairs:
                # Already in the store? Skip before paying for the distill call.
                if pair_item_id(pair) in existing:
                    skipped += 1
                    self._emit("dup_skip", {"cve": pair.cve_id, "function": pair.function})
                    continue
                self._emit("distill", {"cve": cve, "function": pair.function})
                try:
                    item = self.distiller.distill(pair)
                except Exception as exc:
                    errors.append(f"{cve}:{pair.function}: distill failed ({exc})")
                    continue
                if item is not None:
                    new_items.append(item)
                    existing.add(item.id)  # dedupe within this build too
                    made += 1
            self._emit("cve_done", {"cve": cve, "pairs": len(pairs), "items": made})

        self._embed_items(new_items)
        added = self.store.add(new_items)
        self.store.save()
        summary = {
            "added": added,
            "skipped": skipped,
            "errors": errors,
            "stats": self.store.stats(),
        }
        self._emit("kb_build_done", summary)
        return summary

    # --- generic pair pipeline (dataset imports) -----------------------------

    def build_from_pairs(self, pairs, skip_existing: bool = True, limit: Optional[int] = None) -> dict:
        """Distill an arbitrary stream of `CvePair`s (from a dataset source) into
        knowledge and store it. Used by the CVEfixes and OSV bulk importers.

        With `skip_existing` (default) a pair whose knowledge is already in the
        store is skipped before the distill call, so re-imports and overlapping
        datasets don't re-spend LLM budget on duplicates.

        `limit` bounds the number of NEW items added, *not* pairs seen: duplicates
        are skipped without counting against it, so the importer keeps scanning to
        the next CVE until it has collected `limit` genuinely new items (or the
        source is exhausted)."""
        if self.distiller is None:
            raise ValueError("a distiller provider/model is required to build knowledge")
        self._emit("kb_build_start", {"cves": 0})
        existing = self._existing_ids() if skip_existing else set()
        new_items: list[KnowledgeItem] = []
        errors: list[str] = []
        seen = 0
        skipped = 0
        for pair in pairs:
            seen += 1
            if pair_item_id(pair) in existing:
                skipped += 1
                self._emit("dup_skip", {"cve": pair.cve_id, "function": pair.function})
                if seen % 10 == 0:
                    self._emit("import_progress", {"seen": seen, "items": len(new_items), "skipped": skipped})
                continue  # a duplicate does not consume the limit
            self._emit("distill", {"cve": pair.cve_id, "function": pair.function})
            try:
                item = self.distiller.distill(pair)
            except Exception as exc:
                errors.append(f"{pair.cve_id}:{pair.function}: distill failed ({exc})")
                self._emit("distill_error", {
                    "cve": pair.cve_id, "function": pair.function,
                    "message": f"{type(exc).__name__}: {exc}"[:140],
                })
                continue
            if item is not None:
                new_items.append(item)
                existing.add(item.id)  # dedupe within this stream too
            if seen % 10 == 0:
                self._emit("import_progress", {"seen": seen, "items": len(new_items), "skipped": skipped})
            if limit is not None and len(new_items) >= limit:
                break  # collected enough genuinely-new items

        self._embed_items(new_items)
        added = self.store.add(new_items)
        self.store.save()
        summary = {"added": added, "seen": seen, "skipped": skipped, "errors": errors, "stats": self.store.stats()}
        self._emit("kb_build_done", summary)
        return summary

    # --- skill seeding -------------------------------------------------------

    def seed_from_skills(self) -> dict:
        from icewall.config import SkillsConfig
        from icewall.skills import SkillRegistry

        registry = SkillRegistry.discover(SkillsConfig())
        items: list[KnowledgeItem] = []
        for skill in registry.for_role("analyzer"):
            vc = next((c for key, c in _SKILL_CLASS.items() if key in skill.name), None)
            if vc is None:
                continue
            body = skill.body.strip()
            items.append(
                KnowledgeItem(
                    id=new_item_id(f"seed:{skill.name}", vc),
                    vuln_class=vc,
                    abstract_purpose=f"code potentially exposed to {vc.replace('_', ' ')}",
                    detailed_behavior=skill.description or f"{vc} analysis guidance",
                    abstract_cause=skill.description,
                    detailed_cause=body[:1200],
                    fixing_solution=body[:1200],
                    source=f"seed:{skill.name}",
                )
            )
        self._embed_items(items)
        added = self.store.add(items)
        self.store.save()
        summary = {"added": added, "stats": self.store.stats()}
        self._emit("kb_seed_done", summary)
        return summary

    # --- helpers -------------------------------------------------------------

    def _existing_ids(self) -> set[str]:
        """Provenance ids already in the store, for pre-distill dedup."""
        return {it.id for it in self.store.items}

    def _embed_items(self, items: list[KnowledgeItem]) -> None:
        if not items or self.embedder is None:
            return
        try:
            vectors = self.embedder.embed([it.knowledge_text() for it in items])
        except Exception as exc:
            self._emit("embed_error", {"message": str(exc)})
            return
        for it, vec in zip(items, vectors):
            it.embedding = list(vec)

    def _github_token(self) -> Optional[str]:
        import os

        env = self.cfg.github_token_env
        return os.environ.get(env) if env else None
