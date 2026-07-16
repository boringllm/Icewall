"""Data model for the knowledge base (Vul-RAG style).

A `KnowledgeItem` is the structured knowledge distilled from one historical
vulnerability: what the code does (functional semantics), why it was vulnerable
(cause), and what made the patch safe (fix). A `CvePair` is the raw material —
the vulnerable and patched versions of a function plus metadata — that the
distiller turns into a `KnowledgeItem`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CvePair:
    """One {vulnerable, patched} function pair extracted from a CVE fix commit."""

    cve_id: str
    language: str
    vulnerable_code: str
    patched_code: str
    description: str = ""
    commit_url: str = ""
    function: str = ""  # qualname of the changed function, if known
    cwe: Optional[str] = None  # e.g. "CWE-89", when the advisory states it


@dataclass
class KnowledgeItem:
    """Distilled, retrievable knowledge about one vulnerability pattern."""

    id: str
    vuln_class: str  # VulnClass value (the retrieval filter) or "" if unmapped
    cwe: Optional[str] = None
    # Functional semantics — also the retrieval keys.
    abstract_purpose: str = ""
    detailed_behavior: str = ""
    # Cause.
    triggering_action: str = ""
    abstract_cause: str = ""
    detailed_cause: str = ""
    # Fix — the crux: what makes patched code safe.
    fixing_solution: str = ""
    # Provenance (auditable trail): CVE id, "seed:<skill>", or "self:<session>".
    source: str = ""
    languages: list[str] = field(default_factory=list)
    # Populated when an embedding endpoint is configured; empty => BM25 retrieval.
    embedding: list[float] = field(default_factory=list)

    # --- retrieval text ------------------------------------------------------

    def semantics_text(self) -> str:
        """The functional-semantics text a query is matched against."""
        return " ".join(t for t in (self.abstract_purpose, self.detailed_behavior) if t)

    def knowledge_text(self) -> str:
        """The full item as one string (BM25 corpus / embedding input)."""
        return " ".join(
            t
            for t in (
                self.abstract_purpose,
                self.detailed_behavior,
                self.triggering_action,
                self.abstract_cause,
                self.detailed_cause,
                self.fixing_solution,
            )
            if t
        )

    def prompt_line(self) -> str:
        """Compact form injected into the validator prompt."""
        cause = self.abstract_cause or self.detailed_cause or self.triggering_action
        return (
            f"cause: {cause} | triggered by: {self.triggering_action} | "
            f"fix that neutralizes it: {self.fixing_solution} | ({self.source})"
        )

    # --- (de)serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vuln_class": self.vuln_class,
            "cwe": self.cwe,
            "abstract_purpose": self.abstract_purpose,
            "detailed_behavior": self.detailed_behavior,
            "triggering_action": self.triggering_action,
            "abstract_cause": self.abstract_cause,
            "detailed_cause": self.detailed_cause,
            "fixing_solution": self.fixing_solution,
            "source": self.source,
            "languages": list(self.languages),
            "embedding": list(self.embedding),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KnowledgeItem":
        return cls(
            id=d.get("id") or new_item_id(d.get("source", ""), d.get("abstract_cause", "")),
            vuln_class=d.get("vuln_class", ""),
            cwe=d.get("cwe"),
            abstract_purpose=d.get("abstract_purpose", ""),
            detailed_behavior=d.get("detailed_behavior", ""),
            triggering_action=d.get("triggering_action", ""),
            abstract_cause=d.get("abstract_cause", ""),
            detailed_cause=d.get("detailed_cause", ""),
            fixing_solution=d.get("fixing_solution", ""),
            source=d.get("source", ""),
            languages=list(d.get("languages", [])),
            embedding=list(d.get("embedding", [])),
        )


def new_item_id(source: str, salt: str = "") -> str:
    """Stable id from provenance + content, so re-builds dedupe naturally."""
    h = hashlib.sha1(f"{source}::{salt}".encode("utf-8")).hexdigest()
    return h[:16]


def pair_item_id(pair: "CvePair") -> str:
    """The knowledge-item id a `CvePair` distills into.

    Derived purely from provenance — the CVE id (or fix commit) plus the changed
    function — so it is stable across builds and independent of the distiller's
    (possibly nondeterministic) output. This lets a build skip a pair whose
    knowledge is already in the store *before* paying for the distill call.
    """
    return new_item_id(pair.cve_id or pair.commit_url, pair.function)
