"""Knowledge-level RAG (Vul-RAG style): a persistent base of vulnerability
knowledge distilled from real CVE+patch pairs, retrieved per candidate and fed
to the validator to sharpen the vulnerable-vs-patched decision."""
from icewall.knowledge.builder import KnowledgeBuilder
from icewall.knowledge.embed import build_embedder
from icewall.knowledge.schema import CvePair, KnowledgeItem
from icewall.knowledge.store import KnowledgeStore

__all__ = [
    "CvePair",
    "KnowledgeItem",
    "KnowledgeStore",
    "KnowledgeBuilder",
    "build_embedder",
]
