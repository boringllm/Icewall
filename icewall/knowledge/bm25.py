"""A tiny BM25 Okapi ranker, vendored so knowledge retrieval works with no
network and no extra dependency (the offline fallback when no embedding endpoint
is configured or it is unreachable).

Not a general IR engine — just enough to rank a few thousand short knowledge
documents against a query. Deterministic and pure-Python.
"""
from __future__ import annotations

import math
import re
from typing import Iterable

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


class BM25:
    def __init__(self, docs: Iterable[str], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.doc_tokens: list[list[str]] = [tokenize(d) for d in docs]
        self.n = len(self.doc_tokens)
        self.doc_len = [len(t) for t in self.doc_tokens]
        self.avgdl = (sum(self.doc_len) / self.n) if self.n else 0.0
        # Document frequency per term.
        df: dict[str, int] = {}
        for toks in self.doc_tokens:
            for term in set(toks):
                df[term] = df.get(term, 0) + 1
        # Okapi idf (floored at 0 so common terms can't push scores negative).
        self.idf = {
            term: max(0.0, math.log((self.n - d + 0.5) / (d + 0.5) + 1.0))
            for term, d in df.items()
        }
        # Term frequencies per doc.
        self.tf: list[dict[str, int]] = []
        for toks in self.doc_tokens:
            counts: dict[str, int] = {}
            for t in toks:
                counts[t] = counts.get(t, 0) + 1
            self.tf.append(counts)

    def scores(self, query: str) -> list[float]:
        q_terms = tokenize(query)
        out = [0.0] * self.n
        for i in range(self.n):
            dl = self.doc_len[i]
            tf = self.tf[i]
            s = 0.0
            for term in q_terms:
                f = tf.get(term, 0)
                if f == 0:
                    continue
                idf = self.idf.get(term, 0.0)
                denom = f + self.k1 * (1 - self.b + self.b * (dl / self.avgdl if self.avgdl else 0))
                s += idf * (f * (self.k1 + 1)) / (denom or 1.0)
            out[i] = s
        return out
