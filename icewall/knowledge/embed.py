"""Embedding backend for knowledge retrieval.

Talks to an OpenAI-compatible `/v1/embeddings` endpoint (which may be a custom
host, separate from the chat providers). `build_embedder` returns None when no
embedding model is configured, which signals the store to use BM25 instead.

An `Embedder` is intentionally a tiny protocol so tests can inject a fake.
"""
from __future__ import annotations

import math
import os
from typing import Optional, Protocol

from icewall.config import EmbeddingConfig


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAIEmbedder:
    """Batched embeddings via the OpenAI SDK against a configurable base_url."""

    def __init__(self, cfg: EmbeddingConfig) -> None:
        import openai  # lazily imported; only needed when embeddings are used

        key = cfg.api_key or os.environ.get(cfg.api_key_env or "OPENAI_API_KEY") or "not-needed"
        kwargs: dict = {"api_key": key, "timeout": cfg.timeout}
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        if cfg.max_retries is not None:
            kwargs["max_retries"] = cfg.max_retries
        if not cfg.verify_ssl:
            import httpx

            kwargs["http_client"] = httpx.Client(verify=False, timeout=cfg.timeout)
        self._client = openai.OpenAI(**kwargs)
        self._model = cfg.model
        self._dimensions = cfg.dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        kwargs: dict = {"model": self._model, "input": texts}
        if self._dimensions:
            kwargs["dimensions"] = self._dimensions
        resp = self._client.embeddings.create(**kwargs)
        # Preserve input order (endpoints return `index`).
        rows = sorted(resp.data, key=lambda d: getattr(d, "index", 0))
        return [list(r.embedding) for r in rows]


def build_embedder(cfg: EmbeddingConfig) -> Optional[Embedder]:
    """An OpenAIEmbedder if a model is configured, else None (=> BM25 fallback)."""
    if not cfg.model:
        return None
    try:
        return OpenAIEmbedder(cfg)
    except Exception:
        # Missing SDK or bad config: degrade to BM25 rather than break the build.
        return None


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)
