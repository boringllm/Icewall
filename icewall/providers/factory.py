"""Build provider instances from config, with a per-process cache so agents
sharing a provider reuse one client."""
from __future__ import annotations

from icewall.config import ProviderConfig, ProviderType
from icewall.providers.base import LLMProvider


_CACHE: dict[tuple, LLMProvider] = {}


def _cache_key(cfg: ProviderConfig) -> tuple:
    # Content-based key so equivalent configs share a client. NOT id(cfg):
    # CPython reuses object ids after GC, which would return a stale provider.
    return (
        cfg.type.value,
        cfg.base_url,
        cfg.api_key_env,
        cfg.api_key,
        tuple(sorted(cfg.extra_headers.items())),
        cfg.verify_ssl,
        cfg.timeout,
        cfg.max_retries,
    )


def build_provider(cfg: ProviderConfig) -> LLMProvider:
    key = _cache_key(cfg)
    if key in _CACHE:
        return _CACHE[key]

    if cfg.type == ProviderType.MOCK:
        from icewall.providers.mock import MockProvider

        provider: LLMProvider = MockProvider()
    elif cfg.type == ProviderType.ANTHROPIC:
        from icewall.providers.anthropic_provider import AnthropicProvider

        provider = AnthropicProvider(
            api_key_env=cfg.api_key_env or "ANTHROPIC_API_KEY",
            base_url=cfg.base_url,
            extra_headers=cfg.extra_headers,
            api_key=cfg.api_key,
            verify_ssl=cfg.verify_ssl,
            timeout=cfg.timeout,
            max_retries=cfg.max_retries,
        )
    elif cfg.type == ProviderType.OPENAI:
        from icewall.providers.openai_provider import OpenAICompatProvider

        provider = OpenAICompatProvider(
            api_key_env=cfg.api_key_env or "OPENAI_API_KEY",
            base_url=cfg.base_url,
            extra_headers=cfg.extra_headers,
            api_key=cfg.api_key,
            verify_ssl=cfg.verify_ssl,
            timeout=cfg.timeout,
            max_retries=cfg.max_retries,
        )
    else:  # pragma: no cover
        raise ValueError(f"Unknown provider type: {cfg.type}")

    # Only cache the mock provider unconditionally; real providers are cached
    # too (they are stateless clients), keyed by content so they're reused
    # across agents that share credentials.
    _CACHE[key] = provider
    return provider
