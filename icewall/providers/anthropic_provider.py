"""Anthropic provider. SDK is imported lazily so mock-only runs need no install."""
from __future__ import annotations

import os
from typing import Optional

from icewall.providers.base import LLMMessage, LLMProvider, LLMResponse


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self,
        api_key_env: Optional[str] = "ANTHROPIC_API_KEY",
        base_url: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        try:
            import anthropic  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install with: pip install anthropic"
            ) from e
        import anthropic

        key = api_key or os.environ.get(api_key_env or "ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                f"Anthropic API key not found (set env var '{api_key_env}' "
                "or the provider's inline 'api_key')."
            )
        kwargs = {"api_key": key}
        if base_url:
            kwargs["base_url"] = base_url
        if extra_headers:
            kwargs["default_headers"] = extra_headers
        if not verify_ssl:
            import httpx

            kwargs["http_client"] = httpx.Client(verify=False)
        self._client = anthropic.Anthropic(**kwargs)

    def complete(
        self,
        *,
        system: str,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking_tokens: int = 0,
        params: dict | None = None,
    ) -> LLMResponse:
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": api_messages,
        }
        if thinking_tokens and thinking_tokens > 0:
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": thinking_tokens}
            # Extended thinking requires the default temperature.
        else:
            kwargs["temperature"] = temperature
        # Extra params (top_p, top_k, stop_sequences, metadata, …) forwarded
        # verbatim into the request body.
        if params:
            kwargs["extra_body"] = dict(params)

        resp = self._client.messages.create(**kwargs)
        # Concatenate text blocks (ignore thinking blocks for the parsed output).
        text_parts = [
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        ]
        # Capture extended-thinking blocks separately for the trace view.
        thinking = "".join(
            getattr(block, "thinking", "") or ""
            for block in resp.content
            if getattr(block, "type", None) == "thinking"
        )
        return LLMResponse(
            text="".join(text_parts),
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            model=model,
            reasoning=thinking,
            raw=resp,
        )
