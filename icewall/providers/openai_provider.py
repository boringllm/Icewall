"""OpenAI-compatible provider — works with the OpenAI API or any endpoint that
speaks the same chat-completions protocol (local models, gateways, vLLM, etc.)
via a custom base_url. SDK imported lazily."""
from __future__ import annotations

import os
from typing import Optional

from icewall.providers.base import LLMMessage, LLMProvider, LLMResponse


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key_env: Optional[str] = "OPENAI_API_KEY",
        base_url: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        try:
            import openai  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "The 'openai' package is required for the OpenAI-compatible provider. "
                "Install with: pip install openai"
            ) from e
        import openai

        # Custom endpoints may not require a key; fall back to a placeholder.
        key = api_key or os.environ.get(api_key_env or "OPENAI_API_KEY") or "not-needed"
        kwargs = {"api_key": key}
        if base_url:
            kwargs["base_url"] = base_url
        if extra_headers:
            kwargs["default_headers"] = extra_headers
        if not verify_ssl:
            # Skip TLS verification (self-signed / MITM proxies). Insecure.
            import httpx

            kwargs["http_client"] = httpx.Client(verify=False)
        self._client = openai.OpenAI(**kwargs)

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
        api_messages = [{"role": "system", "content": system}]
        api_messages += [{"role": m.role, "content": m.content} for m in messages]
        kwargs = {
            "model": model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        # Extra generation params (top_p, stop, seed, reasoning_effort,
        # response_format, …) go in the request body verbatim, so any parameter
        # the endpoint supports is forwarded — including non-standard ones.
        if params:
            kwargs["extra_body"] = dict(params)
        try:
            resp = self._client.chat.completions.create(**kwargs)
        except Exception as e:
            # Reasoning models (o-series, some Kimi/DeepSeek builds) reject a
            # non-default temperature. Retry once without it.
            msg = str(e).lower()
            if "temperature" in msg:
                kwargs.pop("temperature", None)
                resp = self._client.chat.completions.create(**kwargs)
            else:
                raise

        choice = resp.choices[0]
        text = choice.message.content or ""

        # Reasoning models spend hidden tokens against max_tokens; if reasoning
        # overflows the budget the visible content comes back empty/truncated.
        # Retry once with a much larger budget so findings aren't silently lost.
        if not text.strip() and getattr(choice, "finish_reason", None) == "length":
            retry = dict(kwargs)
            retry["max_tokens"] = min(max(max_tokens * 4, 8000), 32000)
            resp = self._client.chat.completions.create(**retry)
            choice = resp.choices[0]
            text = choice.message.content or ""

        # Reasoning models expose their chain-of-thought separately; capture it
        # if present (naming varies across OpenAI-compatible endpoints).
        msg = choice.message
        reasoning = (
            getattr(msg, "reasoning_content", None)
            or getattr(msg, "reasoning", None)
            or ""
        )

        usage = resp.usage
        return LLMResponse(
            text=text,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            model=model,
            reasoning=reasoning or "",
            raw=resp,
        )
