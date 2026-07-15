"""Provider-agnostic LLM interface.

Every agent talks to an `LLMProvider`. Implementations wrap Anthropic, any
OpenAI-compatible endpoint, or the offline heuristic mock. The interface is
synchronous; concurrency is handled one level up by the thread pools, which
keeps providers simple and thread-safe (one HTTP call per invocation).
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMMessage:
    role: str  # "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    # Reasoning/thinking content, when the model/endpoint exposes it separately
    # from the answer (Anthropic thinking blocks, reasoning-model reasoning_content).
    reasoning: str = ""
    raw: Optional[object] = field(default=None, repr=False)

    def json(self) -> dict:
        """Best-effort parse of a JSON object from the response text.

        Models sometimes wrap JSON in prose or ```json fences; we extract the
        first balanced object rather than trusting the whole string.
        """
        return extract_json(self.text)


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of arbitrary model text."""
    if not text:
        return {}
    # Strip code fences.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    candidate = fence.group(1) if fence else text
    # Find the first balanced {...}.
    start = candidate.find("{")
    if start == -1:
        return {}
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(candidate)):
        ch = candidate[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = candidate[start : i + 1]
                try:
                    return json.loads(blob)
                except json.JSONDecodeError:
                    return {}
    return {}


class LLMProvider(ABC):
    """Base class for all LLM backends."""

    name: str = "base"

    @abstractmethod
    def complete(
        self,
        *,
        system: str,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking_tokens: int = 0,
        params: Optional[dict] = None,
    ) -> LLMResponse:
        """Return a single completion. Must be thread-safe.

        `params` is a dict of extra generation parameters forwarded to the
        underlying API (provider-appropriate names); implementations merge it
        into the request body."""
        raise NotImplementedError
