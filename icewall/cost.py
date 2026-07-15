"""Model pricing and cost estimation.

Prices are USD per 1,000,000 tokens (input, output), current as of 2026-07.
Unknown models fall back to a conservative default so cost is never silently
zero. Override or extend PRICING for custom endpoints via `register_price`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    input_per_mtok: float
    output_per_mtok: float


# Anthropic list prices (USD / 1M tokens).
PRICING: dict[str, Price] = {
    "claude-fable-5": Price(10.0, 50.0),
    "claude-mythos-5": Price(10.0, 50.0),
    "claude-opus-4-8": Price(5.0, 25.0),
    "claude-opus-4-7": Price(5.0, 25.0),
    "claude-opus-4-6": Price(5.0, 25.0),
    "claude-sonnet-5": Price(3.0, 15.0),
    "claude-sonnet-4-6": Price(3.0, 15.0),
    "claude-haiku-4-5": Price(1.0, 5.0),
    "claude-haiku-4-5-20251001": Price(1.0, 5.0),
    # Mock provider is free.
    "mock-1": Price(0.0, 0.0),
}

# Used when a model id is not in PRICING (e.g. a custom OpenAI-compatible model).
DEFAULT_PRICE = Price(1.0, 5.0)


def register_price(model: str, input_per_mtok: float, output_per_mtok: float) -> None:
    PRICING[model] = Price(input_per_mtok, output_per_mtok)


Overrides = dict[str, tuple[float, float]]  # model -> (input/Mtok, output/Mtok)


def price_for(model: str, overrides: Overrides | None = None) -> Price:
    # Config-supplied custom prices win, by exact model id.
    if overrides and model in overrides:
        i, o = overrides[model]
        return Price(i, o)
    if model in PRICING:
        return PRICING[model]
    # Prefix match for dated snapshots / provider-prefixed ids.
    for known, price in PRICING.items():
        if model.startswith(known) or known in model:
            return price
    return DEFAULT_PRICE


def cost_of(
    model: str, input_tokens: int, output_tokens: int, overrides: Overrides | None = None
) -> float:
    p = price_for(model, overrides)
    return (input_tokens / 1_000_000) * p.input_per_mtok + (
        output_tokens / 1_000_000
    ) * p.output_per_mtok


def estimate_cost(
    usage_by_model: dict[str, tuple[int, int]], overrides: Overrides | None = None
) -> float:
    """usage_by_model: model -> (input_tokens, output_tokens). Returns USD."""
    return round(
        sum(cost_of(m, i, o, overrides) for m, (i, o) in usage_by_model.items()), 4
    )


def is_free(usage_by_model: dict[str, tuple[int, int]]) -> bool:
    return all(price_for(m).input_per_mtok == 0 and price_for(m).output_per_mtok == 0
               for m in usage_by_model)
