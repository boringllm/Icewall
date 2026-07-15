"""Configuration model for Icewall.

A single YAML file wires providers, per-agent model tiering, concurrency, and
budget. `IcewallConfig.load` reads it; `IcewallConfig.default` gives a working
config that uses the mock provider (no API keys required) so the tool runs
end-to-end out of the box.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    TRIAGE = "triage"
    TRACER = "tracer"
    ANALYZER = "analyzer"
    VALIDATOR = "validator"
    REMEDIATOR = "remediator"
    # Compresses oversized context on demand (dynamic context management).
    SUMMARIZER = "summarizer"


class ProviderType(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"  # any OpenAI-compatible endpoint (custom base_url)
    MOCK = "mock"


class ProviderConfig(BaseModel):
    """A named LLM backend. Multiple may coexist (e.g. anthropic + a local endpoint).

    API key resolution order: inline `api_key` (if set) → the env var named by
    `api_key_env`. Prefer `api_key_env` — an inline key sits in plaintext in the
    config file; keep such a file out of version control (icewall.yaml is
    git-ignored by default)."""

    type: ProviderType
    base_url: Optional[str] = None
    # Name of the env var holding the API key (never the key itself). Preferred.
    api_key_env: Optional[str] = None
    # Inline key — convenient but plaintext. Overrides api_key_env when set.
    api_key: Optional[str] = None
    # Optional extra headers, e.g. for gateways.
    extra_headers: dict[str, str] = Field(default_factory=dict)
    # Set false to skip TLS certificate verification (self-signed gateways,
    # corporate MITM proxies). Insecure — only for trusted internal endpoints.
    verify_ssl: bool = True


class AgentModelConfig(BaseModel):
    """Binds one agent role to a provider + model + effort settings."""

    provider: str  # key into IcewallConfig.providers
    model: str
    max_tokens: int = 4096
    temperature: float = 0.0
    # Extended-thinking / reasoning-effort budget in tokens. 0 = off.
    thinking_tokens: int = 0
    # Arbitrary generation parameters forwarded verbatim to the provider's API
    # (merged into the request body). Use provider-appropriate names — OpenAI:
    # top_p, stop, seed, frequency_penalty, presence_penalty, reasoning_effort,
    # response_format, …; Anthropic: top_p, top_k, stop_sequences, metadata, ….
    # This is the escape hatch for "every parameter the model supports".
    params: dict[str, Any] = Field(default_factory=dict)
    # Explicit skill selection (by name). Empty => auto-attach all skills whose
    # frontmatter targets this agent's role.
    skills: list[str] = Field(default_factory=list)


class SkillsConfig(BaseModel):
    """Where agent skills are discovered. Bundled skills load by default; add
    your own directories and disable individual skills by name."""

    include_bundled: bool = True
    dirs: list[str] = Field(default_factory=list)
    disabled: list[str] = Field(default_factory=list)


class ModelPrice(BaseModel):
    """Custom price for a model, USD per 1,000,000 tokens. Overrides the built-in
    pricing table so cost estimates are accurate for custom/endpoint models.
    YAML may use the short keys `input:` / `output:`."""

    model_config = {"populate_by_name": True}

    input_per_mtok: float = Field(alias="input")
    output_per_mtok: float = Field(alias="output")


class WorkshopConfig(BaseModel):
    """Per-session working directory. Each scan gets its own folder under `root`
    holding the reports, session metadata, and agent memory. Doubles as the
    audit trail and the substrate for incremental re-scans."""

    enabled: bool = True
    root: str = ".icewall"
    # Keep only the N most recent session folders (0 = keep all).
    keep_last: int = 0


class ContextConfig(BaseModel):
    """Dynamic context management. When an agent's assembled context exceeds
    `max_context_tokens`, a summarizer compresses the non-anchor blocks down
    toward `summarize_to_tokens`, preserving the entry point and sink verbatim."""

    enabled: bool = True
    # Trigger summarization when packed context passes this (rough) token count.
    max_context_tokens: int = 6000
    # Target size for the compressed remainder.
    summarize_to_tokens: int = 2000


class MemoryConfig(BaseModel):
    """Session memory. Agents write notes as they finish (master.md index +
    per-topic sub-notes); later stages recall relevant notes by file/vuln-class
    rather than paying an LLM to decide what to load."""

    enabled: bool = True
    # Feed recalled notes from earlier stages into the validator's context.
    share_across_stages: bool = True


class TraceConfig(BaseModel):
    """Per-task LLM exchange capture powering the UI's task drill-down (the
    prompt, reasoning, answer and tokens for each call). Streamed live and saved
    to the workshop. Disable to avoid persisting prompts/responses."""

    enabled: bool = True
    # Cap on each captured field (system/user/response/reasoning) in characters.
    max_chars: int = 16000


class ConcurrencyConfig(BaseModel):
    neural_workers: int = 8  # bounded by API rate/cost
    symbolic_workers: int = 8  # CPU-bound graph work
    max_context_requests: int = 4  # per tracer subagent (dynamic parent<->child hops)


class BudgetConfig(BaseModel):
    # Hard ceiling for a whole run. Orchestrator stops dispatching past this.
    max_total_tokens: int = 2_000_000
    max_llm_calls: int = 2000
    # Only analyze entry points at/above this triage suspicion.
    min_suspicion: float = 0.3


class ScanConfig(BaseModel):
    languages: list[str] = Field(default_factory=lambda: ["python", "javascript", "typescript"])
    include_globs: list[str] = Field(default_factory=lambda: ["**/*"])
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/venv/**",
            "**/.venv/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/*.min.js",
        ]
    )
    max_file_bytes: int = 400_000
    # Vuln classes to hunt for. Empty => all known classes.
    detectors: list[str] = Field(default_factory=list)
    # Send EVERY function to LLM triage, not just those matching a source/sink
    # pattern. Higher recall (catches novel/unpatterned sinks), higher cost.
    analyze_all_functions: bool = False


class IcewallConfig(BaseModel):
    providers: dict[str, ProviderConfig]
    agents: dict[AgentRole, AgentModelConfig]
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    skills: SkillsConfig = Field(default_factory=SkillsConfig)
    workshop: WorkshopConfig = Field(default_factory=WorkshopConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    trace: TraceConfig = Field(default_factory=TraceConfig)
    # Custom per-model prices (USD / 1M tokens). Overrides the built-in table.
    pricing: dict[str, ModelPrice] = Field(default_factory=dict)

    def price_overrides(self) -> dict[str, tuple[float, float]]:
        return {m: (p.input_per_mtok, p.output_per_mtok) for m, p in self.pricing.items()}

    @classmethod
    def load(cls, path: str | Path) -> "IcewallConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @classmethod
    def default(cls) -> "IcewallConfig":
        """A ready-to-run config backed entirely by the mock provider."""
        mock = AgentModelConfig(provider="mock", model="mock-1")
        return cls(
            providers={"mock": ProviderConfig(type=ProviderType.MOCK)},
            agents={role: mock.model_copy() for role in AgentRole},
        )

    def agent(self, role: AgentRole) -> AgentModelConfig:
        if role not in self.agents:
            raise KeyError(f"No model configured for agent role '{role.value}'")
        return self.agents[role]

    def provider_for(self, role: AgentRole) -> ProviderConfig:
        key = self.agent(role).provider
        if key not in self.providers:
            raise KeyError(f"Agent '{role.value}' references unknown provider '{key}'")
        return self.providers[key]

    def summary(self) -> dict:
        return {
            "providers": {k: v.type.value for k, v in self.providers.items()},
            "agents": {
                r.value: f"{c.provider}:{c.model}" for r, c in self.agents.items()
            },
            "neural_workers": self.concurrency.neural_workers,
            "symbolic_workers": self.concurrency.symbolic_workers,
        }


# Scan intensity — a recall/cost tradeoff that bundles the three highest-leverage
# knobs: the triage suspicion floor, how many context hops a tracer may take, and
# whether EVERY function is triaged (vs only those matching a source/sink pattern).
# Higher intensity finds more (fewer missed paths) but costs more.
INTENSITY_LEVELS: list[dict] = [
    {
        "id": "fast",
        "label": "Fast",
        "description": "Cheapest. High-suspicion entry points only, shallow tracing. Best precision, may miss deeper or subtler paths.",
        "min_suspicion": 0.5,
        "max_context_requests": 2,
        "analyze_all_functions": False,
    },
    {
        "id": "balanced",
        "label": "Balanced",
        "description": "The default. Pattern-flagged functions, moderate tracing depth. Good recall/cost balance.",
        "min_suspicion": 0.3,
        "max_context_requests": 4,
        "analyze_all_functions": False,
    },
    {
        "id": "thorough",
        "label": "Thorough",
        "description": "More entry points and deeper tracing. Catches longer source→sink chains at higher cost.",
        "min_suspicion": 0.15,
        "max_context_requests": 6,
        "analyze_all_functions": False,
    },
    {
        "id": "exhaustive",
        "label": "Exhaustive",
        "description": "Every function is triaged (bypasses the source/sink pre-filter) with the deepest tracing. Highest recall and highest cost.",
        "min_suspicion": 0.0,
        "max_context_requests": 8,
        "analyze_all_functions": True,
    },
]

INTENSITY_IDS = [lvl["id"] for lvl in INTENSITY_LEVELS]


def apply_intensity(cfg: IcewallConfig, name: str) -> IcewallConfig:
    """Override the recall/cost knobs on `cfg` from a named intensity level.
    Unknown names (including 'custom') leave the config untouched."""
    level = next((l for l in INTENSITY_LEVELS if l["id"] == name), None)
    if level is None:
        return cfg
    cfg.budget.min_suspicion = level["min_suspicion"]
    cfg.concurrency.max_context_requests = level["max_context_requests"]
    cfg.scan.analyze_all_functions = level["analyze_all_functions"]
    return cfg
