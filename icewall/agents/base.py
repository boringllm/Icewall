"""Base agent: wraps a provider + model config for one role. Stamps the role
tag the (mock and real) providers key off, enforces budget, and parses JSON out.

Each agent declares a SYSTEM prompt describing its job and required JSON output
shape. The same prompt drives real LLMs and the offline mock."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional

from icewall.config import AgentModelConfig, AgentRole
from icewall.orchestration.budget import BudgetExceeded, BudgetTracker
from icewall.providers.base import LLMMessage, LLMProvider

if TYPE_CHECKING:
    from icewall.skills import Skill


class BaseAgent:
    role: AgentRole
    SYSTEM: str = ""

    def __init__(
        self,
        provider: LLMProvider,
        model_cfg: AgentModelConfig,
        budget: BudgetTracker,
        skills: Optional[list["Skill"]] = None,
        recorder=None,
    ) -> None:
        self.provider = provider
        self.model_cfg = model_cfg
        self.budget = budget
        # Optional TraceRecorder: captures each LLM exchange for the UI drill-down.
        self.recorder = recorder
        # Skills are loaded once, when the agent spawns, and baked into the
        # rendered system prompt for every call this agent makes.
        self.skills = list(skills or [])
        self._skill_block = self._render_skills()

    def _render_skills(self) -> str:
        if not self.skills:
            return ""
        from icewall.skills import render_skills

        return render_skills(self.skills)

    def _system(self) -> str:
        # The [ICEWALL-AGENT:<role>] tag lets providers (esp. the mock) route.
        return f"[ICEWALL-AGENT:{self.role.value}]\n{self.SYSTEM}{self._skill_block}"

    def call(self, payload: dict) -> dict:
        if not self.budget.allow():
            raise BudgetExceeded(f"Budget exhausted before {self.role.value} call")
        user = json.dumps(payload)
        system = self._system()
        messages = [LLMMessage(role="user", content=user)]
        resp = self.provider.complete(
            system=system,
            messages=messages,
            model=self.model_cfg.model,
            max_tokens=self.model_cfg.max_tokens,
            temperature=self.model_cfg.temperature,
            thinking_tokens=self.model_cfg.thinking_tokens,
            params=self.model_cfg.params or None,
        )
        self.budget.record(
            resp.input_tokens, resp.output_tokens, self.model_cfg.model, self.role.value
        )
        if self.recorder is not None:
            self.recorder.record(
                model=self.model_cfg.model,
                system=system,
                user=user,
                response=resp.text,
                input_tokens=resp.input_tokens,
                output_tokens=resp.output_tokens,
                reasoning=getattr(resp, "reasoning", "") or "",
            )
        return resp.json()
