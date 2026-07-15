"""Thread-safe run budget. The orchestrator checks `allow()` before dispatching
LLM work and calls `record()` after each completion, so a large repo cannot run
away on token spend or call count. Tracks usage per model so cost can be priced
accurately across mixed-tier configurations."""
from __future__ import annotations

import threading

from icewall.cost import estimate_cost


class BudgetExceeded(RuntimeError):
    pass


class BudgetTracker:
    def __init__(
        self,
        max_total_tokens: int,
        max_llm_calls: int,
        pricing_overrides: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        self._max_tokens = max_total_tokens
        self._max_calls = max_llm_calls
        self._pricing = pricing_overrides or None
        self._lock = threading.Lock()
        self.input_tokens = 0
        self.output_tokens = 0
        self.calls = 0
        # model -> [input_tokens, output_tokens, calls]
        self._by_model: dict[str, list[int]] = {}
        # role -> [input_tokens, output_tokens, calls]
        self._by_role: dict[str, list[int]] = {}
        # role -> model it used (a role binds to one model), for pricing.
        self._role_model: dict[str, str] = {}

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def allow(self) -> bool:
        with self._lock:
            return self.total_tokens < self._max_tokens and self.calls < self._max_calls

    def record(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str = "",
        role: str = "",
    ) -> None:
        with self._lock:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.calls += 1
            row = self._by_model.setdefault(model or "unknown", [0, 0, 0])
            row[0] += input_tokens
            row[1] += output_tokens
            row[2] += 1
            if role:
                rrow = self._by_role.setdefault(role, [0, 0, 0])
                rrow[0] += input_tokens
                rrow[1] += output_tokens
                rrow[2] += 1
                self._role_model[role] = model or "unknown"

    def usage_by_model(self) -> dict[str, tuple[int, int]]:
        with self._lock:
            return {m: (r[0], r[1]) for m, r in self._by_model.items()}

    def estimated_cost(self) -> float:
        return estimate_cost(self.usage_by_model(), self._pricing)

    def cost_by_model(self) -> dict[str, dict]:
        from icewall.cost import cost_of

        with self._lock:
            out = {}
            for m, r in self._by_model.items():
                out[m] = {
                    "input_tokens": r[0],
                    "output_tokens": r[1],
                    "calls": r[2],
                    "cost_usd": round(cost_of(m, r[0], r[1], self._pricing), 4),
                }
            return out

    def cost_for_role(self, role: str) -> float:
        """Running USD cost for one role — cheap enough to call per event so the
        UI can show live per-agent spend during a scan."""
        from icewall.cost import cost_of

        with self._lock:
            r = self._by_role.get(role)
            if not r:
                return 0.0
            model = self._role_model.get(role, "unknown")
            return round(cost_of(model, r[0], r[1], self._pricing), 6)

    def cost_by_role(self) -> dict[str, dict]:
        """Per-agent (role) cost breakdown for the session dashboard. Each role
        is priced by the model it used."""
        from icewall.cost import cost_of

        with self._lock:
            out = {}
            for role, r in self._by_role.items():
                model = self._role_model.get(role, "unknown")
                out[role] = {
                    "model": model,
                    "input_tokens": r[0],
                    "output_tokens": r[1],
                    "calls": r[2],
                    "cost_usd": round(cost_of(model, r[0], r[1], self._pricing), 4),
                }
            return out

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "llm_calls": self.calls,
            }
