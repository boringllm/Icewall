"""Validator agent — the precision pillar. Independently re-checks each raw
finding for path feasibility and guard/sanitizer presence, and adjusts or
rejects it. This is the single highest-ROI stage for cutting false positives
(cf. QASecClaw, LLM4PFA). Runs on a strong model."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class ValidatorAgent(BaseAgent):
    role = AgentRole.VALIDATOR
    SYSTEM = (
        "You are an independent security validator. A prior agent flagged a finding;\n"
        "your job is to confirm or reject it, skeptically.\n"
        "Input JSON: {\"finding\": {\"vuln_class\",\"confidence\",\"sink\",\"file\",\"line\",\n"
        "  \"description\"}, \"code\": str, \"chain\": [str],\n"
        "  \"knowledge\": [{\"cause\",\"fix\",\"source\"}]  (optional; retrieved from real CVEs)}.\n"
        "Check: (1) is there a FEASIBLE path from untrusted input to the sink? "
        "(2) are there guards/sanitizers/parameterization that neutralize it? "
        "(3) is the sink actually dangerous with attacker-controlled data?\n"
        "If `knowledge` is present, use it: for each item decide whether this code\n"
        "exhibits the same CAUSE while the corresponding FIX is ABSENT — that pattern\n"
        "means vulnerable; if the fix IS present, that argues for rejection.\n"
        "Return ONLY JSON:\n"
        "{\"verdict\": \"confirmed|rejected|uncertain\", \"feasible\": bool,\n"
        " \"guards_present\": bool, \"adjusted_confidence\": int 0..10, \"notes\": str}\n"
        "Reject when a guard (or a retrieved item's fix) makes exploitation infeasible."
    )

    def validate(
        self, finding: dict, code: str, chain: list[str], knowledge: list[dict] | None = None
    ) -> dict:
        payload = {"finding": finding, "code": code, "chain": chain}
        if knowledge:
            payload["knowledge"] = knowledge
        return self.call(payload)
