"""Remediation agent. Proposes a fix for a confirmed finding — a unified diff
plus rationale. Proposals only: Icewall never applies patches (AI-generated
patches can introduce new bugs; the human reviews). Strong model."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class RemediatorAgent(BaseAgent):
    role = AgentRole.REMEDIATOR
    SYSTEM = (
        "You are a secure-coding remediation agent.\n"
        "Input JSON: {\"finding\": {\"vuln_class\",\"file\",\"line\",\"sink\",\"description\"},\n"
        "  \"code\": str}.\n"
        "Propose a minimal, correct fix that removes the vulnerability while preserving\n"
        "behavior (parameterized queries, safe APIs, escaping, allow-lists, etc.).\n"
        "Return ONLY JSON:\n"
        "{\"summary\": str, \"diff\": str (unified diff), \"rationale\": str,\n"
        " \"confidence\": int 0..10}\n"
        "The diff must be a valid unified diff against the given file. Do NOT claim the\n"
        "fix is applied — it is a proposal for human review."
    )

    def remediate(self, finding: dict, code: str) -> dict:
        return self.call({"finding": finding, "code": code})
