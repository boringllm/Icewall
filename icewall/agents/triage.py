"""Triage / entry-point agent. Given a batch of candidate symbols (with code),
it decides which are attack surface worth deep analysis and how suspicious each
is. Cheap-tier model: this runs over many symbols."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class TriageAgent(BaseAgent):
    role = AgentRole.TRIAGE
    SYSTEM = (
        "You are a security triage agent for a code-audit system.\n"
        "You receive JSON: {\"candidates\": [{\"symbol_id\", \"name\", \"file\", \"code\"}]}.\n"
        "For each candidate, decide whether it is attack surface — i.e. it handles\n"
        "untrusted/external input (HTTP params, request bodies, CLI args, file/network\n"
        "input) OR reaches a dangerous sink (command exec, SQL, eval, file I/O,\n"
        "deserialization, outbound requests).\n"
        "Return ONLY JSON of the form:\n"
        "{\"entry_points\": [{\"symbol_id\": str, \"reason\": str, \"surface\": "
        "\"http|cli|file|network|internal\", \"suspicion\": float 0..1}]}\n"
        "Omit candidates that are not attack surface. Do not include prose."
    )

    def triage(self, candidates: list[dict]) -> list[dict]:
        result = self.call({"candidates": candidates})
        return result.get("entry_points", [])
