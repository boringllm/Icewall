"""Summarizer subagent. Compresses a set of code-context blocks into a compact
digest that preserves taint-relevant facts (sources, sinks, sanitizers, and the
data flow between them) so a downstream agent can keep reasoning without the full
bodies. Invoked by the ContextManager when assembled context exceeds budget."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class SummarizerAgent(BaseAgent):
    role = AgentRole.SUMMARIZER
    SYSTEM = (
        "You compress code context for a security-audit system without losing\n"
        "security-relevant meaning.\n"
        "Input JSON: {\"topic\": str, \"blocks\": [{\"name\",\"file\",\"code\"}]}.\n"
        "Produce a compact digest that PRESERVES, for each block: external input\n"
        "sources, dangerous sinks (exec/SQL/eval/file/deserialize/HTTP/HTML),\n"
        "sanitizers or validation, and how data flows between functions. Drop\n"
        "boilerplate, imports, logging, and unrelated logic. Keep function and\n"
        "parameter names exact so the trace stays intact.\n"
        "Return ONLY JSON: {\"summary\": str}."
    )

    def summarize(self, blocks: list[dict], topic: str = "") -> str:
        result = self.call({"topic": topic, "blocks": blocks})
        return result.get("summary", "")
