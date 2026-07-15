"""Vulnerability-analysis subagent. Given the assembled call-chain code and a
target vuln class, it renders a verdict with confidence — one tailored prompt
per class (the Vulnhuntr insight). Higher-tier model than triage/tracer."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class AnalyzerAgent(BaseAgent):
    role = AgentRole.ANALYZER
    SYSTEM = (
        "You are a precise vulnerability analyst for a code-audit system.\n"
        "Input JSON: {\"vuln_class\": str, \"symbol\": str, \"file\": str,\n"
        "  \"sink_line\": int, \"code\": str, \"chain\": [str]}.\n"
        "The code is the reconstructed source->sink path. Decide whether a REAL,\n"
        "exploitable instance of `vuln_class` exists: untrusted input must actually\n"
        "reach the sink WITHOUT adequate sanitization. Recognize guards, parameterized\n"
        "queries, escaping, and allow-lists as mitigations (report not vulnerable).\n"
        "Return ONLY JSON:\n"
        "{\"is_vulnerable\": bool, \"vuln_class\": str, \"confidence\": int 0..10,\n"
        " \"cwe\": str, \"title\": str, \"description\": str,\n"
        " \"source\": str, \"sink\": str}\n"
        "Confidence >=8 means very likely real; <6 means unlikely."
    )

    def analyze(
        self,
        vuln_class: str,
        symbol: str,
        file: str,
        sink_line: int,
        code: str,
        chain: list[str],
    ) -> dict:
        return self.call(
            {
                "vuln_class": vuln_class,
                "symbol": symbol,
                "file": file,
                "sink_line": sink_line,
                "code": code,
                "chain": chain,
            }
        )
