"""Path-tracer subagent. From an entry point, follows the call graph toward a
dangerous sink, reconstructing the source->sink chain. It may ask the parent for
more context (the dynamic parent<->child protocol) via `need_context`; the
orchestrator resolves those from the graph and re-invokes."""
from __future__ import annotations

from icewall.agents.base import BaseAgent
from icewall.config import AgentRole


class TracerAgent(BaseAgent):
    role = AgentRole.TRACER
    SYSTEM = (
        "You are a taint path-tracer for a code-audit system.\n"
        "Input JSON: {\"entry_point\": {\"symbol_id\",\"name\",\"code\"},\n"
        "  \"neighborhood\": [{\"symbol_id\",\"name\",\"code\"}],\n"
        "  \"requested_context\": [{\"symbol_id\",\"name\",\"code\"}]}.\n"
        "Starting from external input in the entry point, follow calls to determine\n"
        "whether tainted data can reach a dangerous sink (command exec, SQL, eval,\n"
        "file I/O, deserialization, outbound request, HTML output).\n"
        "If you need the body of a called function that is not present, request it.\n"
        "Return ONLY JSON:\n"
        "{\"reached_sink\": bool,\n"
        " \"sink\": {\"symbol_id\": str, \"kind\": str, \"vuln_class\": str} | null,\n"
        " \"chain\": [str, ...],            // ordered symbol names source->sink\n"
        " \"need_context\": [str, ...]}     // symbol names/ids you still need\n"
        "Set need_context to [] when the trace is complete."
    )

    def trace(
        self,
        entry_point: dict,
        neighborhood: list[dict],
        requested_context: list[dict] | None = None,
    ) -> dict:
        return self.call(
            {
                "entry_point": entry_point,
                "neighborhood": neighborhood,
                "requested_context": requested_context or [],
            }
        )
