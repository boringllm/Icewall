"""Context broker — the graph-backed answering service for the dynamic
parent<->child protocol. When a tracer subagent asks for more context
("give me `deserialize` and its callers"), the orchestrator resolves the
request here, from the code graph, instead of dumping whole files."""
from __future__ import annotations

from icewall.graph import CodeGraph, Symbol


class ContextBroker:
    def __init__(self, graph: CodeGraph, snippet_chars: int = 4000) -> None:
        self.graph = graph
        self.snippet_chars = snippet_chars

    def _pack(self, sym: Symbol) -> dict:
        return {
            "symbol_id": sym.id,
            "name": sym.name,
            "qualname": sym.qualname,
            "file": sym.file,
            "line": sym.start_line,
            "code": sym.snippet(self.snippet_chars),
        }

    def resolve(self, refs: list[str]) -> list[dict]:
        """Resolve a list of symbol ids or bare names to packed context blocks."""
        out: list[dict] = []
        seen: set[str] = set()
        for ref in refs:
            matches: list[Symbol] = []
            direct = self.graph.get(ref)
            if direct is not None:
                matches = [direct]
            else:
                matches = self.graph.find(ref)
            for sym in matches:
                if sym.id in seen:
                    continue
                seen.add(sym.id)
                out.append(self._pack(sym))
        return out

    def neighborhood(self, sid: str, depth: int = 1) -> list[dict]:
        return [self._pack(s) for s in self.graph.neighborhood(sid, depth)]

    def pack(self, sym: Symbol) -> dict:
        return self._pack(sym)
