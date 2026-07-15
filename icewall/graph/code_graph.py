"""The repository code graph: symbol nodes plus call/reference edges, with the
query API the orchestrator and tracer agents use to scope and expand context."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass
class Symbol:
    id: str
    name: str
    qualname: str
    kind: str  # function | method | class
    file: str
    language: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    code: str
    # Simple names of callees referenced in this symbol's body (unresolved).
    calls: list[str] = field(default_factory=list)

    @property
    def loc(self) -> int:
        return self.end_line - self.start_line + 1

    def snippet(self, max_chars: int = 6000) -> str:
        if len(self.code) <= max_chars:
            return self.code
        return self.code[:max_chars] + f"\n# ... [truncated {len(self.code) - max_chars} chars]"

    def ref(self) -> str:
        return f"{self.file}:{self.start_line}"


class CodeGraph:
    """Holds all symbols and the resolved call edges between them."""

    def __init__(self) -> None:
        self.symbols: dict[str, Symbol] = {}
        self._by_name: dict[str, list[str]] = {}
        self._by_file: dict[str, list[str]] = {}
        self._callees: dict[str, set[str]] = {}
        self._callers: dict[str, set[str]] = {}
        self._files: set[str] = set()

    # --- construction --------------------------------------------------------

    def add_symbol(self, sym: Symbol) -> None:
        self.symbols[sym.id] = sym
        self._by_name.setdefault(sym.name, []).append(sym.id)
        self._by_file.setdefault(sym.file, []).append(sym.id)
        self._files.add(sym.file)

    def build_edges(self) -> None:
        """Resolve each symbol's raw callee names to concrete symbol ids.

        Heuristic name resolution (over-approximate): a callee simple-name links
        to every symbol declared with that name. Good enough to guide context
        expansion; the LLM confirms real reachability.
        """
        self._callees = {sid: set() for sid in self.symbols}
        self._callers = {sid: set() for sid in self.symbols}
        for sid, sym in self.symbols.items():
            for callee_name in set(sym.calls):
                for target in self._by_name.get(callee_name, ()):
                    if target == sid:
                        continue
                    self._callees[sid].add(target)
                    self._callers[target].add(sid)

    # --- queries -------------------------------------------------------------

    def get(self, sid: str) -> Optional[Symbol]:
        return self.symbols.get(sid)

    def find(self, name: str) -> list[Symbol]:
        return [self.symbols[i] for i in self._by_name.get(name, ())]

    def file_symbols(self, file: str) -> list[Symbol]:
        return [self.symbols[i] for i in self._by_file.get(file, ())]

    def callees(self, sid: str) -> list[Symbol]:
        return [self.symbols[i] for i in self._callees.get(sid, ())]

    def callers(self, sid: str) -> list[Symbol]:
        return [self.symbols[i] for i in self._callers.get(sid, ())]

    def neighborhood(self, sid: str, depth: int = 1) -> list[Symbol]:
        """Symbols reachable within `depth` call hops (callees), for context."""
        seen: set[str] = set()
        frontier = {sid}
        for _ in range(depth):
            nxt: set[str] = set()
            for cur in frontier:
                for c in self._callees.get(cur, ()):
                    if c not in seen:
                        nxt.add(c)
            seen |= nxt
            frontier = nxt
            if not frontier:
                break
        seen.discard(sid)
        return [self.symbols[i] for i in seen]

    def functions(self) -> list[Symbol]:
        return [s for s in self.symbols.values() if s.kind in ("function", "method")]

    def all_symbols(self) -> Iterable[Symbol]:
        return self.symbols.values()

    @property
    def files(self) -> set[str]:
        return self._files

    def stats(self) -> dict:
        edge_count = sum(len(v) for v in self._callees.values())
        return {
            "files": len(self._files),
            "symbols": len(self.symbols),
            "functions": len(self.functions()),
            "call_edges": edge_count,
        }
