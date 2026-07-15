"""The repository code graph: symbol nodes plus call/reference edges, with the
query API the orchestrator and tracer agents use to scope and expand context."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


def _norm_join(base_dir: str, rel: str) -> str:
    """Join a relative import path onto the importer's directory, resolving
    '.' and '..' segments. Posix-style throughout (repo paths are normalized)."""
    parts = [p for p in base_dir.split("/") if p] if base_dir else []
    for seg in rel.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


@dataclass
class Import:
    """A single import as written in a file (one `from x import a, b` yields one
    record with names=[a, b]). Resolution against the repo happens in the graph."""

    module: str  # module/source as written: 'utils', '.', '.utils', './utils.js'
    names: list[str] = field(default_factory=list)  # imported member names (empty = whole module)
    module_alias: str | None = None  # local binding for a whole-module/default/namespace import
    is_module: bool = False  # True for `import os` / `import * as x` / default import
    # Filled in by CodeGraph.build_edges():
    target_file: str | None = None  # in-repo file this module resolved to, if any
    targets: list[str] = field(default_factory=list)  # resolved imported symbol ids


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
    # Simple names of base classes (class symbols only; unresolved).
    bases: list[str] = field(default_factory=list)

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
        # inherit edges: subclass -> superclass and the reverse.
        self._bases: dict[str, set[str]] = {}
        self._subclasses: dict[str, set[str]] = {}
        # import edges: importing file -> imported symbol ids, and the reverse.
        self._file_imports: dict[str, list[Import]] = {}
        self._import_targets: dict[str, set[str]] = {}
        self._imported_by: dict[str, set[str]] = {}
        self._files: set[str] = set()

    # --- construction --------------------------------------------------------

    def add_symbol(self, sym: Symbol) -> None:
        self.symbols[sym.id] = sym
        self._by_name.setdefault(sym.name, []).append(sym.id)
        self._by_file.setdefault(sym.file, []).append(sym.id)
        self._files.add(sym.file)

    def add_file_imports(self, file: str, imports: list[Import]) -> None:
        self._file_imports.setdefault(file, []).extend(imports)
        self._files.add(file)

    def build_edges(self) -> None:
        """Resolve raw references into concrete edges: calls, inheritance, imports.

        Heuristic name resolution (over-approximate): a callee/base simple-name
        links to every symbol declared with that name. Good enough to guide
        context expansion; the LLM confirms real reachability. Import edges are
        resolved more precisely, by mapping the module string to a repo file.
        """
        self._callees = {sid: set() for sid in self.symbols}
        self._callers = {sid: set() for sid in self.symbols}
        self._bases = {sid: set() for sid in self.symbols}
        self._subclasses = {sid: set() for sid in self.symbols}
        self._import_targets = {}
        self._imported_by = {}

        # Call edges (name-based, unchanged).
        for sid, sym in self.symbols.items():
            for callee_name in set(sym.calls):
                for target in self._by_name.get(callee_name, ()):
                    if target == sid:
                        continue
                    self._callees[sid].add(target)
                    self._callers[target].add(sid)

        # Inherit edges: a base simple-name links to every class of that name.
        for sid, sym in self.symbols.items():
            if sym.kind != "class":
                continue
            for base_name in set(sym.bases):
                for target in self._by_name.get(base_name, ()):
                    if target == sid or self.symbols[target].kind != "class":
                        continue
                    self._bases[sid].add(target)
                    self._subclasses[target].add(sid)

        # Import edges: resolve each import's module to a repo file, then link the
        # importing file to the top-level definitions it pulls in.
        for file, imports in self._file_imports.items():
            for imp in imports:
                target_file = self._resolve_module(imp.module, file)
                imp.target_file = target_file
                imp.targets = []
                if target_file is None:
                    continue
                wanted = None if (imp.is_module or not imp.names) else set(imp.names)
                for tid in self._by_file.get(target_file, ()):
                    tsym = self.symbols[tid]
                    if "." in tsym.qualname:  # top-level definitions only
                        continue
                    if wanted is not None and tsym.name not in wanted:
                        continue
                    imp.targets.append(tid)
                    self._import_targets.setdefault(file, set()).add(tid)
                    self._imported_by.setdefault(tid, set()).add(file)

    # --- module resolution ---------------------------------------------------

    def _resolve_module(self, module: str, importing_file: str) -> Optional[str]:
        """Map an import's module string to a repo-relative file path, or None
        for external/unresolvable modules (stdlib, third-party, missing)."""
        if not module:
            return None
        base_dir = importing_file.rsplit("/", 1)[0] if "/" in importing_file else ""
        # Relative imports (JS './x', Python '.pkg') resolve against the importer.
        if module.startswith("."):
            if module.startswith("./") or module.startswith("../"):  # JS/TS path
                return self._match_file(_norm_join(base_dir, module), js=True)
            # Python relative: leading dots = how far up; remainder is a dotted path.
            dots = len(module) - len(module.lstrip("."))
            rest = module[dots:]
            parts = base_dir.split("/") if base_dir else []
            up = dots - 1
            if up > 0:
                parts = parts[: len(parts) - up] if up <= len(parts) else []
            target = "/".join([p for p in parts + rest.split(".") if p])
            return self._match_file(target, js=False)
        # Absolute: Python dotted module, or a bare JS specifier (external).
        return self._match_file(module.replace(".", "/"), js=False)

    def _match_file(self, base: str, js: bool) -> Optional[str]:
        if not base:
            return None
        if base in self._files:  # already has an extension that matched
            return base
        exts = (
            (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs") if js else (".py", ".pyi")
        )
        for ext in exts:
            if base + ext in self._files:
                return base + ext
        for ext in exts:  # package/index modules
            idx = f"{base}/__init__.py" if not js else f"{base}/index{ext}"
            if idx in self._files:
                return idx
        # Last resort: unique basename match (over-approximate, like call edges).
        last = base.rsplit("/", 1)[-1]
        hits = [
            f for f in self._files
            if f == last + exts[0] or f.endswith("/" + last + exts[0])
        ]
        return hits[0] if len(hits) == 1 else None

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

    def bases(self, sid: str) -> list[Symbol]:
        """Direct superclasses of a class symbol (inherit edges)."""
        return [self.symbols[i] for i in self._bases.get(sid, ())]

    def subclasses(self, sid: str) -> list[Symbol]:
        """Direct subclasses of a class symbol (reverse inherit edges)."""
        return [self.symbols[i] for i in self._subclasses.get(sid, ())]

    def imports(self, file: str) -> list[Import]:
        """The (resolved) imports declared in a file."""
        return list(self._file_imports.get(file, ()))

    def imported_symbols(self, file: str) -> list[Symbol]:
        """Definitions a file pulls in via imports, resolved to symbols."""
        return [self.symbols[i] for i in self._import_targets.get(file, ())]

    def importing_files(self, sid: str) -> list[str]:
        """Files that import a given symbol (reverse import edges)."""
        return sorted(self._imported_by.get(sid, ()))

    def neighborhood(self, sid: str, depth: int = 1, follow_bases: bool = True) -> list[Symbol]:
        """Symbols reachable within `depth` hops, for context expansion.

        Follows call edges, and (by default) inherit edges — so inspecting a
        subclass or an overriding method also surfaces the base it extends,
        where inherited taint would otherwise be invisible."""
        seen: set[str] = set()
        frontier = {sid}
        for _ in range(depth):
            nxt: set[str] = set()
            for cur in frontier:
                for c in self._callees.get(cur, ()):
                    if c not in seen:
                        nxt.add(c)
                if follow_bases:
                    for b in self._bases.get(cur, ()):
                        if b not in seen:
                            nxt.add(b)
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
        return {
            "files": len(self._files),
            "symbols": len(self.symbols),
            "functions": len(self.functions()),
            "call_edges": sum(len(v) for v in self._callees.values()),
            "inherit_edges": sum(len(v) for v in self._bases.values()),
            "import_edges": sum(len(v) for v in self._import_targets.values()),
        }
