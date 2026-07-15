"""Tree-sitter parsing: turn a source file into `Symbol` records with their
enclosed call sites. Build-free and language-agnostic across our specs."""
from __future__ import annotations

from typing import Optional

from tree_sitter_language_pack import get_parser

from icewall.graph.code_graph import Symbol
from icewall.graph.languages import LanguageSpec

# Cache parsers per grammar (tree-sitter parsers are cheap but reusable).
_PARSERS: dict[str, object] = {}


def _parser(name: str):
    if name not in _PARSERS:
        _PARSERS[name] = get_parser(name)
    return _PARSERS[name]


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _simple_name(callee: str) -> str:
    """Reduce a callee expression like `os.path.join(` to its last identifier."""
    callee = callee.split("(")[0].strip()
    # Drop subscripts / generics.
    for sep in ("[", "<", "?."):
        callee = callee.replace(sep, ".")
    parts = [p for p in callee.replace("::", ".").split(".") if p]
    return parts[-1] if parts else callee


def _decl_name(node, src: bytes, spec: LanguageSpec) -> Optional[str]:
    """Best-effort name for a function/class node, including arrow functions
    bound to a variable or object property."""
    named = node.child_by_field_name(spec.name_field)
    if named is not None:
        return _text(named, src)
    # Anonymous function/arrow: infer from binding context.
    parent = node.parent
    if parent is None:
        return None
    if parent.type in ("variable_declarator", "assignment"):
        target = parent.child_by_field_name("name") or parent.child_by_field_name("left")
        if target is not None:
            return _text(target, src)
    if parent.type in ("pair", "public_field_definition", "property_signature", "assignment_expression"):
        key = (
            parent.child_by_field_name("key")
            or parent.child_by_field_name("name")
            or parent.child_by_field_name("left")
        )
        if key is not None:
            return _text(key, src)
    return None


def _callee_text(call_node, src: bytes, spec: LanguageSpec) -> Optional[str]:
    fn = call_node.child_by_field_name("function")
    if fn is None:
        # Python's call also exposes function as first child in some grammars.
        if call_node.child_count:
            fn = call_node.child(0)
    if fn is None:
        return None
    return _text(fn, src)


def parse_source(relpath: str, source: bytes, spec: LanguageSpec) -> list[Symbol]:
    """Parse one file's bytes into a flat list of Symbols with attributed calls."""
    parser = _parser(spec.name)
    tree = parser.parse(source)
    root = tree.root_node
    symbols: list[Symbol] = []
    # Some grammars nest a redundant `function` node inside `function_declaration`
    # at the same byte; keep only the first (outermost) symbol per start byte.
    seen_starts: set[int] = set()

    def walk(node, qual_stack: list[str], enclosing_fn: Optional[Symbol]):
        node_type = node.type
        is_fn = node_type in spec.function_nodes
        is_cls = node_type in spec.class_nodes
        if (is_fn or is_cls) and node.start_byte in seen_starts:
            is_fn = is_cls = False

        current_fn = enclosing_fn
        new_stack = qual_stack

        if is_fn or is_cls:
            seen_starts.add(node.start_byte)
            name = _decl_name(node, source, spec) or f"anonymous@{node.start_point[0] + 1}"
            qualname = ".".join(qual_stack + [name])
            kind = "class" if is_cls else ("method" if qual_stack else "function")
            sym = Symbol(
                id=f"{relpath}::{qualname}#{node.start_point[0] + 1}",
                name=name,
                qualname=qualname,
                kind=kind,
                file=relpath,
                language=spec.name,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                start_byte=node.start_byte,
                end_byte=node.end_byte,
                code=_text(node, source),
            )
            symbols.append(sym)
            new_stack = qual_stack + [name]
            if is_fn:
                current_fn = sym

        if node_type in spec.call_nodes and enclosing_fn is not None:
            callee = _callee_text(node, source, spec)
            if callee:
                enclosing_fn.calls.append(_simple_name(callee))

        for child in node.children:
            walk(child, new_stack, current_fn)

    walk(root, [], None)
    return symbols
