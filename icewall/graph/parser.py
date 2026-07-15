"""Tree-sitter parsing: turn a source file into `Symbol` records with their
enclosed call sites, base classes, and the file's imports. Build-free and
language-agnostic across our specs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tree_sitter_language_pack import get_parser

from icewall.graph.code_graph import Import, Symbol
from icewall.graph.languages import LanguageSpec


@dataclass
class FileParse:
    """Everything one file contributes to the graph."""

    symbols: list[Symbol]
    imports: list[Import]


# Nodes whose text names a type/module reference (used for base-class extraction).
_NAME_NODES = frozenset(
    {
        "identifier",
        "type_identifier",
        "attribute",
        "member_expression",
        "dotted_name",
        "nested_type_identifier",
        "scoped_identifier",
        "generic_type",
    }
)
# Subtrees to ignore while collecting base classes (generics, `implements`).
_HERITAGE_SKIP = frozenset(
    {"type_arguments", "type_parameters", "implements_clause", "keyword_argument"}
)

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


def _base_names(class_node, src: bytes, spec: LanguageSpec) -> list[str]:
    """Simple names of a class's base classes (`class Foo(Bar)` -> ['Bar']).

    Python hangs them off the `superclasses` field; JS/TS off a `class_heritage`
    child (with the extends target possibly wrapped in an `extends_clause`)."""
    container = None
    if spec.superclass_field:
        container = class_node.child_by_field_name(spec.superclass_field)
    if container is None and spec.heritage_nodes:
        for c in class_node.children:
            if c.type in spec.heritage_nodes:
                container = c
                break
    if container is None:
        return []

    names: list[str] = []

    def collect(n) -> None:
        if n.type in _HERITAGE_SKIP:
            return
        if n.type in _NAME_NODES:
            names.append(_simple_name(_text(n, src)))
            return  # a name is a leaf for our purposes; don't descend into it
        for ch in n.children:
            collect(ch)

    for ch in container.children:
        collect(ch)

    seen: set[str] = set()
    out: list[str] = []
    for x in names:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _module_string(node, src: bytes) -> str:
    """Text of an import's module/source, unquoting JS/TS string literals."""
    if node.type == "string":
        for ch in node.children:
            if ch.type == "string_fragment":
                return _text(ch, src)
        return _text(node, src).strip("'\"`")
    return _text(node, src)


def _extract_imports(node, src: bytes, spec: LanguageSpec) -> list[Import]:
    """Parse one import statement node into Import record(s)."""
    t = node.type
    out: list[Import] = []

    # --- Python -------------------------------------------------------------
    if t == "import_statement" and spec.name == "python":
        for ch in node.children:
            if ch.type == "dotted_name":
                out.append(Import(module=_text(ch, src), is_module=True))
            elif ch.type == "aliased_import":
                mod = ch.child_by_field_name("name") or ch.child(0)
                alias = ch.child_by_field_name("alias")
                out.append(
                    Import(
                        module=_text(mod, src) if mod else "",
                        module_alias=_text(alias, src) if alias else None,
                        is_module=True,
                    )
                )
        return out

    if t == "import_from_statement":
        module = ""
        names: list[str] = []
        wildcard = False
        after_import = False
        for ch in node.children:
            if ch.type == "import":
                after_import = True
                continue
            if ch.type in ("from", ",", "(", ")"):
                continue
            if not after_import:
                if ch.type in ("dotted_name", "relative_import"):
                    module = _text(ch, src)
            else:
                if ch.type == "wildcard_import" or _text(ch, src) == "*":
                    wildcard = True
                elif ch.type == "dotted_name":
                    names.append(_simple_name(_text(ch, src)))
                elif ch.type == "aliased_import":
                    orig = ch.child_by_field_name("name") or ch.child(0)
                    if orig is not None:
                        names.append(_simple_name(_text(orig, src)))
        out.append(Import(module=module, names=names, is_module=wildcard))
        return out

    # --- JS / TS ------------------------------------------------------------
    if t in ("import_statement", "import_declaration"):
        module = ""
        names: list[str] = []
        module_alias: Optional[str] = None
        for ch in node.children:
            if ch.type == "string":
                module = _module_string(ch, src)
            elif ch.type == "import_clause":
                for cc in ch.children:
                    if cc.type == "identifier":  # default import
                        module_alias = _text(cc, src)
                    elif cc.type == "namespace_import":  # * as x
                        ident = cc.child_by_field_name("alias")
                        for gc in cc.children:
                            if gc.type == "identifier":
                                ident = gc
                        module_alias = _text(ident, src) if ident else None
                    elif cc.type == "named_imports":
                        for spec_node in cc.children:
                            if spec_node.type == "import_specifier":
                                ident = spec_node.child_by_field_name("name") or spec_node.child(0)
                                if ident is not None:
                                    names.append(_simple_name(_text(ident, src)))
        out.append(
            Import(
                module=module,
                names=names,
                module_alias=module_alias,
                is_module=not names,
            )
        )
        return out

    return out


def parse_source(relpath: str, source: bytes, spec: LanguageSpec) -> FileParse:
    """Parse one file's bytes into Symbols (with calls + base classes) and imports."""
    parser = _parser(spec.name)
    tree = parser.parse(source)
    root = tree.root_node
    symbols: list[Symbol] = []
    imports: list[Import] = []
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
            if is_cls:
                sym.bases = _base_names(node, source, spec)
            symbols.append(sym)
            new_stack = qual_stack + [name]
            if is_fn:
                current_fn = sym

        if node_type in spec.call_nodes and enclosing_fn is not None:
            callee = _callee_text(node, source, spec)
            if callee:
                enclosing_fn.calls.append(_simple_name(callee))

        if node_type in spec.import_nodes:
            imports.extend(_extract_imports(node, source, spec))

        for child in node.children:
            walk(child, new_stack, current_fn)

    walk(root, [], None)
    return FileParse(symbols=symbols, imports=imports)
