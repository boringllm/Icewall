"""Per-language tree-sitter configuration: which grammar to use for a file, and
which node types represent functions, classes, calls, and imports."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LanguageSpec:
    name: str  # tree-sitter-language-pack grammar name
    extensions: tuple[str, ...]
    function_nodes: frozenset[str]
    class_nodes: frozenset[str]
    call_nodes: frozenset[str]
    import_nodes: frozenset[str]
    # Field name holding the declared name on function/class nodes (best-effort).
    name_field: str = "name"


PYTHON = LanguageSpec(
    name="python",
    extensions=(".py", ".pyi"),
    function_nodes=frozenset({"function_definition"}),
    class_nodes=frozenset({"class_definition"}),
    call_nodes=frozenset({"call"}),
    import_nodes=frozenset({"import_statement", "import_from_statement"}),
)

_JS_FUNC = frozenset(
    {
        "function_declaration",
        "function",
        "method_definition",
        "arrow_function",
        "function_expression",
        "generator_function_declaration",
    }
)
_JS_CLASS = frozenset({"class_declaration", "class"})
_JS_CALL = frozenset({"call_expression"})
_JS_IMPORT = frozenset({"import_statement", "import_declaration"})

JAVASCRIPT = LanguageSpec(
    name="javascript",
    extensions=(".js", ".jsx", ".mjs", ".cjs"),
    function_nodes=_JS_FUNC,
    class_nodes=_JS_CLASS,
    call_nodes=_JS_CALL,
    import_nodes=_JS_IMPORT,
)

TYPESCRIPT = LanguageSpec(
    name="typescript",
    extensions=(".ts", ".mts", ".cts"),
    function_nodes=_JS_FUNC,
    class_nodes=_JS_CLASS,
    call_nodes=_JS_CALL,
    import_nodes=_JS_IMPORT,
)

TSX = LanguageSpec(
    name="tsx",
    extensions=(".tsx",),
    function_nodes=_JS_FUNC,
    class_nodes=_JS_CLASS,
    call_nodes=_JS_CALL,
    import_nodes=_JS_IMPORT,
)

_ALL = (PYTHON, JAVASCRIPT, TYPESCRIPT, TSX)

# Map file extension -> LanguageSpec.
_EXT_MAP: dict[str, LanguageSpec] = {}
for spec in _ALL:
    for ext in spec.extensions:
        _EXT_MAP[ext] = spec

# Map logical language name (as used in config.scan.languages) -> specs.
_LOGICAL: dict[str, tuple[LanguageSpec, ...]] = {
    "python": (PYTHON,),
    "javascript": (JAVASCRIPT,),
    "typescript": (TYPESCRIPT, TSX),
}


def spec_for_path(path: str) -> LanguageSpec | None:
    from os.path import splitext

    _, ext = splitext(path)
    return _EXT_MAP.get(ext.lower())


def enabled_extensions(languages: list[str]) -> set[str]:
    exts: set[str] = set()
    for lang in languages:
        for spec in _LOGICAL.get(lang, ()):
            exts.update(spec.extensions)
    return exts
