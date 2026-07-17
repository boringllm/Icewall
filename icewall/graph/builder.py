"""Walk a repository, honoring include/exclude globs and size limits, and build
the `CodeGraph`. Build-free: only tree-sitter parsing, no compilation."""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Callable, Optional

from icewall.config import ScanConfig
from icewall.graph.code_graph import CodeGraph
from icewall.graph.languages import enabled_extensions, spec_for_path
from icewall.graph.parser import parse_source


def _rel(root: str, path: str) -> str:
    return PurePosixPath(os.path.relpath(path, root).replace(os.sep, "/")).as_posix()


def _seg_regex(seg: str) -> str:
    """Translate a single path segment glob (no `/`) to a regex fragment."""
    out = []
    i, n = 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and seg[j] in ("!", "^"):
                j += 1
            if j < n and seg[j] == "]":
                j += 1
            while j < n and seg[j] != "]":
                j += 1
            if j >= n:
                out.append(r"\[")  # unterminated class -> literal '['
            else:
                inner = seg[i + 1:j].replace("\\", "\\\\")
                if inner.startswith(("!", "^")):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
                i = j + 1
                continue
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@lru_cache(maxsize=1024)
def _glob_regex(pat: str) -> "re.Pattern[str]":
    """Compile a glob to an anchored regex with `**` cross-segment semantics.

    Reproduces `PurePosixPath.full_match` (Python 3.13+) on every supported
    Python: `*`/`?`/`[...]` stay within a segment, `**` spans zero or more
    segments. Used instead of `full_match` so file filtering behaves identically
    on 3.11+ (where `full_match` does not exist and would raise AttributeError).
    """
    parts = pat.split("/")
    out = []
    last = len(parts) - 1
    for i, part in enumerate(parts):
        if part == "**":
            # `**` (with its following slash) = zero or more whole segments.
            out.append(".*" if i == last else "(?:.*/)?")
        else:
            out.append(_seg_regex(part))
            if i != last:
                out.append("/")
    return re.compile("(?s:" + "".join(out) + r")\Z")


def _matches_any(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if _glob_regex(pat).match(rel) is not None:
            return True
    return False


def iter_source_files(root: str, scan: ScanConfig):
    """Yield (abspath, relpath) for every file that passes the filters."""
    exts = enabled_extensions(scan.languages)
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune obviously-excluded directories early for speed.
        pruned = []
        for d in dirnames:
            rel_dir = _rel(root, os.path.join(dirpath, d))
            if _matches_any(rel_dir + "/x", scan.exclude_globs) or _matches_any(rel_dir, scan.exclude_globs):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in exts:
                continue
            abspath = os.path.join(dirpath, fn)
            rel = _rel(root, abspath)
            if _matches_any(rel, scan.exclude_globs):
                continue
            if scan.include_globs and not _matches_any(rel, scan.include_globs):
                continue
            try:
                if os.path.getsize(abspath) > scan.max_file_bytes:
                    continue
            except OSError:
                continue
            yield abspath, rel


def build_graph(
    root: str,
    scan: Optional[ScanConfig] = None,
    on_file: Optional[Callable[[str], None]] = None,
) -> CodeGraph:
    scan = scan or ScanConfig()
    graph = CodeGraph()
    root = os.path.abspath(root)

    attempted = 0
    first_error: Optional[BaseException] = None
    for abspath, rel in iter_source_files(root, scan):
        spec = spec_for_path(abspath)
        if spec is None:
            continue
        try:
            source = open(abspath, "rb").read()
        except OSError:
            continue
        attempted += 1
        try:
            parsed = parse_source(rel, source, spec)
        except Exception as exc:
            # A single malformed file must not abort the whole scan, but remember
            # the failure so a *systemic* one (e.g. tree-sitter grammars that
            # won't load) surfaces instead of silently yielding a 0-file graph.
            if first_error is None:
                first_error = exc
            continue
        for sym in parsed.symbols:
            graph.add_symbol(sym)
        if parsed.imports:
            graph.add_file_imports(rel, parsed.imports)
        if on_file:
            on_file(rel)

    # tree-sitter is error-tolerant (it produces ERROR nodes rather than raising)
    # so an exception on *every* parsed file means the parser itself is broken —
    # a misinstalled/incompatible tree-sitter-language-pack, not bad source. Make
    # that loud rather than reporting an empty graph as success.
    if attempted and first_error is not None and len(graph.files) == 0:
        raise RuntimeError(
            f"Parsing failed for all {attempted} source file(s); the tree-sitter "
            f"grammars could not be used. This usually means "
            f"'tree-sitter-language-pack' is missing or incompatible with this "
            f"Python build. First error: {first_error!r}"
        ) from first_error

    graph.build_edges()
    return graph
