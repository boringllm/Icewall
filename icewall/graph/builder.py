"""Walk a repository, honoring include/exclude globs and size limits, and build
the `CodeGraph`. Build-free: only tree-sitter parsing, no compilation."""
from __future__ import annotations

import os
from pathlib import PurePosixPath
from typing import Callable, Optional

from icewall.config import ScanConfig
from icewall.graph.code_graph import CodeGraph
from icewall.graph.languages import enabled_extensions, spec_for_path
from icewall.graph.parser import parse_source


def _rel(root: str, path: str) -> str:
    return PurePosixPath(os.path.relpath(path, root).replace(os.sep, "/")).as_posix()


def _matches_any(rel: str, patterns: list[str]) -> bool:
    p = PurePosixPath(rel)
    for pat in patterns:
        try:
            if p.full_match(pat):
                return True
        except ValueError:
            # Fallback for odd patterns.
            if p.match(pat):
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

    for abspath, rel in iter_source_files(root, scan):
        spec = spec_for_path(abspath)
        if spec is None:
            continue
        try:
            source = open(abspath, "rb").read()
        except OSError:
            continue
        try:
            symbols = parse_source(rel, source, spec)
        except Exception:
            # A single malformed file must not abort the whole scan.
            continue
        for sym in symbols:
            graph.add_symbol(sym)
        if on_file:
            on_file(rel)

    graph.build_edges()
    return graph
