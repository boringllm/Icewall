"""Serialize a CodeGraph into a compact node/edge view for visualization.

Large graphs are capped to the most-connected symbols so the browser renders
smoothly; edges are kept only between included nodes. Used both live (streamed
during a scan) and for a session's saved graph.json.
"""
from __future__ import annotations

from icewall.detectors.patterns import find_sinks, has_source
from icewall.graph import CodeGraph


def graph_view(graph: CodeGraph, cap: int = 300) -> dict:
    syms = list(graph.all_symbols())
    # Degree = callees + callers; keep the most connected within the cap.
    degree: dict[str, int] = {}
    for s in syms:
        degree[s.id] = len(graph.callees(s.id)) + len(graph.callers(s.id))

    def rank(s):
        # Prefer taint-relevant symbols, then highly connected ones.
        taint = 1 if (has_source(s.code) or find_sinks(s.code)) else 0
        return (taint, degree.get(s.id, 0))

    kept = sorted(syms, key=rank, reverse=True)[:cap]
    kept_ids = {s.id for s in kept}

    files = sorted({s.file for s in kept})
    file_index = {f: i for i, f in enumerate(files)}

    nodes = []
    for s in kept:
        src = has_source(s.code)
        sinks = find_sinks(s.code)
        nodes.append(
            {
                "id": s.id,
                "label": s.name,
                "qualname": s.qualname,
                "file": s.file,
                "file_group": file_index[s.file],
                "kind": s.kind,
                "lines": s.loc,
                "start_line": s.start_line,
                "degree": degree.get(s.id, 0),
                "has_source": bool(src),
                "has_sink": bool(sinks),
                "sink_kinds": sorted({m for _, m in sinks})[:4],
                "bases": [b.name for b in graph.bases(s.id)],
            }
        )

    edges = []
    seen = set()
    for s in kept:
        for c in graph.callees(s.id):
            if c.id in kept_ids:
                key = (s.id, c.id, "call")
                if key not in seen:
                    seen.add(key)
                    edges.append({"source": s.id, "target": c.id, "kind": "call"})
        # Inherit edges (subclass -> superclass) are symbol-to-symbol too.
        for b in graph.bases(s.id):
            if b.id in kept_ids:
                key = (s.id, b.id, "inherit")
                if key not in seen:
                    seen.add(key)
                    edges.append({"source": s.id, "target": b.id, "kind": "inherit"})

    st = graph.stats()
    return {
        "nodes": nodes,
        "edges": edges,
        "files": files,
        "total_symbols": len(syms),
        "shown": len(nodes),
        "capped": len(syms) > cap,
        "inherit_edges": st["inherit_edges"],
        "import_edges": st["import_edges"],
    }
