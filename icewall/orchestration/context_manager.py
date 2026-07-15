"""Dynamic context management.

Agents accumulate context as they work — the tracer keeps pulling function bodies
across `need_context` hops, and the analyzer assembles a whole source->sink path.
Left unchecked this overflows the model's window and inflates cost. The
`ContextManager` measures the assembled context and, when it exceeds the budget,
compresses the *non-anchor* blocks while keeping the anchors (entry point + sink)
verbatim.

Compression uses a `SummarizerAgent` when one is configured; otherwise it falls
back to a deterministic header-only digest (function signatures + a note), so the
feature works offline and never blocks a scan on a missing model. Every summary is
recorded to session memory, so the compressed detail is auditable, not lost.
"""
from __future__ import annotations

from typing import Callable, Optional

# summarizer(blocks, topic) -> compact summary text
Summarizer = Callable[[list[dict], str], str]


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token), matching the mock provider's."""
    return max(1, len(text) // 4)


def _block_tokens(block: dict) -> int:
    return estimate_tokens(block.get("code", "")) + estimate_tokens(
        block.get("name", "")
    )


def _blocks_tokens(blocks: list[dict]) -> int:
    return sum(_block_tokens(b) for b in blocks)


def _first_lines(code: str, n: int = 2) -> str:
    lines = [ln for ln in code.splitlines() if ln.strip()]
    return "\n".join(lines[:n])


class ContextManager:
    def __init__(
        self,
        *,
        enabled: bool = True,
        max_tokens: int = 6000,
        target_tokens: int = 2000,
        summarizer: Optional[Summarizer] = None,
        memory=None,
        emit_agent: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.enabled = enabled
        self.max_tokens = max_tokens
        self.target_tokens = target_tokens
        self.summarizer = summarizer
        self.memory = memory
        # emit_agent(phase, label) surfaces summarizer activity to the live UI.
        self.emit_agent = emit_agent

    def fit(
        self,
        anchors: list[dict],
        blocks: list[dict],
        *,
        topic: str = "",
    ) -> list[dict]:
        """Return anchors + (possibly compressed) blocks within the token budget.

        Anchors are always kept verbatim. If the total exceeds `max_tokens`, the
        blocks are summarized into a single digest block targeting `target_tokens`.
        """
        combined = list(anchors) + list(blocks)
        if not self.enabled or not blocks:
            return combined
        total = _blocks_tokens(combined)
        if total <= self.max_tokens:
            return combined

        # Keep as many whole blocks as fit under the target, summarize the rest.
        budget = max(0, self.target_tokens)
        kept: list[dict] = []
        overflow: list[dict] = []
        used = 0
        for b in blocks:
            bt = _block_tokens(b)
            if used + bt <= budget:
                kept.append(b)
                used += bt
            else:
                overflow.append(b)
        if not overflow:  # target smaller than a single block; force at least one
            overflow = blocks
            kept = []

        digest = self._summarize(overflow, topic)
        result = list(anchors) + kept
        if digest is not None:
            result.append(digest)
        return result

    def _summarize(self, blocks: list[dict], topic: str) -> Optional[dict]:
        names = [b.get("name") or b.get("symbol_id") or "?" for b in blocks]
        before = _blocks_tokens(blocks)
        label = f"Compressing {len(blocks)} blocks (~{before} tok)"
        if self.emit_agent:
            self.emit_agent("start", label)
        if self.summarizer is not None:
            try:
                text = self.summarizer(blocks, topic)
            except Exception:
                text = self._heuristic_digest(blocks)
        else:
            text = self._heuristic_digest(blocks)
        if self.emit_agent:
            self.emit_agent("end", label, outcome=f"compressed to ~{estimate_tokens(text)} tok")

        digest = {
            "symbol_id": "context-summary",
            "name": f"[summary of {len(blocks)} symbols]",
            "file": "",
            "line": 0,
            "code": text,
            "summarized": True,
        }
        if self.memory is not None:
            self.memory.note(
                title=f"Context summary: {topic or ', '.join(names[:3])}",
                body=(
                    f"Compressed {len(blocks)} context blocks "
                    f"(~{before} tokens) covering: {', '.join(names)}.\n\n{text}"
                ),
                role="summarizer",
                tags=["context-summary"],
            )
        return digest

    @staticmethod
    def _heuristic_digest(blocks: list[dict]) -> str:
        """Deterministic fallback: signatures + a note, no model call."""
        parts = ["# Condensed context (headers only; bodies elided):"]
        for b in blocks:
            head = _first_lines(b.get("code", ""))
            loc = f"{b.get('file','')}:{b.get('line','')}".strip(":")
            parts.append(f"# {b.get('name','?')} ({loc})\n{head}")
        return "\n\n".join(parts)
