"""Per-task LLM exchange capture.

Records the full input/output of each LLM call — the system prompt, the user
payload, the model's answer, any reasoning/thinking, and token counts — and tags
it with the *task* it belongs to so the UI can let you click a task and see the
agent actually working.

Tasks nest on a single worker thread (a summarizer runs inside a tracer task, for
example), so the "current task" is a per-thread stack. Agents read the top of the
stack when they record an exchange; the engine pushes/pops around each work unit.
"""
from __future__ import annotations

import threading
from typing import Callable, Optional

# on_trace(record: dict) -> None
TraceCB = Callable[[dict], None]


def _clip(text: str, limit: int) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated {len(text) - limit} chars]"


class TraceRecorder:
    def __init__(
        self,
        on_trace: Optional[TraceCB] = None,
        *,
        enabled: bool = True,
        max_chars: int = 16000,
    ) -> None:
        self.on_trace = on_trace or (lambda rec: None)
        self.enabled = enabled
        self.max_chars = max_chars
        self._local = threading.local()
        self._seq = 0
        self._seq_lock = threading.Lock()

    # --- task stack (per thread) --------------------------------------------

    def _stack(self) -> list:
        s = getattr(self._local, "stack", None)
        if s is None:
            s = self._local.stack = []
        return s

    def push_task(self, task_id: str, role: str, label: str) -> None:
        self._stack().append((task_id, role, label))

    def pop_task(self) -> None:
        s = self._stack()
        if s:
            s.pop()

    def current(self) -> Optional[tuple]:
        s = self._stack()
        return s[-1] if s else None

    # --- recording -----------------------------------------------------------

    def record(
        self,
        *,
        model: str,
        system: str,
        user: str,
        response: str,
        input_tokens: int,
        output_tokens: int,
        reasoning: str = "",
    ) -> None:
        if not self.enabled:
            return
        cur = self.current()
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        rec = {
            "seq": seq,
            "task_id": cur[0] if cur else None,
            "role": cur[1] if cur else "",
            "model": model,
            "system": _clip(system, self.max_chars),
            "user": _clip(user, self.max_chars),
            "response": _clip(response, self.max_chars),
            "reasoning": _clip(reasoning, self.max_chars),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
        self.on_trace(rec)
