"""Two bounded thread pools, mirroring the RepoAudit split:
  - neural: LLM calls, bounded by API rate/cost
  - symbolic: CPU-bound graph/parse work
Keeping them separate stops a burst of cheap graph work from starving (or being
starved by) expensive model calls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from icewall.config import ConcurrencyConfig


class WorkerPools:
    def __init__(self, neural_workers: int, symbolic_workers: int) -> None:
        self.neural = ThreadPoolExecutor(
            max_workers=neural_workers, thread_name_prefix="icewall-neural"
        )
        self.symbolic = ThreadPoolExecutor(
            max_workers=symbolic_workers, thread_name_prefix="icewall-symbolic"
        )

    @classmethod
    def from_config(cls, cfg: ConcurrencyConfig) -> "WorkerPools":
        return cls(cfg.neural_workers, cfg.symbolic_workers)

    def shutdown(self) -> None:
        self.neural.shutdown(wait=True)
        self.symbolic.shutdown(wait=True)

    def __enter__(self) -> "WorkerPools":
        return self

    def __exit__(self, *exc) -> None:
        self.shutdown()
