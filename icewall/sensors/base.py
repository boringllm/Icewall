"""Sensor interface — the future seam for external scanners (Semgrep, Bandit,
ESLint-security, osv-scanner). Unimplemented in v1 by design.

A Sensor scans a repo path and returns cheap candidate signals that the
orchestrator can fold into entry-point selection (boosting suspicion for
symbols a scanner already flagged). Sensors are always optional: if the
underlying binary is absent, `available()` returns False and the engine
proceeds on LLM-driven triage alone.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SensorCandidate:
    """A finding/sink hint from an external tool, mapped to a file location."""

    file: str
    line: int
    vuln_class: Optional[str] = None  # maps to schemas.VulnClass where possible
    rule_id: str = ""
    message: str = ""
    tool: str = ""
    extra: dict = field(default_factory=dict)


class Sensor(ABC):
    """Base class for optional external-scanner integrations."""

    name: str = "sensor"

    @abstractmethod
    def available(self) -> bool:
        """True iff the underlying tool/binary is installed and runnable."""
        raise NotImplementedError

    @abstractmethod
    def scan(self, root: str) -> list[SensorCandidate]:
        """Run the tool over `root` and return normalized candidates.

        Implementations MUST degrade gracefully (return [] on any failure) so a
        sensor never blocks or aborts an Icewall run.
        """
        raise NotImplementedError


class SemgrepSensor(Sensor):
    """Planned v1.1 sensor. Intentionally not implemented yet.

    Design: shell out to `semgrep --json --config auto <root>`, then map each
    result's `check_id`/path/line into SensorCandidate, translating common
    Semgrep rule categories into Icewall VulnClass values. The orchestrator will
    boost triage suspicion for symbols overlapping these candidates.
    """

    name = "semgrep"

    def available(self) -> bool:  # pragma: no cover - stub
        return False

    def scan(self, root: str) -> list[SensorCandidate]:  # pragma: no cover - stub
        raise NotImplementedError(
            "SemgrepSensor is a v1.1 stub. v1 runs pure LLM + tree-sitter; "
            "no external scanner is wired in yet."
        )
