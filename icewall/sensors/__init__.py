"""Optional external-scanner integration point (design stub for v1.1).

Icewall's v1 engine is pure: LLM + tree-sitter graph, no external binaries.
The `Sensor` interface below is the documented hook where fast SAST tools
(Semgrep first) will plug in to *seed* candidate findings/sinks so the LLM
agents spend tokens validating and tracing rather than reading blind — the
QASecClaw "SAST seeds, LLM validates" pattern.

No sensor is wired into the pipeline yet. This module exists so the contract is
fixed and adding Semgrep later is additive, never a hard dependency.
"""
from icewall.sensors.base import Sensor, SensorCandidate

__all__ = ["Sensor", "SensorCandidate"]
