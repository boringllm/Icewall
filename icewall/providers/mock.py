"""Offline heuristic provider — a stand-in "LLM" with no network calls.

It reads the `[ICEWALL-AGENT:<role>]` tag that every agent stamps as the first
line of its system prompt, then produces role-appropriate JSON by running the
shared taint patterns over whatever code the agent passed in. This makes the
entire multi-agent pipeline runnable and deterministically testable without API
keys, and doubles as a `--dry-run` engine.

It is a genuine (crude) analyzer: it flows the real repo code through the real
orchestration/graph/report machinery, with only the "reasoning" stubbed.
"""
from __future__ import annotations

import json
import re

from icewall.detectors.patterns import find_sinks, has_sanitizer, has_source
from icewall.providers.base import LLMMessage, LLMProvider, LLMResponse
from icewall.schemas import CWE_MAP, VulnClass

_ROLE_RE = re.compile(r"\[ICEWALL-AGENT:(?P<role>[a-z_]+)\]")


def _tokens(text: str) -> int:
    # Rough token estimate for budget accounting in offline mode.
    return max(1, len(text) // 4)


class MockProvider(LLMProvider):
    name = "mock"

    def complete(
        self,
        *,
        system: str,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking_tokens: int = 0,
        params: dict | None = None,
    ) -> LLMResponse:
        role_match = _ROLE_RE.search(system or "")
        role = role_match.group("role") if role_match else "unknown"
        user = messages[-1].content if messages else "{}"
        try:
            payload = json.loads(user)
        except json.JSONDecodeError:
            payload = {"code": user}

        handler = getattr(self, f"_role_{role}", self._role_unknown)
        result = handler(payload)
        text = json.dumps(result)
        return LLMResponse(
            text=text,
            input_tokens=_tokens(system) + _tokens(user),
            output_tokens=_tokens(text),
            model=model,
        )

    # --- per-role heuristics -------------------------------------------------

    def _role_triage(self, payload: dict) -> dict:
        entry_points = []
        for cand in payload.get("candidates", []):
            code = cand.get("code", "")
            sinks = find_sinks(code)
            src = has_source(code)
            if not sinks and not src:
                continue
            suspicion = 0.4
            if src:
                suspicion += 0.3
            if sinks:
                suspicion += 0.3
            surface = "http" if src else "internal"
            entry_points.append(
                {
                    "symbol_id": cand.get("symbol_id"),
                    "reason": "handles external input" if src else "reaches a dangerous sink",
                    "surface": surface,
                    "suspicion": round(min(suspicion, 0.99), 2),
                }
            )
        return {"entry_points": entry_points}

    def _role_tracer(self, payload: dict) -> dict:
        blocks = [payload.get("entry_point", {})] + payload.get("neighborhood", [])
        combined = "\n".join(b.get("code", "") for b in blocks)
        sinks = find_sinks(combined)
        if not sinks:
            return {"reached_sink": False, "need_context": [], "chain": []}
        vc, matched = sinks[0]
        # Identify which block holds the sink.
        sink_block = next(
            (b for b in blocks if matched in b.get("code", "")), blocks[0]
        )
        chain = [b.get("name") for b in blocks if b.get("name")]
        return {
            "reached_sink": True,
            "sink": {
                "symbol_id": sink_block.get("symbol_id"),
                "kind": matched,
                "vuln_class": vc.value,
            },
            "chain": chain or ["entry"],
            "need_context": [],
        }

    def _role_analyzer(self, payload: dict) -> dict:
        code = payload.get("code", "")
        vc_name = payload.get("vuln_class")
        try:
            vc = VulnClass(vc_name)
        except (ValueError, TypeError):
            # Analyze for whatever class shows the strongest sink.
            sinks = find_sinks(code)
            if not sinks:
                return {"is_vulnerable": False, "confidence": 2}
            vc = sinks[0][0]
        sinks = find_sinks(code, [vc])
        if not sinks:
            return {"is_vulnerable": False, "confidence": 2, "vuln_class": vc.value}
        source = has_source(code)
        sanitized = has_sanitizer(code, vc)
        confidence = 8 if source else 6
        if sanitized:
            confidence -= 4
        is_vuln = confidence >= 6
        _, matched = sinks[0]
        return {
            "is_vulnerable": is_vuln,
            "vuln_class": vc.value,
            "confidence": confidence,
            "cwe": CWE_MAP.get(vc),
            "title": f"Potential {vc.value} via {matched}",
            "description": (
                f"Untrusted input appears to reach `{matched}` "
                f"({'no' if not sanitized else 'weak'} sanitization detected)."
            ),
            "source": "external request input" if source else "unknown",
            "sink": matched,
        }

    def _role_validator(self, payload: dict) -> dict:
        finding = payload.get("finding", {})
        code = payload.get("code", "")
        vc_name = finding.get("vuln_class")
        try:
            vc = VulnClass(vc_name)
        except (ValueError, TypeError):
            return {"verdict": "uncertain", "feasible": True, "guards_present": False,
                    "adjusted_confidence": finding.get("confidence", 5), "notes": "unknown class"}
        sanitized = has_sanitizer(code, vc)
        still_present = bool(find_sinks(code, [vc]))
        base_conf = int(finding.get("confidence", 5))
        if not still_present:
            return {"verdict": "rejected", "feasible": False, "guards_present": False,
                    "adjusted_confidence": 2, "notes": "sink not present in confirmed code"}
        if sanitized:
            return {"verdict": "uncertain", "feasible": True, "guards_present": True,
                    "adjusted_confidence": max(3, base_conf - 3),
                    "notes": "sanitizer/guard detected near sink; reachability unclear"}
        return {"verdict": "confirmed", "feasible": True, "guards_present": False,
                "adjusted_confidence": min(9, base_conf + 1),
                "notes": "unsanitized source-to-sink path is feasible"}

    def _role_remediator(self, payload: dict) -> dict:
        finding = payload.get("finding", {})
        vc = finding.get("vuln_class", "vulnerability")
        sink = finding.get("sink", "the dangerous call")
        file = finding.get("file", "affected_file")
        line = finding.get("line", 1)
        diff = (
            f"--- a/{file}\n+++ b/{file}\n"
            f"@@ -{line},1 +{line},3 @@\n"
            f"-    # {sink}  # untrusted input reaches here\n"
            f"+    # Validate/escape untrusted input before this call.\n"
            f"+    # e.g. use parameterized APIs, allow-lists, or shlex.quote as appropriate.\n"
            f"+    # {sink}\n"
        )
        return {
            "summary": f"Neutralize untrusted input before {sink} to fix the {vc}.",
            "diff": diff,
            "rationale": (
                "Introduce input validation / safe-API usage so attacker-controlled "
                "data can no longer influence the sink."
            ),
            "confidence": 6,
        }

    def _role_summarizer(self, payload: dict) -> dict:
        blocks = payload.get("blocks", [])
        lines = []
        for b in blocks:
            code = b.get("code", "")
            facts = []
            if has_source(code):
                facts.append("takes external input")
            sinks = find_sinks(code)
            if sinks:
                facts.append("reaches sink(s): " + ", ".join(m for _, m in sinks[:3]))
            note = "; ".join(facts) if facts else "no taint signal"
            lines.append(f"- {b.get('name','?')} ({b.get('file','')}): {note}")
        summary = "Taint-relevant digest:\n" + "\n".join(lines)
        return {"summary": summary}

    def _role_unknown(self, payload: dict) -> dict:
        return {"note": "mock provider: no handler for this role", "echo_keys": list(payload.keys())}
