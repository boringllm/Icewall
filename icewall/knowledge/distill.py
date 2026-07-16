"""Distill a {vulnerable, patched} pair into a structured `KnowledgeItem`.

Runs one LLM call whose prompt walks the Vul-RAG chain-of-thought — summarize
the function, explain what the patch changed, extract the cause, extract the
fix, then abstract concrete identifiers into generalized descriptions — and
returns the seven-field record. The system prompt is role-tagged so the offline
mock provider can stand in during tests.
"""
from __future__ import annotations

import json
from typing import Optional

from icewall.knowledge.schema import CvePair, KnowledgeItem, pair_item_id
from icewall.providers.base import LLMMessage, LLMProvider, extract_json
from icewall.schemas import CWE_MAP

_CWE_TO_CLASS = {cwe: vc.value for vc, cwe in CWE_MAP.items()}

SYSTEM = (
    "[ICEWALL-AGENT:distiller]\n"
    "You distill a vulnerability into reusable knowledge. You are given a function\n"
    "in its VULNERABLE and PATCHED forms. Think step by step: (1) summarize what the\n"
    "function does, (2) explain what the patch changed, (3) state the root CAUSE of\n"
    "the vulnerability, (4) state the FIX that neutralizes it. Then ABSTRACT away\n"
    "concrete names (functions, variables, types) into general descriptions so the\n"
    "knowledge transfers to other code.\n"
    "Return ONLY JSON:\n"
    "{\"vuln_class\": str, \"abstract_purpose\": str, \"detailed_behavior\": str,\n"
    " \"triggering_action\": str, \"abstract_cause\": str, \"detailed_cause\": str,\n"
    " \"fixing_solution\": str}\n"
    "vuln_class should be one of Icewall's classes (command_injection, sql_injection,\n"
    "xss, ssrf, path_traversal, insecure_deserialization, rce, ...) or \"\" if unclear."
)


def _clip(code: str, max_chars: int) -> str:
    """Cap a code blob so one huge function can't create a giant, slow prompt."""
    if code and len(code) > max_chars:
        return code[:max_chars] + f"\n/* … truncated {len(code) - max_chars} chars */"
    return code or ""


class Distiller:
    def __init__(self, provider: LLMProvider, model: str, max_tokens: int = 1500, max_code_chars: int = 6000) -> None:
        self.provider = provider
        self.model = model
        self.max_tokens = max_tokens
        self.max_code_chars = max_code_chars

    def distill(self, pair: CvePair) -> Optional[KnowledgeItem]:
        payload = {
            "language": pair.language,
            "cwe": pair.cwe,
            "description": pair.description,
            "vulnerable_code": _clip(pair.vulnerable_code, self.max_code_chars),
            "patched_code": _clip(pair.patched_code, self.max_code_chars),
        }
        resp = self.provider.complete(
            system=SYSTEM,
            messages=[LLMMessage(role="user", content=json.dumps(payload))],
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0.0,
        )
        data = extract_json(resp.text)
        if not data:
            return None
        # The advisory's CWE wins for the class filter; else trust the model.
        vuln_class = _CWE_TO_CLASS.get(pair.cwe or "", "") or data.get("vuln_class", "") or ""
        return KnowledgeItem(
            id=pair_item_id(pair),
            vuln_class=vuln_class,
            cwe=pair.cwe,
            abstract_purpose=data.get("abstract_purpose", ""),
            detailed_behavior=data.get("detailed_behavior", ""),
            triggering_action=data.get("triggering_action", ""),
            abstract_cause=data.get("abstract_cause", ""),
            detailed_cause=data.get("detailed_cause", ""),
            fixing_solution=data.get("fixing_solution", ""),
            source=pair.cve_id or pair.commit_url,
            languages=[pair.language] if pair.language else [],
        )
