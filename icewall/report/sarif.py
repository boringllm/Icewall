"""SARIF 2.1.0 output for CI integration (GitHub code scanning, etc.)."""
from __future__ import annotations

import json

from icewall import __version__
from icewall.schemas import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    sarif_results = []

    for f in result.findings:
        rule_id = f.cwe or f.vuln_class.value
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.vuln_class.value,
                "shortDescription": {"text": f.vuln_class.value.replace("_", " ").title()},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
                    if f.cwe and "-" in f.cwe
                    else "https://cwe.mitre.org/"
                ),
            }
        message = f.description or f.title
        if f.remediation and f.remediation.summary:
            message += f"\n\nRemediation: {f.remediation.summary}"
        code_flows = _code_flows(f)
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.file},
                            "region": {
                                "startLine": f.location.start_line,
                                "endLine": f.location.end_line,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": f.confidence,
                    "verdict": f.verdict.value if f.verdict else None,
                    "entryPoint": f.entry_point,
                    "sink": f.sink,
                },
                **({"codeFlows": code_flows} if code_flows else {}),
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Icewall",
                        "version": __version__,
                        "informationUri": "https://github.com/icewall/icewall",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _code_flows(f) -> list:
    if not f.call_chain:
        return []
    locations = []
    for step in f.call_chain:
        loc = {"message": {"text": f"{step.role.value}: {step.symbol}"}}
        if step.location:
            loc["physicalLocation"] = {
                "artifactLocation": {"uri": step.location.file},
                "region": {"startLine": step.location.start_line},
            }
        locations.append({"location": loc})
    return [{"threadFlows": [{"locations": locations}]}]
