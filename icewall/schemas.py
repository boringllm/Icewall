"""Core data model shared across all Icewall agents and outputs.

These are the stable contracts. Agents exchange the JSON forms of these
structures; providers, the graph engine, and the report writers all speak
this vocabulary.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnClass(str, Enum):
    """Vulnerability classes Icewall reasons about. Mapped to CWE ids in CWE_MAP."""

    COMMAND_INJECTION = "command_injection"
    RCE = "rce"
    SQLI = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "local_file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "insecure_deserialization"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_CRYPTO = "weak_crypto"


CWE_MAP: dict[VulnClass, str] = {
    VulnClass.COMMAND_INJECTION: "CWE-78",
    VulnClass.RCE: "CWE-94",
    VulnClass.SQLI: "CWE-89",
    VulnClass.XSS: "CWE-79",
    VulnClass.SSRF: "CWE-918",
    VulnClass.LFI: "CWE-98",
    VulnClass.PATH_TRAVERSAL: "CWE-22",
    VulnClass.DESERIALIZATION: "CWE-502",
    VulnClass.IDOR: "CWE-639",
    VulnClass.OPEN_REDIRECT: "CWE-601",
    VulnClass.XXE: "CWE-611",
    VulnClass.HARDCODED_SECRET: "CWE-798",
    VulnClass.WEAK_CRYPTO: "CWE-327",
}


class CodeLocation(BaseModel):
    file: str
    start_line: int
    end_line: int

    def as_ref(self) -> str:
        return f"{self.file}:{self.start_line}"


class ChainRole(str, Enum):
    SOURCE = "source"
    PROPAGATOR = "propagator"
    SINK = "sink"


class CallChainStep(BaseModel):
    symbol: str
    location: Optional[CodeLocation] = None
    role: ChainRole = ChainRole.PROPAGATOR
    note: Optional[str] = None


class Remediation(BaseModel):
    summary: str
    diff: Optional[str] = None
    rationale: str = ""
    confidence: int = Field(0, ge=0, le=10)


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"


class Finding(BaseModel):
    id: str
    vuln_class: VulnClass
    title: str
    description: str
    severity: Severity = Severity.MEDIUM
    confidence: int = Field(0, ge=0, le=10)
    location: CodeLocation
    entry_point: Optional[str] = None
    sink: Optional[str] = None
    cwe: Optional[str] = None
    call_chain: list[CallChainStep] = Field(default_factory=list)

    # Populated by the validator agent.
    verdict: Optional[Verdict] = None
    validated: bool = False
    validation_notes: Optional[str] = None
    # Knowledge-base items (by source id, e.g. CVE) the validator was shown.
    knowledge_refs: list[str] = Field(default_factory=list)

    # Populated by the remediation agent.
    remediation: Optional[Remediation] = None

    def dedup_key(self) -> tuple:
        """Two findings collapse if they are the same class at the same sink line."""
        return (self.vuln_class, self.location.file, self.location.start_line)


class ScanStats(BaseModel):
    files_scanned: int = 0
    symbols: int = 0
    entry_points: int = 0
    candidate_paths: int = 0
    findings_raw: int = 0
    findings_confirmed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    llm_calls: int = 0
    estimated_cost_usd: float = 0.0
    cost_by_model: dict = Field(default_factory=dict)
    cost_by_role: dict = Field(default_factory=dict)
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    config_summary: dict = Field(default_factory=dict)
    # Path to this run's workshop session folder (None if the workshop is off).
    workshop_dir: Optional[str] = None


def severity_for(vuln_class: VulnClass, confidence: int) -> Severity:
    """Derive a severity from vuln class and model confidence."""
    high_impact = {
        VulnClass.RCE,
        VulnClass.COMMAND_INJECTION,
        VulnClass.SQLI,
        VulnClass.DESERIALIZATION,
        VulnClass.SSRF,
    }
    if vuln_class in high_impact:
        if confidence >= 8:
            return Severity.CRITICAL
        if confidence >= 6:
            return Severity.HIGH
        return Severity.MEDIUM
    if confidence >= 8:
        return Severity.HIGH
    if confidence >= 6:
        return Severity.MEDIUM
    return Severity.LOW
