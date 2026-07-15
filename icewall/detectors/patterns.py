"""Lightweight signal patterns for taint sources, sinks, and sanitizers.

These are NOT the detector — the LLM agents are. They serve two roles:
  1. cheap heuristics to focus/seed LLM work (entry-point hints), and
  2. the "reasoning" of the offline MockProvider so the full pipeline can run
     end-to-end with no API keys.

Patterns are intentionally broad; precision is the LLM/validator's job.
"""
from __future__ import annotations

import re

from icewall.schemas import VulnClass

# User-controlled input surfaces (Python + JS/TS web frameworks).
SOURCE_PATTERNS: list[str] = [
    r"request\.(args|form|values|json|data|files|cookies|headers|GET|POST)",
    r"\breq\.(query|body|params|headers|cookies)\b",
    r"\binput\s*\(",
    r"sys\.argv",
    r"process\.argv",
    r"process\.env",
    r"flask\.request",
    r"self\.get_argument",
    r"ctx\.request",
    r"event\[['\"](queryStringParameters|body|pathParameters)['\"]\]",
]

# Sink patterns per vulnerability class.
SINK_PATTERNS: dict[VulnClass, list[str]] = {
    VulnClass.COMMAND_INJECTION: [
        r"os\.system\s*\(",
        r"os\.popen\s*\(",
        r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
        r"child_process\.(exec|execSync|spawn)\s*\(",
        r"\bexecSync\s*\(",
        r"commands\.getoutput\s*\(",
    ],
    VulnClass.RCE: [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bFunction\s*\(",
        r"vm\.runInThisContext\s*\(",
        r"pickle\.loads\s*\(",
        r"\.render_template_string\s*\(",
    ],
    VulnClass.SQLI: [
        r"cursor\.execute\s*\(",
        r"\.execute\s*\(\s*[f\"']",
        r"\.query\s*\(",
        r"\.raw\s*\(",
        r"sequelize\.query\s*\(",
        r"db\.execute\s*\(",
    ],
    VulnClass.XSS: [
        r"\.innerHTML\s*=",
        r"dangerouslySetInnerHTML",
        r"document\.write\s*\(",
        r"render_template_string\s*\(",
        r"\bMarkup\s*\(",
        r"res\.send\s*\(",
    ],
    VulnClass.SSRF: [
        r"requests\.(get|post|put|delete|head|request)\s*\(",
        r"urllib\.request\.urlopen\s*\(",
        r"httpx\.(get|post|Client)\s*\(",
        r"\bfetch\s*\(",
        r"axios\.(get|post|request)\s*\(",
        r"http\.get\s*\(",
    ],
    VulnClass.LFI: [
        r"send_file\s*\(",
        r"send_from_directory\s*\(",
        r"res\.sendFile\s*\(",
        r"\bopen\s*\(",
    ],
    VulnClass.PATH_TRAVERSAL: [
        r"open\s*\(",
        r"os\.path\.join\s*\(",
        r"fs\.(readFile|readFileSync|createReadStream)\s*\(",
        r"path\.join\s*\(",
        r"pathlib\.Path\s*\(",
    ],
    VulnClass.DESERIALIZATION: [
        r"pickle\.loads?\s*\(",
        r"yaml\.load\s*\(",
        r"marshal\.loads\s*\(",
        r"jsonpickle\.decode\s*\(",
        r"unserialize\s*\(",
        r"cPickle\.loads?\s*\(",
    ],
    VulnClass.OPEN_REDIRECT: [
        r"redirect\s*\(",
        r"res\.redirect\s*\(",
        r"HttpResponseRedirect\s*\(",
    ],
    VulnClass.XXE: [
        r"etree\.parse\s*\(",
        r"etree\.fromstring\s*\(",
        r"lxml\.etree",
        r"libxmljs\.parseXml\s*\(",
    ],
    VulnClass.HARDCODED_SECRET: [
        r"(password|passwd|secret|api_key|apikey|token|access_key)\s*=\s*['\"][^'\"]{6,}['\"]",
    ],
    VulnClass.WEAK_CRYPTO: [
        r"hashlib\.(md5|sha1)\s*\(",
        r"crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]",
        r"\bDES\b",
        r"Math\.random\s*\(",
    ],
}

# Sanitizer / guard patterns per class — presence near a sink lowers confidence.
SANITIZER_PATTERNS: dict[VulnClass, list[str]] = {
    VulnClass.COMMAND_INJECTION: [r"shlex\.quote", r"shlex\.split", r"\bshell\s*=\s*False"],
    VulnClass.RCE: [r"ast\.literal_eval", r"json\.loads"],
    VulnClass.SQLI: [r"%s", r"\?", r"parameterized", r"execute\s*\([^,]+,\s*[\(\[]"],
    VulnClass.XSS: [r"escape\s*\(", r"bleach\.clean", r"markupsafe", r"sanitize", r"encodeURIComponent"],
    VulnClass.SSRF: [r"allowlist", r"allowed_hosts", r"urlparse", r"ipaddress\."],
    VulnClass.LFI: [r"secure_filename", r"os\.path\.abspath", r"\.startswith\("],
    VulnClass.PATH_TRAVERSAL: [r"secure_filename", r"os\.path\.abspath", r"os\.path\.realpath", r"\.\.\s*not"],
    VulnClass.DESERIALIZATION: [r"yaml\.safe_load", r"Loader\s*=\s*SafeLoader", r"json\.loads"],
    VulnClass.OPEN_REDIRECT: [r"url_has_allowed_host", r"allowed_hosts", r"urlparse"],
    VulnClass.XXE: [r"resolve_entities\s*=\s*False", r"defusedxml", r"no_network\s*=\s*True"],
    VulnClass.HARDCODED_SECRET: [r"os\.environ", r"getenv", r"process\.env", r"vault"],
    VulnClass.WEAK_CRYPTO: [r"secrets\.", r"sha256", r"sha512", r"bcrypt", r"argon2"],
}


_compiled_sinks: dict[VulnClass, list[re.Pattern]] = {
    vc: [re.compile(p) for p in pats] for vc, pats in SINK_PATTERNS.items()
}
_compiled_sources: list[re.Pattern] = [re.compile(p) for p in SOURCE_PATTERNS]
_compiled_sanitizers: dict[VulnClass, list[re.Pattern]] = {
    vc: [re.compile(p) for p in pats] for vc, pats in SANITIZER_PATTERNS.items()
}


def has_source(code: str) -> bool:
    return any(p.search(code) for p in _compiled_sources)


def find_sinks(code: str, classes: list[VulnClass] | None = None) -> list[tuple[VulnClass, str]]:
    """Return (vuln_class, matched_text) for every sink pattern present in code."""
    out: list[tuple[VulnClass, str]] = []
    targets = classes if classes else list(_compiled_sinks.keys())
    for vc in targets:
        for pat in _compiled_sinks.get(vc, []):
            m = pat.search(code)
            if m:
                out.append((vc, m.group(0)))
    return out


def has_sanitizer(code: str, vuln_class: VulnClass) -> bool:
    return any(p.search(code) for p in _compiled_sanitizers.get(vuln_class, []))
