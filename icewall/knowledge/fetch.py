"""Fetch CVE metadata and patches, and extract {vulnerable, patched} function
pairs from fix commits.

Metadata comes from OSV.dev (no API key). Patches come from the fix commits the
advisory references — GitHub is supported first-class: we fetch the changed file
at the fix commit and at its parent, then use Icewall's own tree-sitter parser to
recover the individual functions that changed. The HTTP layer is injectable so
the parsing/extraction logic is testable without any network.
"""
from __future__ import annotations

import re
from typing import Optional, Protocol

from icewall.graph.languages import spec_for_path
from icewall.graph.parser import parse_source
from icewall.knowledge.schema import CvePair
from icewall.schemas import CWE_MAP

# Reverse of the class->CWE table, to tag a fetched pair when the advisory says
# which CWE it is.
_CWE_TO_CLASS = {cwe: vc.value for vc, cwe in CWE_MAP.items()}

_OSV_URL = "https://api.osv.dev/v1/vulns/{id}"
_GH_COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

_MAX_COMMITS = 4
_MAX_FILES = 12
_MAX_FILE_BYTES = 400_000


class Http(Protocol):
    def get_json(self, url: str) -> dict: ...
    def get_text(self, url: str) -> str: ...


class HttpxClient:
    """Default HTTP backend (httpx). Honors verify_ssl and an optional GH token."""

    def __init__(self, verify_ssl: bool = True, github_token: Optional[str] = None, timeout: float = 30.0) -> None:
        import httpx

        headers = {"User-Agent": "icewall-kb-builder"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        self._c = httpx.Client(verify=verify_ssl, timeout=timeout, headers=headers, follow_redirects=True)

    def get_json(self, url: str) -> dict:
        r = self._c.get(url)
        r.raise_for_status()
        return r.json()

    def get_text(self, url: str) -> str:
        r = self._c.get(url)
        r.raise_for_status()
        return r.text


def changed_lines(patch: str) -> tuple[set[int], set[int]]:
    """Line numbers touched by a unified diff: (old-side removed, new-side added)."""
    old_ln = new_ln = 0
    old_changed: set[int] = set()
    new_changed: set[int] = set()
    for line in (patch or "").splitlines():
        if line.startswith("@@"):
            m = _HUNK_RE.search(line)
            if m:
                old_ln, new_ln = int(m.group(1)), int(m.group(2))
            continue
        if not line:
            old_ln += 1
            new_ln += 1
            continue
        c = line[0]
        if c == "+":
            new_changed.add(new_ln)
            new_ln += 1
        elif c == "-":
            old_changed.add(old_ln)
            old_ln += 1
        elif c == "\\":  # "\ No newline at end of file"
            continue
        else:
            old_ln += 1
            new_ln += 1
    return old_changed, new_changed


def extract_changed_functions(
    path: str, old_src: bytes, new_src: bytes, old_lines: set[int], new_lines: set[int]
) -> list[tuple[str, str, str]]:
    """Recover (vulnerable_code, patched_code, qualname) for each function whose
    body a diff touched, pairing old and new by qualname."""
    spec = spec_for_path(path)
    if spec is None:
        return []
    try:
        old_syms = parse_source(path, old_src, spec).symbols
        new_syms = parse_source(path, new_src, spec).symbols
    except Exception:
        return []

    def fns(syms):
        return {s.qualname: s for s in syms if s.kind in ("function", "method")}

    old_by_q, new_by_q = fns(old_syms), fns(new_syms)
    touched: set[str] = set()
    for s in new_syms:
        if s.kind in ("function", "method") and any(s.start_line <= ln <= s.end_line for ln in new_lines):
            touched.add(s.qualname)
    for s in old_syms:
        if s.kind in ("function", "method") and any(s.start_line <= ln <= s.end_line for ln in old_lines):
            touched.add(s.qualname)

    out: list[tuple[str, str, str]] = []
    for q in sorted(touched):
        o, n = old_by_q.get(q), new_by_q.get(q)
        if o and n and o.code != n.code:
            out.append((o.code, n.code, q))
    return out


class CveFetcher:
    def __init__(self, http: Optional[Http] = None, verify_ssl: bool = True, github_token: Optional[str] = None) -> None:
        self.http = http or HttpxClient(verify_ssl=verify_ssl, github_token=github_token)

    def fetch(self, cve_id: str) -> list[CvePair]:
        """Return every {vulnerable, patched} function pair for one CVE id."""
        meta = self.http.get_json(_OSV_URL.format(id=cve_id))
        return self.pairs_from_record(meta, cve_id=cve_id)

    def pairs_from_record(self, meta: dict, cve_id: str = "") -> list[CvePair]:
        """Extract pairs from an already-fetched OSV record (e.g. a bulk dump),
        avoiding a second OSV round-trip. Still fetches the code from GitHub."""
        cve_id = cve_id or meta.get("id", "")
        description = (meta.get("summary") or meta.get("details") or "").strip()
        cwe = self._cwe_of(meta)
        vuln_class = _CWE_TO_CLASS.get(cwe or "", "")
        pairs: list[CvePair] = []
        for owner, repo, sha in self._fix_commits(meta)[:_MAX_COMMITS]:
            try:
                pairs += self._pairs_from_commit(cve_id, owner, repo, sha, description, cwe, vuln_class)
            except Exception:
                continue  # a single unreachable/odd commit must not abort the CVE
        return pairs

    @staticmethod
    def has_github_fix(meta: dict) -> bool:
        """Whether an OSV record references at least one GitHub fix commit."""
        return bool(CveFetcher._fix_commits(meta))

    # --- OSV parsing ---------------------------------------------------------

    @staticmethod
    def _cwe_of(meta: dict) -> Optional[str]:
        ds = meta.get("database_specific") or {}
        for key in ("cwe_ids", "cwes"):
            vals = ds.get(key)
            if isinstance(vals, list) and vals:
                first = vals[0]
                return first if isinstance(first, str) else first.get("cweId")
        return None

    @staticmethod
    def _fix_commits(meta: dict) -> list[tuple[str, str, str]]:
        found: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        def add(url: str) -> None:
            m = _GH_COMMIT_RE.search(url or "")
            if m:
                key = (m.group(1), m.group(2).removesuffix(".git"), m.group(3))
                if key not in seen:
                    seen.add(key)
                    found.append(key)

        for ref in meta.get("references", []) or []:
            if isinstance(ref, dict):
                add(ref.get("url", ""))
        # Fix commits also appear as range events with a repo URL.
        for aff in meta.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                repo = rng.get("repo", "")
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev and repo:
                        add(f"{repo}/commit/{ev['fixed']}")
        return found

    # --- GitHub commit -> pairs ---------------------------------------------

    def _pairs_from_commit(
        self, cve_id: str, owner: str, repo: str, sha: str,
        description: str, cwe: Optional[str], vuln_class: str,
    ) -> list[CvePair]:
        commit = self.http.get_json(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}")
        parents = commit.get("parents") or []
        if not parents:
            return []
        parent = parents[0]["sha"]
        commit_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
        out: list[CvePair] = []
        for f in (commit.get("files") or [])[:_MAX_FILES]:
            path = f.get("filename", "")
            patch = f.get("patch", "")
            if spec_for_path(path) is None or f.get("status") == "removed" or not patch:
                continue
            try:
                new_src = self.http.get_text(
                    f.get("raw_url") or f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
                )
                old_src = self.http.get_text(
                    f"https://raw.githubusercontent.com/{owner}/{repo}/{parent}/{path}"
                )
            except Exception:
                continue
            if len(new_src) > _MAX_FILE_BYTES or len(old_src) > _MAX_FILE_BYTES:
                continue
            old_lines, new_lines = changed_lines(patch)
            spec = spec_for_path(path)
            for vuln_code, patched_code, qual in extract_changed_functions(
                path, old_src.encode("utf-8"), new_src.encode("utf-8"), old_lines, new_lines
            ):
                out.append(
                    CvePair(
                        cve_id=cve_id,
                        language=spec.name if spec else "",
                        vulnerable_code=vuln_code,
                        patched_code=patched_code,
                        description=description,
                        commit_url=commit_url,
                        function=qual,
                        cwe=cwe,
                    )
                )
        return out
