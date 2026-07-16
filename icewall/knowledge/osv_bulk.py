"""Import {vulnerable, patched} pairs from OSV's per-ecosystem bulk dumps.

OSV.dev publishes a full export per ecosystem at
`https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`, where
each entry is one advisory in OSV JSON. Ecosystem == language: `PyPI` (Python),
`npm` (JS/TS). Unlike CVEfixes, OSV records only *reference* the fix commit, so
this importer still fetches the code from GitHub via `CveFetcher`.

The zip download is cached under the kb root; `records=` lets tests inject
advisory dicts directly and skip the network.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Iterable, Iterator, Optional

from icewall.knowledge.fetch import CveFetcher
from icewall.knowledge.schema import CvePair

_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
# The ecosystems whose code Icewall can parse.
ECOSYSTEM_LANGS = {"PyPI": {"python"}, "npm": {"javascript", "typescript"}}
_KEEP_LANGS = {"python", "javascript", "typescript"}


class OsvBulkSource:
    def __init__(
        self,
        ecosystems: list[str],
        cwe_ids: Optional[list[str]] = None,
        limit: Optional[int] = None,
        fetcher: Optional[CveFetcher] = None,
        cache_dir: Optional[str] = None,
        records: Optional[Iterable[dict]] = None,
    ) -> None:
        self.ecosystems = ecosystems
        self.cwe_ids = set(cwe_ids) if cwe_ids else None
        self.limit = limit
        self.fetcher = fetcher or CveFetcher()
        self.cache_dir = Path(cache_dir) if cache_dir else Path("kb") / "_osv_cache"
        self._records = records  # test injection: skip the download

    # --- record iteration ----------------------------------------------------

    def _iter_records(self) -> Iterator[dict]:
        if self._records is not None:
            yield from self._records
            return
        for eco in self.ecosystems:
            zpath = self._download(eco)
            with zipfile.ZipFile(zpath) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        yield json.loads(zf.read(name))
                    except (json.JSONDecodeError, KeyError):
                        continue

    def _download(self, ecosystem: str) -> Path:
        import httpx

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        dest = self.cache_dir / f"{ecosystem}.zip"
        if dest.exists() and dest.stat().st_size > 0:
            return dest
        url = _DUMP_URL.format(eco=ecosystem)
        with httpx.stream("GET", url, timeout=120.0, follow_redirects=True) as r:
            r.raise_for_status()
            with dest.open("wb") as fh:
                for chunk in r.iter_bytes():
                    fh.write(chunk)
        return dest

    def _wanted(self, record: dict) -> bool:
        if not CveFetcher.has_github_fix(record):
            return False
        if self.cwe_ids is not None:
            cwe = CveFetcher._cwe_of(record)
            if cwe not in self.cwe_ids:
                return False
        return True

    # --- pairs ---------------------------------------------------------------

    def iter_pairs(self) -> Iterator[CvePair]:
        yielded = 0
        for record in self._iter_records():
            if not self._wanted(record):
                continue
            try:
                pairs = self.fetcher.pairs_from_record(record)
            except Exception:
                continue
            for pair in pairs:
                if pair.language not in _KEEP_LANGS:
                    continue
                yield pair
                yielded += 1
                # `limit` is only a standalone scan cap; the importer leaves it
                # None and bounds the NEW-item count in the builder so duplicates
                # (which still cost a fetch here) don't consume the target.
                if self.limit is not None and yielded >= self.limit:
                    return
