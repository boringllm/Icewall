"""Import {vulnerable, patched} function pairs from a CVEfixes SQLite database.

CVEfixes (https://github.com/secureIT-project/CVEfixes) bundles the vulnerable
and patched code for each CVE fix, so this importer needs **no GitHub access** —
the right path for locked-down environments. The dataset ships as a compressed
SQL dump the user converts once to SQLite:

    gzcat Data/CVEfixes_v1.0.8.sql.gz | sqlite3 Data/CVEfixes.db

We read function-level pairs from the `method_change` table (small, focused
distiller inputs), filtered by programming language and — optionally — to
Icewall's injection CWEs, and stream them so the (very large) db is never loaded
into memory.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Iterator, Optional

from icewall.knowledge.schema import CvePair
from icewall.schemas import CWE_MAP

_CWE_TO_CLASS = {cwe: vc.value for vc, cwe in CWE_MAP.items()}
# Injection-family CWEs Icewall reasons about (the default import filter).
INJECTION_CWES = list(_CWE_TO_CLASS.keys())

# Icewall language arg -> CVEfixes `programming_language` value (PyDriller names).
_LANG_MAP = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript"}


def resolve_db_path(path: str) -> str:
    """Accept a direct .db path or the dataset directory (find Data/CVEfixes.db)."""
    p = Path(path)
    if p.is_dir():
        for cand in (p / "CVEfixes.db", p / "Data" / "CVEfixes.db"):
            if cand.exists():
                return str(cand)
        raise FileNotFoundError(f"no CVEfixes.db under {path} (convert the .sql.gz first)")
    if not p.exists():
        raise FileNotFoundError(f"CVEfixes db not found: {path}")
    return str(p)


class CvefixesSource:
    def __init__(
        self,
        db_path: str,
        languages: Optional[list[str]] = None,
        cwe_ids: Optional[list[str]] = None,
        limit: Optional[int] = None,
        on_progress=None,
        ensure_index: bool = True,
    ) -> None:
        self.db_path = resolve_db_path(db_path)
        langs = languages or ["python", "javascript", "typescript"]
        # Map to CVEfixes names; unknown languages pass through capitalized.
        self.languages = [_LANG_MAP.get(l.lower(), l) for l in langs]
        self.cwe_ids = cwe_ids  # None => no CWE filter
        self.limit = limit
        self._emit = on_progress or (lambda *_: None)
        self.ensure_index = ensure_index

    def _query(self) -> tuple[str, list]:
        # NO `ORDER BY`: on a 50GB db that forces a temp sort of the whole join,
        # which overflows SQLite's temp space ("database or disk is full"). We
        # stream unordered rows and pair before/after in Python instead.
        lang_ph = ",".join("?" for _ in self.languages)
        sql = (
            "SELECT cv.cve_id, cv.description, cc.cwe_id, fc.programming_language, "
            "       mc.file_change_id, mc.name, mc.before_change, mc.code "
            "FROM cwe_classification cc "
            "JOIN fixes fx ON fx.cve_id = cc.cve_id "
            "JOIN file_change fc ON fc.hash = fx.hash "
            "JOIN method_change mc ON mc.file_change_id = fc.file_change_id "
            "JOIN cve cv ON cv.cve_id = cc.cve_id "
            f"WHERE fc.programming_language IN ({lang_ph}) "
        )
        params: list = list(self.languages)
        if self.cwe_ids:
            cwe_ph = ",".join("?" for _ in self.cwe_ids)
            sql += f"AND cc.cwe_id IN ({cwe_ph}) "
            params += list(self.cwe_ids)
        return sql, params

    def iter_pairs(self) -> Iterator[CvePair]:
        """Stream function-level {vulnerable, patched} pairs.

        Rows arrive unordered (no temp sort), so before/after halves of a method
        are matched in a small `pending` dict keyed by (file_change_id, name) and
        emitted as soon as both sides are seen. Yields everything matching the
        language/CWE filters; `limit`, if set, is a standalone scan cap (the
        importer drives the NEW-item count from the builder instead)."""
        if self.ensure_index:
            ensure_indexes(self.db_path, on_progress=self._emit)

        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        yielded = 0
        rows = 0
        last = [time.time()]
        pending: dict = {}
        try:
            sql, params = self._query()
            for row in conn.execute(sql, params):
                rows += 1
                now = time.time()
                if now - last[0] >= 2.0:
                    last[0] = now
                    self._emit("cvefixes_scan", {"rows": rows, "pairs": yielded})
                key = (row["file_change_id"], row["name"])
                slot = pending.get(key)
                if slot is None:
                    slot = {"b": None, "a": None, "meta": {
                        "cve_id": row["cve_id"], "description": row["description"],
                        "cwe": row["cwe_id"], "language": _icewall_lang(row["programming_language"]),
                        "name": row["name"],
                    }}
                    pending[key] = slot
                if row["before_change"] in (1, "1", True, "True"):
                    slot["b"] = row["code"]
                else:
                    slot["a"] = row["code"]
                if slot["b"] is not None and slot["a"] is not None:
                    del pending[key]
                    if slot["b"] != slot["a"]:
                        m = slot["meta"]
                        yield CvePair(
                            cve_id=m["cve_id"], language=m["language"],
                            vulnerable_code=slot["b"], patched_code=slot["a"],
                            description=m["description"] or "", function=m["name"], cwe=m["cwe"],
                        )
                        yielded += 1
                        # A `limit` here is only a standalone scan cap; the
                        # importer normally leaves it None and bounds the NEW-item
                        # count in the builder (so duplicates don't consume it).
                        if self.limit is not None and yielded >= self.limit:
                            return
        finally:
            conn.close()


# Indexes that turn the unindexed 50GB db from "full table scans" into fast
# lookups. Created once (idempotent); harmless if they already exist.
_INDEXES = [
    ("ix_cwec_cwe", "cwe_classification", "cwe_id"),
    ("ix_fixes_cve", "fixes", "cve_id"),
    ("ix_fc_hash", "file_change", "hash"),
    ("ix_mc_fcid", "method_change", "file_change_id"),
]


def ensure_indexes(db_path: str, on_progress=None) -> bool:
    """Create the join indexes the importer needs, once. Best-effort: if the db
    is read-only/locked or a create fails, we log and fall back to scanning."""
    emit = on_progress or (lambda *_: None)
    try:
        w = sqlite3.connect(db_path)
    except sqlite3.Error as exc:
        emit("index_error", {"message": str(exc)})
        return False
    try:
        have = {r[0] for r in w.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        todo = [(n, t, c) for (n, t, c) in _INDEXES if n not in have]
        for i, (name, tbl, col) in enumerate(todo):
            emit("index_build", {"index": name, "table": tbl, "i": i, "total": len(todo)})
            t0 = time.time()
            try:
                w.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {tbl}({col})")
                w.commit()
            except sqlite3.Error as exc:
                emit("index_error", {"index": name, "message": str(exc)})
                return False
            emit("index_done", {"index": name, "table": tbl, "seconds": round(time.time() - t0, 1)})
        return True
    finally:
        w.close()


def _icewall_lang(cvefixes_lang: str) -> str:
    rev = {v: k for k, v in _LANG_MAP.items()}
    return rev.get(cvefixes_lang, (cvefixes_lang or "").lower())


def _iter_decompressed(src: str, on_bytes):
    """Yield decompressed byte chunks from a `.sql` or `.sql.gz`, calling
    `on_bytes(compressed_bytes_read)` per chunk so a caller can show real
    progress against the file size. Handles concatenated gzip members."""
    import zlib

    read = 0
    with open(src, "rb") as raw:
        if src.endswith(".gz"):
            d = zlib.decompressobj(zlib.MAX_WBITS | 16)
            while True:
                comp = raw.read(1 << 20)
                if not comp:
                    tail = d.flush()
                    if tail:
                        yield tail
                    break
                read += len(comp)
                out = d.decompress(comp)
                if out:
                    yield out
                while d.eof and d.unused_data:  # next concatenated member
                    rest = d.unused_data
                    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
                    out = d.decompress(rest)
                    if out:
                        yield out
                on_bytes(read)
        else:
            while True:
                chunk = raw.read(1 << 20)
                if not chunk:
                    break
                read += len(chunk)
                yield chunk
                on_bytes(read)


def prepare_db(src: str, dest: str, on_progress=None, prefer_cli=None) -> dict:
    """Stream a CVEfixes SQL dump (`.sql` or `.sql.gz`) into a new SQLite db.

    Uses the native `sqlite3` CLI when available (fast — the Linux default) and
    otherwise a pure-Python loader (no external tool needed — the Windows path).
    Either way the file is streamed (never held in memory) and progress is
    reported as a fraction of the compressed size via `prepare_progress` events.
    The dump is split with `sqlite3.complete_statement()` so the semicolons in
    code columns don't corrupt it.
    """
    import codecs
    import os
    import shutil
    import subprocess
    import time

    emit = on_progress or (lambda *_: None)
    total = os.path.getsize(src)
    use_cli = (shutil.which("sqlite3") is not None) if prefer_cli is None else prefer_cli
    t0 = time.time()
    last = [0.0]

    def tick(nbytes, force=False):
        now = time.time()
        if force or now - last[0] >= 0.4:
            last[0] = now
            emit("prepare_progress", {
                "pct": round(min(nbytes / total, 0.999), 4) if total else 0.0,
                "bytes": nbytes, "total": total,
                "seconds": round(now - t0, 1),
                "backend": "sqlite3" if use_cli else "python",
            })

    # --- fast path: pipe decompressed SQL into the sqlite3 CLI ---------------
    if use_cli:
        try:
            proc = subprocess.Popen([shutil.which("sqlite3"), dest], stdin=subprocess.PIPE)
        except Exception:
            use_cli = False
        else:
            for out in _iter_decompressed(src, tick):
                proc.stdin.write(out)
            proc.stdin.close()
            rc = proc.wait()
            tick(total, force=True)
            return {"backend": "sqlite3", "returncode": rc,
                    "seconds": round(time.time() - t0, 1), "db": dest}

    # --- fallback: pure-Python statement-by-statement load -------------------
    conn = sqlite3.connect(dest, isolation_level=None)  # autocommit
    cur = conn.cursor()
    dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
    stmts = skipped = 0
    buf = ""
    text_tail = ""
    try:
        for out in _iter_decompressed(src, tick):
            text_tail += dec.decode(out)
            lines = text_tail.split("\n")
            text_tail = lines.pop()  # keep the last, possibly-partial line
            for line in lines:
                buf += line + "\n"
                if sqlite3.complete_statement(buf):
                    try:
                        cur.executescript(buf)
                    except sqlite3.Error:
                        skipped += 1
                    stmts += 1
                    buf = ""
        buf += text_tail
        if buf.strip():
            try:
                cur.executescript(buf)
                stmts += 1
            except sqlite3.Error:
                skipped += 1
    finally:
        conn.close()
    tick(total, force=True)
    return {"backend": "python", "statements": stmts, "skipped": skipped,
            "seconds": round(time.time() - t0, 1), "db": dest}


def resolve_or_prepare(path: str, on_progress=None, prefer_cli=None) -> str:
    """Turn whatever the user points at into a usable CVEfixes SQLite db path.

    Accepts an existing `.db`, the dataset **main folder** (finds `Data/*.db`, or
    the `.sql.gz` and converts it), or a `.sql`/`.sql.gz` file directly. When a
    conversion is needed it runs `prepare_db`, emitting `prepare_start` /
    `prepare_progress` / `prepare_done` so the UI can show a bar.
    """
    emit = on_progress or (lambda *_: None)
    # Already a usable .db (file, or a dir that already holds CVEfixes.db)?
    try:
        return resolve_db_path(path)
    except FileNotFoundError:
        pass

    p = Path(path)
    if p.is_file() and (p.name.endswith(".sql.gz") or p.suffix == ".sql"):
        src, dest = p, p.with_name("CVEfixes.db")
    elif p.is_dir():
        cands = (
            sorted(p.glob("*.sql.gz")) + sorted((p / "Data").glob("*.sql.gz"))
            + sorted(p.glob("*.sql")) + sorted((p / "Data").glob("*.sql"))
        )
        if not cands:
            raise FileNotFoundError(f"no CVEfixes .db or .sql(.gz) found under {path}")
        src = cands[0]
        dest = src.with_name("CVEfixes.db")
    else:
        raise FileNotFoundError(f"CVEfixes path not found: {path}")

    emit("prepare_start", {"src": str(src), "dest": str(dest)})
    if dest.exists():
        dest.unlink()
    summary = prepare_db(str(src), str(dest), on_progress=on_progress, prefer_cli=prefer_cli)
    emit("prepare_done", {"dest": str(dest), **summary})
    return str(dest)
