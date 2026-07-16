"""Offline tests for the knowledge base (Vul-RAG). No network, no API keys:
the CVE fetch uses a fake HTTP layer, distillation uses the mock provider, and
embedding retrieval uses a deterministic bag-of-words fake embedder.
"""
from __future__ import annotations

import hashlib
import re

import pytest

from icewall.config import EmbeddingConfig, IcewallConfig, KnowledgeConfig
from icewall.engine import Engine
from icewall.knowledge.builder import KnowledgeBuilder
from icewall.knowledge.fetch import CveFetcher, changed_lines, extract_changed_functions
from icewall.knowledge.schema import CvePair, KnowledgeItem
from icewall.knowledge.store import KnowledgeStore
from icewall.providers.mock import MockProvider

SAMPLE = __import__("os").path.abspath(
    __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "examples", "vulnerable_app")
)


class FakeEmbedder:
    """Deterministic bag-of-words vectors, so cosine similarity is meaningful."""

    DIM = 96

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            v = [0.0] * self.DIM
            for tok in re.findall(r"[a-z0-9]+", (t or "").lower()):
                b = int(hashlib.md5(tok.encode()).hexdigest(), 16) % self.DIM
                v[b] += 1.0
            out.append(v)
        return out


# --- diff parsing / function extraction (no network) -------------------------

def test_changed_lines_parses_hunks():
    patch = "@@ -1,3 +1,4 @@\n ctx\n-old line\n+new a\n+new b\n more\n"
    old, new = changed_lines(patch)
    assert 2 in old  # the removed line
    assert 2 in new and 3 in new  # the two added lines


def test_extract_changed_functions_pairs_by_qualname():
    old = b"def run(host):\n    return os.system('ping ' + host)\n\ndef other():\n    return 1\n"
    new = b"def run(host):\n    return subprocess.run(['ping', host], shell=False)\n\ndef other():\n    return 1\n"
    old_lines, new_lines = {2}, {2}
    pairs = extract_changed_functions("app.py", old, new, old_lines, new_lines)
    names = {q for _, _, q in pairs}
    assert names == {"run"}  # only the changed function, not `other`
    vuln, patched, _ = pairs[0]
    assert "os.system" in vuln and "subprocess.run" in patched


# --- CVE fetch via a fake HTTP layer -----------------------------------------

class FakeHttp:
    def __init__(self):
        self.vuln_src = "def handler(req):\n    cmd = req.args.get('c')\n    return os.system(cmd)\n"
        self.fixed_src = "def handler(req):\n    cmd = req.args.get('c')\n    return subprocess.run([cmd], shell=False)\n"

    def get_json(self, url: str) -> dict:
        if "api.osv.dev" in url:
            return {
                "summary": "command injection in handler",
                "database_specific": {"cwe_ids": ["CWE-78"]},
                "references": [{"type": "FIX", "url": "https://github.com/acme/app/commit/abc1234"}],
            }
        if "api.github.com" in url:
            return {
                "parents": [{"sha": "parent0"}],
                "files": [{
                    "filename": "handler.py",
                    "status": "modified",
                    "patch": "@@ -1,3 +1,3 @@\n def handler(req):\n     cmd = req.args.get('c')\n-    return os.system(cmd)\n+    return subprocess.run([cmd], shell=False)\n",
                    "raw_url": "https://raw/fixed",
                }],
            }
        return {}

    def get_text(self, url: str) -> str:
        return self.fixed_src if "fixed" in url else self.vuln_src


def test_cve_fetch_extracts_pairs_offline():
    fetcher = CveFetcher(http=FakeHttp())
    pairs = fetcher.fetch("CVE-2023-0001")
    assert pairs, "expected at least one function pair"
    p = pairs[0]
    assert p.cve_id == "CVE-2023-0001"
    assert p.cwe == "CWE-78"
    assert "os.system" in p.vulnerable_code
    assert "subprocess.run" in p.patched_code


# --- distillation (mock provider) --------------------------------------------

def test_distill_via_mock_produces_item(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    b = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    pair = CvePair(
        cve_id="CVE-2023-9",
        language="python",
        vulnerable_code="def f(x):\n    return os.system(x)\n",
        patched_code="def f(x):\n    return subprocess.run([x], shell=False)\n",
        cwe="CWE-78",
        function="f",
    )
    item = b.distiller.distill(pair)
    assert item is not None
    assert item.vuln_class == "command_injection"  # from the CWE
    assert item.fixing_solution and item.source == "CVE-2023-9"


def _pair(cve="CVE-2023-9", fn="f"):
    return CvePair(
        cve_id=cve, language="python", function=fn, cwe="CWE-78",
        vulnerable_code="def f(x):\n    return os.system(x)\n",
        patched_code="def f(x):\n    return subprocess.run([x], shell=False)\n",
    )


def test_pair_item_id_is_deterministic_from_provenance():
    from icewall.knowledge.schema import pair_item_id

    # Same CVE + function => same id, independent of code/description.
    a = pair_item_id(_pair())
    b = CvePair(cve_id="CVE-2023-9", language="python", function="f", cwe="CWE-78",
                vulnerable_code="different", patched_code="also different")
    assert a == pair_item_id(b)
    # Different function => different id.
    assert a != pair_item_id(_pair(fn="g"))


def test_build_from_pairs_skips_existing_before_distilling(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    b = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    first = b.build_from_pairs([_pair(fn="f"), _pair(fn="g")])
    assert first["added"] == 2 and first["skipped"] == 0

    # Re-run with an overlapping batch: 'f' already present -> skipped, 'h' new.
    b2 = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    second = b2.build_from_pairs([_pair(fn="f"), _pair(fn="h")])
    assert second["added"] == 1 and second["skipped"] == 1
    assert KnowledgeStore(cfg).stats()["count"] == 3

    # skip_existing=False re-distills the duplicate (still one stored id).
    b3 = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    third = b3.build_from_pairs([_pair(fn="f")], skip_existing=False)
    assert third["skipped"] == 0 and KnowledgeStore(cfg).stats()["count"] == 3


def test_limit_counts_new_items_not_duplicates(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    # Seed one item so the next build sees a duplicate first in the stream.
    KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1").build_from_pairs([_pair(fn="f")])

    # Ask for 2 NEW items from a stream that leads with the duplicate.
    b = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    stream = [_pair(fn="f"), _pair(fn="g"), _pair(fn="h"), _pair(fn="i")]
    summary = b.build_from_pairs(stream, skip_existing=True, limit=2)
    # The duplicate does NOT consume the limit: it keeps going to g and h.
    assert summary["added"] == 2 and summary["skipped"] == 1
    assert KnowledgeStore(cfg).stats()["count"] == 3  # f + g + h ('i' never reached)


# --- store: seed, persistence, retrieval (BM25 + embeddings) -----------------

def test_seed_from_skills_populates_classes(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    summary = KnowledgeBuilder(cfg).seed_from_skills()
    assert summary["added"] >= 5
    reloaded = KnowledgeStore(cfg)  # persisted to disk
    classes = {it.vuln_class for it in reloaded.items}
    assert {"sql_injection", "command_injection", "xss"} <= classes


def test_retrieve_bm25_filters_by_class_and_ranks(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"), top_k=3)
    store = KnowledgeStore(cfg)
    store.add([
        KnowledgeItem(id="a", vuln_class="sql_injection", abstract_purpose="builds a database query from user input",
                      detailed_cause="string-formats user input into SQL", fixing_solution="use bound parameters"),
        KnowledgeItem(id="b", vuln_class="sql_injection", abstract_purpose="renders a template",
                      detailed_cause="unrelated", fixing_solution="n/a"),
        KnowledgeItem(id="c", vuln_class="xss", abstract_purpose="writes user input into HTML", fixing_solution="escape"),
    ])
    hits = store.retrieve("sql_injection", ["SQL query built from user input string"])
    ids = [h.id for h in hits]
    assert "c" not in ids  # class filter excludes the XSS item
    assert ids and ids[0] == "a"  # the relevant SQLi item ranks first


def test_store_remove_deletes_and_persists(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    store = KnowledgeStore(cfg)
    store.add([
        KnowledgeItem(id="a", vuln_class="sql_injection", abstract_purpose="query from input"),
        KnowledgeItem(id="b", vuln_class="xss", abstract_purpose="html from input"),
    ])
    store.save()
    assert store.remove(["a", "missing"]) == 1  # only the present id counts
    assert [it.id for it in KnowledgeStore(cfg).items] == ["b"]  # persisted


def test_store_search_bm25_ranks_and_filters(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    store = KnowledgeStore(cfg)
    store.add([
        KnowledgeItem(id="a", vuln_class="sql_injection", abstract_purpose="builds a database query from user input",
                      detailed_cause="string-formats user input into SQL"),
        KnowledgeItem(id="b", vuln_class="xss", abstract_purpose="writes user input into an HTML page"),
    ])
    mode, results = store.search("SQL database query from user input", mode="bm25")
    assert mode == "bm25" and results[0][0].id == "a"
    # Class filter narrows the pool.
    _, only_xss = store.search("input", mode="bm25", vuln_class="xss")
    assert {it.id for it, _ in only_xss} == {"b"}


def test_store_search_embedding_errors_without_embedder(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    store = KnowledgeStore(cfg)  # no embedder
    store.add([KnowledgeItem(id="a", vuln_class="sql_injection", abstract_purpose="x")])
    with pytest.raises(ValueError):
        store.search("anything", mode="embedding")


def test_retrieve_uses_embeddings_when_available(tmp_path):
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"), top_k=2)
    emb = FakeEmbedder()
    items = [
        KnowledgeItem(id="q", vuln_class="ssrf", abstract_purpose="fetches a url from user input"),
        KnowledgeItem(id="r", vuln_class="ssrf", abstract_purpose="parses a config file"),
    ]
    for it, v in zip(items, emb.embed([i.knowledge_text() for i in items])):
        it.embedding = v
    store = KnowledgeStore(cfg, embedder=emb)
    store.add(items)
    assert store._use_embeddings(items) is True
    hits = store.retrieve("ssrf", ["fetches a url from user input"])
    assert hits and hits[0].id == "q"


# --- engine integration ------------------------------------------------------

def test_engine_attaches_knowledge_refs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    kbroot = str(tmp_path / "kb")
    KnowledgeBuilder(KnowledgeConfig(root=kbroot), provider=MockProvider(), model="mock-1").seed_from_skills()

    cfg = IcewallConfig.default()
    cfg.knowledge = KnowledgeConfig(enabled=True, root=kbroot)
    cfg.workshop.enabled = False
    result = Engine(cfg).scan(SAMPLE)

    refs = {f.vuln_class.value: f.knowledge_refs for f in result.findings}
    # Classes with a seed get a reference; the validator was shown that knowledge.
    assert refs.get("command_injection")
    assert refs.get("sql_injection")


def test_engine_no_knowledge_when_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = IcewallConfig.default()  # knowledge disabled by default
    cfg.workshop.enabled = False
    result = Engine(cfg).scan(SAMPLE)
    assert all(not f.knowledge_refs for f in result.findings)


# --- dataset importers: CVEfixes (synthetic SQLite) --------------------------

def _make_cvefixes_db(path):
    import sqlite3

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE cve(cve_id TEXT, description TEXT);
        CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);
        CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);
        CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);
        CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
        """
    )
    rows = [
        # Python SQLi — kept
        ("CVE-1", "sqli", "h1", "Python", "CWE-89", "f1", "search",
         'execute("SELECT " + v)', 'execute("SELECT ?", v)'),
        # Java SQLi — excluded by language
        ("CVE-2", "x", "h2", "Java", "CWE-89", "f2", "m", "a", "b"),
        # Python non-injection CWE — excluded by CWE filter
        ("CVE-3", "y", "h3", "Python", "CWE-000", "f3", "g", "p", "r"),
    ]
    for cve, desc, h, lang, cwe, fcid, name, before, after in rows:
        conn.execute("INSERT INTO cve VALUES(?,?)", (cve, desc))
        conn.execute("INSERT INTO fixes VALUES(?,?,?)", (cve, h, "u"))
        conn.execute("INSERT INTO file_change VALUES(?,?,?)", (fcid, h, lang))
        conn.execute("INSERT INTO method_change VALUES(?,?,?,?)", (fcid, name, 1, before))
        conn.execute("INSERT INTO method_change VALUES(?,?,?,?)", (fcid, name, 0, after))
        conn.execute("INSERT INTO cwe_classification VALUES(?,?)", (cve, cwe))
    conn.commit()
    conn.close()


def test_cvefixes_source_filters_language_and_cwe(tmp_path):
    from icewall.knowledge.cvefixes import INJECTION_CWES, CvefixesSource

    db = tmp_path / "CVEfixes.db"
    _make_cvefixes_db(str(db))
    pairs = list(CvefixesSource(str(db), cwe_ids=INJECTION_CWES, limit=100).iter_pairs())
    # Only the Python SQLi pair survives language + CWE filters.
    assert [(p.cve_id, p.language, p.function, p.cwe) for p in pairs] == [
        ("CVE-1", "python", "search", "CWE-89")
    ]
    assert "SELECT" in pairs[0].vulnerable_code


def test_cvefixes_ensure_indexes_creates_join_indexes(tmp_path):
    import sqlite3

    from icewall.knowledge.cvefixes import _INDEXES, ensure_indexes

    db = tmp_path / "CVEfixes.db"
    _make_cvefixes_db(str(db))
    assert ensure_indexes(str(db)) is True
    have = {r[0] for r in sqlite3.connect(str(db)).execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    assert {name for name, _, _ in _INDEXES} <= have


def test_cvefixes_pairs_non_adjacent_before_after(tmp_path):
    # Rows arrive unordered (no ORDER BY): a method's before/after halves may be
    # separated by other rows. The importer must still pair them.
    import sqlite3

    from icewall.knowledge.cvefixes import INJECTION_CWES, CvefixesSource

    db = tmp_path / "CVEfixes.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE cve(cve_id TEXT, description TEXT);"
        "CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);"
        "CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);"
        "CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);"
        "INSERT INTO cve VALUES('CVE-1','sqli');"
        "INSERT INTO fixes VALUES('CVE-1','h1','u');"
        "INSERT INTO file_change VALUES('f1','h1','Python');"
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-89');"
        # interleave: run(before), other(before), run(after), other(after)
        "INSERT INTO method_change VALUES('f1','run',1,'bad_run');"
        "INSERT INTO method_change VALUES('f1','other',1,'x');"
        "INSERT INTO method_change VALUES('f1','run',0,'good_run');"
        "INSERT INTO method_change VALUES('f1','other',0,'x');"  # unchanged -> no pair
    )
    conn.commit()
    conn.close()
    pairs = list(CvefixesSource(str(db), cwe_ids=INJECTION_CWES, ensure_index=False).iter_pairs())
    assert [(p.function, p.vulnerable_code, p.patched_code) for p in pairs] == [
        ("run", "bad_run", "good_run")
    ]


def test_cvefixes_source_respects_limit_and_dir(tmp_path):
    from icewall.knowledge.cvefixes import CvefixesSource, resolve_db_path

    db = tmp_path / "CVEfixes.db"
    _make_cvefixes_db(str(db))
    # No CWE filter => Python + Java rows both language-eligible? Java excluded by lang.
    pairs = list(CvefixesSource(str(db), cwe_ids=None, limit=1).iter_pairs())
    assert len(pairs) == 1  # limit honored
    # A directory path resolves to the .db inside it.
    assert resolve_db_path(str(tmp_path)).endswith("CVEfixes.db")


def test_cvefixes_import_builds_items(tmp_path):
    from icewall.knowledge.cvefixes import INJECTION_CWES, CvefixesSource

    db = tmp_path / "CVEfixes.db"
    _make_cvefixes_db(str(db))
    cfg = KnowledgeConfig(root=str(tmp_path / "kb"))
    builder = KnowledgeBuilder(cfg, provider=MockProvider(), model="mock-1")
    summary = builder.build_from_pairs(CvefixesSource(str(db), cwe_ids=INJECTION_CWES).iter_pairs())
    assert summary["added"] == 1
    assert KnowledgeStore(cfg).items[0].vuln_class == "sql_injection"


# --- dataset importers: OSV bulk (injected records, fake HTTP) ---------------

def test_prepare_db_from_sql_gz_handles_semicolons(tmp_path):
    import gzip

    from icewall.knowledge.cvefixes import INJECTION_CWES, CvefixesSource, prepare_db

    # A dump with BEGIN/COMMIT and a code value containing ';' + a newline — the
    # case a naive split-on-';' would corrupt.
    dump = (
        "PRAGMA foreign_keys=OFF;\n"
        "BEGIN TRANSACTION;\n"
        "CREATE TABLE cve(cve_id TEXT, description TEXT);\n"
        "CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);\n"
        "CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);\n"
        "CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);\n"
        "CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);\n"
        "INSERT INTO cve VALUES('CVE-1','sqli');\n"
        "INSERT INTO fixes VALUES('CVE-1','h1','u');\n"
        "INSERT INTO file_change VALUES('f1','h1','Python');\n"
        "INSERT INTO method_change VALUES('f1','run',1,'a=1; q=\"SELECT \"+v;\nreturn q;');\n"
        "INSERT INTO method_change VALUES('f1','run',0,'return bind(v);');\n"
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-89');\n"
        "COMMIT;\n"
    )
    gz = tmp_path / "dump.sql.gz"
    with gzip.open(gz, "wb") as f:
        f.write(dump.encode())

    db = tmp_path / "out.db"
    summary = prepare_db(str(gz), str(db))
    assert summary["statements"] >= 12 and db.exists()

    # The prepared db is directly consumable by the importer, and the
    # semicolon-laden vulnerable code survived intact.
    pairs = list(CvefixesSource(str(db), cwe_ids=INJECTION_CWES).iter_pairs())
    assert len(pairs) == 1
    assert "q=\"SELECT \"+v" in pairs[0].vulnerable_code


def _write_cvefixes_dump_gz(path):
    import gzip

    dump = (
        "BEGIN TRANSACTION;\n"
        "CREATE TABLE cve(cve_id TEXT, description TEXT);\n"
        "CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);\n"
        "CREATE TABLE file_change(file_change_id TEXT, hash TEXT, programming_language TEXT);\n"
        "CREATE TABLE method_change(file_change_id TEXT, name TEXT, before_change INT, code TEXT);\n"
        "CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);\n"
        "INSERT INTO cve VALUES('CVE-1','sqli');\n"
        "INSERT INTO fixes VALUES('CVE-1','h1','u');\n"
        "INSERT INTO file_change VALUES('f1','h1','Python');\n"
        "INSERT INTO method_change VALUES('f1','run',1,'q=\"S \"+v; go();');\n"
        "INSERT INTO method_change VALUES('f1','run',0,'bind(v);');\n"
        "INSERT INTO cwe_classification VALUES('CVE-1','CWE-89');\n"
        "COMMIT;\n"
    )
    with gzip.open(path, "wb") as f:
        f.write(dump.encode())


def test_prepare_db_python_backend_reports_byte_progress(tmp_path):
    from icewall.knowledge.cvefixes import prepare_db

    gz = tmp_path / "d.sql.gz"
    _write_cvefixes_dump_gz(gz)
    events = []
    summary = prepare_db(str(gz), str(tmp_path / "out.db"),
                         on_progress=lambda e, kw: events.append((e, kw)), prefer_cli=False)
    assert summary["backend"] == "python"
    progs = [kw for e, kw in events if e == "prepare_progress"]
    assert progs and all(0.0 <= p["pct"] <= 1.0 and p["total"] > 0 for p in progs)
    assert progs[-1]["pct"] >= 0.99  # forced 100% at the end


def test_resolve_or_prepare_from_dataset_folder(tmp_path):
    from icewall.knowledge.cvefixes import INJECTION_CWES, CvefixesSource, resolve_or_prepare

    # Lay it out like the real dataset: <folder>/Data/CVEfixes_*.sql.gz
    (tmp_path / "Data").mkdir()
    _write_cvefixes_dump_gz(tmp_path / "Data" / "CVEfixes_v1.0.8.sql.gz")

    events = []
    db = resolve_or_prepare(str(tmp_path), on_progress=lambda e, kw: events.append(e))
    assert db.endswith("CVEfixes.db")
    assert events[0] == "prepare_start" and events[-1] == "prepare_done"
    pairs = list(CvefixesSource(db, cwe_ids=INJECTION_CWES).iter_pairs())
    assert len(pairs) == 1 and "go();" in pairs[0].vulnerable_code  # semicolon-in-code survived

    # A second call reuses the prepared .db (no re-conversion).
    events2 = []
    resolve_or_prepare(str(tmp_path), on_progress=lambda e, kw: events2.append(e))
    assert events2 == []


def test_osv_bulk_source_filters_and_fetches():
    from icewall.knowledge.osv_bulk import OsvBulkSource

    record = {
        "id": "CVE-9",
        "summary": "command injection",
        "database_specific": {"cwe_ids": ["CWE-78"]},
        "references": [{"type": "FIX", "url": "https://github.com/o/r/commit/abcdef1"}],
    }
    noise = {"id": "CVE-X", "summary": "no fix", "references": []}  # no GitHub fix -> skipped
    src = OsvBulkSource(
        ["PyPI"], cwe_ids=["CWE-78"], limit=10,
        fetcher=CveFetcher(http=FakeHttp()), records=[noise, record],
    )
    pairs = list(src.iter_pairs())
    assert [p.cve_id for p in pairs] == ["CVE-9"]
    assert pairs[0].language == "python"
