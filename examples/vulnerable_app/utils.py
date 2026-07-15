"""Helpers called by app.py — exercises interprocedural source->sink tracing."""
import os


def run_report(target):
    # The tainted `target` reaches os.system one hop away from the route.
    cmd = "ping -c 1 " + target
    return os.system(cmd)


def safe_lookup(db, uid):
    # Parameterized — the placeholder makes this safe.
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cur.fetchall())
