"""Deliberately vulnerable Flask-style app for exercising Icewall.

Contains real source->sink flows (some interprocedural), plus a safe
parameterized case to check false-positive handling.
"""
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

from utils import run_report, safe_lookup

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)


@app.route("/ping")
def ping():
    # VULN: command injection — user host flows into os.system via helper.
    host = request.args.get("host")
    return run_report(host)


@app.route("/search")
def search():
    # VULN: SQL injection — f-string interpolation into execute().
    term = request.args.get("q")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM items WHERE name = '{term}'")
    return str(cur.fetchall())


@app.route("/user")
def user():
    # SAFE: parameterized query — should be rejected by the validator.
    uid = request.args.get("id")
    return safe_lookup(db, uid)


@app.route("/download")
def download():
    # VULN: path traversal — user filename flows into send_file/open.
    name = request.args.get("file")
    path = os.path.join("/var/data", name)
    return send_file(path)


@app.route("/calc")
def calc():
    # VULN: RCE — user expression evaluated.
    expr = request.args.get("expr")
    return str(eval(expr))


if __name__ == "__main__":
    app.run()
