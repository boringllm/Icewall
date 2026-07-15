---
name: path-traversal-analysis
description: Detailed guidance for confirming or dismissing path traversal / LFI (CWE-22, CWE-98).
roles: [analyzer, validator]
priority: 7
---
Confirm path traversal / local file inclusion when attacker-controlled data is
used to build a filesystem path that is then opened, read, written, served, or
included — without confinement to an intended base directory. The classic payload
is `../../../etc/passwd` (or `..\\..\\` on Windows, or URL-encoded `%2e%2e%2f`).

# Vulnerable patterns
```python
open(os.path.join("/var/data", request.args["file"]))   # join doesn't confine
send_file(os.path.join(base, name))                      # Flask
send_from_directory(base, user_name)                     # safer but check version
with open(user_path) as f: ...                           # direct user path
include(f"templates/{page}.html")                        # LFI into include/eval
```
```javascript
fs.readFile(path.join(base, req.query.file), cb)
res.sendFile(path.join(__dirname, userPath))
require("./plugins/" + name)                             # LFI via require
```

Key insight: `os.path.join(base, user)` / `path.join` do **not** prevent
traversal — if `user` is absolute or contains `..`, the result escapes `base`.
`os.path.join("/var/data", "/etc/passwd")` returns `/etc/passwd`.

# Safe / mitigating patterns (report NOT vulnerable, or lower confidence)
- **Canonicalize then contain**: resolve the final path and verify it stays under
  the base directory:
```python
final = os.path.realpath(os.path.join(base, name))
if not final.startswith(os.path.realpath(base) + os.sep): abort(403)
```
  or `Path(base).resolve() in Path(final).resolve().parents`, or
  `os.path.commonpath([base, final]) == base`.
- `werkzeug.utils.secure_filename(name)` (strips directory components) for upload
  filenames — good for basenames, insufficient alone if subpaths are expected.
- An **allow-list** of permitted names/ids mapped to fixed paths (the safest).
- Input constrained to a strict pattern with no separators or dots
  (`^[A-Za-z0-9_-]+$`, anchored).

# Traps and bypasses to weigh
- A `..` **rejection** that only checks the raw input misses URL-encoded,
  double-encoded, Unicode, or backslash variants, and misses absolute paths.
  A rejection is weaker than canonicalize-and-contain.
- `startswith(base)` on a **non-canonical** path is bypassable via symlinks or
  `..`; the containment check must be on the resolved/real path.
- Appending a fixed extension (`name + ".html"`) can be defeated by null bytes on
  old runtimes or by traversal that lands on a file with that extension.

# Confidence calibration
- 8–10: user-controlled path segment reaches a file sink with only `join`/no
  containment, or a raw-input `..` check that misses encodings/absolute paths.
- 6–7: some confinement present but incomplete (checks raw input, or `startswith`
  on a non-canonical path).
- ≤5 / not vulnerable: canonicalize-and-contain on the resolved path, an
  allow-list mapping, or a strict no-separator pattern.

Name whether the sink reads, writes, serves, or includes, and describe the guard.
