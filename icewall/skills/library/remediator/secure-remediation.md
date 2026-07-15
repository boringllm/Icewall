---
name: secure-remediation
description: Detailed guidance for proposing minimal, correct, behavior-preserving security fixes as unified diffs.
roles: [remediator]
priority: 10
---
Propose the smallest change that removes the vulnerability while preserving the
code's intended behavior. Reach for the platform's safe primitive before
hand-rolled filtering — validation logic is easy to get wrong, safe APIs are not.
The output is a **proposal for human review**; never claim it is applied.

# Preferred fix per vulnerability class

**SQL injection** → parameterized query / bound placeholders. Move the value out
of the SQL string into the params argument:
```diff
-cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
+cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```
For dynamic identifiers (table/column/sort), map input through an allow-list dict
— never interpolate identifiers directly.

**Command injection** → drop the shell and pass an argument vector:
```diff
-os.system("ping -c 1 " + host)
+subprocess.run(["ping", "-c", "1", host], check=True)
```
If a shell is truly required, `shlex.quote` every interpolated field.

**XSS** → context-correct output encoding; prefer the framework's autoescape.
Replace `innerHTML`/`dangerouslySetInnerHTML`/`| safe`/`Markup(...)` with a
normal template position or an explicit encoder (`markupsafe.escape`,
`encodeURIComponent` for URL parts, `JSON.stringify` for JS context, DOMPurify for
rich HTML).

**Path traversal / LFI** → canonicalize and confirm containment under the base
dir; or map input through an allow-list:
```diff
-return send_file(os.path.join("/var/data", name))
+base = os.path.realpath("/var/data")
+final = os.path.realpath(os.path.join(base, name))
+if not final.startswith(base + os.sep):
+    abort(403)
+return send_file(final)
```

**SSRF / open redirect** → exact-match allow-list on the parsed host + block
private ranges + constrain redirects; validate scheme is `http(s)`.

**Insecure deserialization** → switch to a safe format: `yaml.safe_load`, JSON,
or a signed+safe scheme. Never `pickle.loads` untrusted bytes.

**Weak crypto / secrets** → `secrets`/`os.urandom` for tokens, `bcrypt`/`argon2`
for passwords, SHA-256+ for hashing; move hardcoded secrets to env/secret manager.

# Rules for the diff

- Emit a **valid unified diff** against the given file: correct `--- a/…` /
  `+++ b/…` headers and `@@` hunk lines, changing as few lines as possible.
- Keep imports, signatures, and return types consistent — if the fix needs a new
  import (`import subprocess`, `import shlex`), include it in the diff.
- Preserve behavior for legitimate inputs. If a correct fix necessarily changes an
  API or return shape, say so explicitly in the rationale rather than hiding it.
- Do not introduce new logic beyond the fix (no unrelated refactors, no extra
  error handling for impossible cases).

# Rationale

State: what made it exploitable, why the fix closes it, any assumption you made
(e.g. "assumes `name` should be a bare filename"), and any **residual risk** the
reviewer should check (e.g. "confirm no other caller passes an absolute path").
Set `confidence` to reflect how sure you are the fix is correct and complete, not
how severe the bug is. This is a proposal — the reviewer decides whether to apply.
