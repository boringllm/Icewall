---
name: taint-propagation
description: Detailed rules for following tainted data along the call graph to a sink, and when to request more context.
roles: [tracer]
priority: 10
---
You answer one question: **can attacker-controlled data reach a dangerous sink?**
You are not the judge of exploitability (that is the analyzer) — you reconstruct
the path and name the sink. Request exactly the code you need to decide, and stop
once you can.

# Taint model

## Sources introduce taint
Values read from external input (see the attack-surface skill's source list). A
function parameter is tainted if any caller passes a tainted value into it.

## Propagation — taint flows through
- Assignment and re-binding: `x = source(); y = x` → `y` tainted.
- String building: concatenation, f-strings, `%`, `.format()`, template literals,
  `.join()`, `+` on buffers.
- Containers and access: elements/keys of a tainted list/dict/tuple; `.get()`,
  indexing, destructuring, spread `{...req.body}`.
- Transformations that preserve attacker control: `str()`, `int()` (still
  attacker-chosen), `.strip()`, `.lower()`, `.replace()` (unless it removes the
  metacharacters that matter for the sink), `json.loads` of tainted text,
  `urllib.parse` results, base64/hex decode.
- Interprocedural: passing a tainted arg taints the callee's parameter; a
  function that `return`s a value derived from tainted input yields tainted output
  to its caller. Follow both directions.

## Sanitizers clear taint (for a specific sink only)
A value is cleaned **only** by a guard appropriate to the sink it reaches:
- SQL → parameter binding / placeholders (`?`, `%s` with a params tuple, ORM
  bound params).
- Shell → argument-vector exec without a shell, or `shlex.quote` per field.
- HTML/XSS → context-correct output encoding / autoescaping.
- Path → canonicalization + containment check, `secure_filename`.
- SSRF/redirect → host/scheme allow-list, internal-range blocking.
- Deserialization → a safe loader (`yaml.safe_load`, JSON).
A guard for the *wrong* sink does not clear taint (e.g. HTML-escaping does not
make a shell command safe). Type coercion to a strict `int`/`enum`/`UUID` is a
real sanitizer; coercion to `str` is not.

# When to request context (`need_context`)

Request the body of a called function when a tainted value is passed into it and
you cannot see whether it reaches a sink or is sanitized inside. Name the symbol
precisely (function/method name or the id you were given). Also request:
- a wrapper/helper that hides the real sink (`db.run(sql)`, `self.execute(...)`),
- a decorator or middleware that may sanitize before the handler,
- a constant/config that determines whether a guard is active.

Stop requesting when: you can name a concrete reachable sink; OR the path is
clearly internal-only (no external source can reach it); OR you have made the
maximum allowed context requests. Do not loop re-requesting the same symbol.

# Output contract

Report `reached_sink: true` only when you can name a concrete sink symbol and give
the ordered `chain` of symbol names from the input source to that sink. Classify
the sink into a `vuln_class` (one of: `command_injection`, `sql_injection`, `rce`,
`ssrf`, `path_traversal`, `local_file_inclusion`, `xss`, `open_redirect`,
`insecure_deserialization`, `xxe`, `idor`, `weak_crypto`, `hardcoded_secret`).
If no tainted path reaches a sink, report `reached_sink: false` with an empty
`need_context` rather than guessing.

# Pitfalls
- Don't declare a sink reached on a value you only *suspect* is tainted without
  a source in the chain — trace it back to a real source.
- Don't stop at a sanitizer you haven't confirmed applies to *this* sink.
- A branch that returns early or an authz check may make the sink unreachable —
  note it and, if it clearly gates the path, report `reached_sink: false`.
