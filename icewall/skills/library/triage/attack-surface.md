---
name: attack-surface-triage
description: Comprehensive guide to recognizing external attack surface across Python and JS/TS frameworks.
roles: [triage]
priority: 10
---
Your job is to decide, per symbol, whether it is worth expensive downstream
analysis. Optimize for **recall**: it is cheap to forward a borderline function
to the tracer, and expensive to miss the one entry point that matters. When in
doubt, include it with a moderate suspicion score.

# What counts as attack surface

A symbol is attack surface if it (a) reads attacker-controlled input, (b) sits on
a path that will receive such input from a caller, or (c) performs a dangerous
operation that a tainted value could reach.

## Untrusted input sources (high signal)

**Python web frameworks**
- Flask/Quart: `request.args`, `request.form`, `request.values`, `request.json`,
  `request.data`, `request.files`, `request.cookies`, `request.headers`,
  `request.get_json()`, view function args bound from `<path:...>` route params.
- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`,
  `request.META`, `request.COOKIES`, `self.kwargs`, form `cleaned_data` (only
  trusted *after* validation), DRF `request.data` / `serializer.validated_data`.
- FastAPI/Starlette: path/query/body params (function parameters typed as
  `Query`, `Path`, `Body`, Pydantic models), `request.headers`, `request.cookies`.
- Tornado: `self.get_argument`, `self.get_body_argument`, `self.request.*`.

**Node/JS frameworks**
- Express/Koa/Fastify: `req.query`, `req.body`, `req.params`, `req.headers`,
  `req.cookies`, `req.get(...)`, `ctx.request.body`, `ctx.query`, `ctx.params`.
- Next.js/Remix: `req`/`request` in API routes, `searchParams`, loader/action
  `request.formData()`, `params`.
- GraphQL resolvers: the `args` parameter of any resolver.
- AWS Lambda / serverless: `event.body`, `event.queryStringParameters`,
  `event.pathParameters`, `event.headers`.

**Non-web sources**
- CLI: `sys.argv`, `argparse`/`click` parsed values, `process.argv`, `yargs`.
- Environment/config that an attacker can influence in the deployment.
- Message queues, webhooks, uploaded files, deserialized network payloads,
  `stdin`, inter-service RPC bodies.

## Entry-point markers (raise suspicion even without a visible source)

- Route decorators/registrations: `@app.route`, `@app.get/post`, `@router.*`,
  `app.get("/x", handler)`, `@api_view`, class-based `View`/`ViewSet` methods
  (`get`, `post`, `put`, `delete`), gRPC/RPC service methods.
- Names/paths suggesting handlers: `views.py`, `routes/`, `controllers/`,
  `handlers/`, `api/`, `endpoints/`, names ending in `_view`, `_handler`,
  `_endpoint`, `on_message`, `on_request`.

## Dangerous sinks (a function containing one is worth tracing even absent a source)

Command exec, `eval`/`exec`/`Function`, SQL execution / query string building,
template rendering from strings, deserialization (`pickle`, `yaml.load`,
`unserialize`), file open/read/write with a dynamic path, outbound HTTP requests,
redirects, raw HTML assembly, crypto/secret handling.

# Scoring guidance (`suspicion`, 0..1)

- 0.85–0.99: a source and a dangerous sink in the same function.
- 0.65–0.85: an external-input source present; a sink likely one hop away, OR a
  route handler with no obvious sanitization.
- 0.45–0.65: a dangerous sink present but the source is unclear (a helper that
  probably receives tainted arguments), or a handler that only forwards input.
- 0.30–0.45: weak signal — touches config/env, or a utility that *might* be on a
  tainted path. Include so the tracer can decide.
- Below 0.30 / omit: pure internal logic, constants, getters/setters, pure math,
  test helpers, framework boilerplate with no source and no sink.

Assign `surface` to the most specific of: `http`, `cli`, `file`, `network`,
`internal`. Give a one-line `reason` naming the concrete source or sink you saw.

# Common mistakes to avoid

- Do not dismiss a helper just because it has no source of its own — if it
  reaches a sink, its callers may feed it taint (mark surface `internal`).
- Do not treat framework validation as making a handler safe at triage time —
  that is the analyzer/validator's call; still forward it.
- Do not over-score every function that merely imports a dangerous module.
