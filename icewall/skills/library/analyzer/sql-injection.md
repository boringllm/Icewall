---
name: sql-injection-analysis
description: Detailed guidance for confirming or dismissing SQL injection (CWE-89) across Python and JS ORMs and drivers.
roles: [analyzer]
priority: 8
---
Confirm SQL injection only when attacker-controlled data becomes part of a query
as **SQL code** rather than a **bound parameter**. The single most common false
positive is mistaking a parameter placeholder for actual binding, or the reverse.

# Vulnerable patterns

**String-built queries (the core case)**
```python
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")      # f-string
cur.execute("SELECT * FROM t WHERE id = %s" % uid)             # % formatting
cur.execute("... WHERE x = " + value)                          # concatenation
cur.execute("SELECT * FROM t WHERE id = {}".format(uid))       # .format
```
```javascript
db.query(`SELECT * FROM t WHERE id = ${id}`)                   // template literal
connection.query("SELECT * FROM t WHERE u = '" + user + "'")   // concatenation
```

**ORM escape hatches** (these bypass the ORM's parameterization):
- Django: `.raw(sql)` with interpolation, `.extra(where=[...])`, `RawSQL(...)`,
  `cursor.execute(f"...")`.
- SQLAlchemy: `text("... " + x)` or f-string into `text()`, `session.execute()`
  with a string built from input, `.filter(text(...))`.
- Sequelize: `sequelize.query(literal)` with interpolation, `Sequelize.literal(x)`.
- Knex: `knex.raw("... " + x)`; TypeORM: `.query(str)`, `where("x = " + v)`.

**Dynamic identifiers** — table/column/ORDER BY names taken from input. Parameter
binding covers *values*, never identifiers. Interpolating a column or sort
direction from input is injectable even in an otherwise parameterized query:
```python
cur.execute("SELECT * FROM t ORDER BY %s" % request.args["sort"])  # vulnerable
```
Require an allow-list mapping for identifiers.

# Safe patterns (report NOT vulnerable, or low confidence)

- Placeholders with a separate params argument — the value never touches the SQL
  string:
```python
cur.execute("SELECT * FROM users WHERE id = ?", (uid,))         # sqlite3
cur.execute("... WHERE id = %s", (uid,))                        # psycopg2 (tuple!)
cur.execute("... WHERE id = :id", {"id": uid})                  # named
```
```javascript
connection.query("SELECT * FROM t WHERE id = ?", [id])          // mysql2
client.query("SELECT * FROM t WHERE id = $1", [id])             // pg
```
- ORM query builders with bound values: `.filter(User.id == uid)`,
  `.where({ id })`, `Model.objects.filter(id=uid)`, `findOne({ where: { id } })`.
- Values validated to a strict type before use: `int(uid)`, a UUID parse, an
  enum membership check, an identifier matched against an allow-list.

# The trap: placeholder characters inside a formatted string

`%s` is only a bind placeholder when passed as the query with a **separate params
argument**. Inside an f-string or `%`-format it is just text and the value is
already interpolated — still injectable:
```python
cur.execute(f"... WHERE id = %s")           # %s is literal text here — NOT bound
cur.execute("... WHERE id = %s" % uid)      # % operator interpolates — injectable
```
Look at whether the tainted value reaches `execute()` inside the string or as a
later argument.

# Confidence calibration
- 8–10: tainted value provably concatenated/interpolated into the SQL string,
  no binding, reaches `execute`/`query`.
- 6–7: string-built query where taint is likely but the source is one hop away or
  partially transformed.
- ≤5 / not vulnerable: proper parameter binding, ORM bound values, or the value
  is strictly type-validated (int/enum/UUID/allow-listed identifier) before use.

Report `source`, the exact `sink` call, and name the mechanism (f-string,
concatenation, `.raw`, dynamic identifier) in the description.
