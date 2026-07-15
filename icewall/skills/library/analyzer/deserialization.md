---
name: insecure-deserialization-analysis
description: Detailed guidance for confirming or dismissing insecure deserialization / RCE-via-load (CWE-502).
roles: [analyzer]
priority: 7
---
Confirm insecure deserialization when attacker-controlled bytes are handed to a
deserializer that can instantiate arbitrary objects or execute code during
loading. Several of these are effectively remote code execution.

# Dangerous sinks (RCE-capable)
```python
pickle.loads(data)            # arbitrary code execution by design
pickle.load(fileobj)
cPickle.loads(data)
yaml.load(data)               # UNSAFE without SafeLoader — can construct objects
yaml.load(data, Loader=yaml.Loader)   # also unsafe (FullLoader is safer, not safe for untrusted)
marshal.loads(data)
jsonpickle.decode(data)       # can instantiate arbitrary types
dill.loads / shelve / joblib.load on untrusted input
```
```javascript
node-serialize `unserialize(data)`     // known RCE gadget via _$$ND_FUNC$$_
funcster, cryo, or eval-based revivers
```

Also relevant: Django/Flask **sessions** signed with a guessable/empty secret and
then unpickled; message-queue payloads deserialized with pickle; caches storing
pickled objects fed by user data.

# Why these are dangerous
`pickle`/`marshal`/`yaml.load`/`jsonpickle` reconstruct objects by invoking
constructors and reducers embedded in the data. An attacker who controls the
bytes controls what gets constructed — leading to code execution, not just data
tampering. This is fundamentally different from parsing JSON.

# Safe patterns (report NOT vulnerable, or low confidence)
- `yaml.safe_load(data)` or `yaml.load(data, Loader=yaml.SafeLoader)` — restricts
  to basic types, no object construction.
- `json.loads` / `JSON.parse` — data-only, cannot instantiate arbitrary types
  (still validate the resulting structure, but not an RCE deserializer).
- Deserializing **trusted** data only: bytes that never cross a trust boundary
  (a fixed local file the app wrote, not network/user input). If you cannot show
  the source is trusted, treat it as untrusted.
- Signed/authenticated payloads (HMAC verified with a strong secret) *before*
  deserialization can reduce exposure — but pickle-after-verify is still risky if
  the signing key leaks; prefer a safe format.

# Decisive checks
1. Is the deserializer one that can construct arbitrary objects (`pickle`,
   `yaml.load` unsafe, `marshal`, `jsonpickle`, `node-serialize`)?
2. Does the input cross a trust boundary (network, user upload, cookie, queue)?
3. Is there a safe loader or an integrity check that actually gates the load?

# Confidence calibration
- 8–10: untrusted bytes reach `pickle.loads`/`yaml.load`(unsafe)/`marshal.loads`/
  `unserialize` with no integrity gate.
- 6–7: dangerous loader on data whose untrusted origin is likely but a hop away.
- ≤5 / not vulnerable: `safe_load`/JSON, or provably trusted local input.

Name the loader, the untrusted source, and any (in)effective integrity check.
