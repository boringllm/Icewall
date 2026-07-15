---
name: ssrf-analysis
description: Detailed guidance for confirming or dismissing server-side request forgery (CWE-918).
roles: [analyzer]
priority: 7
---
Confirm SSRF when attacker-controlled data determines the destination of a
server-initiated network request (host, URL, port, or scheme) without an
adequate allow-list or internal-range block. The impact is reaching internal
services, cloud metadata endpoints (`169.254.169.254`), or arbitrary hosts.

# Vulnerable patterns
```python
requests.get(request.args["url"])                     # full URL from input
urllib.request.urlopen(user_url)
httpx.get(f"https://{host}/api")                       # host from input
requests.post(base + user_path)                        # path/host controlled
```
```javascript
fetch(req.query.url)
axios.get(userSuppliedUrl)
http.get({ host: req.body.host, path: "/status" })
```

Also SSRF-relevant: webhook/callback URLs, image/PDF fetchers, URL preview/
unfurl features, XML/SVG parsers that fetch external resources, git/svn clone
from a user URL, and "import from URL" endpoints.

# What makes it exploitable
- The attacker controls the **host/authority** (most severe) or a **scheme**
  (`file://`, `gopher://`, `dict://` broaden impact beyond HTTP).
- Even path-only control can matter against a fixed internal host.
- Redirect following (`allow_redirects=True`, default in `requests`) lets an
  allow-listed host redirect to an internal one — a validated-then-fetched URL
  can still be SSRF if redirects aren't constrained.

# Safe / mitigating patterns (report NOT vulnerable, or lower confidence)
- A strict **allow-list** of permitted hosts/domains checked before the request,
  with the parsed host (via `urlparse`/`URL`) compared — not a substring match
  (`"trusted.com" in url` is bypassable with `trusted.com.evil.com` or
  `evil.com/?x=trusted.com`).
- Blocking private/reserved ranges by resolving the host and checking
  `ipaddress.ip_address(...).is_private/is_loopback/is_link_local/is_reserved`,
  applied **after DNS resolution** and re-checked on redirects.
- Scheme restricted to `http`/`https`; redirects disabled or re-validated.
- The destination is a fixed constant and only a query parameter (not the host)
  is user-controlled against a trusted host.

# Common false positives to dismiss
- Substring/`startswith` checks look like validation but are usually bypassable —
  treat as weak, not safe, unless the host is parsed and compared exactly.
- Fetching a fully constant internal URL where no part is attacker-controlled.

# Confidence calibration
- 8–10: attacker controls the host/scheme of an outbound request with no
  allow-list or SSRF guard; or an allow-list based on an easily-bypassed
  substring check.
- 6–7: host controlled but some weak validation present, or only path control
  against an internal host.
- ≤5 / not vulnerable: exact-match host allow-list on the parsed authority +
  private-range block + constrained redirects, or a constant destination.

Name what the attacker controls (scheme/host/path) and the guard (or its absence).
