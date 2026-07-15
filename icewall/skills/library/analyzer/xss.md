---
name: xss-analysis
description: Detailed guidance for confirming or dismissing cross-site scripting (CWE-79), reflected/stored/DOM.
roles: [analyzer]
priority: 7
---
Confirm XSS when attacker-controlled data reaches an HTML/JS output context
without context-correct encoding. XSS is context-sensitive: the same value is
safe in one position and dangerous in another.

# Output contexts (the encoding must match the context)

1. **HTML body/element** — needs HTML entity encoding (`<`→`&lt;`, etc.).
2. **HTML attribute** — needs attribute encoding + quoting; unquoted attributes
   are exploitable even with entity encoding.
3. **JavaScript context** (inside `<script>` or an event handler) — HTML encoding
   does NOT help; needs JS string escaping / JSON serialization.
4. **URL context** (`href`, `src`) — needs URL encoding *and* scheme validation
   (`javascript:` URLs execute).
5. **CSS context** — needs CSS escaping.

# Vulnerable patterns

**Reflected/stored — server side**
```python
return f"<h1>Hello {name}</h1>"                       # raw interpolation
return render_template_string("Hi " + user)           # Jinja from a string
Markup(user_input)                                     # explicitly marks safe
return HttpResponse("<div>" + comment + "</div>")
```
```javascript
res.send("<h1>Hello " + req.query.name + "</h1>")
res.write(`<div>${userInput}</div>`)
```

**DOM-based — client side**
```javascript
element.innerHTML = location.hash                      // sink: innerHTML
document.write(userInput)
el.insertAdjacentHTML("beforeend", data)
$(el).html(userInput)                                  // jQuery .html()
eval(userControlled); new Function(userControlled)     // also RCE-in-browser
```

**React/templating escape hatches** — frameworks autoescape by default, so look
specifically for the bypasses:
- React: `dangerouslySetInnerHTML={{ __html: userInput }}`.
- Angular: `bypassSecurityTrustHtml`, `[innerHTML]` with untrusted value.
- Vue: `v-html="userInput"`.
- Jinja/Django: `| safe`, `{% autoescape false %}`, `mark_safe(...)`,
  `Markup(...)`, `render_template_string` with a string built from input.

# Safe patterns (report NOT vulnerable, or low confidence)

- Output through an autoescaping template with the value in a normal
  `{{ value }}` / `{value}` position (Jinja, Django templates, JSX text nodes,
  Vue mustache) — autoescape covers the HTML-body/attribute case.
- Explicit context-correct encoding: `markupsafe.escape`, `html.escape`,
  `bleach.clean` (sanitizing HTML), `encodeURIComponent` for URL parts,
  `JSON.stringify` for a JS-context value, a vetted sanitizer (DOMPurify).
- Value constrained to a safe type (int, enum, UUID) before output.

# Decisive checks
1. Which output **context** does the value land in?
2. Is the encoding applied **correct for that context** (HTML-escaping a value
   used inside a `<script>` block is still XSS)?
3. Is autoescaping actually in effect, or bypassed (`| safe`,
   `dangerouslySetInnerHTML`, `innerHTML`, string-built template)?

# Confidence calibration
- 8–10: tainted value reaches `innerHTML`/`document.write`/`dangerouslySetInnerHTML`
  /raw string HTML with no encoding, or lands in a JS/URL context with only
  HTML-encoding.
- 6–7: raw interpolation where the taint is likely but a hop away, or a partial/
  wrong-context encoder.
- ≤5 / not vulnerable: autoescaped template position, correct context encoder,
  or strictly typed value.

Name the output context and the specific sink in the description.
