---
name: command-injection-analysis
description: Detailed guidance for confirming or dismissing OS command injection (CWE-78) in Python and Node.
roles: [analyzer]
priority: 8
---
Confirm command injection when attacker-controlled data reaches a
shell/process-execution sink in a way that lets it alter the command executed.
The decisive question is almost always: **does a shell interpret the string, and
is the input spliced into that string?**

# Vulnerable patterns

**Python — shell interpretation + interpolation**
```python
os.system("ping -c 1 " + host)                       # os.system always uses a shell
os.popen(f"nslookup {domain}")
subprocess.run(f"convert {name} out.png", shell=True) # shell=True + string
subprocess.call("grep " + pattern + " file", shell=True)
subprocess.check_output(cmd, shell=True)              # cmd built from input
commands.getoutput("host " + arg)                     # legacy, uses shell
```

**Node — functions that spawn a shell**
```javascript
child_process.exec("nslookup " + domain, cb)          // exec uses /bin/sh
child_process.execSync(`ping ${host}`)
exec(`ffmpeg -i ${file} out.mp4`)
```

**Indirect** — input reaches a command via a helper, a template, an env var read
back into a command, or an argument that itself contains shell metacharacters
passed to a shell.

Dangerous metacharacters that make splicing exploitable: `; | & $() `` `` > < \n`
and, for argument-boundary attacks, spaces and quotes.

# Safe / mitigating patterns

- **Argument-vector exec without a shell** — the strongest signal of safety.
  Each argument is passed as a distinct list element and no shell parses it:
```python
subprocess.run(["ping", "-c", "1", host])            # shell defaults to False
subprocess.check_output(["git", "log", rev])
```
```javascript
child_process.execFile("ping", ["-c", "1", host])    // no shell
child_process.spawn("convert", [name, "out.png"])    // array args, no shell
```
Even attacker-controlled `host` here cannot inject a second command — it is a
single argv element. (Caveat: an attacker-controlled value used as the **program
name** or as an option like `--output=` can still be abused; and `spawn`/`exec*`
with `{shell: true}` re-introduces the shell — check the options object.)
- `shlex.quote(field)` applied to each interpolated value before a shell command.
- Strict allow-list of permitted values, or input constrained to a safe charset
  (validated integer, enum, `[A-Za-z0-9._-]+` with anchors).

# Decisive checks

1. Is there a shell? `os.system`/`os.popen`/`commands.*` always; `subprocess.*`
   only with `shell=True`; Node `exec`/`execSync` yes, `execFile`/`spawn` only
   with `{shell:true}`.
2. Is the tainted value spliced into the command **string** (vulnerable) or passed
   as a **separate argv element** to a non-shell exec (generally safe)?
3. Is there a real sanitizer for the shell context (`shlex.quote`, strict
   allow-list), or only irrelevant cleaning (HTML-escaping, `.strip()`)?

# Confidence calibration
- 8–10: tainted value concatenated/interpolated into a shell-interpreted command
  with no quoting/allow-list.
- 6–7: shell command built from input where taint is likely but one hop away, or
  quoting is present but incomplete (some fields unquoted).
- ≤5 / not vulnerable: argv-array exec with `shell=False`/`execFile`/`spawn`
  (no `shell:true`), or every interpolated field is `shlex.quote`-d or
  allow-listed.

State in the description whether a shell is involved and which fields are unquoted.
