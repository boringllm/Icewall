"""Human-readable markdown report."""
from __future__ import annotations

from icewall.schemas import ScanResult, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "⚪ INFO",
}


def to_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# Icewall Security Report")
    a("")
    a(f"**Target:** `{result.target}`")
    a("")

    # Summary counts by severity.
    counts = {s: 0 for s in _SEV_ORDER}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    st = result.stats
    a("## Summary")
    a("")
    a(f"- **Findings:** {len(result.findings)} confirmed "
      f"({', '.join(f'{counts[s]} {s.value}' for s in _SEV_ORDER if counts[s])})")
    a(f"- **Scanned:** {st.files_scanned} files, {st.symbols} symbols, "
      f"{st.entry_points} entry points, {st.candidate_paths} candidate paths")
    a(f"- **Pipeline:** {st.findings_raw} raw → {st.findings_confirmed} confirmed after validation")
    cost_str = "free (mock provider)" if st.estimated_cost_usd == 0 else f"~${st.estimated_cost_usd:.4f} (estimated)"
    a(f"- **Cost:** {cost_str} — {st.llm_calls} LLM calls, "
      f"{st.input_tokens + st.output_tokens:,} tokens, {st.duration_seconds}s")
    if st.cost_by_model and st.estimated_cost_usd > 0:
        a("")
        a("| Model | Calls | Tokens | Cost |")
        a("|---|--:|--:|--:|")
        for model, row in sorted(st.cost_by_model.items(), key=lambda kv: -kv[1]["cost_usd"]):
            a(f"| `{model}` | {row['calls']} | "
              f"{row['input_tokens'] + row['output_tokens']:,} | ${row['cost_usd']:.4f} |")
    a("")

    if not result.findings:
        a("_No confirmed vulnerabilities._")
        return "\n".join(lines)

    a("## Findings")
    a("")
    for i, f in enumerate(result.findings, 1):
        a(f"### {i}. {_SEV_BADGE.get(f.severity, f.severity.value)} — {f.title}")
        a("")
        a(f"- **Location:** `{f.location.as_ref()}`")
        if f.cwe:
            a(f"- **CWE:** {f.cwe}")
        a(f"- **Confidence:** {f.confidence}/10"
          + (f" · **Verdict:** {f.verdict.value}" if f.verdict else ""))
        if f.entry_point:
            a(f"- **Entry point:** `{f.entry_point}`")
        if f.sink:
            a(f"- **Sink:** `{f.sink}`")
        if f.call_chain:
            chain = " → ".join(f"`{s.symbol}`" for s in f.call_chain)
            a(f"- **Data flow:** {chain}")
        a("")
        if f.description:
            a(f.description)
            a("")
        if f.validation_notes:
            a(f"> **Validator:** {f.validation_notes}")
            a("")
        if f.remediation:
            r = f.remediation
            a(f"**Proposed remediation** (confidence {r.confidence}/10 — _proposal for review, not applied_):")
            a("")
            a(r.summary)
            if r.rationale:
                a("")
                a(f"_{r.rationale}_")
            if r.diff:
                a("")
                a("```diff")
                a(r.diff.rstrip())
                a("```")
            a("")
        a("---")
        a("")

    return "\n".join(lines)
