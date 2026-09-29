"""Markdown and JSON output."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from . import __version__
from .rules import SEVERITIES, PageReport


def _short_action(action: str, page_url: str) -> str:
    a, p = urlsplit(action or ""), urlsplit(page_url or "")
    if a.scheme == p.scheme and a.netloc == p.netloc:
        return (a.path or "/") + (f"?{a.query}" if a.query else "")
    return action or "-"


def _totals(reports: list[PageReport]) -> dict[str, int]:
    return {s: sum(r.counts()[s] for r in reports) for s in SEVERITIES}


def to_markdown(reports: list[PageReport]) -> str:
    lines = ["# Form audit", "",
             "Read-only: pages loaded with GET only; nothing was typed, clicked or submitted.", ""]
    for r in reports:
        lines.append(f"## {r.url}")
        lines.append("")
        if r.error:
            lines += [f"ERROR: {r.error}", ""]
            continue
        n_forms = sum(1 for f in r.forms if f["form"] != "(controls outside any form)")
        c = r.counts()
        head = f"HTTP {r.status}" if r.status else "loaded"
        if r.final_url and r.final_url != r.url:
            head += f" (now {r.final_url})"
        lines += [f"{head}, {n_forms} form(s). **{c['high']} high, {c['medium']} medium, {c['low']} low**", ""]
        if r.forms:
            lines += ["| Form | Method | Action | Fields | Submit | CAPTCHA | CSRF field |", "|---|---|---|---|---|---|---|"]
            for f in r.forms:
                lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                    f"`{f['form']}`", f.get("method", "-"), _short_action(f.get("action", ""), r.final_url or r.url),
                    f["fields"], "yes" if f["submit"] else "no", f.get("captcha") or "-",
                    "-" if "csrf" not in f else ("yes" if f["csrf"] else "no")))
            lines.append("")
        for sev in SEVERITIES:
            items = [f for f in r.findings if f.severity == sev]
            if items:
                lines.append(f"### {sev.capitalize()}")
                lines += [f"- `{f.fix}` ({f.rule}: {f.why})" for f in items]
                lines.append("")
        if r.notes:
            lines.append("### Notes (informational)")
            lines += [f"- {n.fix}" for n in r.notes]
            lines.append("")
    t = _totals(reports)
    lines.append(f"Total: {t['high']} high, {t['medium']} medium, {t['low']} low across {len(reports)} page(s)")
    return "\n".join(lines) + "\n"


def to_json(reports: list[PageReport]) -> str:
    doc = {
        "tool": "form-audit",
        "version": __version__,
        "read_only": True,
        "pages": [r.to_dict() for r in reports],
        "totals": _totals(reports),
    }
    return json.dumps(doc, indent=2) + "\n"
