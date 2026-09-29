"""Audit rules. Pure Python over the JSON produced by ``extract.py``.

Nothing in this module touches a browser or the network, so every rule can be
tested with a dict.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .autofill import (
    LOW_VALUE_FIELDS,
    NOT_A_NUMBER_FIELDS,
    NUMERIC_CODE_FIELDS,
    PASSWORD_FIELDS,
    PERSONAL_FIELDS,
    SENSITIVE_FIELDS,
    expected_input_type,
    infer_field,
    normalize,
    parse_autocomplete,
)

SEVERITIES = ("high", "medium", "low")
BUTTON_TYPES = frozenset({"submit", "image", "reset", "button"})
TEXTISH = frozenset({"text", "email", "tel", "url", "search", "password", "number", "textarea"})
MIN_TARGET = 24.0  # CSS px, WCAG 2.2 SC 2.5.8 Target Size (Minimum)
CSRF_NAME = re.compile(
    r"csrf|xsrf|authenticity_token|^_token$|requestverificationtoken|^_wpnonce$|nonce|form_key|^token$",
    re.I,
)
HONEYPOT_NAME = re.compile(r"honey|\bhp\b|^hp_|_hp$|trap|bot|leave|blank|do.?not.?fill|website|^url$|^fax$", re.I)
PASTE_BLOCK = re.compile(r"return\s+false|preventDefault\s*\(|returnValue\s*=\s*false")
ACCEPT_TOKEN = re.compile(r"^(\.[A-Za-z0-9][\w.+-]*|[a-z]+/(\*|[\w.+-]+))$", re.I)


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    rule: str
    target: str
    fix: str
    why: str
    form: str = ""


@dataclass
class PageReport:
    url: str
    final_url: str | None = None
    status: int | None = None
    title: str = ""
    error: str | None = None
    forms: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["counts"] = self.counts()
        return d


# ---------------------------------------------------------------- helpers


def accessible_name(c: dict) -> tuple[str, str | None]:
    """Simplified accname for form controls: (name, source)."""
    lb = c.get("labelledby")
    if lb and lb.get("text", "").strip():
        return lb["text"].strip(), "aria-labelledby"
    if (c.get("aria_label") or "").strip():
        return c["aria_label"].strip(), "aria-label"
    labels = [t for t in (c.get("labels_for") or []) + (c.get("labels_wrap") or []) if t and t.strip()]
    if labels:
        return " ".join(labels).strip(), "label"
    if (c.get("title") or "").strip():
        return c["title"].strip(), "title"
    if (c.get("placeholder") or "").strip():
        return c["placeholder"].strip(), "placeholder"
    return "", None


def button_name(b: dict) -> str:
    lb = b.get("labelledby")
    if lb and lb.get("text", "").strip():
        return lb["text"].strip()
    for key in ("aria_label", "content", "title"):
        if (b.get(key) or "").strip():
            return b[key].strip()
    if b.get("type") == "submit" and b.get("tag") == "input" and b.get("value_attr") is None:
        return "Submit"  # user-agent default label
    return ""


def is_submit(b: dict) -> bool:
    return b.get("type") in ("submit", "image")


def _visible_text(c: dict) -> list[str]:
    return [t for t in (c.get("labels_for") or []) + (c.get("labels_wrap") or []) if t]


def _label_texts(c: dict) -> list[str]:
    lb = c.get("labelledby") or {}
    return _visible_text(c) + [c.get("aria_label") or "", lb.get("text") or ""]


def control_field(c: dict) -> str | None:
    """Autofill field name inferred from name, id, labels and placeholder."""
    return infer_field(
        [c.get("name"), c.get("id"), *_label_texts(c), c.get("title"), c.get("placeholder")],
        c.get("tag", "input"),
        c.get("type") or "text",
    )


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _scheme(url: str | None) -> str:
    return (urlsplit(url or "").scheme or "").lower()


def _insecure(url: str | None) -> bool:
    """http:// to anything but loopback (browsers treat localhost as a secure context)."""
    host = _host(url)
    loopback = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
    return _scheme(url) == "http" and not loopback


LAYOUT_HIDDEN = frozenset({"offscreen", "zero-size", "clipped", "opacity-0"})
NOT_RENDERED = frozenset({"display-none", "visibility-hidden"})


def _rendered(c: dict) -> bool:
    """Has a real box on screen. An ancestor fading in (opacity 0) still counts."""
    return not set(c.get("hidden_reasons") or []) & (LAYOUT_HIDDEN | NOT_RENDERED)


def _is_hidden_field(c: dict, form: dict | None) -> bool:
    """A text field kept out of sight on purpose: a honeypot or a collapsed step.

    Custom-styled radios and checkboxes are often visually hidden behind their
    label, so only text-like fields and selects qualify.
    """
    if c.get("type") not in TEXTISH | {"select"}:
        return False
    reasons = set(c.get("hidden_reasons") or [])
    if reasons & LAYOUT_HIDDEN:
        return True
    return bool(reasons & NOT_RENDERED) and (form is None or form.get("visible", True))


def _paste_blockers(c: dict) -> list[str]:
    found = []
    if PASTE_BLOCK.search(c.get("onpaste_attr") or ""):
        found.append("onpaste attribute")
    if PASTE_BLOCK.search(c.get("onpaste_prop") or ""):
        found.append("onpaste property")
    if PASTE_BLOCK.search(c.get("ancestor_onpaste") or ""):
        found.append("onpaste on an ancestor")
    if any(PASTE_BLOCK.search(src or "") for src in c.get("paste_listeners") or []):
        found.append("paste event listener")
    return found


def _describedby_ids(c: dict) -> set[str]:
    ids: set[str] = set()
    for key in ("describedby", "errormessage"):
        ref = c.get(key) or {}
        ids |= set(ref.get("ids") or []) - set(ref.get("missing") or [])
    return ids


def circle_hits_rect(cx: float, cy: float, r: float, rect: dict) -> bool:
    nx = min(max(cx, rect["x"]), rect["x"] + rect["w"])
    ny = min(max(cy, rect["y"]), rect["y"] + rect["h"])
    return math.hypot(cx - nx, cy - ny) < r


def undersized_targets(targets: list[dict], minimum: float = MIN_TARGET) -> list[int]:
    """Indexes of targets that fail WCAG 2.5.8, applying the spacing exception.

    A target smaller than 24x24 passes if a 24 px circle centred on it does not
    intersect any other target, nor the 24 px circle of another small target.
    Each target is a dict with a ``rect`` of x, y, w, h in CSS px.
    """
    small = [i for i, t in enumerate(targets) if t["rect"]["w"] < minimum or t["rect"]["h"] < minimum]
    r = minimum / 2
    centers = {i: (t["rect"]["x"] + t["rect"]["w"] / 2, t["rect"]["y"] + t["rect"]["h"] / 2) for i, t in enumerate(targets)}
    failing = []
    for i in small:
        cx, cy = centers[i]
        bad = False
        for j, other in enumerate(targets):
            if j == i:
                continue
            if circle_hits_rect(cx, cy, r, other["rect"]):
                bad = True
                break
            if j in small and math.hypot(cx - centers[j][0], cy - centers[j][1]) < minimum:
                bad = True
                break
        if bad:
            failing.append(i)
    return failing


# ---------------------------------------------------------------- per control


def _control_findings(c: dict, ctx: dict) -> list[Finding]:
    out: list[Finding] = []
    sel = c["selector"]
    ctype = c.get("type") or "text"
    tag = c.get("tag", "input")

    def add(sev: str, rule: str, fix: str, why: str) -> None:
        out.append(Finding(sev, rule, sel, fix, why))

    # --- accessible name
    if not c.get("aria_hidden"):
        lb = c.get("labelledby")
        if lb and lb.get("missing"):
            ids = " ".join(lb["missing"])
            add("medium", "broken-labelledby", f'fix aria-labelledby on {sel}: no element with id "{ids}"',
                "the reference names nothing")
        name, source = accessible_name(c)
        hint = (c.get("placeholder") or c.get("name") or "").strip() or "..."
        if not name:
            fix = (f'add <label for="{c["id"]}">{hint}</label> for {sel}' if c.get("id")
                   else f"wrap {sel} in <label>{hint} ...</label>")
            add("high", "no-accessible-name", fix, "screen readers announce an unnamed field")
        elif source == "placeholder":
            fix = (f'add <label for="{c["id"]}">{name}</label> for {sel}' if c.get("id")
                   else f"wrap {sel} in <label>{name} ...</label>")
            add("medium", "placeholder-as-label", fix, "the placeholder is the only name and disappears while typing")
        elif source == "title":
            add("low", "title-as-label", f'add a visible <label> for {sel} (title="{name}" is its only name)',
                "title is not shown to touch or keyboard users")

    for key, attr in (("describedby", "aria-describedby"), ("errormessage", "aria-errormessage")):
        ref = c.get(key) or {}
        if ref.get("missing"):
            ids = " ".join(ref["missing"])
            add("medium", f"broken-{key}", f'fix {attr} on {sel}: no element with id "{ids}"',
                "help or error text is never announced")

    # --- errors and required
    invalid = (c.get("aria_invalid") or "").strip().lower()
    if c.get("aria_invalid") is not None and invalid not in ("true", "false", "grammar", "spelling", ""):
        add("low", "invalid-aria-invalid", f'change aria-invalid="{c["aria_invalid"]}" to "true" or "false" on {sel}',
            "unknown values are treated as true")
    linked = _describedby_ids(c)
    candidates = c.get("error_candidates") or []
    for e in candidates:
        if e.get("id") and e["id"] not in linked:
            current = (c.get("describedby") or {}).get("ids") or []
            value = " ".join([*current, e["id"]])
            add("medium", "unassociated-error-message", f'add aria-describedby="{value}" to {sel}',
                f'error text #{e["id"]} is not announced with the field')
        elif not e.get("id") and e.get("visible") and e.get("text"):
            add("low", "unassociated-error-message",
                f"give the error message next to {sel} an id and add it to aria-describedby on {sel}",
                f'"{e["text"][:40]}" is not announced with the field')
    if invalid == "true" and not linked and not any(e.get("id") for e in candidates):
        add("medium", "error-not-associated", f'add aria-describedby="<id of the error message>" to {sel}',
            "aria-invalid=true without a described error message")
    marked = any(re.search(r"\*|\brequired\b|\bobligatoire\b", t, re.I) for t in _label_texts(c) if t)
    if marked and not c.get("required") and (c.get("aria_required") or "").lower() != "true":
        add("medium", "required-not-exposed", f'add required (or aria-required="true") to {sel}',
            "the label marks it required but assistive tech is not told")

    if c.get("id_count", 0) > 1:
        add("medium", "duplicate-id", f'make id="{c["id"]}" unique ({c["id_count"]} elements share it)',
            "labels and aria references bind to the first one only")
    if c.get("form_attr") and c.get("form_index") is None:
        add("medium", "broken-form-attribute", f'fix form="{c["form_attr"]}" on {sel}: no <form id="{c["form_attr"]}">',
            "the field is not submitted with any form")

    # --- file inputs
    if ctype == "file":
        accept = c.get("accept")
        if accept is None or not accept.strip():
            add("low", "file-accept-missing", f'add accept="..." (e.g. accept=".pdf,.jpg,.png") to {sel}',
                "the file picker shows every file type")
        else:
            bad = [t.strip() for t in accept.split(",") if t.strip() and not ACCEPT_TOKEN.match(t.strip())]
            if bad:
                add("low", "file-accept-invalid", f'fix accept on {sel}: "{bad[0]}" is not a MIME type or .extension',
                    "browsers ignore invalid accept tokens")

    # --- paste
    if ctype in TEXTISH:
        blockers = _paste_blockers(c)
        if blockers:
            sev = "high" if ctype == "password" else "medium"
            add(sev, "paste-blocked", f"remove the paste-blocking handler ({', '.join(blockers)}) from {sel}",
                "blocking paste breaks password managers (WCAG 3.3.8)" if ctype == "password"
                else "users cannot paste into the field")

    # --- autocomplete, types, keyboards
    ac_raw = c.get("autocomplete")
    ac = parse_autocomplete(ac_raw) if ac_raw is not None else None
    if ctype == "password":
        out.extend(_password_findings(c, ac, ctx, sel))
        return out

    inferred = control_field(c)
    if ctx.get("has_password") and inferred in ("email", "username"):
        wanted, allowed = "username", {"username", "email"}
    else:
        wanted, allowed = inferred, {inferred}
    if ac and not ac.valid:
        fix = (f'change autocomplete="{ac.raw}" to autocomplete="{wanted}" on {sel}' if wanted
               else f'fix autocomplete="{ac.raw}" on {sel}: {ac.problem}')
        add("medium", "invalid-autocomplete", fix, f"browsers ignore it: {ac.problem}")
    elif wanted and (ac is None or ac.field in (None, "on")):
        sev = "low" if wanted in LOW_VALUE_FIELDS else "medium"
        add(sev, "missing-autocomplete", f'add autocomplete="{wanted}" to {sel}', "lets browsers and password managers fill it")
    elif wanted and ac.field == "off" and wanted in PERSONAL_FIELDS:
        add("low", "autocomplete-off", f'change autocomplete="off" to autocomplete="{wanted}" on {sel}',
            "users have to type personal details by hand")
    field_name = ac.field if ac and ac.valid and ac.field not in (None, "on", "off") else (wanted if wanted in allowed else None)
    if tag == "input" and field_name:
        expected = expected_input_type(field_name)
        mode = (c.get("inputmode") or "").lower()
        if ctype == "number" and field_name in NOT_A_NUMBER_FIELDS:
            add("medium", "number-type-misuse", f'change type="number" to type="text" inputmode="numeric" on {sel}',
                "number inputs drop leading zeros, add spinners and change on scroll")
        elif expected == "url" and ctype == "text" and mode != "url":
            # type="url" rejects "example.com" without a scheme; inputmode keeps free text
            add("low", "inputmode", f'add inputmode="url" to {sel}', "shows the URL keyboard on phones")
        elif expected and ctype == "text" and mode != expected:
            add("medium", "input-type", f'change type="{c.get("type_attr") or "text"}" to type="{expected}" on {sel}',
                f"mobile users get the {expected} keyboard and browsers validate it")
        elif field_name in NUMERIC_CODE_FIELDS and ctype == "text" and mode not in ("numeric", "decimal"):
            add("low", "inputmode", f'add inputmode="numeric" to {sel}', "shows the number pad on phones")
    return out


def _password_findings(c: dict, ac, ctx: dict, sel: str) -> list[Finding]:
    out: list[Finding] = []
    text = normalize(" ".join(filter(None, [c.get("name"), c.get("id"), *_label_texts(c), c.get("placeholder")])))
    new = ctx.get("password_count", 0) >= 2 or ctx.get("signup") or re.search(
        r"\b(new|confirm|repeat|retype|verify|register|signup|sign up|create|choose)\b", text)
    wanted = "new-password" if new else "current-password"
    if ac is None or ac.field in (None, "on"):
        out.append(Finding("medium", "password-autocomplete", sel, f'add autocomplete="{wanted}" to {sel}',
                           "password managers need it to save and fill the right password"))
    elif ac.field == "off":
        out.append(Finding("medium", "password-autocomplete", sel,
                           f'change autocomplete="off" to autocomplete="{wanted}" on {sel}',
                           "off fights password managers and pushes users to weak passwords"))
    elif not ac.valid:
        out.append(Finding("medium", "invalid-autocomplete", sel,
                           f'change autocomplete="{ac.raw}" to autocomplete="{wanted}" on {sel}',
                           f"browsers ignore it: {ac.problem}"))
    elif ac.field not in PASSWORD_FIELDS | {"one-time-code"}:
        out.append(Finding("medium", "password-autocomplete", sel,
                           f'change autocomplete="{ac.raw}" to autocomplete="{wanted}" on {sel}',
                           "a password field should use new-password or current-password"))
    maxlength = c.get("maxlength")
    if maxlength and str(maxlength).isdigit() and int(maxlength) < 64:
        out.append(Finding("low", "password-maxlength", sel, f'raise maxlength="{maxlength}" on {sel} to at least 64 (or remove it)',
                           "long passphrases and generated passwords get cut"))
    return out


# ---------------------------------------------------------------- per form


def _group_findings(page: dict, form: dict | None, controls: list[dict], buttons: list[dict],
                    hidden: list[dict]) -> tuple[list[Finding], list[Finding], dict]:
    label = form["selector"] if form else "(controls outside any form)"
    findings: list[Finding] = []
    notes: list[Finding] = []

    def note(target: str, text: str, rule: str) -> None:
        notes.append(Finding("info", rule, target, text, "", label))

    active = [c for c in controls if not _is_hidden_field(c, form)]
    shadow = [c for c in controls if _is_hidden_field(c, form)]
    passwords = [c for c in active if c.get("type") == "password"]
    signup_text = normalize(" ".join(filter(None, [form and form.get("id"), form and form.get("name"),
                                                   form and form.get("action_attr"), page.get("url")])))
    ctx = {
        "has_password": bool(passwords),
        "password_count": len(passwords),
        "signup": bool(re.search(r"\b(register|signup|sign up|join|create|start)\b", signup_text)) and bool(passwords),
    }
    for c in active:
        findings.extend(_control_findings(c, ctx))

    # radio and checkbox groups
    groups: dict[str, list[dict]] = {}
    for c in active:
        if c.get("type") in ("radio", "checkbox") and c.get("name"):
            groups.setdefault(f'{c["type"]}:{c["name"]}', []).append(c)
    for key, members in groups.items():
        if len(members) < 2:
            continue
        g = members[0].get("group") or {}
        if not (g.get("legend") or g.get("role_group_name")):
            kind, name = key.split(":", 1)
            findings.append(Finding("low", "group-label", f'input[name="{name}"]',
                                    f'wrap the name="{name}" {kind} buttons in <fieldset> with a <legend>',
                                    "the question is not announced with the options"))

    # honeypots and other hidden text fields
    for c in shadow:
        if c.get("type") not in TEXTISH:
            continue
        how = ", ".join(c.get("hidden_reasons") or []) or "hidden"
        ident = " ".join(filter(None, [c.get("name"), c.get("id"), c.get("class"), *_label_texts(c)]))
        kind = "looks like a honeypot" if HONEYPOT_NAME.search(ident) else "possible honeypot or collapsed step"
        note(c["selector"], f"hidden text field {c['selector']} ({how}): {kind}", "honeypot")
        focusable = not set(c.get("hidden_reasons") or []) & {"display-none", "visibility-hidden"}
        if focusable and c.get("tabindex") != "-1" and not c.get("disabled"):
            findings.append(Finding("low", "honeypot-focusable", c["selector"],
                                    f'add tabindex="-1" autocomplete="off" to {c["selector"]}',
                                    "keyboard users can tab into it and autofill can fill it, flagging real people as bots"))

    # touch targets
    targets = [c for c in active + buttons if _rendered(c) and not c.get("disabled") and c.get("rect")]
    for i in undersized_targets(targets):
        t = targets[i]
        if t.get("type") in ("radio", "checkbox") and _visible_text(t):
            continue  # its label is an equivalent, larger target
        w, h = round(t["rect"]["w"]), round(t["rect"]["h"])
        sev = "medium" if t.get("type") in BUTTON_TYPES else "low"
        findings.append(Finding(sev, "touch-target", t["selector"],
                                f"make {t['selector']} at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now {w}x{h})",
                                "WCAG 2.2 SC 2.5.8 target size"))

    submits = [b for b in buttons if is_submit(b)]
    for b in submits:
        if b.get("tag") == "input" and b.get("type") == "image" and not (b.get("alt") or "").strip():
            findings.append(Finding("high", "unnamed-submit", b["selector"], f'add alt="..." to {b["selector"]}',
                                    "an image button without alt has no name"))
        elif not button_name(b):
            findings.append(Finding("high", "unnamed-submit", b["selector"],
                                    f'add visible text or aria-label="..." to {b["selector"]}',
                                    "screen readers announce just \"button\""))

    summary = {"form": label, "fields": len(active), "submit": bool(submits)}
    if form is None:
        findings = [dataclass_replace(f, form=label) for f in findings]
        return findings, notes, summary

    # --- method, action
    method = (form.get("method_attr") or "get").strip().lower()
    if method not in ("get", "post", "dialog"):
        method = "get"
    action = form.get("action") or page.get("url") or ""
    summary.update(method=method.upper(), action=action, host=_host(action))
    fsel = form["selector"]
    fields = {control_field(c) for c in active} | {
        (parse_autocomplete(c["autocomplete"]).field if c.get("autocomplete") else None) for c in active
    }
    if passwords:
        fields.add("current-password")
    collects = bool(active)
    if method != "dialog" and collects:
        if _insecure(page.get("url")):
            findings.append(Finding("high", "insecure-page", fsel, f"serve {page.get('url')} over https",
                                    "the form can be read and altered in transit"))
        elif _insecure(action):
            findings.append(Finding("high", "insecure-action", fsel,
                                    f'change action="{form["action_attr"]}" to an https:// URL on {fsel}',
                                    "the data is sent unencrypted"))
        for b in buttons:
            if is_submit(b) and _insecure(b.get("formaction")):
                findings.append(Finding("high", "insecure-action", b["selector"],
                                        f"change formaction to an https:// URL on {b['selector']}",
                                        "the data is sent unencrypted"))
        if action and _host(action) and _host(page.get("url")) and _host(action) != _host(page.get("url")):
            note(fsel, f"{fsel} sends data to another host: {_host(action)}", "cross-host-action")
    if method == "get":
        if passwords:
            findings.append(Finding("high", "password-in-get", fsel, f'change method="get" to method="post" on {fsel}',
                                    "the password ends up in the URL, history and server logs"))
        elif fields & SENSITIVE_FIELDS:
            findings.append(Finding("high", "sensitive-get", fsel, f'change method="get" to method="post" on {fsel}',
                                    "card or one-time codes end up in the URL and logs"))
        elif fields & PERSONAL_FIELDS:
            findings.append(Finding("medium", "sensitive-get", fsel, f'change method="get" to method="post" on {fsel}',
                                    "personal details end up in the URL, history and server logs"))
    if (form.get("autocomplete_attr") or "").strip().lower() == "off" and fields & (PERSONAL_FIELDS | PASSWORD_FIELDS):
        findings.append(Finding("medium", "form-autocomplete-off", fsel, f'remove autocomplete="off" from {fsel}',
                                "it disables autofill for every field in the form"))

    # --- submit button
    if collects and not submits and method != "dialog":
        plain = [b for b in buttons if b.get("type") == "button"]
        if len(plain) == 1:
            fix = f'change type="button" to type="submit" on {plain[0]["selector"]}'
        else:
            fix = f'add <button type="submit">...</button> to {fsel}'
        findings.append(Finding("medium", "no-submit-button", fsel, fix, "Enter does not submit and the action is not a real button"))

    # --- informational: tokens, captcha
    csrf = [h for h in hidden if CSRF_NAME.search(h.get("name") or h.get("id") or "")]
    summary["csrf"] = bool(csrf)
    for h in csrf:
        note(fsel, f'CSRF-style token field: {h.get("name") or h.get("id")}', "csrf-token")
    for h in hidden:
        if h in csrf:
            continue
        shape = h.get("value_shape")
        if shape in ("jwt", "signed", "hex", "base64"):
            note(fsel, f'hidden field {h.get("name") or h.get("id")} holds a signed/opaque token '
                       f'({h.get("value_length")} chars, {shape})', "signed-token")
        elif shape == "timestamp":
            note(fsel, f'hidden field {h.get("name") or h.get("id")} holds a timestamp (time-trap anti-spam?)',
                 "signed-token")
    if method == "post" and collects and not csrf:
        note(fsel, "no CSRF-looking hidden field (protection may use SameSite cookies, headers or a signed token)",
             "no-csrf-token")

    caps: dict[str, bool] = {}
    for w in page.get("captcha") or []:
        if w.get("form_index") == form.get("index"):
            caps[w["kind"]] = caps.get(w["kind"], False) or (w.get("visible") and not w.get("badge") and not w.get("invisible_mode"))
    for kind, visible in caps.items():
        note(fsel, f"{kind} widget ({'visible challenge' if visible else 'invisible or badge only'})", "captcha")
    summary["captcha"] = ", ".join(f"{k} ({'visible' if v else 'invisible'})" for k, v in caps.items())
    findings = [dataclass_replace(f, form=label) for f in findings]
    return findings, notes, summary


def dataclass_replace(f: Finding, **changes) -> Finding:
    return Finding(**{**asdict(f), **changes})


# ---------------------------------------------------------------- page


def audit_page(page: dict) -> PageReport:
    """Run every rule over one extracted page."""
    report = PageReport(url=page.get("requested_url") or page.get("url") or "", final_url=page.get("url"),
                        status=page.get("status"), title=page.get("title") or "", error=page.get("error"))
    if report.error:
        return report
    forms = page.get("forms") or []
    controls = page.get("controls") or []
    buttons = page.get("buttons") or []
    hidden = page.get("hidden") or []
    groups: list[dict | None] = list(forms)
    if any(c.get("form_index") is None for c in controls):
        groups.append(None)
    for form in groups:
        idx = form["index"] if form else None
        f, n, s = _group_findings(
            page,
            form,
            [c for c in controls if c.get("form_index") == idx],
            [b for b in buttons if b.get("form_index") == idx],
            [h for h in hidden if h.get("form_index") == idx],
        )
        if form is not None or f or n:
            report.findings.extend(f)
            report.notes.extend(n)
            report.forms.append(s)

    for bl in page.get("broken_labels") or []:
        report.findings.append(Finding("medium", "broken-label-for", f'label[for="{bl["for"]}"]',
                                       f'fix <label for="{bl["for"]}">: no form field has id="{bl["for"]}"',
                                       "the label names nothing"))
    in_forms = {w.get("form_index") for w in page.get("captcha") or []}
    if page.get("captcha_scripts") and in_forms <= {None}:
        for s in page["captcha_scripts"]:
            report.notes.append(Finding("info", "captcha", "page", f"CAPTCHA script loaded: {s}", ""))
    blocked = page.get("blocked_requests") or []
    if blocked:
        sample = ", ".join(f"{b['method']} {b['url']}" for b in blocked[:3])
        report.notes.append(Finding("info", "blocked-requests", "page",
                                    f"blocked {len(blocked)} non-GET request(s) made by the page's own scripts: {sample}", ""))
    for n in page.get("load_notes") or []:
        report.notes.append(Finding("info", "load", "page", n, ""))

    # de-duplicate (duplicate ids repeat on every element that shares them)
    seen = set()
    unique = []
    for f in report.findings:
        key = (f.rule, f.fix)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    report.findings = sorted(unique, key=lambda f: order[f.severity])
    return report


def exit_code(reports: list[PageReport], fail_on: str = "high") -> int:
    """0 = nothing at or above ``fail_on``, 1 = issues, 2 = a page could not be loaded."""
    if any(r.error for r in reports):
        return 2
    if fail_on == "never":
        return 0
    limit = SEVERITIES.index(fail_on)
    worst = [f for r in reports for f in r.findings if SEVERITIES.index(f.severity) <= limit]
    return 1 if worst else 0
