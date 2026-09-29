"""Headless Chromium against a local fixture site. No internet needed."""

from form_audit.rules import audit_page


def _rules(page):
    return {f.rule for f in audit_page(page).findings}


def test_never_submits_anything(site, extracted):
    methods = {method for method, _ in site["log"]}
    assert methods <= {"GET", "HEAD"}
    assert not [p for m, p in site["log"] if m == "POST"]
    # the beacon page tried to POST twice by itself; both were stopped in the browser
    blocked = extracted["beacon.html"]["blocked_requests"]
    assert len(blocked) == 2 and {b["method"] for b in blocked} == {"POST"}


def test_extraction_shape(extracted):
    bad = extracted["bad.html"]
    assert bad["status"] == 200
    assert [f["selector"] for f in bad["forms"]] == ["form#contact", "form#login"]
    email = next(c for c in bad["controls"] if c["name"] == "email")
    assert email["placeholder"] == "Email" and email["labels_for"] == []
    phone = next(c for c in bad["controls"] if c["name"] == "phone")
    assert phone["labels_for"] == ["Phone *"]
    assert phone["describedby"]["missing"] == ["phone-help"]
    company = next(c for c in bad["controls"] if c["name"] == "company")
    assert company["labels_wrap"] == ["Company"]
    honeypot = next(c for c in bad["controls"] if c["name"] == "website")
    assert not honeypot["visible"] and "offscreen" in honeypot["hidden_reasons"]
    search = next(c for c in bad["controls"] if c["name"] == "q")
    assert search["form_index"] is None and search["form_attr"] == "missing-form"
    token = next(h for h in bad["hidden"] if h["name"] == "_token")
    assert token["value_shape"] == "hex" and "value" not in token  # values are never exported
    assert bad["broken_labels"][0]["for"] == "nowhere"


def test_findings_on_bad_page(extracted):
    found = _rules(extracted["bad.html"])
    assert {
        "placeholder-as-label", "missing-autocomplete", "input-type", "invalid-autocomplete", "number-type-misuse",
        "unassociated-error-message", "required-not-exposed", "broken-describedby", "broken-label-for",
        "paste-blocked", "password-in-get", "insecure-action", "unnamed-submit", "no-submit-button",
        "touch-target", "group-label", "file-accept-missing", "honeypot-focusable", "broken-form-attribute",
    } <= found


def test_good_page_is_clean(extracted):
    report = audit_page(extracted["good.html"])
    assert report.findings == []
    notes = [n.fix for n in report.notes]
    assert "CSRF-style token field: csrfmiddlewaretoken" in notes
    assert any("hp_field" in n and "honeypot" in n for n in notes)


def test_paste_listener_found_through_devtools(extracted):
    email = next(c for c in extracted["beacon.html"]["controls"] if c["name"] == "email")
    assert any("preventDefault" in src for src in email["paste_listeners"])
    assert "paste-blocked" in _rules(extracted["beacon.html"])


def test_unreachable_url_is_an_error():
    from form_audit.extract import extract_pages

    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    [page] = extract_pages([f"http://127.0.0.1:{port}/"], timeout=10)
    assert page["error"]
    assert audit_page(page).error
