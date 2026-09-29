from form_audit.rules import accessible_name, audit_page, button_name, exit_code, undersized_targets

PAGE_URL = "https://shop.example/contact"


def ctl(**kw):
    c = {
        "tag": "input", "type": "text", "name": None, "id": None, "selector": "input#x", "form_index": 0,
        "visible": True, "hidden_reasons": [], "rect": {"x": 0, "y": 0, "w": 200, "h": 40},
        "labels_for": ["Field"], "labels_wrap": [], "autocomplete": None,
    }
    c.update(kw)
    return c


def btn(**kw):
    b = {"tag": "button", "type": "submit", "selector": "button#go", "form_index": 0, "visible": True,
         "rect": {"x": 0, "y": 100, "w": 120, "h": 44}, "content": "Send"}
    b.update(kw)
    return b


def page(controls=(), buttons=None, hidden=(), form=None, url=PAGE_URL, **extra):
    f = {"index": 0, "selector": "form#f", "method_attr": "post", "action_attr": "/send",
         "action": "https://shop.example/send", "visible": True}
    f.update(form or {})
    p = {"url": url, "forms": [f], "controls": list(controls),
         "buttons": [btn()] if buttons is None else list(buttons), "hidden": list(hidden)}
    p.update(extra)
    return p


def rules(report, severity=None):
    return [f.rule for f in report.findings if severity is None or f.severity == severity]


def fixes(report):
    return [f.fix for f in report.findings]


# ---------------------------------------------------------------- names


def test_clean_form_has_no_findings():
    r = audit_page(page([ctl(name="email", id="email", type="email", autocomplete="email", labels_for=["Email"],
                             selector="input#email")]))
    assert r.findings == []


def test_no_accessible_name_is_high():
    r = audit_page(page([ctl(id="q1", labels_for=[], selector="input#q1")]))
    assert ("high", "no-accessible-name") in [(f.severity, f.rule) for f in r.findings]
    assert 'add <label for="q1">...</label> for input#q1' in fixes(r)


def test_placeholder_as_label():
    r = audit_page(page([ctl(name="email", id="email", type="email", autocomplete="email", labels_for=[],
                             placeholder="Email", selector="input#email")]))
    assert rules(r) == ["placeholder-as-label"]
    assert fixes(r) == ['add <label for="email">Email</label> for input#email']


def test_placeholder_without_id_suggests_wrapping():
    r = audit_page(page([ctl(labels_for=[], placeholder="Message", tag="textarea", type="textarea",
                             selector="textarea[name=\"msg\"]")]))
    assert fixes(r) == ['wrap textarea[name="msg"] in <label>Message ...</label>']


def test_name_sources_priority():
    assert accessible_name(ctl(aria_label="A", labels_for=["B"])) == ("A", "aria-label")
    lb = {"ids": ["h"], "missing": [], "text": "Heading"}
    assert accessible_name(ctl(labelledby=lb, aria_label="A")) == ("Heading", "aria-labelledby")
    assert accessible_name(ctl(labels_for=[], title="T")) == ("T", "title")
    assert accessible_name(ctl(labels_for=[""], labels_wrap=["  "])) == ("", None)


def test_broken_labelledby_and_describedby():
    r = audit_page(page([ctl(labels_for=[], labelledby={"ids": ["gone"], "missing": ["gone"], "text": ""},
                             describedby={"ids": ["help"], "missing": ["help"], "text": ""})]))
    assert {"broken-labelledby", "broken-describedby", "no-accessible-name"} <= set(rules(r))
    assert not {"broken-labelledby"} & set(rules(r, "high"))


def test_aria_hidden_control_is_not_named():
    r = audit_page(page([ctl(labels_for=[], aria_hidden=True)]))
    assert "no-accessible-name" not in rules(r)


# ---------------------------------------------------------------- autocomplete and keyboards


def test_missing_autocomplete_exact_fix():
    r = audit_page(page([ctl(name="email", id="email", type="email", selector="input#email")]))
    assert fixes(r) == ['add autocomplete="email" to input#email']
    assert r.findings[0].severity == "medium"


def test_invalid_autocomplete_suggests_valid_token():
    r = audit_page(page([ctl(name="company", autocomplete="company-name", selector="input#company")]))
    assert fixes(r) == ['change autocomplete="company-name" to autocomplete="organization" on input#company']


def test_invalid_autocomplete_without_inference():
    r = audit_page(page([ctl(name="xyz", autocomplete="nope")]))
    assert r.findings[0].rule == "invalid-autocomplete"
    assert "not an autofill field name" in r.findings[0].fix


def test_valid_but_different_token_is_respected():
    r = audit_page(page([ctl(name="email", type="email", autocomplete="section-work email")]))
    assert r.findings == []


def test_type_text_for_email_and_tel():
    r = audit_page(page([ctl(name="email", autocomplete="email", selector="input#e"),
                         ctl(name="phone", autocomplete="tel", selector="input#p")]))
    assert fixes(r) == ['change type="text" to type="email" on input#e', 'change type="text" to type="tel" on input#p']


def test_inputmode_satisfies_keyboard_rule():
    r = audit_page(page([ctl(name="phone", autocomplete="tel", inputmode="tel")]))
    assert r.findings == []


def test_number_type_for_postal_code():
    r = audit_page(page([ctl(name="postal", type="number", autocomplete="postal-code")]))
    assert rules(r) == ["number-type-misuse"]
    assert 'type="text" inputmode="numeric"' in r.findings[0].fix


def test_one_time_code_wants_numeric_keyboard():
    r = audit_page(page([ctl(name="otp", autocomplete="one-time-code")]))
    assert fixes(r) == ['add inputmode="numeric" to input#x']


def test_login_identifier_suggests_username():
    r = audit_page(page([
        ctl(name="email", type="email", selector="input#u"),
        ctl(name="pw", type="password", autocomplete="current-password", selector="input#pw"),
    ]))
    assert fixes(r) == ['add autocomplete="username" to input#u']


def test_login_identifier_accepts_email_token():
    r = audit_page(page([
        ctl(name="email", type="email", autocomplete="email"),
        ctl(name="pw", type="password", autocomplete="current-password", selector="input#pw"),
    ]))
    assert r.findings == []


def test_autocomplete_off_on_personal_field_and_form():
    r = audit_page(page([ctl(name="email", type="email", autocomplete="off")], form={"autocomplete_attr": "off"}))
    assert {"autocomplete-off", "form-autocomplete-off"} == set(rules(r))
    assert 'remove autocomplete="off" from form#f' in fixes(r)


# ---------------------------------------------------------------- passwords


def test_password_current_vs_new():
    login = audit_page(page([ctl(name="pw", type="password", selector="input#pw")]))
    assert fixes(login) == ['add autocomplete="current-password" to input#pw']
    signup = audit_page(page([ctl(name="pw", type="password", selector="input#a"),
                              ctl(name="pw2", type="password", selector="input#b", labels_for=["Confirm password"])]))
    assert fixes(signup) == ['add autocomplete="new-password" to input#a', 'add autocomplete="new-password" to input#b']


def test_password_autocomplete_off_and_maxlength():
    r = audit_page(page([ctl(name="password", type="password", autocomplete="off", maxlength="20")]))
    assert rules(r) == ["password-autocomplete", "password-maxlength"]
    assert fixes(r)[0] == 'change autocomplete="off" to autocomplete="current-password" on input#x'


def test_paste_blocked_detection():
    r = audit_page(page([ctl(name="password", type="password", autocomplete="current-password",
                             onpaste_attr="return false;")]))
    assert [(f.severity, f.rule) for f in r.findings] == [("high", "paste-blocked")]
    r = audit_page(page([ctl(name="email2", type="email", labels_for=["Confirm email"], autocomplete="email",
                             paste_listeners=["(e) => { e.preventDefault(); }"])]))
    assert [(f.severity, f.rule) for f in r.findings] == [("medium", "paste-blocked")]
    r = audit_page(page([ctl(type="text", paste_listeners=["function (e) { track(e) }"])]))
    assert "paste-blocked" not in rules(r)


def test_password_in_get_form():
    r = audit_page(page([ctl(name="pw", type="password", autocomplete="current-password")],
                        form={"method_attr": "get"}))
    assert rules(r, "high") == ["password-in-get"]
    assert fixes(r) == ['change method="get" to method="post" on form#f']


def test_missing_method_defaults_to_get():
    r = audit_page(page([ctl(name="email", type="email", autocomplete="email")], form={"method_attr": None}))
    assert rules(r) == ["sensitive-get"]


def test_search_form_get_is_fine():
    r = audit_page(page([ctl(name="q", type="search", aria_label="Search", labels_for=[])],
                        form={"method_attr": "get"}))
    assert r.findings == []


# ---------------------------------------------------------------- transport


def test_insecure_action_and_page():
    r = audit_page(page([ctl()], form={"action_attr": "http://shop.example/send", "action": "http://shop.example/send"}))
    assert rules(r, "high") == ["insecure-action"]
    r = audit_page(page([ctl()], url="http://shop.example/contact",
                        form={"action": "http://shop.example/send"}))
    assert rules(r, "high") == ["insecure-page"]


def test_localhost_is_a_secure_context():
    r = audit_page(page([ctl()], url="http://127.0.0.1:5000/", form={"action": "http://127.0.0.1:5000/send"}))
    assert r.findings == []


def test_cross_host_action_is_a_note():
    r = audit_page(page([ctl()], form={"action": "https://forms.example.net/f/1"}))
    assert r.findings == []
    assert [n.rule for n in r.notes] == ["cross-host-action", "no-csrf-token"]


# ---------------------------------------------------------------- errors and required


def test_error_message_by_id_convention():
    r = audit_page(page([ctl(id="email", name="email", type="email", autocomplete="email", selector="input#email",
                             describedby={"ids": ["hint"], "missing": [], "text": "We never share it"},
                             error_candidates=[{"id": "email-error", "text": "", "visible": False, "how": "id"}])]))
    assert fixes(r) == ['add aria-describedby="hint email-error" to input#email']


def test_aria_invalid_without_description():
    r = audit_page(page([ctl(aria_invalid="true")]))
    assert rules(r) == ["error-not-associated"]
    ok = audit_page(page([ctl(aria_invalid="true", errormessage={"ids": ["e"], "missing": [], "text": "Bad"})]))
    assert ok.findings == []
    odd = audit_page(page([ctl(aria_invalid="yes")]))
    assert rules(odd) == ["invalid-aria-invalid"]


def test_required_mark_not_exposed():
    r = audit_page(page([ctl(labels_for=["Budget *"])]))
    assert rules(r) == ["required-not-exposed"]
    assert audit_page(page([ctl(labels_for=["Budget *"], required=True)])).findings == []
    assert audit_page(page([ctl(labels_for=["Budget *"], aria_required="true")])).findings == []


def test_duplicate_id_reported_once():
    r = audit_page(page([ctl(id="dup", id_count=2, selector="input#a"), ctl(id="dup", id_count=2, selector="input#b")]))
    assert rules(r) == ["duplicate-id"]


def test_broken_label_and_form_attribute():
    r = audit_page(page([ctl(form_index=None, form_attr="nope", selector="input#s")],
                        broken_labels=[{"for": "ghost", "text": "Ghost", "form_index": 0}]))
    assert set(rules(r)) == {"broken-form-attribute", "broken-label-for"}


# ---------------------------------------------------------------- submit, files, groups


def test_submit_button_rules():
    r = audit_page(page([ctl()], buttons=[btn(content="")]))
    assert rules(r) == ["unnamed-submit"]
    r = audit_page(page([ctl()], buttons=[btn(type="button", selector="button#b")]))
    assert fixes(r) == ['change type="button" to type="submit" on button#b']
    r = audit_page(page([ctl()], buttons=[]))
    assert fixes(r) == ['add <button type="submit">...</button> to form#f']
    img = btn(tag="input", type="image", content="", alt=None, selector="input#img")
    assert rules(audit_page(page([ctl()], buttons=[img]))) == ["unnamed-submit"]


def test_button_name_sources():
    assert button_name(btn(content="", aria_label="Search")) == "Search"
    assert button_name(btn(tag="input", content="", value_attr=None)) == "Submit"
    assert button_name(btn(content="", title="Go")) == "Go"
    assert button_name(btn(content="")) == ""


def test_file_accept():
    r = audit_page(page([ctl(type="file", name="cv")]))
    assert rules(r) == ["file-accept-missing"]
    r = audit_page(page([ctl(type="file", accept=".pdf, image/*, application/msword")]))
    assert r.findings == []
    r = audit_page(page([ctl(type="file", accept="pdf,.doc")]))
    assert rules(r) == ["file-accept-invalid"]


def test_radio_group_needs_fieldset():
    radios = [ctl(type="radio", name="plan", selector=f"input#r{i}", rect={"x": 0, "y": i * 60, "w": 13, "h": 13})
              for i in range(2)]
    r = audit_page(page(radios))
    assert rules(r) == ["group-label"]
    for c in radios:
        c["group"] = {"legend": "Plan", "role_group_name": None, "in_fieldset": True}
    assert audit_page(page(radios)).findings == []


# ---------------------------------------------------------------- targets


def test_undersized_targets_spacing_exception():
    far = [{"rect": {"x": 0, "y": 0, "w": 16, "h": 16}}, {"rect": {"x": 100, "y": 0, "w": 16, "h": 16}}]
    assert undersized_targets(far) == []
    near = [{"rect": {"x": 0, "y": 0, "w": 16, "h": 16}}, {"rect": {"x": 18, "y": 0, "w": 16, "h": 16}}]
    assert undersized_targets(near) == [0, 1]
    touching_big = [{"rect": {"x": 0, "y": 0, "w": 16, "h": 16}}, {"rect": {"x": 17, "y": 0, "w": 100, "h": 40}}]
    assert undersized_targets(touching_big) == [0]
    assert undersized_targets([{"rect": {"x": 0, "y": 0, "w": 24, "h": 24}}]) == []


def test_touch_target_finding():
    tiny = btn(selector="button#x", rect={"x": 0, "y": 0, "w": 16, "h": 16})
    r = audit_page(page([ctl(rect={"x": 18, "y": 0, "w": 200, "h": 40})], buttons=[tiny]))
    assert [(f.severity, f.rule) for f in r.findings] == [("medium", "touch-target")]
    assert "(now 16x16)" in r.findings[0].fix
    # 12 px from its centre to the field: the spacing exception applies
    r = audit_page(page([ctl(rect={"x": 20, "y": 0, "w": 200, "h": 40})], buttons=[tiny]))
    assert r.findings == []


def test_labelled_checkbox_is_exempt_from_target_size():
    boxes = [ctl(type="checkbox", name=f"c{i}", rect={"x": 0, "y": i * 16, "w": 13, "h": 13}) for i in range(2)]
    assert audit_page(page(boxes)).findings == []


# ---------------------------------------------------------------- informational


def test_honeypot_and_tokens_are_notes():
    hp = ctl(name="website", visible=False, hidden_reasons=["offscreen"], selector="input#hp")
    hidden = [{"name": "csrf_token", "value_shape": "hex", "value_length": 40, "form_index": 0},
              {"name": "sig", "value_shape": "jwt", "value_length": 120, "form_index": 0},
              {"name": "ts", "value_shape": "timestamp", "value_length": 10, "form_index": 0}]
    r = audit_page(page([ctl(), hp], hidden=hidden))
    assert rules(r) == ["honeypot-focusable"]
    notes = [n.fix for n in r.notes]
    assert any("looks like a honeypot" in n for n in notes)
    assert "CSRF-style token field: csrf_token" in notes
    assert any("signed/opaque token (120 chars, jwt)" in n for n in notes)
    assert any("timestamp" in n for n in notes)
    display_none = ctl(name="website", visible=False, hidden_reasons=["display-none"])
    assert audit_page(page([ctl(), display_none])).findings == []


def test_honeypot_inside_fading_form_is_still_a_honeypot():
    hp = ctl(name="sitio_web", labels_for=[], labels_wrap=["Website"], autocomplete="off", tabindex="-1",
             visible=False, hidden_reasons=["ancestor-opacity-0", "offscreen"], selector="input#hp")
    real = ctl(name="email", type="email", autocomplete="email", visible=False, hidden_reasons=["ancestor-opacity-0"],
               rect={"x": 0, "y": 0, "w": 300, "h": 20})
    close = btn(rect={"x": 100, "y": 21, "w": 120, "h": 44})
    r = audit_page(page([real, hp], buttons=[close], form={"visible": True}))
    assert rules(r) == ["touch-target"]  # the faded-in field is still measured
    assert any("looks like a honeypot" in n.fix for n in r.notes)


def test_visually_hidden_radio_keeps_label_checks():
    radio = ctl(type="radio", name="plan", labels_for=[], visible=False, hidden_reasons=["zero-size", "clipped"])
    assert rules(audit_page(page([radio]))) == ["no-accessible-name"]


def test_url_field_gets_inputmode_not_type():
    r = audit_page(page([ctl(name="website", autocomplete="url")]))
    assert fixes(r) == ['add inputmode="url" to input#x']


def test_hidden_form_still_gets_markup_checks():
    r = audit_page(page([ctl(labels_for=[], visible=False, hidden_reasons=["display-none"])],
                        form={"visible": False}))
    assert rules(r) == ["no-accessible-name"]


def test_captcha_notes():
    r = audit_page(page([ctl()], captcha=[{"kind": "Turnstile", "visible": True, "form_index": 0},
                                          {"kind": "reCAPTCHA", "visible": True, "badge": True, "form_index": 0}]))
    notes = [n.fix for n in r.notes]
    assert "Turnstile widget (visible challenge)" in notes
    assert "reCAPTCHA widget (invisible or badge only)" in notes
    assert r.forms[0]["captcha"] == "Turnstile (visible), reCAPTCHA (invisible)"


def test_blocked_requests_note():
    r = audit_page(page([ctl()], blocked_requests=[{"method": "POST", "url": "https://shop.example/beacon"}]))
    assert any("blocked 1 non-GET request" in n.fix for n in r.notes)


# ---------------------------------------------------------------- fixture page and exit codes


def test_fixture_page_prioritised(bad_page):
    r = audit_page(bad_page)
    sev = [f.severity for f in r.findings]
    assert sev == sorted(sev, key=["high", "medium", "low"].index)
    high = set(rules(r, "high"))
    assert {"paste-blocked", "unnamed-submit", "insecure-action", "password-in-get"} <= high
    all_fixes = fixes(r)
    assert 'add autocomplete="email" to input#email' in all_fixes
    assert 'add <label for="email">Email</label> for input#email' in all_fixes
    assert 'change type="text" to type="tel" on input#phone' in all_fixes
    assert 'add aria-describedby="fullname-error" to input#fullname' in all_fixes
    assert 'fix <label for="nowhere">: no form field has id="nowhere"' in all_fixes
    assert 'add autocomplete="username" to input#user' in all_fixes


def test_error_page_and_exit_codes(bad_page):
    ok = audit_page(page([ctl(name="email", type="email", autocomplete="email")]))
    bad = audit_page(bad_page)
    low_only = audit_page(page([ctl(type="file")]))
    down = audit_page({"requested_url": "https://x.example", "error": "net::ERR_NAME_NOT_RESOLVED"})
    assert exit_code([ok]) == 0
    assert exit_code([bad]) == 1
    assert exit_code([low_only]) == 0
    assert exit_code([low_only], "low") == 1
    assert exit_code([bad], "never") == 0
    assert exit_code([ok, down]) == 2
