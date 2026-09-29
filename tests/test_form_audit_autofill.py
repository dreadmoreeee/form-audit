import pytest

from form_audit.autofill import expected_input_type, infer_field, normalize, parse_autocomplete


@pytest.mark.parametrize(
    "value, field",
    [
        ("email", "email"),
        ("EMAIL", "email"),
        ("on", "on"),
        ("off", "off"),
        ("shipping postal-code", "postal-code"),
        ("section-blue billing street-address", "street-address"),
        ("section-a shipping work tel", "tel"),
        ("home email", "email"),
        ("username webauthn", "username"),
        ("current-password webauthn", "current-password"),
        ("one-time-code", "one-time-code"),
        ("cc-exp", "cc-exp"),
    ],
)
def test_valid_tokens(value, field):
    ac = parse_autocomplete(value)
    assert ac.valid, ac.problem
    assert ac.field == field


@pytest.mark.parametrize(
    "value, problem",
    [
        ("nope", "not an autofill field name"),
        ("company-name", "not an autofill field name"),
        ("off email", "alone"),
        ("home postal-code", "can only precede"),
        ("billing section-x email", "misordered"),
        ("email shipping", "not an autofill field name"),
        ("webauthn", "must follow"),
        ("section- email", "misordered"),
    ],
)
def test_invalid_tokens(value, problem):
    ac = parse_autocomplete(value)
    assert not ac.valid
    assert problem in ac.problem


def test_empty_autocomplete_is_default_state():
    ac = parse_autocomplete("   ")
    assert ac.valid and ac.field is None


def test_normalize():
    assert normalize("billingAddress_1") == "billing address 1"
    assert normalize("Email *") == "email"
    assert normalize("Phone (required)") == "phone"


@pytest.mark.parametrize(
    "sources, tag, itype, field",
    [
        (["email"], "input", "text", "email"),
        (["user_email"], "input", "text", "email"),
        (["fname"], "input", "text", "given-name"),
        (["lastName"], "input", "text", "family-name"),
        (["phone_number"], "input", "tel", "tel"),
        (["zip"], "input", "text", "postal-code"),
        (["country"], "select", "select", "country"),
        (["country"], "input", "text", "country-name"),
        (["card-number"], "input", "text", "cc-number"),
        (["cardholder"], "input", "text", "cc-name"),
        (["cvc"], "input", "text", "cc-csc"),
        (["otp"], "input", "text", "one-time-code"),
        (["username"], "input", "text", "username"),
        (["name"], "input", "text", "name"),
        (["fullname"], "input", "text", "name"),
        (["address"], "textarea", "textarea", "street-address"),
        (["company"], "input", "text", "organization"),
        (["x1", "Your name"], "input", "text", "name"),
        (["dob"], "input", "date", "bday"),
    ],
)
def test_infer_field(sources, tag, itype, field):
    assert infer_field(sources, tag, itype) == field


@pytest.mark.parametrize(
    "sources, tag, itype",
    [
        (["message"], "textarea", "textarea"),
        (["email"], "textarea", "textarea"),  # a textarea is not an email field
        (["email"], "input", "checkbox"),  # "email me updates" checkbox
        (["q"], "input", "text"),
        (["search_email"], "input", "text"),
        (["product name"], "input", "text"),
        (["subject"], "input", "text"),
        (["start"], "input", "date"),
    ],
)
def test_infer_field_negative(sources, tag, itype):
    assert infer_field(sources, tag, itype) is None


def test_name_attribute_beats_label():
    assert infer_field(["email", "Your company"], "input", "text") == "email"


def test_expected_input_type():
    assert expected_input_type("email") == "email"
    assert expected_input_type("tel-national") == "tel"
    assert expected_input_type("url") == "url"
    assert expected_input_type("tel-extension") is None
    assert expected_input_type("name") is None
