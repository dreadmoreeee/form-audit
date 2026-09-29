"""Autofill tokens from the HTML Living Standard and field-name inference.

The grammar (HTML 4.10.18.7.1):

    [section-*] [shipping | billing] [home | work | mobile | fax | pager] field-name [webauthn]

or a lone "on" / "off".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

NORMAL_FIELDS = frozenset(
    """
    name honorific-prefix given-name additional-name family-name honorific-suffix
    nickname username new-password current-password one-time-code
    organization-title organization street-address address-line1 address-line2
    address-line3 address-level4 address-level3 address-level2 address-level1
    country country-name postal-code cc-name cc-given-name cc-additional-name
    cc-family-name cc-number cc-exp cc-exp-month cc-exp-year cc-csc cc-type
    transaction-currency transaction-amount language bday bday-day bday-month
    bday-year sex url photo
    """.split()
)

CONTACT_FIELDS = frozenset(
    """
    tel tel-country-code tel-national tel-area-code tel-local tel-local-prefix
    tel-local-suffix tel-extension email impp
    """.split()
)

FIELD_NAMES = NORMAL_FIELDS | CONTACT_FIELDS
CONTACT_TYPES = frozenset({"home", "work", "mobile", "fax", "pager"})
ADDRESS_HINTS = frozenset({"shipping", "billing"})
PASSWORD_FIELDS = frozenset({"new-password", "current-password"})


@dataclass(frozen=True)
class Autocomplete:
    """Result of parsing an autocomplete attribute value."""

    raw: str
    valid: bool
    field: str | None  # autofill field name, "on", "off", or None when empty
    problem: str | None = None


def parse_autocomplete(value: str) -> Autocomplete:
    """Validate an autocomplete attribute value against the HTML spec grammar."""
    tokens = value.lower().split()
    if not tokens:
        return Autocomplete(value, True, None)
    if tokens in (["on"], ["off"]):
        return Autocomplete(value, True, tokens[0])
    if "on" in tokens or "off" in tokens:
        return Autocomplete(value, False, None, '"on" and "off" must be used alone')
    if tokens[-1] == "webauthn":
        tokens.pop()
        if not tokens:
            return Autocomplete(value, False, None, '"webauthn" must follow a field name')
    field = tokens.pop()
    if field not in FIELD_NAMES:
        return Autocomplete(value, False, None, f'"{field}" is not an autofill field name')
    if tokens and tokens[-1] in CONTACT_TYPES:
        kind = tokens.pop()
        if field not in CONTACT_FIELDS:
            return Autocomplete(value, False, field, f'"{kind}" can only precede tel*, email or impp')
    if tokens and tokens[-1] in ADDRESS_HINTS:
        tokens.pop()
    if tokens and tokens[-1].startswith("section-") and len(tokens[-1]) > len("section-"):
        tokens.pop()
    if tokens:
        return Autocomplete(value, False, field, f"unexpected or misordered token(s): {' '.join(tokens)}")
    return Autocomplete(value, True, field)


# (field name, pattern) in priority order; applied to normalized name/id/label text.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (f, re.compile(p))
    for f, p in [
        ("cc-name", r"\b(card ?holder|name on (the )?card|cc name|card name)\b"),
        ("cc-number", r"\b(card ?number|card no|cc ?num(ber)?|credit ?card( number)?|ccnumber)\b"),
        ("cc-exp", r"\b(expiry|expiration|exp date|cc ?exp|mm ?yy)\b"),
        ("cc-csc", r"\b(cvc|cvv|cvv2|csc|security code|card code)\b"),
        ("one-time-code", r"\b(otp|one ?time( code| password)?|2fa|mfa|totp|verification code|auth(entication)? code)\b"),
        ("username", r"\b(user ?name|user ?id|login( id| name)?)\b"),
        ("email", r"\b(e ?mail|courriel)\b"),
        ("given-name", r"\b(first ?name|given ?name|fname|forename|prenom)\b"),
        ("family-name", r"\b(last ?name|surname|family ?name|lname)\b"),
        ("additional-name", r"\b(middle ?name|mname)\b"),
        ("organization-title", r"\b(job ?title)\b"),
        ("organization", r"\b(company|organi[sz]ation|business name|org|employer|entreprise)\b"),
        ("tel-extension", r"\b(ext|extension)\b"),
        ("tel", r"\b(tel|telephone|phone|mobile|cell|telefono)\b"),
        ("address-line2", r"\b(address ?(line )?2|addr2|apt|apartment|suite)\b"),
        ("address-line1", r"\b(address ?(line )?1|addr1|street( address)?)\b"),
        ("address-level2", r"\b(city|town|municipality|ville)\b"),
        ("address-level1", r"\b(state|province|region)\b"),
        ("postal-code", r"\b(zip( ?code)?|postal( code)?|post ?code|postcode)\b"),
        ("country", r"\b(country|pays)\b"),
        ("street-address", r"\b(address|addr)\b"),
        ("bday", r"\b(birth ?date|date of birth|dob|birthday|bday)\b"),
        ("url", r"\b(website|web site|homepage|url)\b"),
        ("name", r"^(your |full |contact |customer )?name$|^(fullname|yourname|nom|nombre)$"),
    ]
]

# Input types where a text-ish autofill suggestion makes sense.
TEXT_INPUT_TYPES = frozenset({"text", "email", "tel", "url", "number", ""})


def normalize(text: str | None) -> str:
    """'billingAddress_1' -> 'billing address 1'; strips required marks."""
    if not text:
        return ""
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Za-z])(\d)", r"\1 \2", text)
    text = re.sub(r"[^A-Za-z0-9]+", " ", text)
    text = re.sub(r"\brequired\b|\boptional\b", " ", text.lower())
    return " ".join(text.split())


def infer_field(sources: list[str | None], tag: str = "input", input_type: str = "text") -> str | None:
    """Guess the autofill field name from the control's name, id, label or placeholder.

    Sources are tried in order; the first one that matches any pattern wins, so
    a precise ``name`` attribute beats a chatty label.
    """
    if tag == "input" and input_type not in TEXT_INPUT_TYPES and input_type != "date":
        return None
    for source in sources:
        text = normalize(source)
        if not text or re.search(r"\b(search|query|q|coupon|promo)\b", text):
            continue
        for field, pattern in _PATTERNS:
            if pattern.search(text):
                if tag == "textarea" and field not in ("street-address",):
                    return None
                if input_type == "date" and field != "bday":
                    return None
                if field == "country" and tag == "input":
                    return "country-name"
                if field == "address-line1" and tag == "textarea":
                    return "street-address"
                return field
    return None


def expected_input_type(field: str | None) -> str | None:
    """The input type that brings up the right mobile keyboard for a field."""
    if field == "email":
        return "email"
    if field and field.startswith("tel") and field != "tel-extension":
        return "tel"
    if field == "url":
        return "url"
    return None


NUMERIC_CODE_FIELDS = frozenset({"one-time-code", "cc-number", "cc-csc"})
NOT_A_NUMBER_FIELDS = frozenset(
    {"tel", "tel-national", "tel-local", "postal-code", "cc-number", "cc-csc", "cc-exp", "one-time-code"}
)
LOW_VALUE_FIELDS = frozenset({"url", "organization", "organization-title", "bday", "tel-extension"})
SENSITIVE_FIELDS = frozenset(
    {"cc-name", "cc-number", "cc-exp", "cc-csc", "one-time-code", "new-password", "current-password"}
)
PERSONAL_FIELDS = frozenset(
    {
        "name", "given-name", "family-name", "additional-name", "email", "tel",
        "street-address", "address-line1", "address-line2", "postal-code", "bday", "username",
    }
)
