# Form audit

Read-only: pages loaded with GET only; nothing was typed, clicked or submitted.

## https://shop.example/bad.html

HTTP 200, 2 form(s). **4 high, 19 medium, 10 low**

| Form | Method | Action | Fields | Submit | CAPTCHA | CSRF field |
|---|---|---|---|---|---|---|
| `form#contact` | GET | /send | 8 | no | - | yes |
| `form#login` | GET | http://insecure.example/login | 2 | yes | - | no |
| `(controls outside any form)` | - | - | 1 | no | - | - |

### High
- `remove the paste-blocking handler (onpaste attribute, paste event listener) from input#pw` (paste-blocked: blocking paste breaks password managers (WCAG 3.3.8))
- `add visible text or aria-label="..." to form#login > button` (unnamed-submit: screen readers announce just "button")
- `change action="http://insecure.example/login" to an https:// URL on form#login` (insecure-action: the data is sent unencrypted)
- `change method="get" to method="post" on form#login` (password-in-get: the password ends up in the URL, history and server logs)

### Medium
- `add <label for="email">Email</label> for input#email` (placeholder-as-label: the placeholder is the only name and disappears while typing)
- `add autocomplete="email" to input#email` (missing-autocomplete: lets browsers and password managers fill it)
- `change type="text" to type="email" on input#email` (input-type: mobile users get the email keyboard and browsers validate it)
- `fix aria-describedby on input#phone: no element with id "phone-help"` (broken-describedby: help or error text is never announced)
- `add required (or aria-required="true") to input#phone` (required-not-exposed: the label marks it required but assistive tech is not told)
- `add autocomplete="tel" to input#phone` (missing-autocomplete: lets browsers and password managers fill it)
- `change type="text" to type="tel" on input#phone` (input-type: mobile users get the tel keyboard and browsers validate it)
- `change autocomplete="company-name" to autocomplete="organization" on input[name="company"]` (invalid-autocomplete: browsers ignore it: "company-name" is not an autofill field name)
- `change type="number" to type="text" inputmode="numeric" on input#postal` (number-type-misuse: number inputs drop leading zeros, add spinners and change on scroll)
- `add aria-describedby="fullname-error" to input#fullname` (unassociated-error-message: error text #fullname-error is not announced with the field)
- `add autocomplete="name" to input#fullname` (missing-autocomplete: lets browsers and password managers fill it)
- `make form#contact > button at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 16x16)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `change method="get" to method="post" on form#contact` (sensitive-get: personal details end up in the URL, history and server logs)
- `remove autocomplete="off" from form#contact` (form-autocomplete-off: it disables autofill for every field in the form)
- `change type="button" to type="submit" on form#contact > button` (no-submit-button: Enter does not submit and the action is not a real button)
- `add autocomplete="username" to input#user` (missing-autocomplete: lets browsers and password managers fill it)
- `add autocomplete="current-password" to input#pw` (password-autocomplete: password managers need it to save and fill the right password)
- `fix form="missing-form" on input[name="q"]: no <form id="missing-form">` (broken-form-attribute: the field is not submitted with any form)
- `fix <label for="nowhere">: no form field has id="nowhere"` (broken-label-for: the label names nothing)

### Low
- `add a visible <label> for input#fullname (title="Full name" is its only name)` (title-as-label: title is not shown to touch or keyboard users)
- `add accept="..." (e.g. accept=".pdf,.jpg,.png") to input[name="cv"]` (file-accept-missing: the file picker shows every file type)
- `wrap the name="plan" radio buttons in <fieldset> with a <legend>` (group-label: the question is not announced with the options)
- `add tabindex="-1" autocomplete="off" to input[name="website"]` (honeypot-focusable: keyboard users can tab into it and autofill can fill it, flagging real people as bots)
- `make input#email at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 177x21)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `make input#phone at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 177x21)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `make input[name="cv"] at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 253x21)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `make input[name="plan"][value="a"] at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 13x13)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `make input[name="plan"][value="b"] at least 24x24 CSS px, e.g. min-height: 24px; min-width: 24px (now 13x13)` (touch-target: WCAG 2.2 SC 2.5.8 target size)
- `raise maxlength="16" on input#pw to at least 64 (or remove it)` (password-maxlength: long passphrases and generated passwords get cut)

### Notes (informational)
- hidden text field input[name="website"] (offscreen): looks like a honeypot
- CSRF-style token field: _token
- form#login sends data to another host: insecure.example

Total: 4 high, 19 medium, 10 low across 1 page(s)
