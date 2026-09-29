# form-audit

Audit the forms on a web page **without submitting anything**, and get a prioritized list of fixes, each naming the exact attribute to add or change:

```
- `add autocomplete="email" to input#email` (missing-autocomplete: lets browsers and password managers fill it)
- `add <label for="email">Email</label> for input#email` (placeholder-as-label: the placeholder is the only name and disappears while typing)
- `change type="number" to type="text" inputmode="numeric" on input#postal` (number-type-misuse: ...)
```

**Read-only.** Headless Chromium loads each URL with a GET, waits for the network to go idle and reads the DOM with one script. It never types, fills, clicks, presses keys, focuses or dispatches events. As a second guard, every request that is not GET or HEAD is aborted inside the browser, so not even the page's own scripts can post anything (the report lists what was blocked). Hidden field values are never exported, only their length and shape.

What it checks, for every `<form>` and for fields outside forms (or tied to one with `form=`):

- **Transport**: page and `action` over https, `method="get"` with a password (high) or personal data, action on another host (note).
- **Names**: `label[for]`, wrapping `<label>`, `aria-label`, `aria-labelledby`, `title`; placeholder-only is flagged as `placeholder-as-label`; broken `aria-labelledby`, `label for` pointing nowhere, duplicate ids, radio groups without `<fieldset>`/`<legend>`.
- **Autocomplete**: tokens validated against the HTML spec grammar (`section-*`, `shipping`/`billing`, `home`/`work`/..., field names, `webauthn`), and suggested tokens inferred from name, id and label (`fname` -> `given-name`, a sign-in identifier -> `username`, `company` -> `organization`, ...).
- **Mobile keyboards**: `type="email"`/`"tel"`, `inputmode="url"`/`"numeric"`, and `type="number"` misused for phone numbers, postal codes, card numbers or one-time codes.
- **Errors and required**: `aria-describedby`/`aria-errormessage` pointing to real ids, `aria-invalid` wiring, error elements (`#email-error`, `.error` next to the field) not associated, labels marked `*` without `required`/`aria-required`.
- **Passwords**: `new-password` vs `current-password`, `autocomplete="off"`, `maxlength` under 64, paste blocking (inline `onpaste`, and `paste` listeners read through the DevTools protocol whose source calls `preventDefault` or returns false).
- **Submit**: a real submit button exists and has an accessible name.
- **Touch targets**: every rendered control and button measured with `getBoundingClientRect` against 24x24 CSS px (WCAG 2.2 SC 2.5.8), with the spacing exception; labelled checkboxes and radios are exempt.
- **Informational**: visible vs invisible reCAPTCHA / hCaptcha / Turnstile, honeypot fields (and whether keyboard users or autofill can reach them), signed-token or timestamp hidden fields, CSRF-style token fields, file inputs without `accept`.

The rules are plain Python working on the extracted JSON, so they are tested without a browser.

## Measured result

My own pages: the contact form, the sign-up page (only loaded, never filled), a demo site and the demo app login.

```
$ python -m form_audit https://demarkstudio.ca/en/contact https://demarkstudio.ca/en/start https://demo.demarkstudio.ca/riverside-pub/site https://demo.demarkstudio.ca/app/login
# Form audit

Read-only: pages loaded with GET only; nothing was typed, clicked or submitted.

## https://demarkstudio.ca/en/contact

HTTP 200, 1 form(s). **0 high, 0 medium, 0 low**

| Form | Method | Action | Fields | Submit | CAPTCHA | CSRF field |
|---|---|---|---|---|---|---|
| `main#contenido > section:nth-of-type(2) > div > form` | POST | /en/contact | 7 | yes | - | no |

### Notes (informational)
- hidden text field input[name="sitio_web"] (ancestor-opacity-0, offscreen): looks like a honeypot
- hidden field sello holds a signed/opaque token (43 chars, signed)
- no CSRF-looking hidden field (protection may use SameSite cookies, headers or a signed token)
- blocked 1 non-GET request(s) made by the page's own scripts: POST https://demarkstudio.ca/cdn-cgi/rum

## https://demarkstudio.ca/en/start

HTTP 200, 1 form(s). **0 high, 0 medium, 0 low**

| Form | Method | Action | Fields | Submit | CAPTCHA | CSRF field |
|---|---|---|---|---|---|---|
| `main#contenido > section:nth-of-type(2) > div > form` | POST | /en/start | 18 | yes | - | no |

### Notes (informational)
- hidden text field input[name="sitio_web"] (ancestor-opacity-0, offscreen): looks like a honeypot
- hidden field sello holds a signed/opaque token (43 chars, signed)
- no CSRF-looking hidden field (protection may use SameSite cookies, headers or a signed token)
- blocked 1 non-GET request(s) made by the page's own scripts: POST https://demarkstudio.ca/cdn-cgi/rum

## https://demo.demarkstudio.ca/riverside-pub/site

HTTP 200, 0 form(s). **0 high, 0 medium, 0 low**

## https://demo.demarkstudio.ca/app/login

HTTP 200, 2 form(s). **0 high, 0 medium, 0 low**

| Form | Method | Action | Fields | Submit | CAPTCHA | CSRF field |
|---|---|---|---|---|---|---|
| `main > div:nth-of-type(2) > form:nth-of-type(1)` | POST | /app/login | 0 | yes | - | no |
| `main > div:nth-of-type(2) > form:nth-of-type(2)` | POST | /app/login | 2 | yes | - | no |

### Notes (informational)
- hidden field sello holds a signed/opaque token (43 chars, signed)
- hidden field sello holds a signed/opaque token (43 chars, signed)
- no CSRF-looking hidden field (protection may use SameSite cookies, headers or a signed token)

Total: 0 high, 0 medium, 0 low across 4 page(s)

$ python -m pytest -q
115 passed in 6.04s
```

No fixes needed on these four pages: the contact and login fields have visible labels, valid autocomplete tokens (`username` + `current-password` on the login) and the right input types, the contact form's error messages are wired with `aria-describedby`, and the sign-up page's plan choices sit in fieldsets with legends. The notes are the anti-spam design (an off-screen honeypot plus a signed `sello` token instead of a CAPTCHA) and Cloudflare's analytics beacon, which the guard stopped.

The first run was not this clean, and the tool was wrong: those forms fade in on scroll (an ancestor at `opacity: 0`), so the honeypot counted as a real field and got a keyboard suggestion. The tool now tells an element hidden on purpose from one inside an animation, and suggests `inputmode="url"` rather than `type="url"` (which rejects `example.com` without a scheme).

To see what findings look like, [examples/bad-form.html](examples/bad-form.html) packs the common mistakes; [examples/bad-form.json](examples/bad-form.json) is its extracted data, so this runs offline:

```
$ python -m form_audit --input examples/bad-form.json
...
Total: 4 high, 19 medium, 10 low across 1 page(s)
```

Full report: [examples/bad-form-report.md](examples/bad-form-report.md).

## CLI

```
pip install .            # or just: pip install playwright
python -m playwright install chromium
python -m form_audit URL [URL ...] [--format md|json] [--fail-on high|medium|low|never] [--mobile] [-o FILE]
```

Also installed as `form-audit`. Exit code 0 when there is nothing at or above `--fail-on` (default `high`), 1 when there is, 2 for usage errors or a page that could not be loaded (network error or HTTP 4xx/5xx).

- `--mobile` uses a 390x844 touch viewport, which matters for target sizes.
- `--raw` prints the extracted page data as JSON; `--input FILE` audits that data later without a browser.
- Pages are loaded at least 1 s apart (`--delay`), with the User-Agent `form-audit/1.0 (+https://github.com/dreadmoreeee/form-audit)`. It only loads the URLs you give it; it does not crawl.

## Limitations

- Heuristics are heuristics: autocomplete suggestions come from names and labels (English, some French and Spanish), and paste blocking is only seen when the handler's own source shows it (a delegated jQuery handler on `document` is not).
- Custom widgets (`role="combobox"` divs, `contenteditable`) and forms inside shadow DOM are not audited.
- Nothing is submitted, so server-side validation and the error states that appear after submitting are out of reach; only the markup that is already in the page is checked.
- Touch-target spacing only considers the form's own controls, not nearby links.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
