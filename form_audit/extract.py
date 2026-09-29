"""Read-only page loading with headless Chromium.

The browser loads each URL with a GET, waits for the network to go idle and
then reads the DOM with one ``page.evaluate`` call. It never types, fills,
clicks, presses keys or dispatches events. As a second line of defence every
request that is not GET or HEAD (a form submission, a fetch POST or a beacon
fired by the page's own scripts) is aborted before it leaves the browser.
"""

from __future__ import annotations

import time

USER_AGENT = "form-audit/1.0 (+https://github.com/dreadmoreeee/form-audit)"
CONTROL_SELECTOR = "input, select, textarea, button"
ALLOWED_METHODS = frozenset({"GET", "HEAD"})

EXTRACT_JS = r"""
() => {
  const SEL = 'input, select, textarea, button';
  const LABELABLE = ['INPUT', 'SELECT', 'TEXTAREA', 'BUTTON', 'METER', 'OUTPUT', 'PROGRESS'];
  const ws = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const attr = (el, n) => el.getAttribute(n);
  const forms = Array.from(document.querySelectorAll('form'));
  const formIndex = (f) => { const i = f ? forms.indexOf(f) : -1; return i < 0 ? null : i; };
  const q = (v) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const count = (s) => { try { return document.querySelectorAll(s).length; } catch (e) { return 0; } };

  function selector(el) {
    const tag = el.tagName.toLowerCase();
    const id = attr(el, 'id');
    if (id && count('#' + CSS.escape(id)) === 1) {
      return /^[A-Za-z][\w-]*$/.test(id) ? tag + '#' + id : tag + '[id="' + q(id) + '"]';
    }
    const name = attr(el, 'name');
    if (name) {
      const s = tag + '[name="' + q(name) + '"]';
      if (count(s) === 1) return s;
      const val = attr(el, 'value');
      if (val !== null && count(s + '[value="' + q(val) + '"]') === 1) return s + '[value="' + q(val) + '"]';
    }
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && cur !== document.body && cur !== document.documentElement) {
      const t = cur.tagName.toLowerCase();
      const cid = attr(cur, 'id');
      if (cur !== el && cid && count('#' + CSS.escape(cid)) === 1) { parts.unshift(t + '#' + CSS.escape(cid)); break; }
      let n = 1, total = 0;
      for (const sib of cur.parentElement ? cur.parentElement.children : []) {
        if (sib.tagName === cur.tagName) { total++; if (sib === cur) n = total; }
      }
      parts.unshift(total > 1 ? t + ':nth-of-type(' + n + ')' : t);
      cur = cur.parentElement;
    }
    return parts.join(' > ');
  }

  function textOf(root) {
    if (!root) return '';
    let out = '';
    const walk = (n) => {
      if (n.nodeType === 3) { out += n.nodeValue; return; }
      if (n.nodeType !== 1) return;
      const t = n.tagName.toLowerCase();
      if (['script', 'style', 'template', 'noscript'].includes(t)) return;
      if (n !== root && attr(n, 'aria-hidden') === 'true') return;
      if (n !== root && ['input', 'select', 'textarea', 'button'].includes(t)) return;
      if (n !== root && n.hasAttribute('aria-label')) { out += ' ' + attr(n, 'aria-label') + ' '; return; }
      if (t === 'img') { out += ' ' + (attr(n, 'alt') || '') + ' '; return; }
      if (t === 'svg') {
        const ti = n.querySelector('title');
        out += ' ' + (attr(n, 'aria-label') || (ti ? ti.textContent : '')) + ' ';
        return;
      }
      for (const c of n.childNodes) walk(c);
      if (['br', 'div', 'p', 'li', 'span'].includes(t)) out += ' ';
    };
    walk(root);
    return ws(out);
  }

  function idrefs(el, name) {
    const raw = attr(el, name);
    if (raw === null) return null;
    const ids = raw.split(/\s+/).filter(Boolean);
    const missing = [], texts = [];
    for (const id of ids) {
      const t = document.getElementById(id);
      if (!t) missing.push(id); else texts.push(textOf(t));
    }
    return { ids, missing, text: ws(texts.join(' ')) };
  }

  function vis(el) {
    const r = el.getBoundingClientRect();
    const rect = { x: r.left + window.scrollX, y: r.top + window.scrollY, w: r.width, h: r.height };
    const reasons = [];
    if (!el.checkVisibility()) {
      reasons.push('display-none');
    } else {
      const cs = getComputedStyle(el);
      if (cs.visibility !== 'visible') reasons.push('visibility-hidden');
      // own opacity 0 hides a field; an ancestor at opacity 0 is usually a reveal-on-scroll animation
      if (!el.checkVisibility({ opacityProperty: true })) reasons.push(cs.opacity === '0' ? 'opacity-0' : 'ancestor-opacity-0');
      if (r.width < 2 || r.height < 2) reasons.push('zero-size');
      if (rect.x + r.width <= 0 || rect.y + r.height <= 0) reasons.push('offscreen');
      if ((cs.clip && /rect\(\s*[01]px,?\s*[01]px/.test(cs.clip)) || /inset\(\s*(50|100)%/.test(cs.clipPath || '')) reasons.push('clipped');
    }
    return { visible: reasons.length === 0, reasons, rect };
  }

  function shape(v) {
    if (!v) return 'empty';
    if (/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(v)) return 'jwt';
    if (/^\d{9,13}[.:|_-][A-Za-z0-9+\/=_-]{16,}$/.test(v) || /^[A-Za-z0-9+\/=_-]{16,}[.:|][A-Za-z0-9+\/=_-]{8,}$/.test(v)) return 'signed';
    if (/^[0-9a-f]{32,}$/i.test(v)) return 'hex';
    if (v.length >= 24 && /^[A-Za-z0-9+\/=_-]+$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) return 'base64';
    if (/^\d{9,13}$/.test(v)) return 'timestamp';
    if (/^\d+$/.test(v)) return 'number';
    return 'text';
  }

  const controls = [], buttons = [], hidden = [];
  Array.from(document.querySelectorAll(SEL)).forEach((el, idx) => {
    const tag = el.tagName.toLowerCase();
    const type = (tag === 'input' || tag === 'button') ? el.type : tag;
    const base = {
      idx, tag, type, type_attr: attr(el, 'type'), name: attr(el, 'name'), id: attr(el, 'id'),
      selector: selector(el), form_index: formIndex(el.form), form_attr: attr(el, 'form'),
    };
    if (tag === 'input' && type === 'hidden') {
      const val = el.value || '';
      hidden.push({ ...base, value_length: val.length, value_shape: shape(val) });
      return;
    }
    const v = vis(el);
    Object.assign(base, {
      visible: v.visible, hidden_reasons: v.reasons, rect: v.rect, disabled: el.disabled,
      aria_hidden: !!el.closest('[aria-hidden="true"]'), tabindex: attr(el, 'tabindex'),
      aria_label: attr(el, 'aria-label'), labelledby: idrefs(el, 'aria-labelledby'), title: attr(el, 'title'),
    });
    if (tag === 'button' || ['submit', 'image', 'reset', 'button'].includes(type)) {
      let content = '';
      if (tag === 'button') content = textOf(el);
      else if (type === 'image') content = attr(el, 'alt') || '';
      else content = attr(el, 'value') || '';
      let formaction = null;
      if (attr(el, 'formaction')) { try { formaction = new URL(attr(el, 'formaction'), document.baseURI).href; } catch (e) {} }
      buttons.push({ ...base, content, value_attr: attr(el, 'value'), alt: attr(el, 'alt'), formaction, formmethod: attr(el, 'formmethod') });
      return;
    }
    const labelsFor = [], labelsWrap = [];
    for (const lb of Array.from(el.labels || [])) (lb.contains(el) ? labelsWrap : labelsFor).push(textOf(lb));
    let group = null;
    if (type === 'radio' || type === 'checkbox') {
      const fs = el.closest('fieldset');
      const lg = fs ? fs.querySelector(':scope > legend') : null;
      const rg = el.closest('[role="radiogroup"], [role="group"]');
      let rgName = null;
      if (rg) rgName = ws(attr(rg, 'aria-label') || ((idrefs(rg, 'aria-labelledby') || {}).text) || '');
      group = { legend: lg ? textOf(lg) : null, role_group_name: rgName, in_fieldset: !!fs };
    }
    const errs = [], seen = new Set();
    for (const k of [attr(el, 'id'), attr(el, 'name')].filter(Boolean)) {
      for (const cand of [k + '-error', k + '_error', k + 'Error', 'error-' + k, k + '-errors', k + '-feedback', k + '-invalid', k + '-err', 'err-' + k]) {
        const e = document.getElementById(cand);
        if (e && e !== el && !seen.has(e)) { seen.add(e); errs.push({ id: cand, text: textOf(e).slice(0, 120), visible: vis(e).visible, how: 'id' }); }
      }
    }
    const parent = el.parentElement;
    if (parent && parent.querySelectorAll('input:not([type=hidden]), select, textarea').length === 1) {
      for (const e of parent.querySelectorAll('[class*="error" i], [class*="invalid-feedback" i], [role="alert"]')) {
        if (e === el || e.contains(el) || seen.has(e)) continue;
        seen.add(e);
        const t = textOf(e);
        if (t) errs.push({ id: attr(e, 'id'), text: t.slice(0, 120), visible: vis(e).visible, how: 'sibling' });
      }
    }
    const anc = el.parentElement ? el.parentElement.closest('[onpaste]') : null;
    const onpasteAttr = attr(el, 'onpaste');
    const id = attr(el, 'id');
    controls.push({
      ...base,
      describedby: idrefs(el, 'aria-describedby'), errormessage: idrefs(el, 'aria-errormessage'),
      placeholder: attr(el, 'placeholder'), labels_for: labelsFor, labels_wrap: labelsWrap,
      autocomplete: attr(el, 'autocomplete'), inputmode: attr(el, 'inputmode'),
      required: el.hasAttribute('required'), aria_required: attr(el, 'aria-required'), aria_invalid: attr(el, 'aria-invalid'),
      pattern: attr(el, 'pattern'), maxlength: attr(el, 'maxlength'), accept: attr(el, 'accept'),
      multiple: el.hasAttribute('multiple'), readonly: el.hasAttribute('readonly'),
      id_count: id ? count('[id="' + q(id) + '"]') : 0,
      group, error_candidates: errs,
      onpaste_attr: onpasteAttr,
      onpaste_prop: (onpasteAttr === null && typeof el.onpaste === 'function') ? String(el.onpaste).slice(0, 500) : null,
      ancestor_onpaste: anc ? attr(anc, 'onpaste') : null,
      class: (attr(el, 'class') || '').slice(0, 200),
      paste_listeners: [],
    });
  });

  const formsOut = forms.map((f, i) => {
    const a = attr(f, 'action');
    let action = document.URL;
    if (a) { try { action = new URL(a, document.baseURI).href; } catch (e) { action = null; } }
    return {
      index: i, selector: selector(f), id: attr(f, 'id'), name: attr(f, 'name'),
      method_attr: attr(f, 'method'), action_attr: a, action, autocomplete_attr: attr(f, 'autocomplete'),
      novalidate: f.hasAttribute('novalidate'), enctype: attr(f, 'enctype'), target: attr(f, 'target'),
      visible: f.checkVisibility({ visibilityProperty: true }),
    };
  });

  const brokenLabels = Array.from(document.querySelectorAll('label[for]')).filter((l) => {
    const t = document.getElementById(attr(l, 'for'));
    return !t || !LABELABLE.includes(t.tagName) || (t.tagName === 'INPUT' && t.type === 'hidden');
  }).map((l) => ({ for: attr(l, 'for'), text: textOf(l).slice(0, 80), form_index: formIndex(l.closest('form')) }));

  const captcha = [];
  const capSel = [
    ['reCAPTCHA', '.g-recaptcha, .grecaptcha-badge, iframe[src*="/recaptcha/"]'],
    ['hCaptcha', '.h-captcha, iframe[src*="hcaptcha.com"]'],
    ['Turnstile', '.cf-turnstile, iframe[src*="challenges.cloudflare.com"]'],
    ['Friendly Captcha', '.frc-captcha'],
  ];
  for (const [kind, s] of capSel) {
    for (const e of document.querySelectorAll(s)) {
      captcha.push({
        kind, visible: vis(e).visible, invisible_mode: attr(e, 'data-size') === 'invisible',
        badge: e.classList.contains('grecaptcha-badge'), form_index: formIndex(e.closest('form')),
      });
    }
  }
  const captchaScripts = Array.from(document.scripts).map((s) => s.src).filter((s) =>
    /recaptcha|hcaptcha\.com|challenges\.cloudflare\.com\/turnstile|friendlycaptcha/i.test(s)
  ).map((s) => s.split('?')[0] + (/[?&]render=(?!explicit)/.test(s) ? ' (render=<key>: v3, invisible)' : ''));

  return {
    url: document.URL, title: document.title, forms: formsOut, controls, buttons, hidden,
    broken_labels: brokenLabels, captcha, captcha_scripts: captchaScripts,
    viewport: { w: window.innerWidth, h: window.innerHeight },
  };
}
"""


def _paste_listeners(cdp, idx: int) -> list[str]:
    """Source of 'paste' listeners attached to control ``idx`` (Chrome DevTools Protocol, read-only)."""
    res = cdp.send("Runtime.evaluate", {
        "expression": f"document.querySelectorAll({CONTROL_SELECTOR!r})[{idx}]",
        "objectGroup": "form-audit",
    })
    oid = res.get("result", {}).get("objectId")
    if not oid:
        return []
    listeners = cdp.send("DOMDebugger.getEventListeners", {"objectId": oid, "depth": 0}).get("listeners", [])
    return [(l.get("handler") or {}).get("description", "")[:500] for l in listeners if l.get("type") == "paste"]


def _add_paste_listeners(page, context, data: dict) -> None:
    try:
        cdp = context.new_cdp_session(page)
    except Exception:  # not Chromium
        return
    try:
        for c in data.get("controls", []):
            if c.get("type") in ("text", "email", "password", "tel", "url", "number", "textarea"):
                c["paste_listeners"] = _paste_listeners(cdp, c["idx"])
        cdp.send("Runtime.releaseObjectGroup", {"objectGroup": "form-audit"})
    except Exception as exc:  # heuristic only; never fail the audit over it
        data.setdefault("load_notes", []).append(f"paste listener check skipped: {exc.__class__.__name__}")
    finally:
        try:
            cdp.detach()
        except Exception:
            pass


def extract_pages(
    urls: list[str],
    *,
    timeout: float = 30.0,
    delay: float = 1.0,
    user_agent: str = USER_AGENT,
    mobile: bool = False,
    log=None,
) -> list[dict]:
    """Load each URL read-only and return the extracted DOM data (one dict per URL)."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright

    results: list[dict] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        viewport = {"width": 390, "height": 844} if mobile else {"width": 1280, "height": 800}
        context = browser.new_context(
            user_agent=user_agent, viewport=viewport, is_mobile=mobile, has_touch=mobile,
            service_workers="block", accept_downloads=False,
        )
        try:
            for i, url in enumerate(urls):
                if i and delay > 0:
                    time.sleep(delay)
                if log:
                    log(f"loading {url}")
                blocked: list[dict] = []

                def guard(route, request, blocked=blocked):
                    if request.method.upper() in ALLOWED_METHODS:
                        route.continue_()
                    else:
                        blocked.append({"method": request.method, "url": request.url.split("?")[0]})
                        route.abort("blockedbyclient")

                page = context.new_page()
                page.route("**/*", guard)
                page.on("dialog", lambda d: d.dismiss())
                data: dict = {"requested_url": url}
                try:
                    resp = page.goto(url, wait_until="load", timeout=timeout * 1000)
                    notes = []
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(timeout, 15) * 1000)
                    except PlaywrightTimeout:
                        notes.append("network never went idle; audited the page as loaded")
                    status = resp.status if resp else None
                    if status is not None and status >= 400:
                        data.update(status=status, url=page.url, error=f"HTTP {status}")
                    else:
                        data.update(page.evaluate(EXTRACT_JS))
                        data["status"] = status
                        data["load_notes"] = notes
                        _add_paste_listeners(page, context, data)
                except PlaywrightError as exc:
                    data["error"] = str(exc).splitlines()[0][:300]
                data["blocked_requests"] = blocked
                results.append(data)
                page.close()
        finally:
            context.close()
            browser.close()
    return results
