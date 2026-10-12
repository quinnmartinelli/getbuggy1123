# Form-check / request-interception review — `check_forms` and friends

Scope: `website-checker/core.py` — `_fill_value_for`, `_fill_form`, `check_forms`
(including `_block_mutating_requests` and the injected `submit` listener), and
how `check_forms` is wired into `run_check` via `all_responses` /
`deliberately_blocked_urls`. Read-only review; no source files were modified.

Findings are ranked by how likely they are to produce a *wrong* report (false
"broken," false "working," or a crash) on a real small-business site, with
silent false-"working" results weighted as worst-case, since they defeat the
entire point of this check (catching leads that vanish with no one aware of
it).

---

## 1. Multi-step/wizard forms: "Next" step can register as a false success via the `"confirm"` keyword

**Scenario.** Many quote/booking forms (a very common pattern for local-service
businesses — "get a quote," "book now") are wizards: step 1 collects contact
info, a "Next"/"Continue" button advances to step 2, and a final step is often
literally labeled "Confirm your details" or "Please confirm" before the real
submit. Two sub-cases:

- If the advance button has no explicit `type` attribute, it matches the
  current selector (`button:not([type])`, since the HTML default type for a
  `<button>` in a form *is* "submit"), so clicking it actually fires the
  form's native `submit` event — even though the wizard's own JS almost
  certainly `preventDefault()`s it and just reveals step 2. Fine so far
  (`native_attempted` would correctly be false, since defaultPrevented is
  true) — but nothing exercises the actual final-step submission at all.
- The real problem: after the click, `post_text` now contains "Confirm your
  details" (or similar) because the wizard advanced a step. `"confirm"` is
  one of `CONFIRMATION_KEYWORDS` (`core.py` line ~149), matched as a bare
  substring. `confirmation_appeared` becomes `True`, and the code does
  `if redirected or got_success_response or confirmation_appeared: continue`
  — no problem is ever recorded. The checker silently reports the form as
  fine, having never gotten past step 1, let alone exercised the real submit
  handler.

**Why it matters.** This is a *silent false "working"* result — the worst
class of error for a tool whose core promise is catching forms that quietly
lose leads. A wizard form whose final-step submission is genuinely broken
would be reported as completely healthy, because step navigation alone
produces a keyword match.

**Fix direction.** Don't treat "the visible text changed to contain a generic
word like confirm/continue" as proof of success by itself; require either a
real network success response, a URL change, or a much more specific/longer
confirmation phrase (the existing list already leans generic — "confirm" and
"received" are especially prone to false matches). Separately, detecting that
a click revealed new form fields (a step change) rather than left the page
static could be used to attempt one more click cycle to actually reach the
form's terminal submit action before giving up.

---

## 2. Iframe-embedded forms are silently skipped, with no indication in the report

**Scenario.** `page.query_selector_all("form")` (`core.py` line 261) only
searches the main frame's document. Embedded booking/scheduling/lead widgets
— Calendly, Typeform, HubSpot forms, many "contact us" widgets — are
overwhelmingly delivered via `<iframe>`. `check_forms` finds zero `<form>`
elements for these pages (or finds only unrelated forms on the host page) and
never looks inside the iframe at all.

**Why it matters.** This isn't a wrong verdict on a form that was inspected —
it's an entire class of forms never inspected, with the final report giving
no signal that anything was skipped. For exactly the audience GetBuggy
targets (small business owners using a no-code embed for their contact/
booking form), this is likely to be one of the most common real-world setups,
and the tool would report "no form problems" while never having tested the
one form that actually matters. A business owner reading a clean report would
reasonably conclude their lead form is fine.

**Fix direction.** At minimum, iterate `page.frames` (Playwright, unlike
in-page JS, is not blocked by cross-origin same-origin-policy when querying
frame contents via CDP) and run the same detection/fill/submit logic per
frame, applying the existing `MAX_FORMS_TO_CHECK` cap globally. If full
per-frame submission handling is out of scope for now, at least detect
"iframe present with no form found in main frame" and surface it as an
explicit low-severity "couldn't verify iframe-embedded content" note rather
than staying silent.

---

## 3. No-submit-button fallback (`requestSubmit()`) can exercise a code path the real site never uses

**Scenario.** The submit-button selector (`button[type=submit],
input[type=submit], button:not([type])`, line ~300) only matches semantic
HTML submit elements. Many JS-framework-built forms (React/Vue component
libraries, custom-styled "buttons" that are actually `<div role="button">`
or `<span onclick=...>`) trigger submission purely from a `click` listener
bound to that non-matching element — never via the form's native `submit`
event at all. When no button matches, the code falls back to
`form.evaluate("f => f.requestSubmit ? f.requestSubmit() : f.submit()")`,
which synthesizes a `submit` event on the form element directly. If the
site's real submission logic is only wired to `click` on the custom element,
this fallback:
- never invokes the site's actual submission code (so a real bug in that
  code is never exercised — a *missed* real bug), and
- still gets caught by the injected bubble-phase `submit` listener (since
  nothing else calls `preventDefault`), so `native_attempted` becomes `True`
  and the form is reported as "Form Not Fully Verified" (LOW) — a status
  that implies "this form does something" when in fact nothing representative
  of a real user's interaction was ever tested.

This is a more precise version of the general "no submit button" question:
`requestSubmit()` *does* correctly reproduce a real click's `submit`-event/
`defaultPrevented` semantics when the form's real trigger is itself a native
submit action — the gap is specifically forms whose real trigger isn't a
submit action at all.

**Why it matters.** Produces a misleading "unverified but seems to try
something" signal on forms that may be fully broken (real bug missed) or
fully fine (false alarm demoted to a LOW note that still isn't measuring the
right thing) — either way the report doesn't reflect what a real visitor's
click would actually do.

**Fix direction.** Widen the "found a trigger" search to include elements
carrying `role="button"` or any element the page's own `click` listeners are
bound to being harder to detect generically; failing that, treat the
`requestSubmit()`-fallback path's result with an even more hedged status/
wording than the current "Form Not Fully Verified" message, since it's
testing a synthetic path rather than confirmed real user behavior.

---

## 4. HTML5 constraint validation can silently block the synthetic submission entirely (false "Broken Form" HIGH)

**Scenario.** Both `submit_button.click()` and `f.requestSubmit()` go through
the browser's native "submit the form" algorithm, which runs interactive
constraint validation first. If any `required` field is left invalid, the
browser blocks the submit event from ever firing (shows a native validation
bubble instead) — no `submit` event, no navigation, no request. `_fill_form`
(lines 199–239) skips `type="file"` and `type="password"` fields entirely,
and its generic `.fill("Test")` fallback can fail HTML5 pattern/format
constraints it doesn't understand (e.g. `type="date"`/`type="time"` inputs
expecting ISO format, or a `pattern="\d{3}-\d{3}-\d{4}"` phone field being
filled with `"5555555555"`, no dashes). A `.fill()` failure is swallowed by
the per-field `except Exception: continue` (line 233), leaving the field
empty. If any such field is `required`, the entire submission silently never
attempts anything — and the outer code has no way to distinguish "the form
is broken" from "our test data failed this form's validation rules."

**Why it matters.** This produces a false `HIGH` "Broken Form" report on
forms that work perfectly for real visitors who fill in valid-format data —
plausibly one of the more common false positives in practice, since required
file-upload fields ("attach a photo of the issue"), phone/zip patterns, and
date pickers are all common on real contact/quote/booking forms.

**Fix direction.** After a submission attempt produces no signal at all,
check `form.evaluate("f => f.checkValidity()")` (or inspect `:invalid`
fields) before concluding "broken" — if native validation is why nothing
happened, report a distinct, lower-severity/differently-worded finding
("couldn't fully test this form — it has a required file upload / pattern
field our automated test couldn't fill") instead of `Broken Form` `HIGH`.

---

## 5. CORS preflight (OPTIONS) requests to third-party form endpoints aren't blocked

**Scenario.** `_block_mutating_requests` only intercepts
`POST/PUT/PATCH/DELETE` non-navigation requests (line ~276). A cross-origin
AJAX submission with a non-"simple" content type (e.g. `application/json`,
typical for modern form widgets posting to Formspree/Netlify
Forms/etc.) triggers a browser-initiated CORS preflight `OPTIONS` request
before the real `POST`. `OPTIONS` isn't in the blocked-method set, so
`route.continue_()` lets it through — a real network request reaches the
third party's server. The subsequent actual `POST` is correctly intercepted
and aborted, so no submission body/test data ever leaves the browser, but the
"no real test data ever reaches the target site's backend" guarantee
(`check_forms` docstring, lines 250–259) is technically slightly weaker than
stated: a third party does see one harmless, bodyless preflight hit per
check run.

**Why it matters.** Low real-world harm (no data leaks — preflights carry no
body), but it's a gap versus the documented safety guarantee, and worth
knowing about explicitly rather than discovering it later during a safety
audit.

**Fix direction.** Either block `OPTIONS` too (simplest, and still safe since
blocking a preflight just makes the browser correctly fail the deferred real
POST as a CORS error, which is already the desired outcome) or explicitly
document this as an accepted minor exception to the "nothing leaves the
browser" claim.

---

## Minor / lower-priority observations

- **Cookie-consent / overlay banners covering the submit button** —
  `submit_button.click(timeout=3000)` uses Playwright's actionability checks
  (visible, not obscured, receives events). A cookie/GDPR banner sitting over
  a below-the-fold submit button — extremely common on real small-business
  sites on first load — would time out the click, fall through to the
  outcome check with nothing having happened, and get reported as `Broken
  Form` `HIGH`, even though a real visitor (who dismisses the banner) would
  have a working form. `run_check` doesn't attempt to dismiss consent banners
  anywhere. Worth a quick check for common consent-banner dismiss patterns
  before the form pass, given how common this is in practice.

- **Multi-form stale-handle skip in `ENABLE_REAL_FORM_SUBMISSION=true` mode
  only** — `forms = page.query_selector_all("form")[:MAX_FORMS_TO_CHECK]` is
  computed once up front. If form 1's real submission (opt-in mode only)
  causes an actual full-page navigation, the element handles for forms 2+
  become detached; `form.is_visible()` on them throws and is caught by the
  `except Exception: continue` at the top of the loop, so subsequent forms
  are silently skipped rather than checked or reported as skipped. Since this
  mode is explicitly dev-only/opt-in (never on in production per
  `PROJECT_STATUS.md`), the real-world exposure is low, but worth knowing if
  local testing against a multi-form page ever "loses" forms after the first.

- **Fixed 4-second wait (`FORM_SUBMIT_WAIT_MS`)** — a form whose real
  backend/spam-check takes longer than 4s to respond (slow third-party form
  services, deliberately-delayed spam honeypots) could be read too early and
  reported as broken. Not investigated in depth here, but worth a note since
  it compounds with several of the above.

- **Coincidental unrelated navigation during the wait window** — the
  `redirected` check is a blunt `page.url` diff over the full 4-second
  window; an unrelated same-page script (ad redirect, A/B test tool, geo
  redirect) firing during that window while the form's own submission
  actually failed would misreport a broken form as working. Rare in
  practice, included for completeness.

## Confirmed non-issue (investigated per request, no bug found)

**`history.pushState`-based SPA routing on submit** — Playwright's `page.url`
is kept in sync with `Page.navigatedWithinDocument`-style CDP events, which
fire for both hash changes and `pushState`/`replaceState`. A form whose
"success" is a client-side route change to e.g. `/thank-you` via `pushState`
(no real navigation, no new document) is correctly detected as `redirected =
True` via the existing `pre_url`/`post_url` diff — same mechanism that
already correctly handles plain hash changes. This path did not need a fix.
