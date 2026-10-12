GetBuggy — Step 7 of 9: Cookies and consent

Follow the standing rules in `CLAUDE.md`. Read `PROJECT_STATUS.md` and `PLAN.md` first. Jurisdiction is decided: default `us`, with a `jurisdiction` field (`us` / `eu_uk` / `both`) on the run request that adjusts which findings show and their wording.

- Record all cookies set and all third-party requests made before any user interaction.
- Classify cookies and trackers (analytics, advertising, functional) using a bundled classification list.
- Consent banner detection: look for known CMP scripts (Cookiebot, OneTrust, Osano, CookieYes, Termly, Iubenda) and generic banner patterns.
- Findings: tracking cookies with no banner → MEDIUM; banner present but tracking fires before consent → MEDIUM ("your banner isn't blocking anything"); reject not as easy as accept → LOW; banner blocks the entire mobile viewport with no dismiss → LOW.
- First-party cookie attributes: missing `Secure` → LOW; auth-looking cookies missing `HttpOnly` → MEDIUM; missing `SameSite` → LOW.
- Privacy policy page: exists, linked from the footer, not a placeholder, has a date within about 2 years. Missing while tracking is present → MEDIUM.
- Policy-vs-observed mismatch: if the policy text does not mention a third party that is observably loading (Google Analytics, Meta, Hotjar, TikTok) → MEDIUM.
- Informational section: "Your site sets N cookies from M companies," listed.
- All compliance copy uses "may" language and includes the not-legal-advice line.

**Definition of Done:** fixtures for no-banner, banner-not-blocking, and compliant cases; harness passes; the `jurisdiction` field works and defaults to `us`.

Commit and push, run `post_deploy_check.py` against the live URL, then give me the Step 7 summary with harness output and live `/version` pasted.
