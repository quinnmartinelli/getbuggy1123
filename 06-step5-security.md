GetBuggy — Step 5 of 9: Endpoints, transport, and passive security (ownership-gated)

Follow the standing rules in `CLAUDE.md`. Read `PROJECT_STATUS.md` and `PLAN.md` first. Only run this step after the ten-business test.

**Gating — build this first, in this step**
- Every finding from this step carries `category: security`.
- Public reports render security findings at category level only: "We found N possible security exposures on this site. Verify you own this site to see the details." No paths, no values, no version numbers.
- Full detail renders only when `GETBUGGY_SHOW_SECURITY_DETAILS=true` is set on the server. Full detail is never included in a shareable permalink or the "send to your web person" export unless that flag is on.
- Add the authorisation clause to the legal drafts now: "You confirm you own the site you are checking or are authorised by its owner to do so."

**Endpoint checklist** (GET only, pasted site only, every probe logged)

| Path | Expected | Finding |
|---|---|---|
| `/robots.txt` | 200 or 404 | 500 → HIGH |
| sitemap variants | 200 XML | none found → LOW |
| favicon (`/favicon.ico` and `<link rel=icon>`) | 200 | missing → LOW |
| random nonexistent path | real 404 | 200 (soft 404) → MEDIUM; raw server error page → LOW |
| `/.env`, `/.git/HEAD`, `/.git/config`, `/wp-config.php.bak`, `/backup.zip`, `/phpinfo.php`, `/.DS_Store` | 404/403 | 200 with plausible content → HIGH |
| `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` (only if WordPress detected) | — | `xmlrpc` open → MEDIUM; user enumeration via `/wp-json/wp/v2/users` or `/?author=1` → MEDIUM |
| `http://` root | 301/308 to https | no redirect → HIGH |
| `www` vs apex | one redirects to the other | both serve content → LOW |
| `/site.webmanifest` / `/manifest.json` (only if referenced) | 200 | missing → LOW |
| directory listing (`Index of /` on any crawled path) | none | present → MEDIUM |

**Transport**
- Certificate: validity, chain, hostname match, self-signed (HIGH each); expiry under 14 days HIGH, under 30 days MEDIUM; TLS 1.0/1.1 enabled → LOW.
- HTTPS on every crawled page; split mixed content into passive (images, LOW) and active (scripts/iframes, MEDIUM).

**Headers** (each LOW; none present at all → MEDIUM): HSTS, `X-Content-Type-Options`, `X-Frame-Options` or CSP `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`, CSP presence. Version leakage in `Server` / `X-Powered-By` → LOW.

**Exposure in page source**
- Regex for live secrets: AWS access keys, Stripe secret keys (`sk_live_`), SendGrid/Mailgun/Twilio keys, private keys, SMTP credentials. Any hit → HIGH, value masked in the report and in logs. Stripe publishable keys (`pk_`) and Google Maps/Analytics IDs are not findings.
- Public `*.js.map` files → LOW.

**Platform and dependencies**
- Detect CMS/platform (WordPress, Shopify, Wix, Squarespace, Webflow, Joomla, Drupal) and store it on the report; use it to add platform-specific fix instructions to findings.
- WordPress core and plugin versions where discoverable; compare against a locally-bundled known-vulnerable list (updated via a script, never fetched at runtime). Known CVE → HIGH; merely outdated → MEDIUM.
- Front-end library versions (jQuery, Bootstrap, Swiper, etc.) against a bundled retire.js-style list. Known vuln → MEDIUM.

**Third-party scripts**
- Inventory every third-party script domain. Loaded over http → MEDIUM. Script domain that no longer resolves or whose registrable domain is unregistered → HIGH. Missing SRI on CDN scripts → LOW.

**Compromise signals** → HIGH "your site may be hacked": hidden spam text/links, unexpected `<meta refresh>` or JS redirects to off-site domains, heavily obfuscated inline JS, server HTML that differs wildly from rendered content. Add a Google Safe Browsing lookup if an API key is configured; skip gracefully if not.

**Definition of Done:** fixtures for each endpoint case, an exposed-secret page, a hacked-signal page, and an outdated-WordPress fingerprint; harness passes; every security finding carries plain-English copy and a "who fixes it"; the public report shows category level only and the flag reveals detail; the authorisation clause is in the legal drafts.

Commit and push, run `post_deploy_check.py` against the live URL, then give me the Step 5 summary with harness output and live `/version` pasted.
