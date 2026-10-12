# GetBuggy — Checks Reference

One row per finding category the checker can produce, as of Step 9 (2026-10-11). Cross-checked against the code: every category string in `core.py`, `checks_links.py`, `checks_seo.py`, `checks_performance.py`, `checks_security.py` and `checks_accessibility.py` has a row here. This is the reference sheet for the ten-business test: when a report says something, look it up here to see how sure GetBuggy is and what should make you doubt it. Things GetBuggy does **not** check yet are listed at the end — if it isn't in a table, the checker doesn't do it.

**How to read the columns**

- **Category / group** = the finding's name in the report (`category`) and the area it belongs to.

- **Severity** = how bad it is *if true*. **Confidence** = how sure GetBuggy is that it's true. They're independent: `verified` means the checker directly observed the thing (a tag is missing, a request really failed); `needs_look` means the signal is indirect, single-shot, or depends on where the check ran from, so a person should judge it. The report labels those "Needs a look."
- **Could not check** is a separate list, not a finding: things GetBuggy couldn't observe either way (a login wall, a timeout, a site that blocks bots). It's shown under "What we couldn't check."
- Every network probe (link checks, sitemap URL tests) is made from GetBuggy's server, not from a real visitor's device or country. That's why link failures are always `needs_look`.

## Per page

| Check (category) | Category group | Severity rule | Confidence rule | Triggers `needs_look` / "could not check" |
|---|---|---|---|---|
| JavaScript Crash *(Step 5)* | Scripts | HIGH — only when the error came from a first-party script (same domain as the page) **and** something else on the same page load visibly broke (a `Broken Form`, `Failed Network Request`, or `Mobile Horizontal Scroll` finding — see *(Step 5.2)* below for what this deliberately does NOT count) | verified | never — anything short of both conditions is a `Script Error` or `Third-Party Resource Failed` instead (see below), never this category |
| JavaScript Console Error *(Step 5.2)* | Scripts | Same first-party-and-visible-break rule as JavaScript Crash — a `console.error()` call is a weaker signal than an uncaught exception (code often logs an error on purpose: a CSP violation report, a feature-detection warning, a widget's own diagnostic message), so it's judged the same way, not unconditionally HIGH | verified | never — anything short of both conditions is a `Script Error` or `Third-Party Resource Failed` instead, same as JavaScript Crash |
| Script Error *(Step 5)* | Scripts | LOW — a first-party script error/console message with no confirmed visible effect, or one whose origin couldn't be determined at all | needs_look (always) | always `needs_look` — "may be an app or tracker, not something you need to fix" |
| Failed Network Request | Broken resources | HIGH if from the site's own domain | verified (an ambiguous signal never becomes a finding at all — see next column) | `ERR_ABORTED`, `ERR_NETWORK_CHANGED`, or `ERR_INTERNET_DISCONNECTED` → could not check, **not** a finding *(Step 5.1)* — often just a large video/image still downloading when the check finished, or our own network dropping mid-check, not the site being broken (confirmed on a real report: a promotion video that plays fine was flagged this way). HTTP 401 → could not check (login wall). `403`/`406`/`429` on the *page itself* *(Step 5.2)* → could not check, and the rest of that page's checks are skipped entirely (see "Bot-blocked pages" below) |
| Third-Party Resource Failed | Broken resources | LOW (trackers/widgets fail constantly, out of the owner's control) | verified | same `ERR_ABORTED`/`ERR_NETWORK_CHANGED`/`ERR_INTERNET_DISCONNECTED`/401 → could not check rule. On a whole-site crawl report, every remaining instance of this category is rolled into one "Third-Party Resources Didn't Load" finding *(Step 5 — see `dedupe_site_problems`/`_rollup_third_party_failures` in `core.py`)*, expandable to the individual trackers |
| Missing Alt Text | Accessibility | LOW — grouped into one finding per page listing every image missing alt text *(Step 5)*, not one finding per image | verified | never |
| Broken Link | Links | MEDIUM by default; **HIGH *(Step 5.5)*** for a same-site (internal) link confirmed 404/410 by both our server probe **and** a real-browser recheck — your own site, confirmed broken two independent ways | needs_look by default (single probe from our server); **verified** for the HIGH internal case above | Timeout → could not check. 401 → could not check. External/bot-blocked links always stay needs_look, even when a browser recheck also sees 404/410 — we have no more-authoritative way to check someone else's site |
| Broken Social Link *(Step 4)* | Links | HIGH — a social profile link (Facebook, Instagram, LinkedIn, X, TikTok, YouTube, …) that returns 404/410 | verified only if both our server **and** a real-browser retry saw 404/410 | Blocked/403/429 or a browser retry that disagrees → downgrades to "Link Needs A Look" |
| Link Needs A Look *(Step 4)* | Links | LOW | needs_look | A link that refused our check (403/406/429) even from a real browser. Never HIGH. Links to sites known to block bots (Google, Amazon, Yelp, …) are tolerated silently with a could-not-check note |
| Broken In-Page Link *(Step 4)* | Links | LOW — `#section` link whose target id/name doesn't exist on the page | verified | never (`#`, `#top` and hash routes like `#/about` are not flagged) |
| Placeholder Links *(Step 4)* | Links | MEDIUM — `javascript:void(0)` links | needs_look (we don't click, so we can't tell whether it opens a menu) | always `needs_look` |
| Vague Link Text *(Step 4)* | Links / accessibility | LOW — "click here", "read more", "here", bare URLs; grouped into one finding per page | verified | An `aria-label` on the link suppresses it |
| Links Only Appear After Scripts Run *(Step 4)* | Links / SEO | LOW — fewer than 20% of the rendered links exist in the server HTML (only judged when 5+ links) | verified | never; if the original HTML can't be read → could not check |
| Redirect Chain *(Step 4)* | Links / speed | LOW — a page (or grouped links on a page) reached through 3+ redirects; notes when more than 5 | verified | never |
| Soft 404 Page *(Step 4)* | SEO / broken pages | MEDIUM — a page that answers 200 but reads like the site's own "not found" page (never the homepage) | verified only if the text is word-for-word identical to the site's not-found page; otherwise needs_look (≥90% match) | Only runs if the site answers a made-up address with 200 |
| Page Blocked From Search (noindex) *(Step 4)* | SEO | HIGH on the homepage; MEDIUM elsewhere | verified | never (meta robots/googlebot tag or `X-Robots-Tag` header). **Skipped entirely on a utility page** *(Step 5.3 — see below)*, since noindex is the *correct*, expected state there, not a finding |
| Missing Page Title | SEO | MEDIUM | verified | never. **Skipped entirely on a utility page** *(Step 5.3)* |
| Missing Meta Description | SEO | LOW | verified | never. **Skipped entirely on a utility page** *(Step 5.3)* |
| Missing H1 Heading / Multiple H1 Headings | SEO | LOW | verified | never. **Skipped entirely on a utility page** *(Step 5.3)* |
| Missing Favicon | SEO | LOW | verified | never. Still runs on every page, including utility ones — a favicon is site-wide regardless of which page loaded it. *(Step 5 change)* Not reported on a crawl when the page has no `<link rel=icon>` but the site's `/favicon.ico` loads (browsers find that on their own) |
| Mixed Content (Active) *(Step 5)* | Security 🔒 | MEDIUM — scripts, frames, stylesheets, embeds over `http://` on an `https://` page | verified | never |
| Mixed Content (Passive) *(Step 5)* | Security 🔒 | LOW — images, video, audio over `http://` on an `https://` page | verified | never |
| Render-Blocking Scripts | Speed | MEDIUM | verified | never |
| Oversized Images | Speed | LOW | verified | never |
| Many Requests | Speed | LOW (> 100) | verified | never |
| Slow Server Response (first byte) | Speed | MEDIUM if > 1.8 s; LOW if > 0.8 s | verified (measures the site's server, not our rendering) | Network distance from our server can still play a part |
| Page Load Time *(Step 5.3)* | Speed | Absolute seconds, not a multiple of a reference page: no finding under 3s; LOW 3-5s; MEDIUM over 5s | needs_look (always — derived from our own render time) | Skipped when the reference page itself is currently loading slowly (>2s) — our own environment can't be trusted to judge the target page fairly right then |
| Largest Contentful Paint *(Step 5.3)* | Speed / Core Web Vitals | Google's own published LCP thresholds, absolute seconds, not a multiple of a reference page: no finding under 2.5s; LOW 2.5-4s; MEDIUM over 4s | needs_look | Same reference-page-unreliable skip as Page Load Time above |
| Layout Shifts While Loading | Speed / Core Web Vitals | MEDIUM if "poor", LOW if "needs improvement" | verified | never |
| Core Web Vitals Check Failed | Speed | LOW | needs_look | The measurement itself failed |
| Mobile Horizontal Scroll | Mobile | MEDIUM | verified | Whole pass failing → "Mobile Check Failed" |
| Mobile Check Failed | Mobile | LOW | needs_look | The mobile pass couldn't run |
| Broken Form | Forms | HIGH — submitted a test entry, nothing visibly happened | verified | never |
| Form Needs A Look | Forms | MEDIUM — couldn't reach/complete the form (wizard step won't advance, no submit control found, a field we couldn't fill validly) | needs_look | always |
| Form Not Fully Verified | Forms | LOW — front-end worked, delivery to the business can't be proven | needs_look | always. **Real submission is off; forms are never truly submitted.** |
| Embedded Form | Forms | HIGH when a known provider's iframe (Calendly, Typeform, HubSpot, Jotform, Google Forms, Tally, Cognito) fails to load; LOW "loads correctly" notes; MEDIUM when it couldn't be checked | verified when we saw the failure/success | MEDIUM note = `needs_look` |

**Removed *(Step 5.4, 2026-09-26)*: Mobile Text Too Small, Mobile Tap Targets Too Small.** Product decision, not a bug fix: small text and small tap targets on a brand site are usually a deliberate design choice, and flagging them read as the tool not understanding the business. `check_mobile_responsiveness` no longer measures either at all (not just suppressed — the underlying per-element JS scan was removed). `Mobile Horizontal Scroll` stays: an unambiguous layout break, never a design choice.

**Forms skipped entirely** *(Step 5.3)*: no form check of any kind (including Embedded Form) runs on a utility page (see below) — a login/account/search page's forms aren't leads the business is trying to capture. Independent of that, any single form (on any page) whose `action` resolves to the platform's own domain (`shopify.com`, `myshopify.com`, `squarespace.com`, `wix.com`, `webflow.io`, `wordpress.com`) is skipped without being filled, clicked, or submitted at all — it's the platform's own login/account infrastructure, not the business's.

## Whole site (shown once, above the pages) — Step 4

| Check (category) | Category group | Severity rule | Confidence rule | Triggers `needs_look` / "could not check" |
|---|---|---|---|---|
| Site Blocked From Search (robots.txt) | SEO | HIGH — `Disallow: /` for all agents or for Googlebot | verified | never |
| Sitemap Lists Missing Pages | SEO / sitemap | MEDIUM — sitemap URLs that 404/410 (confirmed by a second request) | verified | Only the first 100 sitemap URLs are tested (noted) |
| Sitemap Lists Redirecting Pages | SEO / sitemap | MEDIUM — sitemap URLs that answer with a redirect | verified | same 100-URL limit |
| Sitemap Lists URLs On Another Host | SEO / sitemap | MEDIUM | verified (`www` vs no-`www` is not "another host") | never |
| Sitemap Lists Insecure URLs | SEO / sitemap | MEDIUM — `http://` entries on a site served over `https://` | verified | never |
| Menu Pages Missing From Sitemap | SEO / sitemap | LOW — pages linked from the homepage's menu but absent from the sitemap | verified | Only when a sitemap was found. Never fires for a page GetBuggy expects to be absent from any sitemap (see below), for the site's own homepage/root, or for a URL already reported as a broken link elsewhere in the crawl |
| Heavy Page *(Step 5.5 — moved here from per-page)* | Speed | LOW — only the single heaviest page on a whole-site crawl (> ~3 MB), named by URL; never one finding per heavy page | verified | never. On a single-page check (not a crawl) this still reports per-page, since there's no "site" to pick a heaviest page from |
| Too Many Redirects | Links | MEDIUM — the submitted address redirects more than 5 times | needs_look | always |
**Sitemap discovery order:** `robots.txt` `Sitemap:` lines → `/sitemap.xml` → `/sitemap_index.xml` → `/sitemap-index.xml` → `/wp-sitemap.xml`. Sitemap indexes (nested) and `.gz` sitemaps are supported; child sitemaps must stay on the same site.

**Pages checked** (free tier: 5): homepage → primary-menu pages → pages whose address contains contact/pricing/book/order/shop → sitemap order. The report says "Checked N of M pages" and lists the skipped pages.

**Sitemap exclusions *(Step 5, keywords extended Step 5.3)*:** a menu link is never flagged as "missing from sitemap" when it's a page normal sites (especially Shopify) intentionally keep out of their sitemap: `/cart`, `/checkout`, `/account`, `/customer_authentication/*`, `/search`, `/collections/all`, anything with "login", "logout", "signin", or "signout" as a path segment, or any URL carrying a query string (a filtered/sorted view of another page, not a distinct page). See `_expected_absent_from_sitemap` in `core.py`.

**Two more sitemap-comparison exclusions *(Step 5.5)*, found testing housejanolo.com (Squarespace):** (1) the site's own root ("/") is never flagged, even if the sitemap lists the homepage's content under a different, platform-internal path (e.g. Squarespace's `/home`) — a domain's homepage is discoverable by definition, sitemap or not; this was never actually a www/apex/trailing-slash bug in `page_key` (that already worked correctly), just two genuinely different paths that happen to serve the same content. (2) a URL already reported as a broken link elsewhere in the crawl is never also listed as "missing from sitemap" — telling a business to add a broken page to their sitemap is confusing, redundant noise on top of the real finding. Computed once the crawl's pages are known (`_menu_pages_missing_from_sitemap_finding` in `core.py`), not from the early, before-any-page-is-checked pass the other sitemap findings above come from.

## Security and site setup *(Step 5)*

🔒 = a **security** finding (`"group": "security"`). These are ownership-gated: the public report (web and CLI) shows only "We found N possible security exposures on this site. Verify you own this site to see the details." — no paths, values or version numbers. Full detail is returned only when the server has `GETBUGGY_SHOW_SECURITY_DETAILS=true`. The gate sits in `server.check_status`, the one route report data leaves by, so it also covers in-progress pages and saved reports reopened by id. Rows without 🔒 are ordinary public findings from the same endpoint checklist.

Everything here is passive: what the page load already returned, plus plain GETs (never following redirects) to the fixed paths below on the site the user pasted, at most 4 at a time, every one through the SSRF guard and logged as `SECURITY_PROBE GET <path> -> <status>` (path only — never the site). Every finding names who fixes it (`who_fixes`). `GETBUGGY_SKIP_SECURITY_CHECKS=true` turns the whole pass off, recorded in the report.

Category group: 🔒 rows are **Security** (ownership-gated); rows without it are **Site setup** (public).

| Check (category) | Severity rule | Confidence rule | Triggers `needs_look` / "could not check" |
|---|---|---|---|
| robots.txt Is Erroring | HIGH — `/robots.txt` answers 5xx (Google treats that as "stay out") | verified | |
| No Sitemap Found | LOW | verified | none of robots.txt's `Sitemap:`, `/sitemap.xml`, `/sitemap_index.xml`, `/sitemap-index.xml`, `/wp-sitemap.xml` |
| Favicon Doesn't Load | LOW — the `<link rel=icon>` file isn't a 200 | verified | `data:` icons are skipped |
| Missing Pages Don't Say "Not Found" | MEDIUM — a made-up address answers 200 | verified | probe can't connect → could not check |
| Plain Server Error Page | LOW — a made-up address gets a bare nginx/Apache/IIS-style error page | verified | |
| Web App Manifest Missing | LOW — only if a page links one | verified | |
| Site Answers On Both www And Non-www | LOW — the other variant answers 200 HTML without redirecting | verified | skipped for IP addresses |
| Exposed Sensitive File 🔒 | HIGH — `/.env`, `/.git/HEAD`, `/.git/config`, `/wp-config.php.bak`, `/backup.zip`, `/phpinfo.php`, `/.DS_Store` answers 200 **and** the content looks like the real thing (not a soft-404 page) | verified | unreachable probes → could not check |
| WordPress XML-RPC Is Open 🔒 | MEDIUM — WordPress only | verified | |
| WordPress Usernames Are Public 🔒 | MEDIUM — `/wp-json/wp/v2/users` lists users, or `/?author=1` redirects to `/author/<name>/` | verified | |
| WordPress Version Has Known Security Problems 🔒 | HIGH — WordPress.org's own stable-check list marks the version "insecure" | verified from the generator tag; needs_look if only from asset `?ver=` | version not in the bundled list → could not check |
| WordPress Out Of Date 🔒 | MEDIUM — "outdated" in the same list | as above | |
| WordPress Plugins Out Of Date 🔒 | MEDIUM — plugin `?ver=` older than WordPress.org's latest release | needs_look (`?ver=` isn't always the plugin version) | plugin **vulnerability** lists aren't bundled (no free feed) — always noted as not checked |
| Site Doesn't Use HTTPS 🔒 | HIGH — the site is `http://` (message says whether an https version exists) | verified | |
| Insecure Version Of Site Doesn't Redirect 🔒 | HIGH — `http://` root answers 200 on an https site | verified | |
| Security Certificate Problem 🔒 | HIGH — expired, not yet valid, self-signed, incomplete chain, wrong hostname | verified | couldn't connect → could not check |
| Security Certificate Expiring Soon 🔒 | HIGH under 14 days, MEDIUM under 30 | verified | |
| *(TLS 1.0/1.1)* | — | — | **never checked** — needs non-GET handshakes; always noted as not checked |
| Page Not On HTTPS 🔒 | MEDIUM — a crawled page is `http://` on an https site | verified | |
| No Security Headers 🔒 | MEDIUM — none of HSTS (https only), X-Content-Type-Options, X-Frame-Options/`frame-ancestors`, Referrer-Policy, Permissions-Policy, CSP | verified | homepage response only |
| Missing Security Headers 🔒 | LOW — one finding listing the missing ones | verified | |
| Server Software Version Revealed 🔒 | LOW — `Server`/`X-Powered-By` carries a version number | verified | |
| Secret Key Exposed In Page Source 🔒 | HIGH — AWS access key, Stripe secret/restricted key, SendGrid, Mailgun, Twilio auth token, private key, SMTP password, in the server HTML, the live page or the site's own scripts | verified | value masked (`sk_l••••••••`) in the report; never logged. `pk_` keys and Google/Analytics IDs aren't findings |
| Source Code Map Files Are Public 🔒 | LOW — a first-party script's `.map` answers 200 with source-map JSON | verified | |
| Outdated JavaScript Library 🔒 | MEDIUM — version (from file name/path, file banner, or the library's own version property) is in a vulnerable range of the bundled Retire.js list | verified | |
| Script From A Domain That No Longer Exists 🔒 | HIGH — a third-party script host gets "no such domain" from DNS | needs_look (DNS says it doesn't exist; can't prove it's unregistered) | |
| Shared-Server Scripts Without Integrity Check 🔒 | LOW — scripts from public CDNs (cdnjs, jsDelivr, unpkg, code.jquery.com, …) without `integrity` | verified | |
| Folder Contents Are Public 🔒 | MEDIUM — a crawled page is an "Index of /" listing | verified | |
| Site May Be Hacked 🔒 | HIGH — one per signal: off-site `<meta refresh>`; off-site JS redirect; execute+decode+long-blob scrambled script; 2+ hidden links to spam sites; server HTML full of spam words the browser never shows; Google Safe Browsing match | needs_look | Safe Browsing only runs with `GOOGLE_SAFE_BROWSING_API_KEY`; otherwise noted as not checked |

The bundled lists live in `security_data/` and are refreshed by hand with `python update_security_data.py` (never fetched while checking a site). Platform (WordPress, Shopify, Wix, Squarespace, Webflow, Joomla, Drupal) is detected once per crawl, stored as the report's `platform`, and adds platform-specific advice to header, HTTPS and exposed-file findings.

## Utility pages *(Step 5.3)*

A distinct, narrower concept from the sitemap exclusions above: a page whose whole purpose is a transient, session-specific, or personal action — log in, view your cart, search — rather than content a visitor reads or a search engine ranks (`/cart`, `/checkout`, `/account`, `/customer_authentication/*`, `/search`, or a "login"/"logout"/"signin"/"signout" path segment; see `core._is_utility_page`). Deliberately excludes `/collections/all` and any URL with a query string — both real, readable content, just excluded from sitemaps for unrelated reasons (pagination/duplication). On a utility page:

- SEO-discoverability checks are skipped entirely (see the SEO rows above) — favicon and mixed-content still run everywhere.
- No form check of any kind runs (see "Forms skipped entirely" above).

Found testing heavenmayhem.com: its `/search`, `/account`, and `/cart` pages were getting "missing meta description"/"missing H1" and being form-checked as if they were lead-generation pages, on an otherwise clean Shopify store.

## Cross-page deduplication *(Step 5)*

A whole-site crawl's problem count is the number of **unique** problems, not the number of times something wrong showed up on some page. The same real thing — an image, a broken link, a failing tracker, a script's own error text — reported on more than one page counts once, shown with "Found on: N pages" and the list of pages. Checks that involve one concrete "thing" record it explicitly (Missing Alt Text: the image's `src`; Broken Link/Broken Social Link/Link Needs A Look: the link's URL; Failed Network Request/Third-Party Resource Failed: the resource's URL). Everything else (a generic per-page count like "12 elements are hard to tap on a phone," or "Missing Page Title") has no single concrete thing to key on, so it's deduplicated by category alone — the same kind of issue recurring across pages is one problem to report, wherever the exact count differs page to page. See `dedupe_site_problems` in `core.py`. This is why cakesbody.com's report went from 382 "problems" on 5 pages to a real, individually-actionable count in the 40-60 range — not the same recurring thing counted once per page or once per tracker (see PROJECT_STATUS.md Step 5).

## Bot-blocked pages *(Step 5.2)*

When a page's own navigation (not a sub-resource on it) comes back HTTP 403, 406, or 429, that's very often a WAF/bot-protection service blocking this specific automated check, not the page being broken for a real visitor (`CLAUDE.md`'s standing rule: "never evade a bot block — report 'this site blocks automated checks' instead"). Whatever actually rendered in that case is likely the WAF's own challenge/error page, not the site's real content, so none of the rest of that page's checks run — they'd be reporting on the block page, not the business's page. A single "could not check" note is recorded instead, and the page counts as checked (not skipped), just with nothing else to report. Confirmed on a real report: blaze.ai's own "Log In" page returned 403 (almost certainly bot protection on their app subdomain) and, before this fix, produced a HIGH "Failed Network Request" plus a HIGH "JavaScript Console Error" from whatever page the WAF actually served.

## Accessibility *(Step 6)*

Every finding here carries `"topic": "accessibility"` and, where it counts elements, an `element_count`. They're ordinary public findings (not ownership-gated) and appear in each page's problem list like everything else. On top of that the report has an **Accessibility** section (`accessibility_summary` in `checks_accessibility.py`): the top 5 accessibility findings, ordered by severity then by elements affected, each with its page and element counts — and always, even on a clean result, this note: *"Automated checks like these catch only part of the accessibility problems a real visitor can run into — many can only be found by a person, for example by using the site with just a keyboard or with a screen reader. A clean result here does not mean your site is accessible or legally compliant."* The CLI prints the same note after every report.

**Severity principle:** MEDIUM when it stops someone using the site (can't read it, can't fill in a form, can't press a button, can't zoom); LOW for structure and code problems a screen reader mostly copes with. Nothing in this section is HIGH — HIGH in GetBuggy means "broken for everyone." Every finding says what's wrong, why it matters, how to fix it and who fixes it.

All of it runs on the already-loaded page (no extra page load), on every checked page including utility pages, and **before** the form check — so it sees the page as a visitor first does, not with test entries typed in. It's passive: it reads the page and presses Tab, never clicks, submits or fetches anything.

### Automated scan (axe-core)

axe-core **4.14.0**, vendored in `vendor/axe-core/` (byte-identical to the npm release; never fetched from a CDN at check time), injected into the page and run with the WCAG 2.0/2.1/2.2 level A and AA rules, plus `heading-order`, `duplicate-id` and `duplicate-id-active` (axe files those under best practice, but the Step 6 spec names them). Only violations are requested — axe's "incomplete" (unsure) results never are — so every axe finding is `verified`. Rules that mean the same thing to a business owner share one category, merged into one finding per page; the message gives the element count, up to 3 examples in words a visitor would recognize (`"Order now" (button)`), and, for the web person, the axe rule IDs and first CSS selectors. Cross-origin frames aren't scanned.

| Check (category) | Severity | Confidence | Triggers `needs_look` / "could not check" | axe rules |
|---|---|---|---|---|
| Hard-to-Read Text (Low Contrast) | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `color-contrast` |
| Form Fields Without Labels | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `label`, `select-name`, `form-field-multiple-labels`, `aria-input-field-name`, `aria-toggle-field-name` |
| Buttons Without a Name | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `button-name`, `input-button-name`, `aria-command-name`, `summary-name` |
| Empty Links (No Link Text) | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `link-name` |
| Page Language Not Set | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `html-has-lang`, `html-lang-valid`, `html-xml-lang-mismatch`, `valid-lang` |
| Page Blocks Zooming | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `meta-viewport` |
| Page Refreshes or Redirects on a Timer | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `meta-refresh` |
| Content Not Reachable by Keyboard | MEDIUM | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `scrollable-region-focusable`, `frame-focusable-content` |
| Button or Link Name Doesn't Match Its Text | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `label-content-name-mismatch` |
| Images or Icons Without a Description | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `area-alt`, `input-image-alt`, `role-img-alt`, `svg-img-alt`, `object-alt`, `server-side-image-map` |
| Headings Skip Levels | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `heading-order` |
| Duplicate IDs in the Page Code | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `duplicate-id`, `duplicate-id-active`, `duplicate-id-aria` |
| Lists or Tables Built Incorrectly | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `list`, `listitem`, `definition-list`, `dlitem`, `td-has-header`, `td-headers-attr`, `th-has-data-cells`, `table-fake-caption` |
| Screen-Reader Code (ARIA) Used Incorrectly | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | every other `aria-*` rule |
| Clickable Elements Nested Inside Each Other | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `nested-interactive` |
| Links Only Distinguished by Color | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `link-in-text-block` |
| Embedded Frames Without a Title | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `frame-title`, `frame-title-unique` |
| No Way to Skip to the Main Content | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `bypass` |
| Form Autofill Settings Are Wrong | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `autocomplete-valid` |
| Text Spacing Locked | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `avoid-inline-spacing` |
| Page Locked to One Screen Orientation | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `css-orientation-lock` |
| Blinking or Scrolling Text | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `blink`, `marquee` |
| Text Styled to Look Like a Heading | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | `p-as-heading` |
| Accessibility: *(axe's own description)* | LOW | verified | never — only axe violations are reported. Scan timed out or skipped for time → could not check | any rule with no translation above (e.g. one added in a future axe version) — reported in axe's own words, never silently dropped |

**Rules switched off on purpose:** `image-alt` (Missing Alt Text above already reports it, bundled per page — no double counting); `document-title` (Missing Page Title covers it); `video-caption` and `no-autoplay-audio` (replaced by the media check below, which can tell a silent background loop from a real video); `target-size` (small tap targets were removed as a finding in Step 5.4 — axe ships it off, and it's pinned off so an axe upgrade can't quietly bring it back).

**Across pages:** an axe finding is deduplicated on its category plus the exact set of axe rules that fired for it (`evidence`), so the same issue on several pages is one finding with "Found on: N pages", and its element count is summed across those pages. Two pages where a different mix of rules fired under the same category (say, `label` on one and `label` + `select-name` on another) show as two entries.

### Other accessibility checks

| Check (category) | Severity | Confidence rule | How it's decided / what triggers `needs_look` / "could not check" |
|---|---|---|---|
| No Visible Keyboard Focus | MEDIUM | needs_look (always — the focus indicator could live somewhere this can't see, like a separate overlay element) | Presses Tab for real, up to 20 times, and compares how each focused element looks with how it looked before anything was focused: outline, box-shadow ring, border, background/text color, underline, size/position (a sliding skip link), `::before`/`::after`, and the parent (a `:focus-within` ring). CSS transitions are finished before reading. Frames are stepped over. Message names up to 3 elements with no visible change, out of how many were reached |
| Media Plays Automatically With Sound | MEDIUM | verified | A `<video>` or `<audio>` set to autoplay (or already playing) and not muted. Sound 3 seconds or shorter is exempt (WCAG 1.4.2) |
| Video Without Captions | MEDIUM | needs_look (captions burned into the picture can't be detected) | A `<video>` with no `captions`/`subtitles` `<track>`. A muted, autoplaying video with no controls is a background loop and isn't flagged. Embedded YouTube/Vimeo/Wistia/Loom players → could not check ("we can't see inside those players") |
| Accessibility Overlay Widget | LOW | needs_look | A script, frame, stylesheet or any loaded resource from accessiBe, UserWay, EqualWeb or AudioEye. The message says plainly that an overlay doesn't make a site accessible or compliant, and points to the other findings as the real to-do list |
| No Accessibility Statement | LOW | needs_look ("in case it exists somewhere we didn't check") | Site-level, whole-site crawls only (shown once, above the pages): no homepage link — text, `aria-label` or address, footer included — and no sitemap page mentioning "accessib" or "a11y". Homepage links unreadable → could not check. Not run on a single-page check |

### Time budget

A single axe scan is stopped after `A11Y_SCAN_TIMEOUT_SECONDS` (default 20s); that page gets a "results are incomplete" could-not-check note. The **first** scan in a crawl that's slower than `A11Y_SLOW_SCAN_SECONDS` (default 10s), or times out, switches the rest of that crawl to scanning only the homepage and pages whose address contains contact/book/appointment/reserv/schedul (`A11yScanBudget`). Every page skipped gets its own could-not-check note, and the site gets one note saying how many pages weren't scanned and why. The focus, media and overlay checks are cheap and still run on every page. If axe can't run at all on a page, that's a could-not-check note too, never a silent clean result. Both thresholds are env vars, tunable on Render without a deploy. Measured 2026-10-11 on the seven baseline sites' homepages: axe 0.1–0.4s, focus check at most 0.9s — far inside the 60-second per-page budget.

## Cookies and consent *(Step 7)*

`checks_cookies.py`, once per whole-site crawl, on the homepage, shown under "Across your whole site". It opens the homepage in a **fresh browser** (no cookies, nothing clicked), waits for the network to go quiet (up to 5s), and records every cookie set and every third-party request made — before any interaction. Each is classified from the bundled list `cookie_data/trackers.json` (company + `analytics` / `advertising` / `functional`; anything not on the list is "unknown", never guessed). "Tracking" means analytics or advertising cookies, or requests to analytics/advertising companies — Google Consent Mode's "consent denied" pings (`gcs=G100`) don't count. Not run on a single-page or local-file check.

**`jurisdiction`** — `us` (default), `eu_uk` or `both`, chosen on the form ("Where are most of your visitors?") or sent as `jurisdiction` to `POST /api/check` (anything else → a plain-English 400). It decides which consent findings show and how they're worded; `both` uses the EU/UK wording plus a US line. All compliance copy says "may" and ends with: *"This is general information, not legal advice — a lawyer can tell you what applies to your business."*

**Banner detection:** a known consent tool's script (Cookiebot, OneTrust, Osano, CookieYes, Termly, Iubenda, plus Usercentrics, Quantcast, TrustArc, Complianz, CookieHub, Didomi), or a visible block that is pinned (fixed/sticky) or named cookie/consent/CMP, contains consent wording ("we use cookies", "consent", "cookie policy"…), and has a button that answers it (accept/reject/close). A sticky header that says "Order cookies" is not a banner. Buttons are judged by their wording: reject (reject, decline, necessary only, continue without accepting…), accept (accept, allow, agree, OK, got it…), settings, close.

| Check (category) | Shows for | Severity | Confidence | How it's decided / "could not check" |
|---|---|---|---|---|
| Tracking With No Cookie Notice | `us`: only when an **advertising** tracker loads (state opt-out rules); `eu_uk`/`both`: any tracking | MEDIUM | needs_look (a custom banner can be missed) | Tracking on load, no banner seen, no consent tool installed. A consent tool installed but no banner shown to us → could not check ("it may only appear in some places, or hide from automated checks") |
| Tracking Starts Before Consent | `eu_uk`, `both` | MEDIUM | verified (we saw it) | Banner visible **and** tracking already happened before we touched it — "your banner isn't blocking anything" |
| Rejecting Cookies Is Harder Than Accepting | `eu_uk`, `both` | LOW | needs_look (judged by wording) | Banner's first screen has an accept button and no reject-type button |
| Cookie Banner Covers The Phone Screen | all | LOW | needs_look | Second fresh visit at 390×844 (phone): the banner covers ≥90% of the screen, can't be scrolled, and no accept/reject/close button is fully on screen. Only run when the desktop visit saw a banner. Phone visit fails → could not check |
| No Privacy Policy Found | all | MEDIUM with tracking, else LOW | needs_look | No homepage link whose text or address says privacy (also datenschutz/privacidad…; "Your privacy choices"/cookie-settings links don't count) and no such page in the sitemap |
| Privacy Policy Not In Your Footer | all | LOW | needs_look | Found, but not inside the footer (`<footer>`, `role=contentinfo`, or an element named footer; on a page with none of those, the bottom 20% of the page) — or only in the sitemap |
| Privacy Policy Looks Like A Placeholder | all | MEDIUM with tracking, else LOW | needs_look | Template text (lorem ipsum, "[Your Company Name]", "insert date"…) or under 100 words. When this fires, the date and tracker checks below are skipped |
| Privacy Policy Isn't Dated | all | LOW | needs_look | No date found on the policy page |
| Privacy Policy May Be Out Of Date | all | LOW | needs_look | Latest date near "updated/effective/revised" (else the latest date on the page) is more than about 2 years old (730 + 60 days). A month or year alone counts as the end of that period |
| Privacy Policy Doesn't Mention Your Trackers | all | MEDIUM | needs_look (text search) | A tracking company seen on the homepage (Google Analytics, Meta/Facebook, TikTok, Hotjar, Google Ads, Microsoft Clarity/Bing, LinkedIn, Pinterest, Snapchat, X, Criteo, Klaviyo, HubSpot, Segment, Mixpanel, Adobe, Yandex, YouTube) isn't named in the policy. Lenient: "Google" anywhere counts for Google Analytics. One finding naming all missing companies |
| Cookies Not Marked Secure 🔒 | all, `https://` sites only | LOW | verified | Security, ownership-gated. Read from the site's **own** `Set-Cookie` headers (cookies set by a tracker's script aren't the owner's to change). One finding naming the cookies |
| Login Cookie Readable By Scripts 🔒 | all | MEDIUM | needs_look (login-ness judged by name: sess/session/auth/token/login/jwt/sid…; csrf/xsrf and known tracker cookies excluded) | Security, gated. A login-looking cookie the site sets without `HttpOnly` |
| Cookies Missing SameSite Setting 🔒 | all | LOW | verified | Security, gated. A cookie the site sets with no `SameSite` |

The three 🔒 checks are skipped on Shopify, Wix, Squarespace and Webflow sites (the platform sets those cookies, not the owner) — the report says so under "What we couldn't check".

**The cookie list** (report section "Cookies and tracking"): *"Your site sets N cookies from M companies[, and contacts K more companies without setting cookies] — before a visitor clicks anything."*, then each company with what it's for and its cookies. It covers every page checked — each page's own cookies and requests are snapshotted right after it loads, before any other check touches it — while the findings above are judged on the homepage alone.

**Time and skipping:** page loads here are capped at 30s each inside a 75s budget for the whole pass; anything that doesn't fit is noted under "What we couldn't check". `GETBUGGY_SKIP_COOKIE_CHECKS=true` turns the pass off (the report says so).

## Report-level states

| State | What it means |
|---|---|
| "Checked N of M pages" | Normal, complete crawl. |
| "Partial report — N of M pages checked before the 6-minute time limit" | The crawl hit its hard cap; everything gathered is returned and the unfinished pages are listed. |
| "Partial report — N of M pages checked before the check stopped unexpectedly" *(Step 8)* | The worker died (or its final answer was unreadable) after the site-wide checks or some pages finished; those come back, never a bare error. |
| "Partial report — N of M pages could be opened and checked" *(Step 8)* | One or more pages timed out or refused to load. They count as attempted, not checked; the banner lists each one. |
| "(N pages couldn't be opened at all)" | A page timed out or refused to load; it counts as attempted, not checked, and says so. |
| Score *(Step 8)* | 0–100 from verified findings only (`needs_look` and "loads correctly" notes never count): −15 HIGH, −5 MEDIUM, −1 LOW, at most −25 per area. No score when no page opened. A partial report is scored on what was checked and says so. Formula: `PLAN.md` "Report score and severity rubric". |
| What we found, by area *(Step 8)* | One line per area — Links and pages, Forms, Errors and broken files, Speed, Mobile, Search engines, Accessibility, Security, Site setup (plus Cookies) — either "N problems found", a positive line ("No exposed files or hacked-site signals found on the pages we checked."), or "We couldn't check this" when the area's checks didn't run. |
| Queued *(Step 8)* | Both check slots busy: "You're 2nd in line — your check should start in about 4 minutes." Starts by itself. |
| Shared link / export *(Step 8)* | `/r/<id>` and "Copy for your web person": the same report, always without security details, for 30 days. |
| What we couldn't check | Login walls, timeouts, bot-blocked links, `#`-routed single-page apps (checked as one page), links to private addresses (never fetched), accessibility scans skipped or stopped for time, embedded video players' captions. |
| Accessibility *(Step 6)* | Always shown: the "automated checks catch only part of it" note, then either the top 5 accessibility problems (with page and element counts) or "The automated accessibility checks found nothing on the pages checked." |

## Not checked yet *(as of Step 9, 2026-10-11)*

Nothing below produces a finding. (Step 8's score, queue, permalinks and export landed the same day and are in "Report-level states" above.)

| Not checked | Why / status |
|---|---|
| Consent banners inside frames or closed shadow DOM; banners shown only to some countries | Step 7 detects banners in the page and open shadow roots, from a US server. A consent tool that's installed but shows us no banner → "What we couldn't check" |
| Cookies set after a visitor clicks or accepts | Step 7 records only what happens before any interaction — it never clicks the banner |
| TLS 1.0/1.1 still accepted | Needs non-GET handshakes, outside the passive-checks rule. Every report says so |
| WordPress plugin vulnerabilities (CVEs) | No free feed exists. Plugins are only compared with their latest release |
| Moving content without a pause button (WCAG 2.2.2) | A muted, autoplaying, control-less video is treated as a background loop and not flagged |
| Whether a form's message actually reaches the business | Real submission is off by default and stays off; that's what "Form Not Fully Verified" means |
| Inside embedded video players (YouTube, Vimeo, Wistia, Loom) and cross-origin frames | Can't be inspected from the page; shown under "What we couldn't check" |
| Pages beyond the free-tier cap | `DEFAULT_CRAWL_PAGE_CAP` in `core.py` (5); skipped pages are listed in the report |
