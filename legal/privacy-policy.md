> **DRAFT — FOR LAWYER REVIEW. This is not legal advice and has not been reviewed by an attorney. Do not treat this as a final or binding legal document.**

# GetBuggy — Privacy Policy (Draft)

*Last updated: 2026-10-11*

## 1. Scope

This policy covers GetBuggy as it exists today: a free, no-login tool where you paste in a URL and get back an automated report on that site's homepage and a small number of its other pages ("Phase 1"). It does not cover future planned features — like accounts, site integrations, or scheduled monitoring — which don't exist yet. This policy will be revised before any of those features launch.

## 2. What we collect

When you run a check, we collect and store:

- **The URL you submit** for checking.
- **The report GetBuggy generates** for that site (the problems found, or that none were found, and the pages that were checked).
- **A timestamp** of when the check was run.
- **That you ticked the box** confirming you own the site or have permission to check it. This is kept with the running check only, not with the saved report.

If you sign up for early access, we also collect:

- **Your email address** and the time you signed up.

To stop the free tool from being overused, our server also holds **your IP address in memory** for up to one hour, so it can count how many checks you've run. Our code does not save it to disk, does not put it in our logs, and does not store it with your report. It is forgotten when the hour is up or the server restarts. Our hosting provider may keep its own standard request logs under its own policies.

That's it, as far as data tied to your use of the tool goes.

## 3. What we do NOT collect

- **No accounts or login.** Phase 1 has no user accounts, so we don't collect usernames, passwords, or login credentials.
- **No payment information.** GetBuggy is free in Phase 1; we don't collect or process any payment or billing details.
- **No cookies or tracking on the GetBuggy site.** We don't set cookies, and we don't use advertising or visitor-tracking tools. We count how many checks are started and finished, without recording the address checked, your email address, or anything that ties one count to you.
- **No deliberate personal data scraping.** GetBuggy isn't designed to extract or store personal data from the pages it checks. Anything that technically passes through the automated browser as an incidental side effect of loading the page normally (for example, the kind of request data any visitor's browser would generate) is not something we deliberately collect, store, or use.

## 4. About the automated check itself

Checks are run by an automated headless browser, not a human. As part of running a check, if the page you submit has a web form on it, GetBuggy will attempt to fill it in with harmless test values to see if the form works. As of this writing, real submission of that data is **off by default** — a front-end-only version of the check runs instead, which prevents the filled-in test data from actually reaching the target site's real backend (so no real email, lead, or database record is created on a normal check). A separate opt-in setting exists for deliberate local development testing only and is not enabled in how GetBuggy is normally run. See the Terms of Service for more detail on this.

Security findings in a report are only shown in full to the site's verified owner. Everyone else who sees the report sees only how many possible security problems were found.

## 5. How long we keep data

- **Reports.** We keep a submitted URL, the report generated for it, and the time of the check for **30 days**, then delete them automatically. While a check is running and for up to 30 minutes afterwards, a copy is also held in our server's memory; that copy is gone after 30 minutes or when the server restarts, whichever comes first.
- **Report links.** Each report has its own long, hard-to-guess link. Anyone you give that link to can open the report — never the security details — until the report is deleted at 30 days. We don't list reports anywhere or link them to each other.
- **Early-access email addresses.** We keep these until early access ends or until you ask us to remove yours, whichever comes first.
- **IP addresses.** Up to one hour, in memory only (see section 2).

If you'd like a submitted URL and its report, or your email address, removed sooner, contact us and we'll do our best to accommodate that.

## 6. Do we sell your data?

No. We do not sell the URLs you submit, the reports generated, your email address, or any related data to third parties.

## 7. Third parties

**Services that run GetBuggy.** We use outside providers to host the website, store saved reports for their 30 days, and deliver early-access sign-up notifications by email. If error tracking is switched on, technical details about an error — which may include the address being checked when the error happened — are sent to our error-tracking provider. These providers handle that data on our behalf.

**Fonts.** The GetBuggy page loads its font from Google Fonts, so your browser contacts Google when the page loads, and Google receives your IP address as part of that request.

**The site being checked.** Loading a page as part of a check may cause that page's own third-party resources (analytics scripts, trackers, embedded widgets, etc.) to load, the same way they would for any real visitor. GetBuggy does not control what those third parties do with requests generated this way, and this policy does not cover their practices — check the target site's own privacy policy for that.

## 8. Changes to this policy

Because GetBuggy is early and actively changing, this policy will need to be revised — in particular once Phase 2 features like accounts and verified email are introduced, which will mean collecting more information than described here. We'll update the "Last updated" date above when that happens.

## 9. Contact

Questions about this policy, or requests about data we hold, can be directed to the site operator through the contact information provided on the GetBuggy website.
