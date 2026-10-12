> **DRAFT — FOR LAWYER REVIEW. This is not legal advice and has not been reviewed by an attorney. Do not treat this as a final or binding legal document.**

# GetBuggy — Terms of Service (Draft)

*Last updated: 2026-10-11*

## 1. What GetBuggy is (right now)

GetBuggy is currently a free, no-login website checking tool. You paste in a URL, and GetBuggy opens that site's homepage and a small number of its other pages (the free check has a fixed page limit) and gives you back a plain-English report of problems it found — things like broken links, missing images, script errors, slow loads, search-engine basics, accessibility issues, form problems, mobile layout issues, and basic security problems.

This is the entire product today ("Phase 1"). There is no account system, no login, and no payment collection. We do have plans for future features — things like a score, shareable report links, connecting GetBuggy directly to your site, scheduled monitoring, and automated fixes — but none of that exists yet. If and when those features launch, these Terms will be updated to cover them, and you'll be told what's changed before you rely on them.

## 2. The check is fully automated

When you submit a URL, GetBuggy runs an automated check using a headless browser (a real browser engine, controlled by software, with no human watching or reviewing your page). No person at GetBuggy looks at your site as part of a normal check. The report you get back is generated entirely by this automated process, and — like any automated tool — it can miss real problems or flag things that aren't actually problems. Use your own judgment before acting on it.

## 3. You need permission to check a site

You confirm you own the site you are checking or are authorised by its owner to do so.

By submitting a URL to GetBuggy, you're representing that you own the site or otherwise have the right to have it checked. Don't run GetBuggy against a website you don't own or don't have permission to test.

This matters in particular because of what the checker does to forms — see the next section. Running an automated tool against someone else's website without permission can also violate that website's own terms of use, and you're responsible for making sure you're not doing that.

## 4. Form testing and its safety mode

If a page you check has a web form on it (like a contact form, sign-up form, or booking form), GetBuggy will try to fill it in with harmless placeholder test values, to check whether the form actually works.

As of this writing, **real submission of that test data is turned off by default.** Instead, GetBuggy runs a front-end-only version of the check: it fills the form in and then intercepts the submission before it reaches the site's real backend, so no real test lead, email, or database entry is created on your (or anyone else's) system from a normal check. GetBuggy still reports back what it can observe from this safer check — for example, whether the form appeared to do nothing at all when submitted.

There is a separate, opt-in setting a developer can deliberately enable for local testing purposes, which would allow a real test submission to go through instead of being intercepted. That setting is not turned on in the way GetBuggy is normally run or offered publicly. If this ever changes for accounts with verified site ownership, we will update these Terms and tell you clearly before it applies to your checks.

## 4a. Security checks are passive

GetBuggy also looks for common security problems. These checks are passive and read-only: GetBuggy reads what a normal visit already shows (the page, its code, the headers the server sends back) and asks the site for a short, fixed list of standard addresses that are often left exposed by mistake (for example a `/.env` settings file or a `/.git` folder) using ordinary page requests. It never sends attack payloads, never tries to log in, never guesses passwords or addresses, and never scans ports.

Detailed security findings are only shown once the site's ownership has been verified. Everyone else — including anyone a report link is shared with — sees only how many possible security exposures were found, not what or where they are.

## 5. Provided "as-is," no guarantees

GetBuggy is provided free of charge and on an "as-is" and "as-available" basis. We don't guarantee:

- that the service will be available at any particular time, or at all;
- that reports are accurate, complete, or will catch every problem on your site;
- that a page reported as problem-free actually has no problems, or that a page reported as having a problem is actually broken (automated checks can be wrong in both directions);
- that using GetBuggy won't ever have side effects on the page being checked (for example, submitting to third-party analytics or logging systems the way any real visitor's browser would).

You're responsible for verifying anything important before acting on it — especially before making changes to your site based on a GetBuggy report.

## 5a. Compliance-related findings are not legal advice

Some findings touch on laws, regulations, or published standards — for example, accessibility findings (measured against the Web Content Accessibility Guidelines, WCAG 2.2 AA), whether your site links an accessibility statement, and notes about accessibility "overlay" widgets; and cookie, consent-banner and privacy-policy findings, which are written for the region you choose (the US by default, or the EU and UK, or both).

These findings are general, automated information about what GetBuggy observed on the pages it checked. They are **not legal advice**, they don't create a lawyer–client relationship, and they don't tell you whether your site complies with any law (for example the Americans with Disabilities Act, or privacy and cookie laws), in any place. A clean result does not mean your site is compliant, and a finding does not mean you are breaking the law. Laws differ between countries and states and change over time. If you have a legal question about your site, ask a qualified lawyer.

## 5b. No warranty for security findings

GetBuggy's security checks are limited, passive, and automated (see section 4a). They are **not** a security audit, a penetration test, or a certification of any kind.

GetBuggy makes no warranty, express or implied, about security findings. In particular, we don't promise that:

- every security problem on your site has been found — most kinds of security problems can't be seen from the outside at all, and GetBuggy doesn't look for them;
- each reported finding is a real, exploitable problem — some are signs that need a person to check;
- a site with no security findings is secure.

Don't rely on GetBuggy as your only security measure. If your site handles payments, personal information, or anything else sensitive, have a qualified security professional review it. GetBuggy is not responsible for any security incident on your site, whether or not a GetBuggy check reported a related finding.

## 6. Limitation of liability

To the fullest extent allowed by law, GetBuggy and its operator are not liable for any indirect, incidental, special, or consequential damages arising from your use of the service, including but not limited to lost business, lost data, or lost leads. GetBuggy is offered as a free early-stage tool, without warranties of any kind, express or implied. If you're relying on it for something business-critical, get a human to double-check the results.

## 6a. How long we keep reports

We keep each report — the address you submitted, the findings, and the time of the check — for **30 days**, then delete it automatically. See the Privacy Policy for the details of what is kept and where.

## 7. Respecting other sites

GetBuggy is intended to check sites the way a normal visitor's browser would, not to circumvent a site's own protections. If a site blocks or refuses an automated check, GetBuggy reports that fact ("we couldn't check this") rather than trying to get around the block. The address you submit is always checked; when choosing which *other* pages of the site to check, GetBuggy follows that site's `robots.txt` file. Checks are limited per visitor and in total per day; there is not yet a separate limit per checked website.

## 8. Changes to these Terms

Because GetBuggy is an early-stage product that's actively changing, these Terms may be updated as the product changes — especially once accounts, paid tiers, or any feature involving real submissions to your site are introduced. We'll try to make changes clear (e.g. by updating the "Last updated" date above), but it's worth checking back periodically if you're a regular user.

## 9. Contact

Questions about these Terms can be directed to the site operator through the contact information provided on the GetBuggy website.
