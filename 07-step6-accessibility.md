GetBuggy — Step 6 of 9: Accessibility

Follow the standing rules in `CLAUDE.md`. Read `PROJECT_STATUS.md` and `PLAN.md` first.

- Run axe-core in the real browser on every crawled page, WCAG 2.2 AA ruleset. It must fit the per-page time budget; if it would not, run it on the homepage and the contact/booking page only and say so in the report.
- Group results by rule, translate each rule into plain English, and show the top violations with page and element counts. Cover at minimum: colour contrast, missing form labels, missing button/link names, missing `lang`, empty links, heading order, duplicate IDs, keyboard focus visibility.
- Detect autoplaying media and video without captions → MEDIUM.
- Detect accessibility overlay widgets (accessiBe, UserWay, EqualWeb) → `needs_look`, with a note that overlays do not confer compliance.
- Accessibility statement page missing → LOW.
- Report copy must state that automated checks catch only part of accessibility issues and a clean result is not compliance.

**Definition of Done:** axe runs within the budget on the baseline sites (skip with a report note if it would exceed it); a fixture with known violations passes.

Commit and push, run `post_deploy_check.py` against the live URL, then give me the Step 6 summary with harness output and live `/version` pasted.
