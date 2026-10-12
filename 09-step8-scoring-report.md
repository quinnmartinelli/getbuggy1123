GetBuggy — Step 8 of 9: Scoring, report schema, partial results, queue, permalinks

Follow the standing rules in `CLAUDE.md`. Read `PROJECT_STATUS.md` and `PLAN.md` first. Retention is decided: 30 days.

- **Score.** Define a 0–100 score with a documented formula in `PLAN.md`: per-severity deductions, capped per category so one category cannot zero the score, `needs_look` findings excluded from the score. Store the score on the report so re-checks can show the delta.
- **Finding schema.** Standardise: `id`, `category`, `severity`, `confidence`, `title`, `why_it_matters`, `how_to_fix`, `who_fixes`, `platform_note` (optional), `pages`, `evidence` (masked where sensitive), `check_version`.
- **Severity rubric**, written into `PLAN.md`: HIGH = actively losing customers, money, or search visibility, or a security exposure. MEDIUM = degraded experience or a compliance signal. LOW = polish and best practice.
- **Partial reports.** When the per-page timeout, the 6-minute crawl cap, or a crawl abort occurs, return the findings gathered so far, labelled clearly as partial with what was not completed. Never return a bare error if any check finished.
- **Queue.** At the concurrency cap, return a queued state with position and a rough wait estimate; the UI polls and shows it.
- **Clean states.** Each category shows a positive line when nothing was found ("No exposed files or hacked-site signals found").
- **Permalink.** Each report gets a stable, unguessable URL that renders without login. Reports and any crawled content are deleted after 30 days; implement the deletion job and document it in `PROJECT_STATUS.md` so the privacy policy can match. Security details obey the ownership gate on permalinks.
- **"Send to your web person."** A plain-text/markdown export of the report suitable for pasting into an email; security details gated as above.

**Definition of Done:** the same site run twice produces the same score within the timing tolerance; partial and queued states are rendered and covered by tests; the rubric and formula are in `PLAN.md`; 30-day deletion is implemented and documented.

Commit and push, run `post_deploy_check.py` against the live URL, then give me the Step 8 summary with harness output, two consecutive scores for medvi.org through the live site, and `/version` pasted.
