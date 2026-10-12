// GetBuggy Step 8 — the parts of the report page that come with the score:
// the score card, the "what we found, by area" list with its clean lines,
// the partial-report banner, the share / "send to your web person" bar,
// the queue message, and loading a shared report from /r/<id>.
// Loaded before index.html's own script, which calls these from
// renderResults() and its polling loop. Everything is built with
// textContent — report text is never parsed as HTML.

// The permalink id of the last report shown on this page. Sent with the
// next check so a re-check of the same site can show its score change
// (the server ignores it for a different site).
window.gbPreviousReportId = null;

function gbEl(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text != null) el.textContent = text;
  return el;
}

function gbAppend(parent, child) {
  if (child) parent.appendChild(child);
}

function gbFriendlyDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return "";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function gbReportMeta(data) {
  if (!data.url) return null;
  const when = gbFriendlyDate(data.checked_at);
  return gbEl("div", "gb-meta", `Report for ${data.url}${when ? ` · checked ${when}` : ""}`);
}

function gbPartialBanner(data) {
  if (!data.partial) return null;
  const banner = gbEl("div", "partial-banner");
  const planned = data.pages_planned || 0;
  let text;
  if (!planned) {
    text = "This is a partial report: the check ran out of time before it could check any pages.";
  } else if (data.partial_reason === "pages_failed") {
    text = "This is a partial report: some pages couldn't be opened, so nothing on them was checked.";
  } else if (data.partial_reason === "worker_stopped") {
    text = `This is a partial report: the check stopped unexpectedly after ${data.pages_checked} of ${planned} pages.`;
  } else {
    text = `This is a partial report: ${data.pages_checked} of ${planned} pages were checked before the time limit ran out.`;
  }
  banner.appendChild(gbEl("div", null, text));
  const items = data.not_completed || [];
  if (items.length) {
    const list = gbEl("ul", "gb-not-completed");
    for (const item of items) list.appendChild(gbEl("li", null, item));
    banner.appendChild(list);
  }
  return banner;
}

function gbNotCheckedTitle(data) {
  return data.partial_reason === "worker_stopped"
    ? "Not checked before the check stopped"
    : "Not checked before the time limit";
}

function gbScoreCard(data) {
  const s = data.score;
  if (!s) return null;
  const card = gbEl("div", "gb-score");
  if (s.value == null) {
    card.appendChild(gbEl("div", "gb-score-none", "No score this time"));
    card.appendChild(gbEl("div", "gb-score-basis", s.reason || ""));
    return card;
  }
  const top = gbEl("div", "gb-score-top");
  const num = gbEl("div", "gb-score-number");
  num.appendChild(gbEl("span", "gb-score-value", String(s.value)));
  num.appendChild(gbEl("span", "gb-score-out-of", `/${s.out_of || 100}`));
  top.appendChild(num);
  const words = gbEl("div", "gb-score-words");
  words.appendChild(gbEl("div", "gb-score-band", s.band || ""));
  words.appendChild(gbEl("div", "gb-score-basis", s.basis || ""));
  if (s.change && s.change.message) {
    const cls = s.change.delta > 0 ? "up" : s.change.delta < 0 ? "down" : "";
    words.appendChild(gbEl("div", `gb-score-change ${cls}`, s.change.message));
  }
  top.appendChild(words);
  card.appendChild(top);

  const how = gbEl("details", "finding-details gb-score-how");
  how.appendChild(gbEl("summary", null, "How this score is worked out"));
  const list = gbEl("ul", "finding-detail-list");
  const rules = s.rules || { high: 15, medium: 5, low: 1, area_cap: 25 };
  list.appendChild(gbEl("li", null,
    `Every site starts at 100. Each confirmed problem takes points off: ${rules.high} for High, ` +
    `${rules.medium} for Medium, ${rules.low} for Low. No single area can take off more than ` +
    `${rules.area_cap}, so one bad area can't sink the whole score.`));
  for (const d of s.deductions || []) {
    list.appendChild(gbEl("li", null,
      `${d.title}: −${d.points}${d.capped ? " (capped)" : ""} from ${d.findings_counted} problem${d.findings_counted === 1 ? "" : "s"}`));
  }
  list.appendChild(gbEl("li", null,
    `Things marked "Needs a look" don't count toward your score${s.needs_look_not_counted ? ` (${s.needs_look_not_counted} this time)` : ""}.`));
  how.appendChild(list);
  card.appendChild(how);
  return card;
}

function gbSections(data) {
  const sections = data.sections || [];
  if (!sections.length) return null;
  const box = gbEl("div", "page-group");
  box.appendChild(gbEl("div", "page-header", "What we found, by area"));
  const list = gbEl("ul", "gb-sections");
  const marks = { clean: "✓", issues: "!", not_checked: "–" };
  for (const s of sections) {
    const li = gbEl("li", `gb-section ${s.status}`);
    li.appendChild(gbEl("span", "gb-section-mark", marks[s.status] || ""));
    const text = gbEl("span", "gb-section-text");
    text.appendChild(gbEl("strong", null, `${s.title}: `));
    text.appendChild(document.createTextNode(s.line));
    li.appendChild(text);
    list.appendChild(li);
  }
  box.appendChild(list);
  return box;
}

async function gbCopyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    const area = gbEl("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
    area.remove();
    return ok;
  }
}

function gbButton(label, onClick) {
  const b = gbEl("button", "gb-btn", label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function gbFlash(note, text) {
  note.textContent = text;
  clearTimeout(note._t);
  note._t = setTimeout(() => { note.textContent = ""; }, 4000);
}

function gbExportBar(data) {
  if (!data.report_id) return null;
  window.gbPreviousReportId = data.report_id;
  const bar = gbEl("div", "gb-export");
  const note = gbEl("span", "gb-export-note");
  const permalink = `${location.origin}/r/${data.report_id}`;
  const exportUrl = `/api/report/${encodeURIComponent(data.report_id)}/export`;

  bar.appendChild(gbButton("Copy link to this report", async () => {
    gbFlash(note, (await gbCopyText(permalink))
      ? "Link copied. Anyone with it can see this report for 30 days."
      : `Couldn't copy — here's the link: ${permalink}`);
  }));
  bar.appendChild(gbButton("Copy for your web person", async () => {
    try {
      const resp = await fetch(exportUrl);
      if (!resp.ok) throw new Error(String(resp.status));
      const text = await resp.text();
      gbFlash(note, (await gbCopyText(text))
        ? "Copied — paste it into an email to whoever looks after your site."
        : "Couldn't copy. Try \"Download as text\" instead.");
    } catch (e) {
      gbFlash(note, "We couldn't fetch the report text just now. Please try again.");
    }
  }));
  bar.appendChild(gbButton("Download as text", async () => {
    try {
      const resp = await fetch(exportUrl);
      if (!resp.ok) throw new Error(String(resp.status));
      const blob = new Blob([await resp.text()], { type: "text/markdown" });
      const a = gbEl("a");
      let host = "site";
      try { host = new URL(data.url).hostname.replace(/^www\./, ""); } catch (e) { /* keep "site" */ }
      a.href = URL.createObjectURL(blob);
      a.download = `getbuggy-report-${host}.md`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    } catch (e) {
      gbFlash(note, "We couldn't fetch the report text just now. Please try again.");
    }
  }));
  if (data.url) {
    bar.appendChild(gbButton("Check this site again", () => {
      const input = document.getElementById("url-input");
      const box = document.getElementById("authorize-checkbox");
      if (input) input.value = data.url;
      window.scrollTo({ top: 0, behavior: "smooth" });
      if (box) box.focus();
      gbFlash(note, "Tick the box and press the arrow — we'll show how the score changed.");
    }));
  }
  bar.appendChild(note);
  return bar;
}

function gbQueueText(job) {
  if (job.queue_message) return job.queue_message;
  if (job.queue_position) return `You're number ${job.queue_position} in line — your check will start by itself.`;
  return "Waiting for a free spot — your check will start by itself.";
}

// /r/<id>: show that shared report (always the public, ownership-gated
// version) using the page's normal report renderer.
async function gbLoadSharedReport(renderResults, statusEl, errorEl) {
  const m = location.pathname.match(/^\/r\/([A-Za-z0-9_-]+)\/?$/);
  if (!m) return;
  statusEl.textContent = "Loading the shared report…";
  try {
    const resp = await fetch(`/api/report/${encodeURIComponent(m[1])}`);
    const body = await resp.json();
    if (!resp.ok) {
      errorEl.textContent = body.detail || "We couldn't find that report.";
      errorEl.style.display = "block";
      return;
    }
    renderResults(body.result);
    const results = document.getElementById("results");
    if (results) results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    errorEl.textContent = "Could not reach the server. Please try again.";
    errorEl.style.display = "block";
  } finally {
    statusEl.textContent = "";
  }
}
