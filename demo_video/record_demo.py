"""Records the hackathon demo video of GetBuggy as it is today.

Needs both demo servers running (see README.md in this folder). Drives the
real app in a real browser against the local Sunrise Bakery demo site, then
uses ffmpeg to speed up the wait while the crawl runs (labelled on screen)
and writes demo_video/getbuggy-demo.mp4.
"""
import json
import os
import shutil
import subprocess
import time

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
APP = "http://127.0.0.1:8010/"
SITE = "http://127.0.0.1:8765/"
W, H = 1280, 720
WAIT_SPEEDUP = 4
RAW_DIR = os.path.join(HERE, "raw")
OUT = os.path.join(HERE, "getbuggy-demo.mp4")
FFMPEG = os.environ.get("FFMPEG", "ffmpeg")  # needs libx264

# A visible cursor (headless video has none) and a caption bar, re-created
# on every page load.
INIT_JS = """
(() => {
  const add = () => {
    if (document.getElementById('demo-cursor')) return;
    const c = document.createElement('div');
    c.id = 'demo-cursor';
    c.style.cssText = 'position:fixed;z-index:2147483647;width:22px;height:22px;' +
      'border-radius:50%;background:rgba(255,80,60,.55);border:2px solid #fff;' +
      'box-shadow:0 0 6px rgba(0,0,0,.4);pointer-events:none;left:-40px;top:-40px;' +
      'transform:translate(-50%,-50%);transition:transform .08s';
    document.body.appendChild(c);
    document.addEventListener('mousemove', e => {
      c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px';
    }, true);
    document.addEventListener('mousedown', () => c.style.transform = 'translate(-50%,-50%) scale(.7)', true);
    document.addEventListener('mouseup', () => c.style.transform = 'translate(-50%,-50%)', true);
  };
  if (document.body) add(); else document.addEventListener('DOMContentLoaded', add);
})();
"""

CAPTION_JS = """
(text) => {
  let el = document.getElementById('demo-caption');
  if (!el) {
    el = document.createElement('div');
    el.id = 'demo-caption';
    el.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);' +
      'z-index:2147483646;max-width:1100px;padding:14px 26px;border-radius:14px;' +
      'background:rgba(17,17,24,.88);color:#fff;font:600 22px/1.35 -apple-system,' +
      'Helvetica,Arial,sans-serif;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.35);' +
      'pointer-events:none;transition:opacity .25s';
    document.body.appendChild(el);
  }
  el.style.opacity = text ? '1' : '0';
  if (text) el.innerHTML = text;
}
"""

CARD_HTML = """
<html><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(circle at 30% 20%,#2b2250,#0e0c1a 70%);color:#fff;
font-family:-apple-system,Helvetica,Arial,sans-serif;text-align:center">
<div style="max-width:1000px;padding:0 40px">{body}</div></body></html>
"""

TITLE = """
<div style="font-size:30px;letter-spacing:.2em;opacity:.7;margin-bottom:18px">HACKATHON DEMO</div>
<div style="font-size:96px;font-weight:800;margin-bottom:24px">🐞 GetBuggy</div>
<div style="font-size:34px;line-height:1.4;opacity:.92">Tells a small-business owner what's broken on their website —<br>in plain English, no developer needed.</div>
"""

END = """
<div style="font-size:72px;font-weight:800;margin-bottom:30px">🐞 GetBuggy</div>
<div style="font-size:28px;line-height:1.7;opacity:.92;text-align:left;display:inline-block">
✔ Real browser crawl — 5 pages per free check<br>
✔ Broken links, missing images, script crashes, forms that silently fail<br>
✔ Mobile layout, speed, SEO and an automated accessibility scan<br>
✔ Read-only security checks, details shown only to the site owner<br>
✔ Every finding: what's wrong, why it matters, how to fix it, who fixes it
</div>
<div style="font-size:24px;opacity:.6;margin-top:36px">Python · FastAPI · Playwright · axe-core</div>
"""


def caption(page, text):
    page.evaluate(CAPTION_JS, text)


def glide(page, x, y, steps=25):
    page.mouse.move(x, y, steps=steps)


def click_el(page, locator, pause=250):
    box = locator.bounding_box()
    glide(page, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    page.wait_for_timeout(pause)
    locator.click()


def smooth_scroll(page, total_px, px_per_step=6, ms=16):
    step = px_per_step if total_px > 0 else -px_per_step
    moved = 0
    while moved < abs(total_px):
        page.mouse.wheel(0, step)
        page.wait_for_timeout(ms)
        moved += px_per_step


def scroll_to(page, locator, offset=120):
    """Smoothly scrolls (up or down) until `locator` sits `offset` px below the top."""
    y = locator.evaluate("e => e.getBoundingClientRect().top")
    if abs(y - offset) > 10:
        smooth_scroll(page, int(y - offset), px_per_step=8)


def spotlight(page, locator, cap, hold=4200, offset=200):
    if not locator.count():
        print("demo: not found, skipped:", cap)
        return
    scroll_to(page, locator, offset=offset)
    caption(page, cap)
    locator.evaluate("e => { e.style.transition='box-shadow .3s'; e.style.boxShadow='0 0 0 4px #ffb020'; }")
    page.wait_for_timeout(hold)
    locator.evaluate("e => e.style.boxShadow=''")


def record():
    shutil.rmtree(RAW_DIR, ignore_errors=True)
    marks = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(
            viewport={"width": W, "height": H},
            record_video_dir=RAW_DIR,
            record_video_size={"width": W, "height": H},
        )
        ctx.add_init_script(INIT_JS)
        page = ctx.new_page()
        t0 = time.monotonic()

        # 1. Title card
        page.set_content(CARD_HTML.format(body=TITLE))
        page.wait_for_timeout(4500)

        # 2. The bakery's site
        page.goto(SITE)
        page.mouse.move(640, 360)
        caption(page, "Meet Sunrise Bakery <span style='opacity:.6'>(a demo site, running locally)</span>. Looks fine… right?")
        page.wait_for_timeout(3500)
        caption(page, "The owner has no idea what's broken. Let's ask GetBuggy.")
        page.wait_for_timeout(3000)

        # 3. GetBuggy landing page
        page.goto(APP)
        page.wait_for_load_state("networkidle")
        caption(page, "GetBuggy: no login, no install — just paste your website address")
        page.wait_for_timeout(2500)
        url_input = page.locator("#url-input")
        click_el(page, url_input)
        url_input.press_sequentially(SITE, delay=55)
        page.wait_for_timeout(500)
        caption(page, "Owners confirm they have permission — checked in the browser <i>and</i> on the server")
        click_el(page, page.locator("#authorize-checkbox"), pause=600)
        page.wait_for_timeout(1800)
        caption(page, "")
        click_el(page, page.locator("#submit-btn"), pause=400)

        # 4. The crawl (sped up in post, labelled on screen)
        page.wait_for_timeout(1500)
        page.mouse.move(1100, 500, steps=15)
        smooth_scroll(page, 200, px_per_step=8)
        caption(page, f"A real browser checks every page <span style='opacity:.6'>(sped up {WAIT_SPEEDUP}×)</span>")
        marks["wait_start"] = time.monotonic() - t0
        page.wait_for_selector("#results .summary", timeout=360_000)
        marks["wait_end"] = time.monotonic() - t0
        caption(page, "")
        page.wait_for_timeout(600)

        # 5. The report
        r = "#results "
        spotlight(page, page.locator(r + ".summary"),
                  "About 30 seconds later: the problems, page by page — in plain English", hold=3800, offset=180)
        spotlight(page, page.locator(r + ".security-card"),
                  "Security checks are read-only — details stay hidden until the owner verifies the site", hold=4200, offset=180)
        spotlight(page, page.locator(r + ".couldnt-check").first,
                  "It also lists what it <i>couldn't</i> check — GetBuggy never guesses", hold=3800, offset=220)
        for text, cap in [
            ("Broken Link", "A dead link to the catering page — confirmed twice, once in a real browser"),
            ("JavaScript Crash", "A script crashes on load — and GetBuggy says it's the site's own code"),
            ("Broken Form", "The cake-order form was filled with test values and silently did nothing (forms are never actually sent)"),
            ("Hard-to-Read Text", "Every finding says why it matters, how to fix it, and who should fix it"),
            ("Mobile Horizontal Scroll", "Layout that breaks on a phone — caught on a simulated phone screen"),
        ]:
            spotlight(page, page.locator(r + ".problem", has_text=text).first, cap)

        spotlight(page, page.locator(r + "table").first,
                  "Plus an automated accessibility scan (axe-core) — with an honest note about its limits",
                  hold=4200, offset=260)
        caption(page, "")

        # 6. End card
        page.set_content(CARD_HTML.format(body=END))
        page.wait_for_timeout(6500)
        marks["end"] = time.monotonic() - t0

        video_path = page.video.path()
        ctx.close()
        browser.close()
    json.dump(marks, open(os.path.join(RAW_DIR, "marks.json"), "w"))
    return video_path, marks


def render(raw, marks):
    ws, we = marks["wait_start"], marks["wait_end"]
    f = WAIT_SPEEDUP
    filt = (
        f"[0:v]trim=0:{ws},setpts=PTS-STARTPTS[a];"
        f"[0:v]trim={ws}:{we},setpts=(PTS-STARTPTS)/{f}[b];"
        f"[0:v]trim=start={we},setpts=PTS-STARTPTS[c];"
        "[a][b][c]concat=n=3:v=1:a=0,fps=30,format=yuv420p[v]"
    )
    subprocess.run(
        [FFMPEG, "-y", "-loglevel", "error", "-i", raw, "-filter_complex", filt,
         "-map", "[v]", "-c:v", "libx264", "-crf", "18", "-preset", "slow",
         "-movflags", "+faststart", OUT],
        check=True,
    )


if __name__ == "__main__":
    import sys
    if "--render-only" in sys.argv:  # re-encode the last take
        raw = next(os.path.join(RAW_DIR, f) for f in os.listdir(RAW_DIR) if f.endswith(".webm"))
        marks = json.load(open(os.path.join(RAW_DIR, "marks.json")))
    else:
        raw, marks = record()
    print("raw:", raw, "marks:", marks)
    render(raw, marks)
    print("wrote", OUT)
