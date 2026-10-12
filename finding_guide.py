"""Plain-English guidance for every finding category (GetBuggy Step 8).

CLAUDE.md asks every finding to say what's wrong, why it matters to the
owner, how to fix it and who fixes it. A check's `message` already says
what's wrong on this particular site (with the page, file or count); this
module adds the other three as separate fields, the same for every site,
keyed by category — so the report, the export and a future "fix it" flow
can show them as their own lines instead of digging them out of a
sentence. Accessibility categories reuse checks_accessibility's own
translation table, so there is one source of truth for those.

No dependency on core.py (core imports the check modules; this is only
imported by report.py).

`AREA` maps each category to the report area it is scored and summarised
under (see report.SECTIONS). Security findings always go to "security"
and accessibility findings to "accessibility" by their `group`/`topic`
field, whatever this table says, so the ownership gate and the
accessibility section can't be split by a missing row here.
"""
from checks_accessibility import A11Y_CATEGORIES

YOU = "you"
WEB_PERSON = "your web person"
HOST = "your host"
LAWYER = "your lawyer"
WHO_VALUES = (YOU, WEB_PERSON, HOST, LAWYER)


def _g(area, why, how, who):
    return {"area": area, "why": why, "how": how, "who": who}


GUIDE = {
    # --- Errors and broken files -------------------------------------------
    "JavaScript Crash": _g(
        "errors",
        "Part of your site's own code stopped working, and something visitors use on the same page "
        "(a form, a button or the layout) broke with it.",
        "Open the page, look for the error described above, and fix the script it comes from.",
        WEB_PERSON,
    ),
    "JavaScript Console Error": _g(
        "errors",
        "Your site's own code reported an error, and something visitors use on the same page also "
        "failed to work.",
        "Find where the error described above comes from and fix that script.",
        WEB_PERSON,
    ),
    "Script Error": _g(
        "errors",
        "A script reported an error. We didn't see anything visibly break, so it may be harmless — "
        "but errors like this often come before something does break.",
        "Look at the error described above and fix or remove the script it comes from.",
        WEB_PERSON,
    ),
    "Failed Network Request": _g(
        "errors",
        "A file your own site asks for (an image, script or style) didn't load, so part of the page "
        "may look broken or stop working.",
        "Put the missing file back, or remove or correct the reference to it.",
        WEB_PERSON,
    ),
    "Third-Party Resource Failed": _g(
        "errors",
        "Something from another company (a tracker, chat widget or ad) didn't load. This is usually "
        "harmless and often caused by ad blockers.",
        "Nothing to do unless that tool matters to you — if it does, check its settings or contact "
        "the company that makes it.",
        YOU,
    ),
    "Third-Party Resources Didn't Load": _g(
        "errors",
        "Some tools from other companies (trackers, widgets, ads) didn't load. This is usually "
        "harmless and often caused by ad blockers.",
        "Nothing to do unless one of the tools listed matters to you — if it does, check its "
        "settings or contact the company that makes it.",
        YOU,
    ),
    "Missing Alt Text": _g(
        "accessibility",
        "People using screen readers can't tell what these images show, and search engines can't "
        "either.",
        "Add a short description (alt text) to each image listed — most site builders have an "
        "\"alt text\" box on every image.",
        YOU,
    ),
    # --- Links and pages ---------------------------------------------------
    "Broken Link": _g(
        "links",
        "Visitors who click it hit a dead end instead of the page they wanted, and search engines "
        "count dead links against a site.",
        "Point the link at the right page, or remove it.",
        YOU,
    ),
    "Broken Social Link": _g(
        "links",
        "Visitors looking for you on social media land on an error page, which can make it look "
        "like the business has closed.",
        "Update the link to your current profile address, or remove it.",
        YOU,
    ),
    "Link Needs A Look": _g(
        "links",
        "We couldn't confirm this link works — the other site may block automated checks — so it "
        "may well be fine.",
        "Click it yourself. If it's broken, update or remove it.",
        YOU,
    ),
    "Broken In-Page Link": _g(
        "links",
        "A \"jump to section\" link points at a section that isn't on the page, so clicking it does "
        "nothing.",
        "Fix the link so it points at a section that exists, or remove it.",
        WEB_PERSON,
    ),
    "Placeholder Links": _g(
        "links",
        "These links don't go anywhere by themselves. Unless they open a menu, visitors who click "
        "them get nothing.",
        "Click each one. If nothing happens, give it a real address or remove it.",
        WEB_PERSON,
    ),
    "Vague Link Text": _g(
        "links",
        "Links that just say \"click here\" or \"read more\" don't tell screen-reader users or "
        "search engines where they go.",
        "Reword the link to say where it goes, for example \"See our menu\".",
        YOU,
    ),
    "Links Only Appear After Scripts Run": _g(
        "links",
        "Search engines may miss pages that are only linked once scripts have run, so those pages "
        "can show up less in search.",
        "Include the main menu and page links in the page's HTML itself, not only through scripts.",
        WEB_PERSON,
    ),
    "Redirect Chain": _g(
        "links",
        "Every extra hop slows the page down, and long chains can stop search engines following "
        "them at all.",
        "Point links and old addresses straight at the final page.",
        WEB_PERSON,
    ),
    "Too Many Redirects": _g(
        "setup",
        "Browsers and search engines may give up before they ever reach your site.",
        "Point your address straight at the final page instead of through a chain of redirects.",
        HOST,
    ),
    "Soft 404 Page": _g(
        "links",
        "This page reads like a \"not found\" page but tells search engines everything is fine, so "
        "they may keep listing an empty page.",
        "Bring the content back, or make the page answer with a real \"not found\" (404).",
        WEB_PERSON,
    ),
    # --- Forms -------------------------------------------------------------
    "Broken Form": _g(
        "forms",
        "When someone fills it in and sends it, nothing happens — you may be losing every enquiry, "
        "booking or order sent through it without knowing.",
        "Fill the form in yourself to confirm, then have the form's sending settings fixed right "
        "away.",
        WEB_PERSON,
    ),
    "Form Needs A Look": _g(
        "forms",
        "Our check couldn't get all the way through this form, so we can't tell whether it works.",
        "Fill it in yourself and check that the message reaches you.",
        YOU,
    ),
    "Form Not Fully Verified": _g(
        "forms",
        "The form tried to send, but we never send real messages through anyone's form, so we can't "
        "prove they reach you.",
        "Send yourself a test message through it and check that it arrives.",
        YOU,
    ),
    "Embedded Form": _g(
        "forms",
        "This form (booking, contact or sign-up) comes from another company's service. If it doesn't "
        "load, visitors can't use it.",
        "Check the form in that service's own dashboard and re-copy its embed code if needed.",
        YOU,
    ),
    # --- Speed -------------------------------------------------------------
    "Page Load Time": _g(
        "speed",
        "Slow pages lose visitors — many leave if a page takes more than a few seconds.",
        "Shrink large images and remove apps or scripts the site doesn't need.",
        WEB_PERSON,
    ),
    "Largest Contentful Paint": _g(
        "speed",
        "The main part of the page takes a while to appear, and visitors may leave before it does.",
        "Shrink the biggest image or video near the top of the page and remove scripts that delay it.",
        WEB_PERSON,
    ),
    "Layout Shifts While Loading": _g(
        "speed",
        "Things jump around while the page loads, so visitors tap the wrong thing or lose their place.",
        "Give images, videos and ads a fixed size so the page doesn't move as they load.",
        WEB_PERSON,
    ),
    "Slow Server Response": _g(
        "speed",
        "Your server takes a while to start answering, which slows down every single page.",
        "Ask about caching or faster hosting.",
        HOST,
    ),
    "Heavy Page": _g(
        "speed",
        "Big pages load slowly, especially on phones and slow connections.",
        "Compress or resize the largest images and videos on the page named above.",
        WEB_PERSON,
    ),
    "Many Requests": _g(
        "speed",
        "The page loads a lot of separate files, which slows it down.",
        "Remove apps, fonts and scripts the site doesn't use.",
        WEB_PERSON,
    ),
    "Oversized Images": _g(
        "speed",
        "Images much bigger than the space they're shown in make the page slower for no benefit.",
        "Resize the images listed to roughly the size they're shown at, and compress them.",
        YOU,
    ),
    "Render-Blocking Scripts": _g(
        "speed",
        "The browser has to download these scripts before it can show anything, so the page stays "
        "blank for longer.",
        "Load these scripts with \"defer\" or \"async\", or move them to the end of the page.",
        WEB_PERSON,
    ),
    "Core Web Vitals Check Failed": _g(
        "speed",
        "We couldn't measure loading speed on this page, so speed wasn't checked here.",
        "Nothing to fix. For a second opinion, try Google's free PageSpeed Insights.",
        YOU,
    ),
    # --- Mobile ------------------------------------------------------------
    "Mobile Horizontal Scroll": _g(
        "mobile",
        "On a phone the page is wider than the screen, so visitors have to scroll sideways and "
        "things get cut off.",
        "Find the part that's too wide (often a table, image or embed) and make it fit small screens.",
        WEB_PERSON,
    ),
    "Mobile Check Failed": _g(
        "mobile",
        "We couldn't check how this page looks on a phone.",
        "Open the page on your own phone to check it.",
        YOU,
    ),
    # --- Search engines ----------------------------------------------------
    "Missing Page Title": _g(
        "seo",
        "The title is what shows in Google results and browser tabs — without one, fewer people "
        "click through.",
        "Add a page title in your site builder's SEO settings for that page.",
        YOU,
    ),
    "Missing Meta Description": _g(
        "seo",
        "Google shows this short summary under your link. Without one, it picks some text from the "
        "page itself.",
        "Write a one- or two-sentence description in the page's SEO settings.",
        YOU,
    ),
    "Missing H1 Heading": _g(
        "seo",
        "The main heading tells search engines and screen readers what the page is about.",
        "Make the page's main title a \"Heading 1\".",
        YOU,
    ),
    "Multiple H1 Headings": _g(
        "seo",
        "More than one main heading makes it less clear what the page is about.",
        "Keep one \"Heading 1\" and change the others to \"Heading 2\".",
        YOU,
    ),
    "Missing Favicon": _g(
        "seo",
        "The small icon in browser tabs and bookmarks helps people recognise your site.",
        "Upload a site icon (favicon) in your site builder's settings.",
        YOU,
    ),
    "Page Blocked From Search (noindex)": _g(
        "seo",
        "This page tells Google not to list it, so people can't find it through search.",
        "Turn off \"hide from search engines\" for this page — unless you meant to hide it.",
        WEB_PERSON,
    ),
    "Site Blocked From Search (robots.txt)": _g(
        "seo",
        "Your robots.txt file tells search engines to stay away, so your site can drop out of Google.",
        "Remove the rule blocking search engines from robots.txt (often a leftover \"hide while "
        "building\" setting).",
        WEB_PERSON,
    ),
    # --- Site setup --------------------------------------------------------
    "Sitemap Lists Missing Pages": _g(
        "setup",
        "Your sitemap sends search engines to pages that don't exist, which wastes their visits.",
        "Remove those addresses from the sitemap, or bring the pages back.",
        WEB_PERSON,
    ),
    "Sitemap Lists Redirecting Pages": _g(
        "setup",
        "Search engines expect a sitemap to list final addresses, not ones that redirect somewhere "
        "else.",
        "Update the sitemap to list the final addresses.",
        WEB_PERSON,
    ),
    "Sitemap Lists URLs On Another Host": _g(
        "setup",
        "Search engines ignore sitemap entries on a different address, so those pages may not get "
        "listed.",
        "Make every address in the sitemap use your site's own address.",
        WEB_PERSON,
    ),
    "Sitemap Lists Insecure URLs": _g(
        "setup",
        "Listing http:// addresses on a secure site points search engines at the insecure version.",
        "Update the sitemap to use https:// addresses.",
        WEB_PERSON,
    ),
    "Menu Pages Missing From Sitemap": _g(
        "setup",
        "Pages missing from your sitemap can take longer to show up in search.",
        "Add them to the sitemap — most site builders do this automatically once a page is published.",
        WEB_PERSON,
    ),
    "No Sitemap Found": _g(
        "setup",
        "A sitemap helps search engines find every page on your site.",
        "Turn on your site builder's sitemap, or have one created.",
        WEB_PERSON,
    ),
    "robots.txt Is Erroring": _g(
        "setup",
        "When robots.txt answers with an error, Google treats it as \"stay out\" and can stop "
        "visiting your site.",
        "Fix the server error on /robots.txt.",
        HOST,
    ),
    "Favicon Doesn't Load": _g(
        "setup",
        "Browsers show a blank icon in tabs and bookmarks instead of yours.",
        "Re-upload the site icon, or fix the link to it.",
        WEB_PERSON,
    ),
    'Missing Pages Don\'t Say "Not Found"': _g(
        "setup",
        "Made-up addresses on your site look like real pages to search engines, which can fill "
        "search results with junk.",
        "Make addresses that don't exist answer with a real \"not found\" (404).",
        WEB_PERSON,
    ),
    "Plain Server Error Page": _g(
        "setup",
        "Visitors who mistype an address see a bare technical error page instead of your site.",
        "Set up a friendly \"page not found\" page that links back to your homepage.",
        WEB_PERSON,
    ),
    "Web App Manifest Missing": _g(
        "setup",
        "Your pages point to an app settings file that doesn't load, so \"add to home screen\" may "
        "look wrong.",
        "Fix or remove the link to the manifest file.",
        WEB_PERSON,
    ),
    "Site Answers On Both www And Non-www": _g(
        "setup",
        "Two copies of every page can split your search ranking between them.",
        "Redirect one version (with or without \"www\") to the other.",
        HOST,
    ),
    # --- Security (ownership-gated in public reports) ----------------------
    "Mixed Content (Active)": _g(
        "security",
        "Parts of your secure page load over an insecure connection; browsers may block them or "
        "warn visitors.",
        "Change those http:// addresses to https://.",
        WEB_PERSON,
    ),
    "Mixed Content (Passive)": _g(
        "security",
        "Some images or media load over an insecure connection, which can show a \"not secure\" "
        "warning.",
        "Change those http:// addresses to https://.",
        WEB_PERSON,
    ),
    "No Security Headers": _g(
        "security",
        "Your site sends none of the standard settings that tell browsers how to protect your "
        "visitors.",
        "Turn on the standard security headers.",
        HOST,
    ),
    "Missing Security Headers": _g(
        "security",
        "Some standard browser protections for your visitors are switched off.",
        "Add the missing headers listed.",
        HOST,
    ),
    "Server Software Version Revealed": _g(
        "security",
        "Showing the exact server version makes it easier for attackers to look up known weaknesses.",
        "Hide the version number in the server's settings.",
        HOST,
    ),
    "Secret Key Exposed In Page Source": _g(
        "security",
        "Anyone can copy this key and use your account with that provider — and you may be the one "
        "who pays.",
        "Cancel (rotate) the key with that provider today, then remove it from the site's code.",
        WEB_PERSON,
    ),
    "Source Code Map Files Are Public": _g(
        "security",
        "These files give anyone a readable copy of your site's code, which can reveal how it works "
        "inside.",
        "Stop publishing .map files on the live site.",
        WEB_PERSON,
    ),
    "Outdated JavaScript Library": _g(
        "security",
        "This version of the library has publicly known security problems.",
        "Update it to the latest version.",
        WEB_PERSON,
    ),
    "Exposed Sensitive File": _g(
        "security",
        "A private file can be downloaded by anyone and may contain passwords or customer data.",
        "Remove the file from the server today and change any passwords it contains.",
        WEB_PERSON,
    ),
    "WordPress XML-RPC Is Open": _g(
        "security",
        "This old WordPress feature is a common target for password-guessing attacks.",
        "Turn it off with a reputable security plugin, or ask your host to.",
        WEB_PERSON,
    ),
    "WordPress Usernames Are Public": _g(
        "security",
        "Anyone can see your login names, which is half of what they need to guess a login.",
        "Hide user and author listings with a reputable security plugin.",
        WEB_PERSON,
    ),
    "WordPress Version Has Known Security Problems": _g(
        "security",
        "WordPress.org lists your version as insecure, and attackers scan for exactly this.",
        "Update WordPress now and keep automatic updates switched on.",
        WEB_PERSON,
    ),
    "WordPress Out Of Date": _g(
        "security",
        "Older WordPress versions are missing fixes.",
        "Update WordPress.",
        WEB_PERSON,
    ),
    "WordPress Plugins Out Of Date": _g(
        "security",
        "Old plugins are the most common way WordPress sites get broken into.",
        "Update the plugins listed, and remove any you don't use.",
        WEB_PERSON,
    ),
    "Site Doesn't Use HTTPS": _g(
        "security",
        "Browsers mark your site \"Not secure\", which puts visitors off and hurts your Google ranking.",
        "Turn on HTTPS (a security certificate) — most hosts do this free in a few clicks.",
        HOST,
    ),
    "Insecure Version Of Site Doesn't Redirect": _g(
        "security",
        "Visitors who type your address without https:// stay on the insecure version.",
        "Redirect every http:// address to its https:// version.",
        HOST,
    ),
    "Security Certificate Problem": _g(
        "security",
        "Browsers show visitors a full-page security warning, and most of them leave.",
        "Renew or fix the certificate now.",
        HOST,
    ),
    "Security Certificate Expiring Soon": _g(
        "security",
        "Once it expires, browsers show visitors a security warning instead of your site.",
        "Renew the certificate, or switch on automatic renewal.",
        HOST,
    ),
    "Page Not On HTTPS": _g(
        "security",
        "This page loads without encryption on an otherwise secure site.",
        "Redirect it to its https:// address.",
        WEB_PERSON,
    ),
    "Folder Contents Are Public": _g(
        "security",
        "Anyone can browse a list of the files in this folder, which can expose private files.",
        "Turn off folder listings on the server.",
        HOST,
    ),
    "Site May Be Hacked": _g(
        "security",
        "We saw signs someone may have tampered with your site, such as hidden spam links or "
        "redirects to other sites.",
        "Have the site checked for malware today and change every password connected to it.",
        WEB_PERSON,
    ),
    "Script From A Domain That No Longer Exists": _g(
        "security",
        "Your site loads a script from an address that no longer exists. Someone could register it "
        "and run their own code on your site.",
        "Remove that script from your site.",
        WEB_PERSON,
    ),
    "Shared-Server Scripts Without Integrity Check": _g(
        "security",
        "If that shared server were ever tampered with, your site would run the changed code "
        "without noticing.",
        "Add an \"integrity\" value to these script tags, or host the files on your own site.",
        WEB_PERSON,
    ),
    # --- Accessibility checks outside axe ----------------------------------
    "No Visible Keyboard Focus": _g(
        "accessibility",
        "People who use a keyboard instead of a mouse can't see where they are on the page.",
        "Make links, buttons and form fields show a clear outline when someone tabs to them.",
        WEB_PERSON,
    ),
    "Media Plays Automatically With Sound": _g(
        "accessibility",
        "Sound that starts by itself is startling and drowns out screen readers.",
        "Turn off autoplay, or start the video muted.",
        YOU,
    ),
    "Video Without Captions": _g(
        "accessibility",
        "Deaf and hard-of-hearing visitors — and anyone watching with the sound off — miss what's said.",
        "Add captions to the video.",
        YOU,
    ),
    "Accessibility Overlay Widget": _g(
        "accessibility",
        "Overlay widgets don't make a site accessible or compliant, and can get in the way of "
        "screen-reader users.",
        "Fix the underlying problems on the site itself, and consider removing the overlay.",
        WEB_PERSON,
    ),
    "No Accessibility Statement": _g(
        "accessibility",
        "A short statement tells disabled visitors how to get help and shows you take accessibility "
        "seriously.",
        "Publish a short accessibility page with a contact for problems, and link it from your footer.",
        YOU,
    ),
}

# axe-based categories: one source of truth in checks_accessibility.
for _spec in A11Y_CATEGORIES.values():
    GUIDE.setdefault(
        _spec["category"], _g("accessibility", _spec["why"], _spec["fix"], _spec["who"])
    )

# A category with no row (a check added later that hasn't been written up
# yet) still gets honest, generic guidance by severity — never nothing.
_FALLBACK_WHY = {
    "high": "This is likely costing you customers, money or search visibility right now.",
    "medium": "This makes the site worse to use, or is a sign something needs attention.",
    "low": "This is polish — worth fixing, but not urgent.",
}
_FALLBACK_HOW = "The details above say what we found; your web person can use them to fix it."


def guide_for(category, severity="low"):
    """{"area", "why", "how", "who"} for a category, falling back to
    generic, severity-based wording for one that isn't written up yet."""
    if category in GUIDE:
        return GUIDE[category]
    if category.startswith("Accessibility: "):  # untranslated axe rule
        return _g("accessibility", _FALLBACK_WHY.get(severity, _FALLBACK_WHY["low"]), _FALLBACK_HOW, WEB_PERSON)
    return _g(None, _FALLBACK_WHY.get(severity, _FALLBACK_WHY["low"]), _FALLBACK_HOW, WEB_PERSON)


HOSTED_PLATFORMS = ("Shopify", "Wix", "Squarespace", "Webflow")


def platform_note(who_fixes, platform):
    """One sentence of platform-specific advice, or None. Only says things
    that are true of the platform as a whole (who controls the server),
    never a menu path we haven't verified."""
    if not platform:
        return None
    if platform in HOSTED_PLATFORMS:
        if who_fixes == HOST:
            return (f"Your site runs on {platform}, which runs the server for you — contact "
                    f"{platform} support rather than changing anything yourself.")
        return f"Your site runs on {platform}: look in {platform}'s own settings and help pages first."
    if platform == "WordPress" and who_fixes == HOST:
        return "On WordPress, your host's control panel or a reputable plugin can usually do this."
    return None
