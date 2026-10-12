"""A tiny, purpose-built markdown-to-HTML renderer — not a general markdown
library. Supports only the handful of constructs the docs in legal/
actually use: #/##/### headers, > blockquotes, **bold**, *italic*, - lists,
and plain paragraphs. Deliberately hand-rolled instead of adding a markdown
dependency for such a small, fixed need."""
import html
import re


def _render_inline(text):
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<em>\1</em>", text)
    return text


def render_markdown(md_text):
    html_parts = []
    paragraph_lines = []
    list_open = False

    def flush_paragraph():
        if paragraph_lines:
            html_parts.append(f"<p>{_render_inline(' '.join(paragraph_lines))}</p>")
            paragraph_lines.clear()

    def close_list():
        nonlocal list_open
        if list_open:
            html_parts.append("</ul>")
            list_open = False

    for line in md_text.splitlines():
        stripped = line.strip()

        if not stripped:
            flush_paragraph()
            close_list()
            continue

        if stripped.startswith("### "):
            flush_paragraph()
            close_list()
            html_parts.append(f"<h3>{_render_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            flush_paragraph()
            close_list()
            html_parts.append(f"<h2>{_render_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            flush_paragraph()
            close_list()
            html_parts.append(f"<h1>{_render_inline(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            flush_paragraph()
            close_list()
            html_parts.append(f"<blockquote>{_render_inline(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            flush_paragraph()
            if not list_open:
                html_parts.append("<ul>")
                list_open = True
            html_parts.append(f"<li>{_render_inline(stripped[2:])}</li>")
        else:
            close_list()
            paragraph_lines.append(stripped)

    flush_paragraph()
    close_list()
    return "\n".join(html_parts)
