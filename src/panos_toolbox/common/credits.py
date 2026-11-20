"""Credits box shown at the top of every HTML report (git repository and author).

Standard library only: imported by the offline report tools (tsf, gp, runtime).
The links are plain outbound anchors; the reports still load nothing external.
"""

REPO_URL = "https://github.com/ilbernard/panos-toolbox"
AUTHOR_NAME = "Alberto Bernardi"
AUTHOR_URL = "https://www.linkedin.com/in/alberto-bernardi/"

# Placeholder in the report markup, replaced with CREDITS_HTML when the template is assembled.
CREDITS_PLACEHOLDER = "__CREDITS__"

CREDITS_CSS = (
    ".credits{float:right;display:flex;align-items:center;gap:10px;margin:0 0 8px 16px;"
    "padding:8px 12px;background:#e8f2f6;border:1px solid #b9d6e1;border-left:4px solid #1f6f8b;"
    "border-radius:6px;font-size:13px;line-height:1.45;color:#1c2530}\n"
    ".credits strong{color:#1f6f8b}\n"
    ".credits a{display:inline-block;padding:3px 10px;border-radius:4px;background:#1f6f8b;"
    "color:#fff;font-weight:600;text-decoration:none;white-space:nowrap}\n"
    ".credits a:hover,.credits a:focus-visible{background:#17566c;outline:2px solid #17566c;"
    "outline-offset:1px}\n"
    "@media print{.credits{background:none;border-color:#999}"
    ".credits a{background:none;color:#1c2530;text-decoration:underline}}\n"
)

CREDITS_HTML = (
    '<div class="credits" id="credits"><span>Generated with <strong>panos-toolbox</strong> by '
    f'<strong>{AUTHOR_NAME}</strong></span>'
    f'<a href="{REPO_URL}" target="_blank" rel="noopener noreferrer">Git repository &#8599;</a>'
    f'<a href="{AUTHOR_URL}" target="_blank" rel="noopener noreferrer">LinkedIn &#8599;</a></div>\n'
)
