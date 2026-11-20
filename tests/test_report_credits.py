"""The credits box (git repository and author) is in the header of every HTML report.

Standard library only; no device is contacted.
"""
import re

import pytest

from panos_toolbox.common.credits import (
    AUTHOR_URL,
    CREDITS_CSS,
    CREDITS_HTML,
    CREDITS_PLACEHOLDER,
    REPO_URL,
)
from panos_toolbox.gp import report_template as gp_template
from panos_toolbox.runtime import report_template as runtime_template
from panos_toolbox.tsf import analyzer as tsf_analyzer
from panos_toolbox.tsf import report_template as tsf_template

PAGES = {
    "tsf report": tsf_template.TEMPLATE,
    "tsf summary": tsf_analyzer.render_index([]),
    "gp report": gp_template.TEMPLATE,
    "runtime report": runtime_template.TEMPLATE,
}


@pytest.mark.parametrize("name", sorted(PAGES))
def test_every_report_has_the_credits_box_once(name):
    page = PAGES[name]
    assert page.count(CREDITS_HTML) == 1, name
    assert CREDITS_CSS in page, name
    assert CREDITS_PLACEHOLDER not in page, name
    # The box comes before the page title, so it sits at the top of the header.
    assert page.index(CREDITS_HTML) < page.index("<h1"), name


@pytest.mark.parametrize("name", sorted(PAGES))
def test_credits_are_the_only_outbound_links(name):
    page = PAGES[name]
    assert sorted(re.findall(r'href="(https?:[^"]*)"', page)) == sorted([REPO_URL, AUTHOR_URL]), name
    assert not re.search(r"src=[\"']?https?:", page), name


def test_credits_links_open_in_a_new_tab_without_opener():
    for url in (REPO_URL, AUTHOR_URL):
        assert f'href="{url}" target="_blank" rel="noopener noreferrer"' in CREDITS_HTML
