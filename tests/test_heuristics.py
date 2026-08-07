"""detector.heuristics birim testleri."""

from __future__ import annotations

from detector.heuristics import run_heuristics


def test_https_missing_adds_finding() -> None:
    result = run_heuristics("http://example.com")
    assert any(item.rule_id == "no_https" for item in result.findings)


def test_ip_and_login_are_flagged() -> None:
    result = run_heuristics("http://192.168.0.1/login")
    rule_ids = {item.rule_id for item in result.findings}
    assert "ip_in_url" in rule_ids
    assert "phishing_keyword" in rule_ids
    assert result.total_score > 0


def test_suspicious_tld_flagged() -> None:
    result = run_heuristics("https://safe-looking.xyz")
    assert any(item.rule_id == "suspicious_tld" for item in result.findings)


def test_clean_https_site_low_findings() -> None:
    result = run_heuristics("https://www.example.com")
    # Şüpheli TLD / IP / keyword yok; en fazla zayıf sinyaller olabilir.
    assert "ip_in_url" not in {item.rule_id for item in result.findings}
    assert "suspicious_tld" not in {item.rule_id for item in result.findings}
