"""detector.reputation birim testleri (ağ çağrısı mock'lanır)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from detector.reputation import run_reputation_checks


def test_ip_url_skips_whois() -> None:
    result = run_reputation_checks("http://192.168.1.1/login")
    assert result.findings == []
    assert result.whois_data == {}


@patch("detector.reputation.fetch_whois", return_value=None)
def test_whois_unavailable_finding(_mock_fetch) -> None:
    result = run_reputation_checks("https://brand-new-domain.example")
    assert any(item.rule_id == "whois_unavailable" for item in result.findings)


@patch("detector.reputation.fetch_whois")
def test_very_new_domain_finding(mock_fetch) -> None:
    created = datetime.now(timezone.utc) - timedelta(days=3)
    mock_fetch.return_value = {
        "domain": "newphish.com",
        "creation_date": created,
        "registrar": "TestRegistrar",
        "name_servers": ["ns1.example"],
    }
    result = run_reputation_checks("https://login.newphish.com")
    assert any(item.rule_id == "very_new_domain" for item in result.findings)
    assert result.whois_data.get("age_days") == 3
