"""config modülü birim testleri."""

from __future__ import annotations

from config import RISK_SCORES, get_risk_level


def test_get_risk_level_safe() -> None:
    assert get_risk_level(0) == "SAFE"
    assert get_risk_level(20) == "SAFE"


def test_get_risk_level_suspicious() -> None:
    assert get_risk_level(21) == "SUSPICIOUS"
    assert get_risk_level(50) == "SUSPICIOUS"


def test_get_risk_level_high_risk() -> None:
    assert get_risk_level(51) == "HIGH_RISK"
    assert get_risk_level(100) == "HIGH_RISK"
    # Clamp: 100 üzeri de HIGH_RISK
    assert get_risk_level(250) == "HIGH_RISK"


def test_risk_scores_contain_core_rules() -> None:
    for key in ("no_https", "ip_in_url", "suspicious_tld", "phishing_keyword"):
        assert key in RISK_SCORES
        assert RISK_SCORES[key] > 0
