"""detector.analyzer birim testleri."""

from __future__ import annotations

from unittest.mock import patch

from detector.analyzer import analyze_url
from detector.reputation import ReputationResult


@patch(
    "detector.analyzer.run_reputation_checks",
    return_value=ReputationResult(),
)
def test_analyze_safe_url(_mock_rep) -> None:
    result = analyze_url("https://www.example.com")
    assert result.is_valid is True
    assert result.risk_level == "SAFE"
    assert result.risk_score == 0


@patch(
    "detector.analyzer.run_reputation_checks",
    return_value=ReputationResult(),
)
def test_analyze_high_risk_url(_mock_rep) -> None:
    result = analyze_url("http://192.168.1.1/login.xyz")
    assert result.is_valid is True
    assert result.risk_score >= 51
    assert result.risk_level == "HIGH_RISK"
    assert result.problems
    assert result.recommendations


def test_analyze_empty_and_invalid() -> None:
    empty = analyze_url("")
    assert empty.is_valid is False
    assert empty.error

    invalid = analyze_url("not a url")
    assert invalid.is_valid is False
    assert invalid.error
