"""api.server birim testleri."""

from __future__ import annotations

from unittest.mock import patch

from api.server import create_app
from detector.analyzer import AnalysisResult
from detector.heuristics import HeuristicFinding


def test_health_endpoint() -> None:
    client = create_app().test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


@patch("api.server.analyze_url")
def test_analyze_endpoint(mock_analyze) -> None:
    mock_analyze.return_value = AnalysisResult(
        url="http://evil.xyz/login",
        is_valid=True,
        risk_score=80,
        risk_level="HIGH_RISK",
        findings=[HeuristicFinding("suspicious_tld", 25, ".xyz")],
        recommendations=["Tiklamayin."],
    )
    client = create_app().test_client()
    response = client.post("/analyze", json={"url": "http://evil.xyz/login"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["risk_level"] == "HIGH_RISK"
    assert data["risk_score"] == 80
    assert data["problems"]


def test_analyze_requires_url() -> None:
    client = create_app().test_client()
    response = client.post("/analyze", json={})
    assert response.status_code == 400
