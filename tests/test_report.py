"""detector.report birim testleri."""

from __future__ import annotations

import json
from pathlib import Path

from detector.analyzer import AnalysisResult
from detector.heuristics import HeuristicFinding
from detector.report import build_report_payload, save_json_report, save_pdf_report


def test_build_report_payload_structure() -> None:
    result = AnalysisResult(
        url="https://example.com",
        is_valid=True,
        risk_score=10,
        risk_level="SAFE",
        findings=[
            HeuristicFinding(rule_id="no_https", score=20, message="HTTPS yok"),
        ],
        recommendations=["Dikkatli olun."],
    )
    payload = build_report_payload(result)
    assert payload["url"] == "https://example.com"
    assert payload["risk_score"] == 10
    assert payload["problems"] == ["HTTPS yok"]
    assert "generated_at" in payload


def test_save_json_report(tmp_path: Path) -> None:
    result = AnalysisResult(
        url="http://evil.xyz/login",
        is_valid=True,
        risk_score=80,
        risk_level="HIGH_RISK",
        findings=[
            HeuristicFinding(rule_id="suspicious_tld", score=25, message=".xyz"),
        ],
        recommendations=["Tıklamayın."],
    )
    path = save_json_report(result, reports_dir=tmp_path)
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["risk_level"] == "HIGH_RISK"
    assert data["url"] == "http://evil.xyz/login"


def test_save_pdf_report(tmp_path: Path) -> None:
    result = AnalysisResult(
        url="http://evil.xyz/login",
        is_valid=True,
        risk_score=80,
        risk_level="HIGH_RISK",
        findings=[
            HeuristicFinding(rule_id="suspicious_tld", score=25, message=".xyz"),
        ],
        recommendations=["Tiklamayin."],
    )
    path = save_pdf_report(result, reports_dir=tmp_path)
    assert path.exists()
    assert path.suffix == ".pdf"
    assert path.stat().st_size > 0
