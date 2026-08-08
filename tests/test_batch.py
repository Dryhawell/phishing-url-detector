"""detector.batch birim testleri."""

from __future__ import annotations

import json
from pathlib import Path

from detector.analyzer import AnalysisResult
from detector.batch import (
    analyze_batch,
    build_batch_summary,
    load_urls,
    run_batch_file,
    url_fingerprint,
)
from detector.heuristics import HeuristicFinding


def _fake_analyze(raw: str) -> AnalysisResult:
    if "evil" in raw:
        return AnalysisResult(
            url=raw,
            is_valid=True,
            risk_score=80,
            risk_level="HIGH_RISK",
            findings=[
                HeuristicFinding("suspicious_tld", 25, ".xyz"),
            ],
        )
    if " " in raw:
        return AnalysisResult(
            url=raw,
            is_valid=False,
            error="URL formatı geçersiz.",
        )
    return AnalysisResult(url=raw, is_valid=True, risk_score=0, risk_level="SAFE")


def test_url_fingerprint_stable() -> None:
    assert url_fingerprint("https://a.com") == url_fingerprint("https://a.com")
    assert url_fingerprint("https://a.com") != url_fingerprint("https://b.com")


def test_load_urls_txt_and_csv(tmp_path: Path) -> None:
    txt = tmp_path / "u.txt"
    txt.write_text("# yorum\nhttps://a.com\n\nhttp://b.com\n", encoding="utf-8")
    assert load_urls(txt) == ["https://a.com", "http://b.com"]

    csv_path = tmp_path / "u.csv"
    csv_path.write_text("url,note\nhttps://a.com,x\nhttp://b.com,y\n", encoding="utf-8")
    assert load_urls(csv_path) == ["https://a.com", "http://b.com"]


def test_analyze_batch_and_summary() -> None:
    items = analyze_batch(
        ["https://ok.com", "http://evil.xyz", "bad url"],
        analyze_fn=_fake_analyze,
    )
    summary = build_batch_summary("memory", items)
    assert summary.total == 3
    assert summary.safe == 1
    assert summary.high_risk == 1
    assert summary.invalid == 1


def test_run_batch_file(tmp_path: Path) -> None:
    source = tmp_path / "list.txt"
    source.write_text("https://ok.com\nhttp://evil.xyz\n", encoding="utf-8")
    out = tmp_path / "out.json"
    summary, path = run_batch_file(source, output_path=out, analyze_fn=_fake_analyze)
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["total"] == 2
    assert data["high_risk"] == 1
    assert summary.safe == 1
