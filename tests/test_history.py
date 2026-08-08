"""gui.history birim testleri."""

from __future__ import annotations

from detector.analyzer import AnalysisResult
from gui.history import HistoryStore


def test_history_add_and_order() -> None:
    store = HistoryStore(limit=3)
    first = AnalysisResult(url="https://a.com", is_valid=True, risk_score=0, risk_level="SAFE")
    second = AnalysisResult(
        url="http://b.xyz", is_valid=True, risk_score=70, risk_level="HIGH_RISK"
    )
    store.add("https://a.com", first)
    store.add("http://b.xyz", second)
    assert len(store) == 2
    assert store.get(0) is not None
    assert store.get(0).result.url == "http://b.xyz"
    assert "HIGH_RISK" in store.labels[0]


def test_history_respects_limit() -> None:
    store = HistoryStore(limit=2)
    for index in range(5):
        result = AnalysisResult(
            url=f"https://x{index}.com",
            is_valid=True,
            risk_score=index,
            risk_level="SAFE",
        )
        store.add(f"https://x{index}.com", result)
    assert len(store) == 2
    assert store.get(0).result.url == "https://x4.com"


def test_history_clear() -> None:
    store = HistoryStore()
    store.add("u", AnalysisResult(url="u", is_valid=False, error="x"))
    store.clear()
    assert len(store) == 0
    assert store.get(0) is None
