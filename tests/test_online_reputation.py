"""detector.online_reputation birim testleri (ağ çağrısı mock'lanır)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from detector.online_reputation import (
    OnlineFinding,
    ReputationProvider,
    SafeBrowsingProvider,
    UrlhausProvider,
    run_online_reputation_checks,
)


class _FakeListedProvider(ReputationProvider):
    name = "fake"

    def check(self, url: str) -> list[OnlineFinding]:
        return [
            OnlineFinding(
                rule_id="listed_on_urlhaus",
                score=40,
                message=f"fake hit for {url}",
                provider=self.name,
            )
        ]


@patch("detector.online_reputation.ENABLE_ONLINE_REPUTATION", False)
def test_online_reputation_can_be_disabled() -> None:
    result = run_online_reputation_checks("https://example.com")
    assert result.findings == []


def test_run_online_with_injected_provider() -> None:
    result = run_online_reputation_checks(
        "http://evil.example/phish",
        providers=[_FakeListedProvider()],
    )
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "listed_on_urlhaus"
    assert result.total_score == 40


@patch("detector.online_reputation.requests.post")
def test_urlhaus_listed(mock_post) -> None:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"query_status": "ok", "threat": "phishing_url"}
    mock_post.return_value = response

    findings = UrlhausProvider().check("http://bad.example/login")
    assert len(findings) == 1
    assert findings[0].rule_id == "listed_on_urlhaus"


@patch("detector.online_reputation.requests.post")
def test_safe_browsing_match(mock_post) -> None:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "matches": [{"threatType": "SOCIAL_ENGINEERING"}],
    }
    mock_post.return_value = response

    findings = SafeBrowsingProvider("test-key").check("http://bad.example")
    assert len(findings) == 1
    assert findings[0].rule_id == "listed_on_safe_browsing"
