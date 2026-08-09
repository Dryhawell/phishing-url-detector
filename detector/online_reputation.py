"""Çevrimiçi itibar / blocklist sorguları.

Yerel heuristic + WHOIS yetmez; bilinen kötü URL'ler topluluk listelerinde yer alır.

Sağlayıcılar:
- URLhaus (abuse.ch): API anahtarı gerektirmez
- Google Safe Browsing v4: GOOGLE_SAFE_BROWSING_API_KEY varsa çalışır

Ağ hatasında analizi bozmaz; düşük puanlı uyarı ekleyebilir.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import requests

from config import (
    ENABLE_ONLINE_REPUTATION,
    ONLINE_REPUTATION_TIMEOUT,
    RISK_SCORES,
    SAFE_BROWSING_API_KEY_ENV,
)
from utils.logger import get_logger

logger = get_logger()

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


@dataclass
class OnlineFinding:
    """Tek bir çevrimiçi itibar sinyalinin sonucu."""

    rule_id: str
    score: int
    message: str
    provider: str


@dataclass
class OnlineReputationResult:
    """Tüm çevrimiçi sağlayıcı sonuçlarının özeti."""

    findings: list[OnlineFinding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        """Bulguların puan toplamı."""
        return sum(item.score for item in self.findings)


def _add_finding(
    result: OnlineReputationResult,
    rule_id: str,
    message: str,
    provider: str,
) -> None:
    """Config ağırlıklı bulgu ekle."""
    result.findings.append(
        OnlineFinding(
            rule_id=rule_id,
            score=RISK_SCORES[rule_id],
            message=message,
            provider=provider,
        )
    )


class ReputationProvider(ABC):
    """Çevrimiçi itibar sağlayıcı sözleşmesi."""

    name: str

    @abstractmethod
    def check(self, url: str) -> list[OnlineFinding]:
        """URL'yi sorgula; bulgu listesi döndür (boş olabilir)."""


class UrlhausProvider(ReputationProvider):
    """abuse.ch URLhaus API sağlayıcısı."""

    name = "urlhaus"

    def check(self, url: str) -> list[OnlineFinding]:
        """URLhaus üzerinde URL sorgula."""
        findings: list[OnlineFinding] = []
        try:
            response = requests.post(
                URLHAUS_ENDPOINT,
                data={"url": url},
                timeout=ONLINE_REPUTATION_TIMEOUT,
                headers={"User-Agent": "PhishingURLDetector/1.1"},
            )
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("URLhaus sorgusu başarısız: %s", exc)
            findings.append(
                OnlineFinding(
                    rule_id="online_reputation_error",
                    score=RISK_SCORES["online_reputation_error"],
                    message="URLhaus sorgusu başarısız oldu",
                    provider=self.name,
                )
            )
            return findings

        status = str(payload.get("query_status", "")).lower()
        if status == "ok":
            threat = payload.get("threat") or payload.get("url_status") or "listed"
            findings.append(
                OnlineFinding(
                    rule_id="listed_on_urlhaus",
                    score=RISK_SCORES["listed_on_urlhaus"],
                    message=f"URLhaus listesinde bulundu ({threat})",
                    provider=self.name,
                )
            )
        elif status in {"no_results", "invalid_url"}:
            logger.info("URLhaus: kayıt yok (%s)", status)
        else:
            logger.info("URLhaus yanıt durumu: %s", status)
        return findings


class SafeBrowsingProvider(ReputationProvider):
    """Google Safe Browsing v4 sağlayıcısı (API anahtarı gerekir)."""

    name = "safe_browsing"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def check(self, url: str) -> list[OnlineFinding]:
        """Safe Browsing threatMatches sorgusu."""
        findings: list[OnlineFinding] = []
        body = {
            "client": {"clientId": "phishing-url-detector", "clientVersion": "1.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            response = requests.post(
                f"{SAFE_BROWSING_ENDPOINT}?key={self.api_key}",
                json=body,
                timeout=ONLINE_REPUTATION_TIMEOUT,
            )
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Safe Browsing sorgusu başarısız: %s", exc)
            findings.append(
                OnlineFinding(
                    rule_id="online_reputation_error",
                    score=RISK_SCORES["online_reputation_error"],
                    message="Safe Browsing sorgusu başarısız oldu",
                    provider=self.name,
                )
            )
            return findings

        matches = payload.get("matches") or []
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            findings.append(
                OnlineFinding(
                    rule_id="listed_on_safe_browsing",
                    score=RISK_SCORES["listed_on_safe_browsing"],
                    message=f"Google Safe Browsing eşleşmesi ({threat_type})",
                    provider=self.name,
                )
            )
        return findings


def build_providers() -> list[ReputationProvider]:
    """Config / ortam değişkenlerine göre aktif sağlayıcıları oluştur."""
    providers: list[ReputationProvider] = [UrlhausProvider()]
    api_key = os.getenv(SAFE_BROWSING_API_KEY_ENV, "").strip()
    if api_key:
        providers.append(SafeBrowsingProvider(api_key))
        logger.info("Safe Browsing sağlayıcısı aktif")
    else:
        logger.info(
            "Safe Browsing atlandı (ortam değişkeni yok: %s)",
            SAFE_BROWSING_API_KEY_ENV,
        )
    return providers


def run_online_reputation_checks(
    url: str,
    providers: list[ReputationProvider] | None = None,
) -> OnlineReputationResult:
    """URL için çevrimiçi itibar kontrollerini çalıştır.

    Args:
        url: Normalize edilmiş URL.
        providers: Testlerde enjekte edilebilir sağlayıcı listesi.

    Returns:
        OnlineReputationResult
    """
    result = OnlineReputationResult()
    if not ENABLE_ONLINE_REPUTATION:
        logger.info("Çevrimiçi itibar config ile kapalı")
        return result

    active = providers if providers is not None else build_providers()
    for provider in active:
        logger.info("Çevrimiçi itibar sorgusu: %s", provider.name)
        for finding in provider.check(url):
            result.findings.append(finding)

    logger.info(
        "Çevrimiçi itibar bitti | url=%s | findings=%s",
        url,
        len(result.findings),
    )
    return result
