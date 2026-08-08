"""HTML içerik analizi (requests + BeautifulSoup).

URL şekli (heuristics) ve domain yaşı (reputation) yetmez;
phishing sayfaları genelde şifre formu, iframe veya dış form action içerir.

Bu modül sayfayı indirir, parse eder ve içerik sinyali üretir.
Ağ hatasında analizi bozmaz; düşük puanlı uyarı ekler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from config import (
    CONTENT_FETCH_TIMEOUT,
    CONTENT_MAX_BYTES,
    ENABLE_CONTENT_ANALYSIS,
    RISK_SCORES,
)
from utils.helpers import extract_host, get_domain_parts
from utils.logger import get_logger

logger = get_logger()

# İsteklerde kendini tanımlayan zararsız User-Agent.
_USER_AGENT = "PhishingURLDetector/1.0 (+educational; defensive-security)"


@dataclass
class ContentFinding:
    """Tek bir içerik sinyalinin sonucu."""

    rule_id: str
    score: int
    message: str


@dataclass
class ContentResult:
    """HTML içerik kontrollerinin özeti."""

    findings: list[ContentFinding] = field(default_factory=list)
    fetched: bool = False

    @property
    def total_score(self) -> int:
        """Bulguların puan toplamı."""
        return sum(item.score for item in self.findings)


def _add_finding(result: ContentResult, rule_id: str, message: str) -> None:
    """Config ağırlıklı bulgu ekle."""
    result.findings.append(
        ContentFinding(
            rule_id=rule_id,
            score=RISK_SCORES[rule_id],
            message=message,
        )
    )


def fetch_html(url: str) -> str | None:
    """URL'den HTML gövdesini indir.

    Args:
        url: Normalize edilmiş URL.

    Returns:
        HTML metni veya hata durumunda None.
    """
    try:
        response = requests.get(
            url,
            timeout=CONTENT_FETCH_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
            allow_redirects=True,
        )
        response.raise_for_status()

        # Content-Type HTML değilse içerik analizini atla.
        content_type = (response.headers.get("Content-Type") or "").lower()
        if content_type and "html" not in content_type and "text/" not in content_type:
            logger.info("HTML olmayan içerik tipi atlandı: %s", content_type)
            return None

        raw = response.content[: CONTENT_MAX_BYTES + 1]
        if len(raw) > CONTENT_MAX_BYTES:
            logger.info("İçerik çok büyük; ilk %s bayt analiz edilecek", CONTENT_MAX_BYTES)
            raw = raw[:CONTENT_MAX_BYTES]

        encoding = response.encoding or "utf-8"
        return raw.decode(encoding, errors="replace")
    except requests.RequestException as exc:
        logger.warning("HTML indirme başarısız (%s): %s", url, exc)
        return None


def _registered_or_host(url: str) -> str:
    """Karşılaştırma için domain kökünü döndür."""
    parts = get_domain_parts(url)
    return (parts["registered_domain"] or extract_host(url) or "").lower()


def check_password_fields(soup: BeautifulSoup, result: ContentResult) -> None:
    """Şifre input alanı varsa sinyal ekle."""
    password_inputs = soup.find_all("input", attrs={"type": "password"})
    if password_inputs:
        _add_finding(
            result,
            "password_field",
            f"Sayfada şifre alanı var ({len(password_inputs)} adet)",
        )


def check_external_form_actions(
    soup: BeautifulSoup, page_url: str, result: ContentResult
) -> None:
    """Form action farklı domaine gidiyorsa sinyal ekle.

    Phishing'te kullanıcı sahte sitede form doldurur; veri başka domain'e post edilir.
    """
    page_root = _registered_or_host(page_url)
    if not page_root:
        return

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if not action or action.startswith("#") or action.startswith("javascript:"):
            continue

        absolute = urljoin(page_url, action)
        action_root = _registered_or_host(absolute)
        if action_root and action_root != page_root:
            _add_finding(
                result,
                "external_form_action",
                f"Form verisi dış domain'e gidiyor ({action_root})",
            )
            return


def check_iframes(soup: BeautifulSoup, result: ContentResult) -> None:
    """iframe kullanımı varsa (sık görülen gizleme tekniği) sinyal ekle."""
    frames = soup.find_all("iframe")
    if frames:
        _add_finding(
            result,
            "iframe_present",
            f"Sayfada iframe var ({len(frames)} adet)",
        )


def analyze_html(page_url: str, html: str) -> ContentResult:
    """Ham HTML üzerinde içerik kurallarını çalıştır."""
    result = ContentResult(fetched=True)
    soup = BeautifulSoup(html, "html.parser")
    check_password_fields(soup, result)
    check_external_form_actions(soup, page_url, result)
    check_iframes(soup, result)
    return result


def run_content_checks(url: str) -> ContentResult:
    """URL için HTML içerik analizini çalıştır.

    Args:
        url: Normalize edilmiş URL.

    Returns:
        ContentResult (ağ kapalı/hata olsa bile güvenli).
    """
    if not ENABLE_CONTENT_ANALYSIS:
        logger.info("İçerik analizi config ile kapalı")
        return ContentResult()

    # data: ve file: şemalarında indirme yapma.
    scheme = urlparse(url).scheme.lower()
    if scheme not in {"http", "https"}:
        return ContentResult()

    logger.info("HTML içerik analizi başlıyor: %s", url)
    html = fetch_html(url)
    if html is None:
        result = ContentResult(fetched=False)
        _add_finding(
            result,
            "content_fetch_failed",
            "Sayfa içeriği indirilemedi (ağ/engel olabilir)",
        )
        return result

    result = analyze_html(url, html)
    logger.info(
        "İçerik analizi bitti | url=%s | findings=%s",
        url,
        len(result.findings),
    )
    return result
