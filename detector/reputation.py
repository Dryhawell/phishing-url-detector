"""Domain itibar (reputation) kontrolleri.

Heuristic kurallar URL'nin *şekline* bakar.
Bu modül ise domain'in *geçmişine / kaydına* bakar (WHOIS).

İlk sürümde hafif tutulur:
- Domain yaşını WHOIS creation_date ile tahmin eder.
- Sorgu başarısız olursa analizi bozmaz; düşük puanlı uyarı ekler.

Not: WHOIS sunucuları yavaş/kararsız olabilir; bu yüzden hata
yutulur ve kullanıcıya şeffaf bir mesaj bırakılır.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import whois

from config import NEW_DOMAIN_DAYS, RISK_SCORES
from utils.helpers import extract_host, get_domain_parts, is_ip_address
from utils.logger import get_logger

logger = get_logger()


@dataclass
class ReputationFinding:
    """Tek bir itibar sinyalinin sonucu."""

    rule_id: str
    score: int
    message: str


@dataclass
class ReputationResult:
    """İtibar kontrollerinin özeti."""

    findings: list[ReputationFinding] = field(default_factory=list)
    whois_data: dict[str, Any] = field(default_factory=dict)

    @property
    def total_score(self) -> int:
        """Bulguların puan toplamı."""
        return sum(item.score for item in self.findings)

    @property
    def messages(self) -> list[str]:
        """Kullanıcıya gösterilecek mesajlar."""
        return [item.message for item in self.findings]


def _add_finding(result: ReputationResult, rule_id: str, message: str) -> None:
    """Sonuca config ağırlıklı bir bulgu ekle."""
    result.findings.append(
        ReputationFinding(
            rule_id=rule_id,
            score=RISK_SCORES[rule_id],
            message=message,
        )
    )


def _resolve_lookup_target(url: str) -> str | None:
    """WHOIS için sorgulanacak domain'i belirle.

    IP adreslerinde WHOIS domain sorgusu anlamsızdır; None döner.
    """
    host = extract_host(url)
    if not host or is_ip_address(host):
        return None

    parts = get_domain_parts(url)
    # example.co.uk -> registered_domain daha doğru hedefdir.
    target = parts["registered_domain"] or parts["domain"]
    return target or None


def _as_utc_datetime(value: Any) -> datetime | None:
    """WHOIS tarih alanını timezone-aware datetime'a çevir.

    python-whois bazen datetime, bazen liste, bazen string döner.
    """
    if value is None:
        return None

    # Birden fazla creation_date gelirse en yenisini almayız;
    # en eskisi (ilk kayıt) domain yaşı için daha anlamlıdır.
    if isinstance(value, list):
        parsed = [_as_utc_datetime(item) for item in value]
        valid = [item for item in parsed if item is not None]
        return min(valid) if valid else None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y"):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def fetch_whois(domain: str) -> dict[str, Any] | None:
    """Domain için WHOIS bilgisi çek.

    Args:
        domain: Sorgulanacak kayıtlı domain (ör. example.com).

    Returns:
        Özet sözlük veya hata/boş durumda None.
    """
    try:
        # python-whois senkron çalışır; ağ hatasında exception bekleriz.
        data = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001 - WHOIS hataları çeşitlidir
        logger.warning("WHOIS sorgusu başarısız (%s): %s", domain, exc)
        return None

    if data is None:
        return None

    # Bazı sunucular boş nesne döndürür.
    creation = getattr(data, "creation_date", None)
    registrar = getattr(data, "registrar", None)
    if creation is None and registrar is None:
        logger.info("WHOIS verisi boş veya yetersiz: %s", domain)
        return None

    return {
        "domain": domain,
        "creation_date": creation,
        "registrar": registrar,
        "name_servers": getattr(data, "name_servers", None),
    }


def check_domain_age(whois_data: dict[str, Any], result: ReputationResult) -> None:
    """Domain çok yeniyse risk puanı ekle."""
    created = _as_utc_datetime(whois_data.get("creation_date"))
    if created is None:
        return

    age_days = (datetime.now(timezone.utc) - created).days
    result.whois_data["age_days"] = age_days
    result.whois_data["creation_date"] = created.isoformat()

    if age_days < NEW_DOMAIN_DAYS:
        _add_finding(
            result,
            "very_new_domain",
            f"Domain çok yeni ({age_days} gün; eşik {NEW_DOMAIN_DAYS} gün)",
        )


def run_reputation_checks(url: str) -> ReputationResult:
    """URL için itibar kontrollerini çalıştır.

    Args:
        url: Normalize edilmiş URL.

    Returns:
        ReputationResult: bulgular + varsa WHOIS özeti.
    """
    result = ReputationResult()
    target = _resolve_lookup_target(url)

    if target is None:
        logger.info("İtibar kontrolü atlandı (IP veya host yok): %s", url)
        return result

    logger.info("WHOIS sorgusu başlıyor: %s", target)
    whois_data = fetch_whois(target)

    if whois_data is None:
        _add_finding(
            result,
            "whois_unavailable",
            "WHOIS bilgisi alınamadı (ağ/kayıt kısıtı olabilir)",
        )
        return result

    result.whois_data = dict(whois_data)
    check_domain_age(whois_data, result)
    logger.info(
        "İtibar kontrolü bitti | domain=%s | findings=%s",
        target,
        len(result.findings),
    )
    return result
