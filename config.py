"""Proje genelinde kullanılan sabit ayarlar.

Neden ayrı bir config dosyası?
- Risk puanları, şüpheli uzantılar ve kelimeler tek yerde tutulur.
- Analiz kodunu değiştirmeden eşikleri güncelleyebilirsin (açık/kapalı prensibi).
- Testlerde aynı değerleri import ederek tutarlılık sağlanır.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Risk puan ağırlıkları
# Her tetiklenen kural, toplam skora bu kadar ekler.
# ---------------------------------------------------------------------------

RISK_SCORES: Final[dict[str, int]] = {
    "no_https": 20,
    "ip_in_url": 30,
    "long_domain": 10,
    "long_url": 10,
    "many_subdomains": 15,
    "at_symbol": 25,
    "double_slash_redirect": 20,
    "hyphen_in_domain": 10,
    "too_many_digits": 15,
    "suspicious_tld": 25,
    "phishing_keyword": 15,
    # İtibar (reputation) sinyalleri — WHOIS / domain yaşı
    "very_new_domain": 25,
    "whois_unavailable": 5,
    # HTML içerik sinyalleri (requests + BeautifulSoup)
    "password_field": 20,
    "external_form_action": 25,
    "iframe_present": 10,
    "content_fetch_failed": 5,
}

# Domain bu günden daha yeni ise (gün cinsinden) "çok yeni" sayılır.
NEW_DOMAIN_DAYS: Final[int] = 30

# HTML içerik analizini aç/kapa (testlerde kapatmak kolay olsun).
ENABLE_CONTENT_ANALYSIS: Final[bool] = True

# Sayfa indirme zaman aşımı (saniye).
CONTENT_FETCH_TIMEOUT: Final[int] = 5

# İndirilecek HTML üst boyutu (bayt) — bellek koruması.
CONTENT_MAX_BYTES: Final[int] = 500_000

# ---------------------------------------------------------------------------
# Eşik değerler (threshold)
# Analiz kurallarının "şüpheli" sayılması için sınırlar.
# ---------------------------------------------------------------------------

# Domain adı bu karakter sayısını aşarsa risk puanı eklenir.
MAX_DOMAIN_LENGTH: Final[int] = 25

# Tüm URL bu uzunluğu aşarsa risk puanı eklenir.
MAX_URL_LENGTH: Final[int] = 75

# Alt domain (subdomain) sayısı bu değeri aşarsa risk puanı eklenir.
# Örnek: a.b.evil.com -> "a" ve "b" iki alt domaindir.
MAX_SUBDOMAIN_COUNT: Final[int] = 2

# URL içinde bu kadar veya daha fazla rakam varsa şüpheli kabul edilir.
MAX_DIGIT_COUNT: Final[int] = 5

# ---------------------------------------------------------------------------
# Şüpheli üst seviye alan adları (TLD)
# Phishing kampanyalarında sık görülen ucuz / kötüye kullanılan uzantılar.
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: Final[frozenset[str]] = frozenset(
    {
        "xyz",
        "top",
        "click",
        "ru",
        "tk",
        "gq",
        "ml",
        "cf",
    }
)

# ---------------------------------------------------------------------------
# Phishing'te sık geçen anahtar kelimeler
# URL yolunda veya host kısmında geçerse risk artar.
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "bank",
        "paypal",
        "crypto",
    }
)

# ---------------------------------------------------------------------------
# Risk seviyesi aralıkları (toplam skor)
# 0-20 Güvenli | 21-50 Dikkat | 51-100+ Yüksek Risk
# ---------------------------------------------------------------------------

RISK_LEVELS: Final[dict[str, tuple[int, int]]] = {
    "SAFE": (0, 20),
    "SUSPICIOUS": (21, 50),
    "HIGH_RISK": (51, 100),
}

# Skor 100'ü aşarsa gösterimde 100 ile sınırlamak için kullanılır.
MAX_RISK_SCORE: Final[int] = 100

# ---------------------------------------------------------------------------
# Rapor ve log ayarları
# ---------------------------------------------------------------------------

# JSON raporların kaydedileceği klasör (proje köküne göre).
REPORTS_DIR: Final[str] = "reports"

# Log dosyası yolu.
LOG_FILE: Final[str] = "phishing_detector.log"


def get_risk_level(score: int) -> str:
    """Toplam risk skoruna göre seviye etiketini döndür.

    Args:
        score: 0 veya üzeri toplam risk puanı.

    Returns:
        "SAFE", "SUSPICIOUS" veya "HIGH_RISK" etiketlerinden biri.
    """
    clamped = max(0, min(score, MAX_RISK_SCORE))

    if clamped <= RISK_LEVELS["SAFE"][1]:
        return "SAFE"
    if clamped <= RISK_LEVELS["SUSPICIOUS"][1]:
        return "SUSPICIOUS"
    return "HIGH_RISK"
