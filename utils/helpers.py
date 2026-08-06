"""Genel yardımcı fonksiyonlar.

Bu modül tek bir işi iyi yapan küçük fonksiyonlar içerir.
Analiz kuralları (heuristics) bu yardımcılara dayanır; böylece
aynı mantık birden fazla yerde kopyalanmaz (DRY prensibi).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract
import validators


def normalize_url(url: str) -> str:
    """URL'yi analiz öncesi standart forma getir.

    - Baş/sondaki boşlukları temizler.
    - Şema yoksa varsayılan olarak http:// ekler
      (şemasız girdiler urlparse tarafından yanlış parçalanmasın diye).

    Args:
        url: Kullanıcının girdiği ham URL metni.

    Returns:
        Normalize edilmiş URL string'i.
    """
    cleaned = url.strip()
    if not cleaned:
        return cleaned

    # "example.com" gibi şemasız girdilerde netloc boş kalabilir.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"http://{cleaned}"

    return cleaned


def is_valid_url(url: str) -> bool:
    """URL formatının geçerli olup olmadığını kontrol et.

    Args:
        url: Kontrol edilecek URL (normalize edilmiş olması önerilir).

    Returns:
        Geçerliyse True, aksi halde False.
    """
    result = validators.url(url)
    # validators.url başarıda True, hatada ValidationError benzeri değer dönebilir.
    return result is True


def has_https(url: str) -> bool:
    """URL'nin HTTPS kullanıp kullanmadığını kontrol et.

    Args:
        url: Kontrol edilecek URL.

    Returns:
        Şema https ise True.
    """
    parsed = urlparse(url)
    return parsed.scheme.lower() == "https"


def extract_host(url: str) -> str:
    """URL'den host (alan adı veya IP) kısmını çıkar.

    Args:
        url: Kaynak URL.

    Returns:
        Host string'i; yoksa boş string.
    """
    parsed = urlparse(url)
    return parsed.hostname or ""


def is_ip_address(host: str) -> bool:
    """Host değerinin IPv4 veya IPv6 adresi olup olmadığını kontrol et.

    Phishing'te bazen domain yerine düz IP kullanılır
    (ör. http://192.168.1.1/login). Bu güçlü bir risk sinyalidir.

    Args:
        host: urlparse ile alınan hostname.

    Returns:
        Geçerli bir IP adresi ise True.
    """
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_domain_parts(url: str) -> dict[str, str]:
    """URL'den subdomain, domain ve suffix (TLD) parçalarını ayıkla.

    Örnek: https://login.mail.example.co.uk/path
      subdomain -> "login.mail"
      domain    -> "example"
      suffix    -> "co.uk"

    Args:
        url: Kaynak URL.

    Returns:
        subdomain, domain, suffix ve registered_domain anahtarlı sözlük.
    """
    extracted = tldextract.extract(url)
    return {
        "subdomain": extracted.subdomain or "",
        "domain": extracted.domain or "",
        "suffix": extracted.suffix or "",
        "registered_domain": extracted.registered_domain or "",
    }


def count_subdomains(url: str) -> int:
    """Alt domain sayısını döndür.

    "www" tek başına sık görülen zararsız bir alt domaindir;
    sayımda yine de yer alır. Eşik config'te ayarlanır.

    Args:
        url: Kaynak URL.

    Returns:
        Nokta ile ayrılmış subdomain parçası sayısı.
    """
    subdomain = get_domain_parts(url)["subdomain"]
    if not subdomain:
        return 0
    return len([part for part in subdomain.split(".") if part])


def count_digits(text: str) -> int:
    """Metin içindeki rakam adedini say.

    Args:
        text: İncelenecek string (genelde tüm URL).

    Returns:
        Rakam karakteri sayısı.
    """
    return sum(1 for char in text if char.isdigit())


def contains_at_symbol(url: str) -> bool:
    """URL içinde '@' karakteri var mı?

    Tarayıcılar userinfo@host sözdizimini destekler.
    Saldırganlar 'https://guvenli.com@evil.com' ile aldatabilir.

    Args:
        url: Kaynak URL.

    Returns:
        '@' varsa True.
    """
    # Şema sonrası kısımda ara; 'https://' içindeki karakterler zaten '@' içermez.
    parsed = urlparse(url)
    remainder = f"{parsed.netloc}{parsed.path}{parsed.params}{parsed.query}"
    return "@" in remainder


def has_double_slash_redirect(url: str) -> bool:
    """Path içinde '//' ile olası yönlendirme/obfuscation var mı?

    Örnek: http://evil.com//secure.bank.com
    Kullanıcı ikinci kısmı gerçek host sanabilir.

    Args:
        url: Kaynak URL.

    Returns:
        Path'te '//' geçiyorsa True.
    """
    parsed = urlparse(url)
    # Path başındaki tek '/' normaldir; '//' şüpheli.
    path = parsed.path or ""
    return "//" in path


def domain_has_hyphen(url: str) -> bool:
    """Kayıtlı domain adında '-' karakteri var mı?

    Tek başına zayıf bir sinyaldir; diğer kurallarla birlikte puanlanır.
    Örnek: pay-pal-secure.com

    Args:
        url: Kaynak URL.

    Returns:
        Domain içinde '-' varsa True.
    """
    domain = get_domain_parts(url)["domain"]
    return "-" in domain


def find_phishing_keywords(url: str, keywords: frozenset[str]) -> list[str]:
    """URL içinde geçen phishing anahtar kelimelerini bul.

    Args:
        url: Kaynak URL.
        keywords: Aranacak kelime kümesi (config'ten gelir).

    Returns:
        Bulunan kelimelerin listesi (alfabetik, tekrarsız).
    """
    lowered = url.lower()
    found = [word for word in keywords if word in lowered]
    return sorted(found)


def get_tld(url: str) -> str:
    """URL'nin TLD / suffix değerini küçük harfle döndür.

    Args:
        url: Kaynak URL.

    Returns:
        Örn. "com", "co.uk", "xyz" veya boş string.
    """
    return get_domain_parts(url)["suffix"].lower()
