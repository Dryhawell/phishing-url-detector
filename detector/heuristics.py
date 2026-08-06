"""Sezgisel (heuristic) phishing kuralları.

Her kural:
1) helpers ile bir sinyal ölçer,
2) config'teki puanı ekler,
3) kullanıcıya gösterilecek bir neden üretir.

Bu modül "ne kadar riskli?" sorusuna kural kural cevap verir.
Toplama / orkestrasyon bir sonraki adımda analyzer.py'de olacak.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config import (
    MAX_DIGIT_COUNT,
    MAX_DOMAIN_LENGTH,
    MAX_SUBDOMAIN_COUNT,
    MAX_URL_LENGTH,
    PHISHING_KEYWORDS,
    RISK_SCORES,
    SUSPICIOUS_TLDS,
)
from utils.helpers import (
    contains_at_symbol,
    count_digits,
    count_subdomains,
    domain_has_hyphen,
    extract_host,
    find_phishing_keywords,
    get_domain_parts,
    get_tld,
    has_double_slash_redirect,
    has_https,
    is_ip_address,
)


@dataclass
class HeuristicFinding:
    """Tek bir kuralın sonucu.

    Attributes:
        rule_id: config.RISK_SCORES içindeki anahtar (örn. "no_https").
        score: Bu bulgunun eklediği risk puanı.
        message: Kullanıcıya gösterilecek kısa açıklama.
    """

    rule_id: str
    score: int
    message: str


@dataclass
class HeuristicResult:
    """Tüm heuristic kontrollerinin özeti.

    Attributes:
        findings: Tetiklenen kuralların listesi.
        total_score: Bulguların puan toplamı (henüz clamp edilmemiş olabilir).
    """

    findings: list[HeuristicFinding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        """Tüm bulguların puan toplamını döndür."""
        return sum(item.score for item in self.findings)

    @property
    def messages(self) -> list[str]:
        """Sadece kullanıcıya gösterilecek mesaj listesi."""
        return [item.message for item in self.findings]


def _add_finding(
    result: HeuristicResult,
    rule_id: str,
    message: str,
    score_override: int | None = None,
) -> None:
    """Sonuca yeni bir bulgu ekle.

    Args:
        result: Doldurulan sonuç nesnesi.
        rule_id: RISK_SCORES anahtarı.
        message: Kullanıcı mesajı.
        score_override: Anahtar kelime gibi birden fazla eşleşmede özel puan.
    """
    score = score_override if score_override is not None else RISK_SCORES[rule_id]
    result.findings.append(
        HeuristicFinding(rule_id=rule_id, score=score, message=message)
    )


def check_https(url: str, result: HeuristicResult) -> None:
    """HTTPS kullanılmıyorsa risk ekle."""
    if not has_https(url):
        _add_finding(result, "no_https", "HTTPS kullanılmıyor")


def check_ip_usage(url: str, result: HeuristicResult) -> None:
    """Host bir IP adresi ise risk ekle."""
    host = extract_host(url)
    if is_ip_address(host):
        _add_finding(result, "ip_in_url", f"IP adresi kullanılmış ({host})")


def check_domain_length(url: str, result: HeuristicResult) -> None:
    """Domain adı aşırı uzunsa risk ekle."""
    domain = get_domain_parts(url)["domain"]
    if domain and len(domain) > MAX_DOMAIN_LENGTH:
        _add_finding(
            result,
            "long_domain",
            f"Domain çok uzun ({len(domain)} karakter)",
        )


def check_url_length(url: str, result: HeuristicResult) -> None:
    """Tüm URL aşırı uzunsa risk ekle."""
    if len(url) > MAX_URL_LENGTH:
        _add_finding(
            result,
            "long_url",
            f"URL çok uzun ({len(url)} karakter)",
        )


def check_subdomain_count(url: str, result: HeuristicResult) -> None:
    """Alt domain sayısı eşikleri aşıyorsa risk ekle."""
    count = count_subdomains(url)
    if count > MAX_SUBDOMAIN_COUNT:
        _add_finding(
            result,
            "many_subdomains",
            f"Çok fazla alt domain ({count} adet)",
        )


def check_at_symbol(url: str, result: HeuristicResult) -> None:
    """URL içinde @ karakteri varsa risk ekle."""
    if contains_at_symbol(url):
        _add_finding(result, "at_symbol", "URL içerisinde @ karakteri var")


def check_double_slash(url: str, result: HeuristicResult) -> None:
    """Path içinde // yönlendirme/obfuscation varsa risk ekle."""
    if has_double_slash_redirect(url):
        _add_finding(
            result,
            "double_slash_redirect",
            "URL içerisinde // yönlendirmesi var",
        )


def check_hyphen_in_domain(url: str, result: HeuristicResult) -> None:
    """Domain adında tire varsa risk ekle."""
    if domain_has_hyphen(url):
        _add_finding(result, "hyphen_in_domain", "Domain içinde '-' kullanımı var")


def check_digit_density(url: str, result: HeuristicResult) -> None:
    """URL'de aşırı rakam varsa risk ekle."""
    digits = count_digits(url)
    if digits >= MAX_DIGIT_COUNT:
        _add_finding(
            result,
            "too_many_digits",
            f"URL içinde çok fazla rakam var ({digits} adet)",
        )


def check_suspicious_tld(url: str, result: HeuristicResult) -> None:
    """Şüpheli TLD kullanılıyorsa risk ekle."""
    tld = get_tld(url)
    # co.uk gibi çok parçalı suffix'lerde son parçayı da kontrol et.
    candidates = {tld}
    if "." in tld:
        candidates.add(tld.split(".")[-1])

    matched = candidates & SUSPICIOUS_TLDS
    if matched:
        label = sorted(matched)[0]
        _add_finding(result, "suspicious_tld", f"Şüpheli uzantı (.{label})")


def check_phishing_keywords(url: str, result: HeuristicResult) -> None:
    """Phishing anahtar kelimelerini tara; her kelime için puan ekle."""
    found = find_phishing_keywords(url, PHISHING_KEYWORDS)
    per_keyword = RISK_SCORES["phishing_keyword"]
    for word in found:
        _add_finding(
            result,
            "phishing_keyword",
            f"Şüpheli kelime bulundu: '{word}'",
            score_override=per_keyword,
        )


def run_heuristics(url: str) -> HeuristicResult:
    """Tüm sezgisel kuralları sırayla çalıştır.

    Args:
        url: Normalize edilmiş, geçerli kabul edilen URL.

    Returns:
        Tetiklenen bulguları ve toplam puanı içeren HeuristicResult.
    """
    result = HeuristicResult()

    check_https(url, result)
    check_ip_usage(url, result)
    check_domain_length(url, result)
    check_url_length(url, result)
    check_subdomain_count(url, result)
    check_at_symbol(url, result)
    check_double_slash(url, result)
    check_hyphen_in_domain(url, result)
    check_digit_density(url, result)
    check_suspicious_tld(url, result)
    check_phishing_keywords(url, result)

    return result
