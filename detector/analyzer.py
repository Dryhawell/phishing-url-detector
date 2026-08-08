"""URL analiz orkestratörü.

Bu modül tek giriş noktasıdır:
1) URL'yi normalize eder ve doğrular
2) Heuristic kuralları çalıştırır
3) Risk skorunu sınırlar ve seviye atar
4) Kullanıcıya öneriler üretir
5) Sonucu loglar

GUI ve CLI ileride sadece bu modülü çağırır (Single Responsibility).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config import MAX_RISK_SCORE, get_risk_level
from detector.content import run_content_checks
from detector.heuristics import HeuristicFinding, run_heuristics
from detector.reputation import run_reputation_checks
from utils.helpers import is_valid_url, normalize_url
from utils.logger import get_logger

logger = get_logger()


@dataclass
class AnalysisResult:
    """Tek bir URL analizinin kullanıcıya sunulacak özeti.

    Attributes:
        url: Normalize edilmiş URL.
        is_valid: URL formatı geçerli mi?
        risk_score: 0-100 arası risk puanı.
        risk_level: SAFE / SUSPICIOUS / HIGH_RISK.
        findings: Tetiklenen heuristic bulgular.
        recommendations: Kullanıcıya öneriler.
        error: Doğrulama hatası varsa mesajı.
    """

    url: str
    is_valid: bool
    risk_score: int = 0
    risk_level: str = "SAFE"
    findings: list[HeuristicFinding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def problems(self) -> list[str]:
        """Bulgu mesajlarını düz liste olarak döndür."""
        return [finding.message for finding in self.findings]


def _clamp_score(score: int) -> int:
    """Skoru 0 .. MAX_RISK_SCORE aralığına sıkıştır."""
    return max(0, min(score, MAX_RISK_SCORE))


def _build_recommendations(result: AnalysisResult) -> list[str]:
    """Bulgulara göre pratik öneriler üret.

    Args:
        result: Kısmen doldurulmuş analiz sonucu.

    Returns:
        Kullanıcıya gösterilecek öneri listesi.
    """
    tips: list[str] = []
    rule_ids = {finding.rule_id for finding in result.findings}

    if "no_https" in rule_ids:
        tips.append("Mümkünse yalnızca HTTPS kullanan sitelere giriş yapın.")
    if "ip_in_url" in rule_ids:
        tips.append("Adres çubuğunda düz IP görürseniz siteye güvenmeyin.")
    if "at_symbol" in rule_ids or "double_slash_redirect" in rule_ids:
        tips.append("URL içinde @ veya // gibi yanıltıcı kalıplara dikkat edin.")
    if "suspicious_tld" in rule_ids:
        tips.append("Şüpheli uzantılarda (ör. .xyz, .tk) işlem yapmadan önce doğrulayın.")
    if "phishing_keyword" in rule_ids:
        tips.append(
            "login/verify/bank gibi kelimeler içeren linkleri resmi kanaldan teyit edin."
        )
    if "very_new_domain" in rule_ids:
        tips.append(
            "Yeni kayıtlı domainlerde dolandırıcılık riski daha yüksektir; resmi adresi doğrulayın."
        )
    if "whois_unavailable" in rule_ids:
        tips.append(
            "Domain kayıt bilgisi doğrulanamadı; bağlantıya ek ihtiyatla yaklaşın."
        )
    if "password_field" in rule_ids:
        tips.append(
            "Şifre isteyen sayfalarda adres çubuğundaki domain'i resmi siteyle karşılaştırın."
        )
    if "external_form_action" in rule_ids:
        tips.append(
            "Form başka bir domain'e veri gönderiyor olabilir; bu klasik bir phishing işaretidir."
        )
    if "iframe_present" in rule_ids:
        tips.append(
            "iframe ile gömülü içerik manipülasyonu olabilir; kaynağı doğrulamadan giriş yapmayın."
        )
    if result.risk_level == "HIGH_RISK":
        tips.append("Bu bağlantıya tıklamayın; şifre veya kart bilgisi girmeyin.")
    elif result.risk_level == "SUSPICIOUS":
        tips.append("Dikkatli olun; siteyi resmi uygulamadan veya yer iminden açın.")
    elif result.is_valid and not result.findings:
        tips.append("Belirgin bir heuristic risk yok; yine de kaynak güvenilirliğini kontrol edin.")

    # Öneri yoksa genel güvenlik notu ekle.
    if not tips:
        tips.append("Bağlantının geldiği kaynağı (e-posta, SMS, DM) doğrulamadan ilerlemeyin.")

    return tips


def analyze_url(raw_url: str) -> AnalysisResult:
    """Ham URL'yi analiz et ve sonuç nesnesi döndür.

    Args:
        raw_url: Kullanıcının girdiği URL metni.

    Returns:
        AnalysisResult: skor, seviye, problemler ve öneriler.
    """
    logger.info("Analiz başlatıldı: %s", raw_url)

    normalized = normalize_url(raw_url)
    if not normalized:
        logger.warning("Boş URL girildi")
        return AnalysisResult(
            url="",
            is_valid=False,
            risk_level="SAFE",
            error="URL boş olamaz.",
            recommendations=["Geçerli bir URL girin (ör. https://example.com)."],
        )

    if not is_valid_url(normalized):
        logger.warning("Geçersiz URL formatı: %s", normalized)
        return AnalysisResult(
            url=normalized,
            is_valid=False,
            risk_level="SAFE",
            error="URL formatı geçersiz.",
            recommendations=["URL'yi kontrol edin; https:// ile başlaması önerilir."],
        )

    heuristic_result = run_heuristics(normalized)
    reputation_result = run_reputation_checks(normalized)
    content_result = run_content_checks(normalized)

    # Tüm katman bulgularını tek listeye birleştir (GUI tek panel görür).
    merged_findings = list(heuristic_result.findings)
    for item in reputation_result.findings:
        merged_findings.append(
            HeuristicFinding(
                rule_id=item.rule_id,
                score=item.score,
                message=item.message,
            )
        )
    for item in content_result.findings:
        merged_findings.append(
            HeuristicFinding(
                rule_id=item.rule_id,
                score=item.score,
                message=item.message,
            )
        )

    raw_score = (
        heuristic_result.total_score
        + reputation_result.total_score
        + content_result.total_score
    )
    score = _clamp_score(raw_score)
    level = get_risk_level(score)

    result = AnalysisResult(
        url=normalized,
        is_valid=True,
        risk_score=score,
        risk_level=level,
        findings=merged_findings,
    )
    result.recommendations = _build_recommendations(result)

    logger.info(
        "Analiz tamamlandı | url=%s | score=%s | level=%s | findings=%s",
        result.url,
        result.risk_score,
        result.risk_level,
        len(result.findings),
    )
    return result
