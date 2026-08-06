"""Analiz sonuçlarını rapor olarak kaydetme.

İlk sürüm: JSON çıktı.
İleride PDF eklenecek şekilde soyut bir arayüz (ReportWriter) kullanıyoruz.
Yeni format eklemek = yeni bir writer sınıfı yazmak (Open/Closed).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import REPORTS_DIR
from detector.analyzer import AnalysisResult
from utils.logger import get_logger

logger = get_logger()


def build_report_payload(result: AnalysisResult) -> dict[str, Any]:
    """AnalysisResult'ı serileştirilebilir bir sözlüğe çevir.

    Args:
        result: Analiz sonucu.

    Returns:
        JSON/PDF gibi formatlara ortak kaynak olacak rapor verisi.
    """
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "url": result.url,
        "is_valid": result.is_valid,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "problems": result.problems,
        "recommendations": result.recommendations,
        "error": result.error,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "score": finding.score,
                "message": finding.message,
            }
            for finding in result.findings
        ],
    }


def default_report_path(result: AnalysisResult, reports_dir: str | Path = REPORTS_DIR) -> Path:
    """Zaman damgalı varsayılan rapor dosya yolu üret.

    Args:
        result: Analiz sonucu (dosya adında risk seviyesi kullanılır).
        reports_dir: Rapor klasörü.

    Returns:
        Örn. reports/report_20260806_185700_HIGH_RISK.json
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    level = result.risk_level.lower()
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"report_{stamp}_{level}.json"


class ReportWriter(ABC):
    """Rapor yazıcıları için ortak arayüz.

    JSON ve (ileride) PDF aynı sözleşmeyi uygular.
    """

    @abstractmethod
    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """Raporu diske yaz ve oluşan dosya yolunu döndür."""


class JsonReportWriter(ReportWriter):
    """Analiz sonucunu JSON dosyası olarak kaydeder."""

    def __init__(self, reports_dir: str | Path = REPORTS_DIR, indent: int = 2) -> None:
        """Args:
            reports_dir: Kayıt klasörü.
            indent: JSON girinti seviyesi (okunabilirlik için).
        """
        self.reports_dir = Path(reports_dir)
        self.indent = indent

    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """JSON raporu yaz.

        Args:
            result: Analiz sonucu.
            output_path: Verilmezse zaman damgalı varsayılan yol kullanılır.

        Returns:
            Yazılan dosyanın Path değeri.
        """
        path = output_path or default_report_path(result, self.reports_dir)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = build_report_payload(result)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=self.indent),
            encoding="utf-8",
        )

        logger.info("JSON rapor kaydedildi: %s", path.resolve())
        return path


class PdfReportWriter(ReportWriter):
    """PDF rapor yazıcı iskeleti (gelecek sürüm).

    Şimdilik NotImplementedError fırlatır; arayüz hazır olsun diye durur.
    """

    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """PDF çıktısı henüz uygulanmadı."""
        raise NotImplementedError(
            "PDF rapor desteği henüz eklenmedi. JsonReportWriter kullanın."
        )


def save_json_report(
    result: AnalysisResult,
    output_path: Path | None = None,
    reports_dir: str | Path = REPORTS_DIR,
) -> Path:
    """Kolay kullanım için kısayol: JSON rapor kaydet.

    Args:
        result: Analiz sonucu.
        output_path: İsteğe bağlı özel dosya yolu.
        reports_dir: Varsayılan rapor klasörü.

    Returns:
        Yazılan JSON dosyasının yolu.
    """
    writer = JsonReportWriter(reports_dir=reports_dir)
    return writer.write(result, output_path=output_path)
