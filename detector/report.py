"""Analiz sonuçlarını rapor olarak kaydetme.

JSON ve PDF çıktıları aynı ReportWriter arayüzünü kullanır.
Yeni format eklemek = yeni bir writer sınıfı yazmak (Open/Closed).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fpdf import FPDF

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


def default_report_path(
    result: AnalysisResult,
    reports_dir: str | Path = REPORTS_DIR,
    extension: str = ".json",
) -> Path:
    """Zaman damgalı varsayılan rapor dosya yolu üret.

    Args:
        result: Analiz sonucu (dosya adında risk seviyesi kullanılır).
        reports_dir: Rapor klasörü.
        extension: Dosya uzantısı (ör. .json, .pdf).

    Returns:
        Örn. reports/report_20260806_185700_high_risk.pdf
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    level = result.risk_level.lower()
    suffix = extension if extension.startswith(".") else f".{extension}"
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"report_{stamp}_{level}{suffix}"


def resolve_unicode_font() -> Path:
    """Türkçe karakter destekleyen bir sistem fontu bul.

    fpdf2 çekirdek fontları Latin-1 ile sınırlıdır; Unicode için TTF gerekir.
    """
    candidates = [
        Path(r"C:\Windows\Fonts\segoeui.ttf"),
        Path(r"C:\Windows\Fonts\arial.ttf"),
        Path(r"C:\Windows\Fonts\calibri.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Unicode TTF font bulunamadı. Sisteme Arial/Segoe UI/DejaVu kurun."
    )


class ReportWriter(ABC):
    """Rapor yazıcıları için ortak arayüz."""

    @abstractmethod
    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """Raporu diske yaz ve oluşan dosya yolunu döndür."""


class JsonReportWriter(ReportWriter):
    """Analiz sonucunu JSON dosyası olarak kaydeder."""

    def __init__(self, reports_dir: str | Path = REPORTS_DIR, indent: int = 2) -> None:
        self.reports_dir = Path(reports_dir)
        self.indent = indent

    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """JSON raporu yaz."""
        path = output_path or default_report_path(result, self.reports_dir, ".json")
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = build_report_payload(result)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=self.indent),
            encoding="utf-8",
        )

        logger.info("JSON rapor kaydedildi: %s", path.resolve())
        return path


class PdfReportWriter(ReportWriter):
    """Analiz sonucunu PDF dosyası olarak kaydeder."""

    def __init__(self, reports_dir: str | Path = REPORTS_DIR) -> None:
        self.reports_dir = Path(reports_dir)

    def write(self, result: AnalysisResult, output_path: Path | None = None) -> Path:
        """PDF raporu yaz.

        Args:
            result: Analiz sonucu.
            output_path: Verilmezse zaman damgalı varsayılan yol kullanılır.

        Returns:
            Yazılan PDF dosyasının Path değeri.
        """
        path = output_path or default_report_path(result, self.reports_dir, ".pdf")
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = build_report_payload(result)
        font_path = resolve_unicode_font()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.add_font("ReportFont", style="", fname=str(font_path))
        # Kalın için aynı regular fontu kullan (her sistemde bold TTF olmayabilir).
        pdf.add_font("ReportFont", style="B", fname=str(font_path))

        pdf.set_font("ReportFont", style="B", size=16)
        pdf.cell(0, 10, "Phishing URL Detector - Analiz Raporu", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("ReportFont", size=11)
        pdf.ln(4)
        pdf.multi_cell(0, 7, f"Olusturma (UTC): {payload['generated_at']}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 7, f"URL: {payload['url']}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 7, f"Gecerli URL: {payload['is_valid']}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 7, f"Risk Skoru: {payload['risk_score']}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 7, f"Durum: {payload['risk_level']}", new_x="LMARGIN", new_y="NEXT")
        if payload.get("error"):
            pdf.multi_cell(0, 7, f"Hata: {payload['error']}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)
        pdf.set_font("ReportFont", style="B", size=13)
        pdf.cell(0, 8, "Bulunan Problemler", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("ReportFont", size=11)
        problems = payload["problems"] or ["Belirgin bir problem bulunamadi."]
        for item in problems:
            pdf.multi_cell(0, 6, f"- {item}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(3)
        pdf.set_font("ReportFont", style="B", size=13)
        pdf.cell(0, 8, "Oneriler", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("ReportFont", size=11)
        for tip in payload["recommendations"]:
            pdf.multi_cell(0, 6, f"- {tip}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(3)
        pdf.set_font("ReportFont", style="B", size=13)
        pdf.cell(0, 8, "Detayli Bulgular", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("ReportFont", size=10)
        if not payload["findings"]:
            pdf.multi_cell(0, 6, "- Bulgu yok", new_x="LMARGIN", new_y="NEXT")
        else:
            for finding in payload["findings"]:
                line = (
                    f"- [{finding['rule_id']}] +{finding['score']} :: {finding['message']}"
                )
                pdf.multi_cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")

        pdf.ln(6)
        pdf.set_font("ReportFont", size=9)
        pdf.multi_cell(
            0,
            5,
            "Uyari: Bu rapor sezgisel/yardimci bir analizdir; kesin guvenlik karari degildir.",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        pdf.output(str(path))
        logger.info("PDF rapor kaydedildi: %s", path.resolve())
        return path


def save_json_report(
    result: AnalysisResult,
    output_path: Path | None = None,
    reports_dir: str | Path = REPORTS_DIR,
) -> Path:
    """Kolay kullanım: JSON rapor kaydet."""
    writer = JsonReportWriter(reports_dir=reports_dir)
    return writer.write(result, output_path=output_path)


def save_pdf_report(
    result: AnalysisResult,
    output_path: Path | None = None,
    reports_dir: str | Path = REPORTS_DIR,
) -> Path:
    """Kolay kullanım: PDF rapor kaydet."""
    writer = PdfReportWriter(reports_dir=reports_dir)
    return writer.write(result, output_path=output_path)
