"""Toplu (batch) URL analizi.

Tek tek GUI yerine TXT/CSV dosyasından çoklu URL okur,
her birini analyze_url ile tarar ve özet JSON üretir.

Siber güvenlik operasyonlarında IOC listelerini hızlı taramak için kullanılır.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from config import REPORTS_DIR
from detector.analyzer import AnalysisResult, analyze_url
from utils.logger import get_logger

logger = get_logger()

AnalyzeFn = Callable[[str], AnalysisResult]


@dataclass
class BatchItemResult:
    """Tek bir satırın batch sonucu."""

    source_url: str
    url_hash: str
    is_valid: bool
    risk_score: int
    risk_level: str
    problems: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class BatchSummary:
    """Tüm batch çalışmasının özeti."""

    generated_at: str
    source_file: str
    total: int
    safe: int
    suspicious: int
    high_risk: int
    invalid: int
    items: list[BatchItemResult] = field(default_factory=list)


def url_fingerprint(url: str) -> str:
    """URL için kısa, kararlı bir parmak izi (SHA-256).

    Raporlarda satır kimliği olarak kullanılır; hassas URL'nin tamamını
    her yere kopyalamadan referans vermeyi kolaylaştırır.
    """
    digest = hashlib.sha256(url.strip().encode("utf-8")).hexdigest()
    return digest[:16]


def load_urls_from_txt(path: Path) -> list[str]:
    """TXT dosyasından URL listesi oku (satır başına bir URL, # yorum)."""
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        urls.append(cleaned)
    return urls


def load_urls_from_csv(path: Path, column: str = "url") -> list[str]:
    """CSV dosyasından URL sütununu oku.

    Args:
        path: CSV yolu.
        column: URL içeren sütun adı (yoksa ilk sütun kullanılır).
    """
    urls: list[str] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return urls

        fieldnames = [name.strip() for name in reader.fieldnames]
        chosen = column if column in fieldnames else fieldnames[0]

        for row in reader:
            value = (row.get(chosen) or "").strip()
            if value and not value.startswith("#"):
                urls.append(value)
    return urls


def load_urls(path: Path, csv_column: str = "url") -> list[str]:
    """Dosya uzantısına göre URL listesini yükle."""
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_urls_from_csv(path, column=csv_column)
    if suffix in {".txt", ".list"}:
        return load_urls_from_txt(path)
    raise ValueError(f"Desteklenmeyen dosya türü: {suffix} (txt/csv kullanın)")


def _dedupe_preserve_order(urls: Iterable[str]) -> list[str]:
    """Sırayı bozmadan tekrarları çıkar."""
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        key = url.strip()
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def analyze_batch(
    urls: list[str],
    analyze_fn: AnalyzeFn = analyze_url,
) -> list[BatchItemResult]:
    """URL listesini sırayla analiz et.

    Args:
        urls: Ham URL listesi.
        analyze_fn: Testlerde mock'lanabilir analiz fonksiyonu.

    Returns:
        Her URL için BatchItemResult listesi.
    """
    items: list[BatchItemResult] = []
    for index, raw in enumerate(urls, start=1):
        logger.info("Batch [%s/%s] analiz: %s", index, len(urls), raw)
        result = analyze_fn(raw)
        items.append(
            BatchItemResult(
                source_url=raw,
                url_hash=url_fingerprint(raw),
                is_valid=result.is_valid,
                risk_score=result.risk_score,
                risk_level=result.risk_level if result.is_valid else "INVALID",
                problems=list(result.problems),
                error=result.error,
            )
        )
    return items


def build_batch_summary(source_file: str, items: list[BatchItemResult]) -> BatchSummary:
    """Satır sonuçlarından özet istatistik üret."""
    safe = sum(1 for item in items if item.risk_level == "SAFE")
    suspicious = sum(1 for item in items if item.risk_level == "SUSPICIOUS")
    high_risk = sum(1 for item in items if item.risk_level == "HIGH_RISK")
    invalid = sum(1 for item in items if item.risk_level == "INVALID" or not item.is_valid)

    return BatchSummary(
        generated_at=datetime.now(timezone.utc).isoformat(),
        source_file=source_file,
        total=len(items),
        safe=safe,
        suspicious=suspicious,
        high_risk=high_risk,
        invalid=invalid,
        items=items,
    )


def save_batch_summary(
    summary: BatchSummary,
    output_path: Path | None = None,
    reports_dir: str | Path = REPORTS_DIR,
) -> Path:
    """Batch özetini JSON olarak kaydet."""
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_path or directory / f"batch_report_{stamp}.json"

    payload = {
        "generated_at": summary.generated_at,
        "source_file": summary.source_file,
        "total": summary.total,
        "safe": summary.safe,
        "suspicious": summary.suspicious,
        "high_risk": summary.high_risk,
        "invalid": summary.invalid,
        "items": [
            {
                "source_url": item.source_url,
                "url_hash": item.url_hash,
                "is_valid": item.is_valid,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "problems": item.problems,
                "error": item.error,
            }
            for item in summary.items
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Batch raporu kaydedildi: %s", path.resolve())
    return path


def run_batch_file(
    input_path: Path,
    output_path: Path | None = None,
    csv_column: str = "url",
    analyze_fn: AnalyzeFn = analyze_url,
) -> tuple[BatchSummary, Path]:
    """Dosyadan URL okuyup batch analizi çalıştır ve kaydet.

    Returns:
        (özet, rapor_dosya_yolu)
    """
    if not input_path.exists():
        raise FileNotFoundError(f"Girdi dosyası yok: {input_path}")

    urls = _dedupe_preserve_order(load_urls(input_path, csv_column=csv_column))
    if not urls:
        raise ValueError("Dosyada analiz edilecek URL bulunamadı.")

    logger.info("Batch başlıyor | file=%s | urls=%s", input_path, len(urls))
    items = analyze_batch(urls, analyze_fn=analyze_fn)
    summary = build_batch_summary(str(input_path), items)
    report_path = save_batch_summary(summary, output_path=output_path)
    return summary, report_path
