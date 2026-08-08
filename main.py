"""Phishing URL Detector giriş noktası.

Kullanım:
    python main.py
    python main.py --batch samples/urls.txt
    python main.py --batch samples/urls.csv --output reports/my_batch.json
"""

from __future__ import annotations

import argparse
from pathlib import Path

from detector.batch import run_batch_file
from gui.app import run_app
from utils.logger import setup_logger


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argümanlarını tanımla."""
    parser = argparse.ArgumentParser(
        description="Phishing URL Detector — GUI veya toplu analiz",
    )
    parser.add_argument(
        "--batch",
        type=Path,
        help="TXT/CSV dosyasından toplu URL analizi çalıştır",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Batch JSON rapor çıktı yolu (opsiyonel)",
    )
    parser.add_argument(
        "--csv-column",
        default="url",
        help="CSV içindeki URL sütun adı (varsayılan: url)",
    )
    return parser


def run_batch_mode(args: argparse.Namespace) -> int:
    """Toplu analiz modunu çalıştır; başarıda 0 döner."""
    setup_logger()
    summary, report_path = run_batch_file(
        input_path=args.batch,
        output_path=args.output,
        csv_column=args.csv_column,
    )
    print("Batch tamamlandı")
    print(f"  Kaynak : {summary.source_file}")
    print(f"  Toplam : {summary.total}")
    print(f"  SAFE   : {summary.safe}")
    print(f"  SUSP   : {summary.suspicious}")
    print(f"  HIGH   : {summary.high_risk}")
    print(f"  INVALID: {summary.invalid}")
    print(f"  Rapor  : {report_path}")
    return 0


def main() -> None:
    """GUI (varsayılan) veya batch modunu başlat."""
    parser = build_parser()
    args = parser.parse_args()

    if args.batch is not None:
        raise SystemExit(run_batch_mode(args))

    run_app()


if __name__ == "__main__":
    main()
