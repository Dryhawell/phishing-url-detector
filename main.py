"""Phishing URL Detector giriş noktası.

Kullanım:
    python main.py
    python main.py --batch samples/urls.txt
    python main.py --api
    python main.py --api --port 8765
"""

from __future__ import annotations

import argparse
from pathlib import Path

from api.server import DEFAULT_HOST, DEFAULT_PORT, run_api_server
from detector.batch import run_batch_file
from gui.app import run_app
from utils.logger import setup_logger


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argümanlarını tanımla."""
    parser = argparse.ArgumentParser(
        description="Phishing URL Detector — GUI, batch veya yerel API",
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
    parser.add_argument(
        "--api",
        action="store_true",
        help="Yerel REST API sunucusunu başlat (eklenti köprüsü)",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"API host (varsayılan: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"API port (varsayılan: {DEFAULT_PORT})",
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
    """GUI (varsayılan), batch veya API modunu başlat."""
    parser = build_parser()
    args = parser.parse_args()

    if args.batch is not None:
        raise SystemExit(run_batch_mode(args))

    if args.api:
        run_api_server(host=args.host, port=args.port)
        return

    run_app()


if __name__ == "__main__":
    main()
