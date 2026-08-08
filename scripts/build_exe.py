"""Windows için tek dosya .exe derleme yardımcısı.

Kullanım (proje kökünde):
    pip install -r requirements-dev.txt
    python scripts/build_exe.py

Çıktı:
    dist/PhishingURLDetector.exe
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "main.py"
NAME = "PhishingURLDetector"


def main() -> int:
    """PyInstaller ile onefile GUI exeesi üret."""
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0

    if not ENTRY.exists():
        print(f"Giriş noktası bulunamadı: {ENTRY}")
        return 1

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onefile",
        f"--name={NAME}",
        "--paths",
        str(ROOT),
        # WHOIS / BS4 / fpdf dinamik importları için toplama gevşetilir.
        "--collect-all",
        "tldextract",
        "--collect-all",
        "fpdf",
        str(ENTRY),
    ]
    print("Çalıştırılıyor:", " ".join(cmd))
    completed = subprocess.run(cmd, cwd=ROOT, check=False)
    if completed.returncode != 0:
        return completed.returncode

    exe_path = ROOT / "dist" / f"{NAME}.exe"
    if exe_path.exists():
        print(f"Hazır: {exe_path}")
    else:
        print("Derleme bitti ama exe bulunamadı; dist/ klasörünü kontrol edin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
