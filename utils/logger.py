"""Merkezi logging yapılandırması.

Neden ayrı bir logger modülü?
- print() yerine logging kullanmak profesyonel standarttır.
- Seviye (DEBUG/INFO/WARNING/ERROR) ile çıktıyı kontrol ederiz.
- Hem dosyaya hem konsola yazarak hata ayıklamayı kolaylaştırırız.
- Analiz motoru, GUI ve rapor modülleri aynı logger'ı paylaşır.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from config import LOG_FILE

# Proje genelinde kullanılacak logger adı.
# getLogger aynı isimle çağrılırsa aynı logger örneği döner (singleton benzeri).
LOGGER_NAME: str = "phishing_detector"


def setup_logger(
    name: str = LOGGER_NAME,
    log_file: str = LOG_FILE,
    level: int = logging.INFO,
) -> logging.Logger:
    """Uygulama logger'ını yapılandır ve döndür.

    Args:
        name: Logger adı. Modüller arası tutarlılık için sabittir.
        log_file: Logların yazılacağı dosya yolu.
        level: Minimum log seviyesi (INFO = INFO ve üzeri kaydedilir).

    Returns:
        Yapılandırılmış logging.Logger örneği.
    """
    logger = logging.getLogger(name)

    # Logger bir kez kurulmalı. Handler varsa tekrar ekleme (çift log önlenir).
    if logger.handlers:
        return logger

    logger.setLevel(level)
    # Kök logger'a iletmesin; sadece bizim handler'larımız yazsın.
    logger.propagate = False

    # Ortak format: zaman | seviye | modül | mesaj
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # --- Dosya handler: kalıcı kayıt ---
    log_path = Path(log_file)
    # Klasör yoksa oluştur (ileride logs/ altına taşınabilir).
    if log_path.parent != Path("."):
        log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # --- Konsol handler: anlık geri bildirim ---
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.info("Logger başlatıldı. Log dosyası: %s", log_path.resolve())
    return logger


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    """Mevcut logger'ı al; yoksa varsayılan ayarla kur.

    Args:
        name: İstenen logger adı.

    Returns:
        Hazır logging.Logger örneği.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name=name)
    return logger
