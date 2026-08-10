"""Yerel HTTP API (yalnızca localhost).

Tarayıcı eklentisi veya diğer istemciler, tam Python analiz motorunu
http://127.0.0.1:8765 üzerinden çağırabilir.

Güvenlik: sunucu varsayılan olarak yalnızca 127.0.0.1'e bağlanır.
"""

from __future__ import annotations

from flask import Flask, jsonify, request
from flask_cors import CORS

from detector.analyzer import analyze_url
from utils.logger import get_logger, setup_logger

logger = get_logger()

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def create_app() -> Flask:
    """Flask uygulamasını oluştur."""
    app = Flask(__name__)
    # Eklenti (chrome-extension://...) localhost'a istek atabilsin.
    CORS(app, resources={r"/*": {"origins": "*"}})

    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        """Servisin ayakta olduğunu doğrula."""
        return {"status": "ok", "service": "phishing-url-detector"}, 200

    @app.post("/analyze")
    def analyze() -> tuple[dict, int]:
        """JSON gövde: {"url": "https://..." } — tam analiz sonucunu döndür."""
        payload = request.get_json(silent=True) or {}
        raw_url = str(payload.get("url", "")).strip()
        if not raw_url:
            return {"error": "url alanı zorunludur"}, 400

        logger.info("API analiz isteği: %s", raw_url)
        result = analyze_url(raw_url)
        body = {
            "url": result.url,
            "is_valid": result.is_valid,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "problems": result.problems,
            "recommendations": result.recommendations,
            "error": result.error,
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "score": item.score,
                    "message": item.message,
                }
                for item in result.findings
            ],
        }
        return body, 200

    return app


def run_api_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Yerel API sunucusunu başlat (blocking)."""
    setup_logger()
    app = create_app()
    logger.info("Yerel API dinleniyor: http://%s:%s", host, port)
    # threaded=True: eklentiden gelen paralel istekler UI'yi kilitlemesin.
    app.run(host=host, port=port, debug=False, threaded=True)
