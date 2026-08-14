# Phishing URL Detector (Türkçe)

[![CI](https://github.com/Dryhawell/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/Dryhawell/phishing-url-detector/actions/workflows/ci.yml)

[English README](README.md)

Python ile yazılmış, katmanlı bir **phishing URL analiz aracıdır**.  
URL sezgisel kuralları, WHOIS domain yaşı, HTML içerik sinyalleri ve isteğe bağlı çevrimiçi blocklist’lerle risk skoru üretir; GUI, batch CLI, yerel API ve tarayıcı eklentisi üzerinden kullanılabilir.

**Sürüm:** `1.4.3` · [Release](https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.3) · [Demo metni](docs/DEMO_SCRIPT.md)

---

## Özellikler

- URL doğrulama ve normalize etme
- Sezgisel kontroller (HTTPS, IP host, `@`, `//`, şüpheli TLD, phishing kelimeleri, …)
- WHOIS ile domain yaşı
- HTML analizi (şifre alanı, dış form action, iframe)
- URLhaus + isteğe bağlı Google Safe Browsing
- Risk skoru: `0–20` SAFE · `21–50` SUSPICIOUS · `51–100` HIGH RISK
- Koyu temalı Tkinter GUI (geçmiş paneli, JSON/PDF kayıt)
- TXT/CSV toplu analiz
- Chrome/Edge eklentisi (hızlı + derin analiz)
- Logging, birim testleri, CI, otomatik Release

---

## Kurulum

```bash
git clone https://github.com/Dryhawell/phishing-url-detector.git
cd phishing-url-detector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## Kullanım

### GUI

```bash
python main.py
```

### Toplu analiz

```bash
python main.py --batch samples/urls.txt
python main.py --batch samples/urls.csv --output reports/my_batch.json
```

### Yerel API (eklenti köprüsü)

```bash
python main.py --api
# http://127.0.0.1:8765/health
# POST /analyze  {"url":"https://example.com"}
```

### Tarayıcı eklentisi

1. `chrome://extensions` → Developer mode
2. **Load unpacked** → `browser-extension/`
3. Hızlı analiz varsayılan çalışır
4. Derin analiz için önce `python main.py --api` çalıştırın

Detay: [browser-extension/README.md](browser-extension/README.md)

### Windows demo

```powershell
.\scripts\demo.ps1
```

### Testler

```bash
python -m pytest tests -v
```

---

## Örnek çıktı

```text
Risk Skoru : 82
Durum      : HIGH_RISK

Nedenler
❌ HTTPS kullanılmıyor
❌ Şüpheli uzantı (.xyz)
❌ Şüpheli kelime bulundu: 'login'
```

![GUI önizleme](docs/screenshot.png)

---

## Yapılandırma

Skorlar ve eşikler `config.py` içindedir:

- `RISK_SCORES`
- `SUSPICIOUS_TLDS` / `PHISHING_KEYWORDS`
- `ENABLE_CONTENT_ANALYSIS` / `ENABLE_ONLINE_REPUTATION`

Safe Browsing (opsiyonel):

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="anahtarin"
python main.py
```

---

## Güvenlik notu

Bu araç **savunma / eğitim** içindir. Yetkisiz sistemleri taramak için kullanmayın.  
Yerel API varsayılan olarak yalnızca `127.0.0.1` dinler; internete açmayın.

Daha fazla: [SECURITY.md](SECURITY.md)

---

## Lisans

MIT © Talha Tarlabaz
