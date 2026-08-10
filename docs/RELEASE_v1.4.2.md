# Release v1.4.2

Published tag: `v1.4.2`

## Highlights

- GitHub Actions CI on Python 3.11 and 3.12
- Local REST API (`python main.py --api`) bridged to the browser extension
- Manifest V3 extension with quick + deep analysis modes
- Desktop GUI with session history, JSON/PDF export
- Batch TXT/CSV analysis
- Heuristics + WHOIS + HTML content + URLhaus / optional Safe Browsing

## Install

```bash
git clone https://github.com/Dryhawell/phishing-url-detector.git
cd phishing-url-detector
git checkout v1.4.2
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Verify

```bash
python -m pytest tests -q
```

## Notes

- Safe Browsing requires `GOOGLE_SAFE_BROWSING_API_KEY`
- Extension deep analysis needs the local API running on `127.0.0.1:8765`
- Full history: [CHANGELOG.md](../CHANGELOG.md)
