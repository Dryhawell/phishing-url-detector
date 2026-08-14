# Release v1.4.3

Published tag: `v1.4.3`

## Highlights since v1.4.2

- Dependabot for pip and GitHub Actions
- Windows demo script: `scripts/demo.ps1`
- GitHub issue templates
- Automated Release workflow on version tags

## Core product (unchanged capabilities)

- Desktop GUI + session history + JSON/PDF export
- Batch TXT/CSV analysis
- Local REST API for browser-extension deep analysis
- Heuristics + WHOIS + HTML + URLhaus / optional Safe Browsing
- CI on Python 3.11 / 3.12

## Install

```bash
git clone https://github.com/Dryhawell/phishing-url-detector.git
cd phishing-url-detector
git checkout v1.4.3
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Verify

```bash
python -m pytest tests -q
# or on Windows:
.\scripts\demo.ps1
```

## Notes

- Safe Browsing requires `GOOGLE_SAFE_BROWSING_API_KEY`
- Extension deep analysis needs `python main.py --api`
- Full history: [CHANGELOG.md](../CHANGELOG.md)
