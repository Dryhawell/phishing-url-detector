# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.4.3] - 2026-08-14

### Added
- Dependabot for pip and GitHub Actions
- Windows portfolio demo script (`scripts/demo.ps1`)
- GitHub issue templates (bug / feature)
- GitHub Actions Release workflow (creates a Release when a `v*` tag is pushed)

## [1.4.2] - 2026-08-10

### Added
- GitHub Actions CI workflow (pytest on Python 3.11 and 3.12)
- CI status badge in README
- `SECURITY.md`, `Makefile`, and portfolio checklist docs

## [1.4.1] - 2026-08-10

### Added
- Browser extension icons (`16/48/128`)
- README GUI preview image (`docs/screenshot.png`)
- `scripts/generate_assets.py` to regenerate visual assets

## [1.4.0] - 2026-08-10

### Added
- Local Flask API (`python main.py --api`) on `127.0.0.1:8765`
- Extension **Derin Analiz** button calling the local Python analyzer
- `/health` and `/analyze` endpoints with CORS for the MV3 popup

## [1.3.0] - 2026-08-10

### Added
- Chrome/Edge Manifest V3 companion extension (`browser-extension/`)
- Client-side heuristic scoring aligned with Python `config.py` weights

## [1.2.0] - 2026-08-10

### Added
- Online reputation providers: URLhaus (no API key) and optional Google Safe Browsing v4
- Pluggable `ReputationProvider` interface for future blocklist sources
- Config flags: `ENABLE_ONLINE_REPUTATION`, `ONLINE_REPUTATION_TIMEOUT`

## [1.1.0] - 2026-08-08

### Added
- HTML content analysis (`requests` + BeautifulSoup)
- PDF report export (`fpdf2`) and GUI **PDF Kaydet** button
- Batch analysis CLI (`--batch` TXT/CSV) with URL SHA-256 fingerprints
- In-session GUI history panel (`gui/history.py`)
- Packaging: `pyproject.toml`, `pip install -e .`, PyInstaller helper script

### Changed
- Analyzer merges heuristic + WHOIS + HTML (+ later online) findings into one score

## [1.0.0] - 2026-08-07

### Added
- Project skeleton and dependency pinning
- Central `config.py` scoring model
- Logging utilities
- URL helpers and heuristic rule engine
- Analysis orchestrator (`analyze_url`)
- WHOIS domain-age reputation checks
- JSON report writer with PDF-ready interface
- Dark-themed Tkinter GUI
- Unit test suite (mocked network where needed)
- Professional README

[1.4.3]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.3
[1.4.2]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.2
[1.4.1]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.1
[1.4.0]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.0
[1.3.0]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.3.0
[1.2.0]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.2.0
[1.1.0]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.1.0
[1.0.0]: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.0.0
