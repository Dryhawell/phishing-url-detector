# Contributing

Thanks for your interest in improving **Phishing URL Detector**.

## Development setup

```bash
git clone https://github.com/Dryhawell/phishing-url-detector.git
cd phishing-url-detector
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest tests -v
```

## Guidelines

1. Keep functions small; prefer clear names over clever tricks.
2. Add type hints and docstrings for public functions.
3. Put tunable values in `config.py` (do not hardcode scores in detectors).
4. Mock network calls in unit tests (WHOIS, HTTP, blocklists).
5. Follow PEP 8; avoid unrelated refactors in the same PR.
6. Update `CHANGELOG.md` for user-visible changes.
7. Do not commit secrets, API keys, generated `reports/*.json`, or log files.

## Suggested workflow

1. Create a feature branch.
2. Implement + test.
3. Open a pull request with a short summary and test plan.

## Security / ethics

This project is for **defensive** analysis and education only. Do not use it to probe systems you do not own or lack permission to test.
