# Final portfolio checklist

Use this before sharing the repo on your CV / LinkedIn.

## Must-have

- [x] Clean modular Python package layout
- [x] Tests passing locally (`python -m pytest tests -q`)
- [x] GitHub Actions CI green on `main`
- [x] Annotated tag `v1.4.2` pushed
- [x] Release workflow added (auto-publish on `v*` tags)
- [ ] Confirm GitHub Release appears after pushing `v1.4.3`
  - Releases page: https://github.com/Dryhawell/phishing-url-detector/releases
- [ ] Repo description + topics set on GitHub (phishing, python, security, osint)
- [ ] Optional: replace `docs/screenshot.png` with a real GUI capture

## Quick demo (Windows)

```powershell
.\scripts\demo.ps1
```

## Demo script (2 minutes)

1. `python main.py` → analyze a high-risk sample URL → export PDF
2. `python main.py --batch samples/urls.txt`
3. `python main.py --api` + browser extension **Derin Analiz**
4. Show CI badge + Actions run

## Talking points

- Config-driven scoring (no magic numbers in detectors)
- Layered analysis: heuristics → WHOIS → HTML → online lists
- Extension + localhost API bridge
- Graceful network failure handling + mocked tests
