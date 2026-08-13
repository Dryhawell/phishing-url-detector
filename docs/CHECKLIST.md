# Final portfolio checklist

Use this before sharing the repo on your CV / LinkedIn.

## Must-have

- [x] Clean modular Python package layout
- [x] Tests passing locally (`python -m pytest tests -q`)
- [x] GitHub Actions CI green on `main`
- [x] Annotated tag `v1.4.2` pushed
- [ ] GitHub **Release** published from tag `v1.4.2`  ← still open
  - Open: https://github.com/Dryhawell/phishing-url-detector/releases/new?tag=v1.4.2
  - Paste body from `docs/RELEASE_v1.4.2.md`
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
