# Portfolio Demo Talk Track (≈2–3 minutes)

Use this script when presenting the project in an interview or class.

## 1) Hook (15s)

> “I built a defensive phishing URL analyzer that scores links with layered signals — URL heuristics, WHOIS age, HTML form tricks, and optional blocklists — then exposes the same engine through a GUI, batch CLI, local API, and a Chrome extension.”

## 2) Architecture (30s)

Show the repo tree briefly:

- `detector/` → analysis core (SOLID-ish separation)
- `config.py` → tunable scores (no magic numbers buried in logic)
- `gui/` → Tkinter UI + session history
- `api/` → localhost bridge for the extension
- `browser-extension/` → instant client-side check + deep scan button
- `.github/workflows/` → CI + automated Releases

## 3) Live demo flow (90s)

1. Run `.\scripts\demo.ps1` (tests + batch report)
2. Open GUI: `python main.py`
   - Paste: `http://secure-login.paypal-verify.xyz/update`
   - Show HIGH_RISK score, findings, recommendations
   - Export PDF
3. Start API: `python main.py --api`
4. Extension popup → **Derin Analiz**
5. Open GitHub Actions + Releases pages

## 4) Engineering talking points (30s)

- Config-driven scoring / Open-Closed report writers
- Network calls fail gracefully and are mocked in tests
- GUI uses threads so WHOIS/HTML do not freeze the UI
- Extension stays useful offline; deep mode opts into full Python pipeline
- CI on 3.11/3.12 and tag-based automated releases

## 5) Honest limitations (15s)

> “Heuristics can false-positive. This is an assistant, not a verdict. Production would add richer intel feeds, better UX telemetry, and stronger API auth if ever exposed beyond localhost.”

## Links

- Repo: https://github.com/Dryhawell/phishing-url-detector
- Release: https://github.com/Dryhawell/phishing-url-detector/releases/tag/v1.4.3
- Checklist: [CHECKLIST.md](CHECKLIST.md)
