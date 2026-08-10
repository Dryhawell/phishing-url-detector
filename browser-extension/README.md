# Browser Extension Companion

Manifest V3 Chrome / Edge eklentisi. Aktif sekme URL'sini **istemci tarafında**
sezgisel kurallarla puanlar.

> Bu eklenti Python masaüstü aracının **hafif tamamlayıcısıdır**.
> WHOIS, HTML içerik ve URLhaus/Safe Browsing için `python main.py` kullanın.

## Install (Chrome / Edge)

1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select this folder: `browser-extension/`

## Modes

### Quick analysis (default)
Client-side heuristics only — works offline, no Python process required.

### Deep analysis (Python API)
1. In a terminal from the repo root:

```bash
pip install -r requirements.txt
python main.py --api
```

2. Click **Derin Analiz (Python API)** in the popup.

The extension calls `POST http://127.0.0.1:8765/analyze`.
This unlocks WHOIS / HTML / URLhaus / optional Safe Browsing from the Python engine.

## Usage

1. Open any tab
2. Click the extension icon
3. The current URL is analyzed automatically (you can edit and re-run)

## What it checks

Same idea as Python heuristics:

- HTTPS / IP host / long URL-domain
- `@` and `//` tricks
- Suspicious TLDs and phishing keywords

## Limits

- No WHOIS
- No HTML fetch
- No online blocklists
- Domain parsing is simplified (not `tldextract`)

## Icons

Icons live in `icons/icon{16,48,128}.png` and are referenced by `manifest.json`.
Regenerate with:

```bash
python scripts/generate_assets.py
```

Risk weights mirror `config.py` as of v1.2. If you change Python scores,
update `heuristics.js` `RISK_SCORES` to keep both tools aligned.
