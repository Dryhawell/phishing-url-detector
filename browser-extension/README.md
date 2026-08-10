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

## Sync with Python scores

Risk weights mirror `config.py` as of v1.2. If you change Python scores,
update `heuristics.js` `RISK_SCORES` to keep both tools aligned.
