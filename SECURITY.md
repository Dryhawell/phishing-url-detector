# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.4.x   | Yes       |
| < 1.4   | Best effort |

## Defensive use only

This project is intended for **defensive security education** and personal/portfolio analysis of URLs you are allowed to inspect.

Do **not** use it to:

- probe or attack systems without authorization
- bypass security controls
- harvest credentials or personal data

## Local API warning

`python main.py --api` binds to `127.0.0.1` by default on purpose.

- Do not expose the API to the public internet.
- Do not change the bind address to `0.0.0.0` unless you understand the risk and add authentication.

## Secrets

Never commit:

- Google Safe Browsing API keys
- `.env` files
- personal access tokens

Set keys via environment variables only (see README).

## Reporting issues

If you discover a vulnerability in this repository (for example unsafe defaults or secret leakage), open a GitHub issue with a clear reproduction **without** including secret values, or contact the maintainer via GitHub.
