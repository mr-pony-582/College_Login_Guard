# 🛡️ College Login Guard

A Chrome extension (Manifest V3) that protects students from phishing pages impersonating their college's login portals. It watches every page you visit and flags fake or suspicious sites before you type a password.

## Features

- **Domain Verification** — checks the current site against your college's official domains.
- **Typosquat Detection** — catches lookalike domains (e.g. `kct-login.com`) using Levenshtein distance and substring matching.
- **IP Match Check** — resolves the page's DNS (via HackerTarget + Cloudflare DoH) and compares against known-good IPs/ASNs for your college.
- **SSL Certificate Analysis** — grades HTTPS setup (HTTPS DNS record, CAA records, certificate authority).
- **Domain Age Check** — flags newly registered domains (a common phishing signal) via RDAP lookups.
- **Redirect Chain Tracking** — flags long or suspicious redirect chains, including HTTPS → HTTP downgrades.
- **Password Field Alarm** — sounds an alert and shows a toast when a password field is detected, especially on insecure (HTTP) pages.
- **Form Action Monitoring** — detects forms that submit to unexpected external domains.
- **Sensitivity Slider** — tune how aggressively the extension escalates warnings (Lenient → Strict).
- **Verdict Override** — manually mark a site safe/warning/danger if you disagree with the automatic verdict.
- **Risk Score Meter** — a 0–100 composite score shown in the popup.
- **History & Reporting** — keeps a log of flagged sites and can export a plain-text threat report.
- **Config Export/Import** — back up or transfer your settings, whitelist, and history as a JSON file.
- **Guided Onboarding** — a first-run wizard to set up your college's domains.

## How it works

| Verdict | Meaning |
|---|---|
| ✅ Safe | Official domain, trusted IP, valid SSL |
| ⚠️ Warning | Something looks off — double-check before logging in |
| 🚨 Danger | High-confidence fake page — leave immediately |

The badge icon and popup always reflect the current tab's verdict. Warning and Danger verdicts also trigger an in-page banner.

## Installation (load unpacked)

1. Clone or download this repository.
2. Add your own extension icons at `icons/icon16.png`, `icons/icon48.png`, and `icons/icon128.png` (required — referenced in `manifest.json` but not included in this repo).
3. Open `chrome://extensions` in Chrome.
4. Enable **Developer mode** (top-right toggle).
5. Click **Load unpacked** and select this project's folder.
6. The onboarding page will open automatically — enter your college's domains to finish setup.

## Project structure

```
.
├── manifest.json       # Extension manifest (MV3)
├── background.js       # Service worker: analysis engine, tab status, messaging
├── content.js           # Injected into every page: warning banner, password alarm, form monitoring
├── popup.html / popup.js     # Toolbar popup UI (status, settings, whitelist, history)
├── onboarding.html / onboarding.js  # First-run setup wizard
└── icons/               # Extension icons (add your own — see Installation)
```

## Permissions

| Permission | Why it's needed |
|---|---|
| `storage` | Save settings, whitelist, history, and overrides |
| `scripting` / `activeTab` / `tabs` | Inspect and message the active tab |
| `webRequest` | Track redirect chains |
| `<all_urls>` + DNS/RDAP host permissions | Run checks on any page and call HackerTarget, Cloudflare DoH, ip-api.com, and RDAP for domain/IP/SSL/age lookups |

No API keys are required — all external lookups use free, keyless endpoints.

## Notes

- Configure your college's domains and trusted IPs in the **Settings** tab of the popup, or during onboarding.
- The Settings "Save" action automatically re-resolves IPs for the domains you list.
- This is a defensive tool for personal/educational use and is not affiliated with any college or the services it queries (HackerTarget, Cloudflare, ip-api.com, RDAP).

## License

This project is licensed under the [MIT License](LICENSE).
