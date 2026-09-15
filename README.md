# ShieldScan

A privacy-first, client-side file analyzer designed for GitHub Pages.

## What it does

- Drag-and-drop / multi-file selection
- SHA-256 hashes using Web Crypto
- Basic file magic/signature detection
- Suspicious extension heuristics
- Double-extension detection
- Archive/container warnings
- Mismatch warning when executable bytes do not match the filename extension
- Responsive dark UI
- No backend and no file upload

## Important limitation

This is **not a full antivirus engine**. A clean result only means that this lightweight browser analyzer found no obvious indicators.

For real malware scanning, add a server-side component using a reputable antivirus engine such as ClamAV, YARA rules, or a multi-engine threat-intelligence provider. Never expose private API keys in this repository.

## GitHub Pages

1. Create a GitHub repository.
2. Upload the project files.
3. Go to **Settings → Pages**.
4. Select **GitHub Actions** as the source.
5. The included workflow deploys the repository to GitHub Pages.

If the repository is `username/shieldscan`, the usual URL is:

`https://username.github.io/shieldscan/`
