# VisualPing password scraper

Finds the eight `VISUALPING{0000000000000000}`-style passwords hidden
across a site, starting from the homepage. Same crawl and detection logic
as the original single-file script, reorganized into modules and with
credentials moved out of source into `.env`.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # fill in AUTH_USERNAME / AUTH_PASSWORD
```

Please modify .env-example with your credentials to run script

## Run

```bash
python3 main.py http://54.214.7.161/ --exclude-prefix /report --verbose
```

Options:
- `--dynamic` — also do a Playwright pass over every visited page with a
  to simulate a real browser
- `--exclude-prefix /some/path/` — add path (/report) to avoid infinite loop
- `-v` / `--verbose` — show the full diagnostic dumps 

## Files

| File | Purpose |
|---|---|
| `main.py` | CLI entry point |
| `config.py` | Loads `.env` (credentials, tuning knobs) |
| `crawler.py` | `Crawler`: fetch, dispatch, BFS loop, trap protection, stats |
| `extractors.py` | Content-type-aware processing (HTML/CSS/JS/JSON/PDF/image/binary) |
| `scanner.py` | `PasswordScanner`: regex match + obfuscation checks + found-set |
| `decoders.py` | Pure obfuscation-decoding functions (base64, hex, ROT13, etc.) |
| `image_forensics.py` | Raw PNG chunk parsing + LSB steganography brute-force |
| `utils.py` | URL helpers + `TrapTracker` (crawler-trap protection) |
| `dynamic.py` | Optional Playwright pass for JS-only content |
| `requirements.txt` | Core + optional dependencies |
| `.env.example` / `.env` | Config template / actual (gitignored) config |

