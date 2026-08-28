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

(A `.env` is already included here, pre-filled with the credentials from
your original script, so you can run immediately — just don't commit it.)

## Run

```bash
python main.py https://target-site.example
```

Options:
- `--dynamic` — also do a Playwright pass over every visited page with a
  real browser, to catch content that only appears after JS runs (nav
  built client-side, XHR-triggered content). Runs automatically anyway if
  the static crawl doesn't find all 8. Needs `pip install playwright &&
  playwright install chromium`.
- `--exclude-prefix /some/path/` — mark a path prefix as a known infinite
  trap (repeatable). It'll still be sampled a limited number of times in
  case a password lives there, but never expanded further.
- `-v` / `--verbose` — show the full diagnostic dumps (raw JS/CSS bodies,
  EXIF tag listings, PNG chunk detail) that the original always printed.
  Default output stays readable; pass this when you need to dig in.

## What changed vs. the original file, and why

**Structure only — no detection logic was dropped.** Every technique from
the original is still here: encoded-password detection (base64, hex,
JS char-code arrays, reversed text, percent/HTML/unicode escapes, ROT13,
zero-width-character stripping, unicode normalization), LSB steganography
brute-forcing, raw PNG chunk parsing, PDF text/metadata extraction, OCR,
crawler-trap protection, inline-script hash tracking, and the final stats
report (URL-pattern histogram, content-type breakdown, per-section article
counts).

What moved:

| Concern | Was | Now |
|---|---|---|
| Credentials | Hardcoded `USERNAME`/`PASSWORD` constants | `.env` via `config.py` |
| Password regex + found-set + example-password exclusion | Module globals (`found_passwords`, `password_sources`) | `scanner.PasswordScanner` |
| Encoding obfuscation checks | `scan_encoded_variants()`, called inline everywhere | `decoders.find_encoded_passwords()` — pure function, called once from `PasswordScanner.scan_text()` |
| Crawler-trap tracking | Module globals (`pattern_counts`, `known_trap_counts`) | `utils.TrapTracker` |
| PNG chunk parsing / LSB stego | Free functions mixed into image handling | `image_forensics.py` |
| Per-content-type handling | `process_html/css/js/json/pdf/image/*` functions closing over globals | Same functions, now in `extractors.py`, taking an explicit `scanner` argument |
| Fetch + BFS loop + stats | `fetch()`, `crawl()`, print blocks at module level | `crawler.Crawler` class |
| Diagnostic dumps | Unconditional `print()` of full JS/CSS bodies etc. | `logging`, gated behind `--verbose` / `log.debug` so default output isn't overwhelming |
| Dynamic JS pass | `run_dynamic_pass()` at module level, closing over globals | `dynamic.py`, takes the `Crawler` instance so it shares the same scanner/visited-pages state |

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

## If you're stuck at fewer than 8

Same troubleshooting the original suggested, printed automatically at the
end of a run if fewer than 8 are found:
- View-source vs. rendered DOM differences
- robots.txt / sitemap.xml (can still seed useful URLs even if not "the trick")
- WebSocket traffic (browser devtools → Network → WS)
- Font files, favicons, manifest.json, service workers
- Query parameters or paths differing only by case

Also try `-v` to see the full per-resource diagnostic dumps, and `--dynamic`
if you suspect some navigation only exists after JavaScript runs.
