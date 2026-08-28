#!/usr/bin/env python3
"""Hunt VISUALPING{<16 hex chars>} passwords hidden across a site.

Usage:
    pip install -r requirements.txt
    cp .env.example .env   # fill in AUTH_USERNAME / AUTH_PASSWORD
    python main.py https://target-site.example
    python main.py https://target-site.example --dynamic
    python main.py https://target-site.example --exclude-prefix /report/
    python main.py https://target-site.example --verbose

Optional extras (see requirements.txt comments):
    pip install playwright && playwright install chromium   # --dynamic
    pip install pytesseract  # + the tesseract binary        # OCR on images
"""
import argparse
import logging
import sys

from config import load_config
from crawler import Crawler
from dynamic import run_dynamic_pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Hunt VISUALPING passwords on a site.")
    parser.add_argument("base_url", help="Homepage URL of the target site")
    parser.add_argument(
        "--dynamic", action="store_true",
        help="Also run a Playwright pass to catch JS-only content",
    )
    parser.add_argument(
        "--exclude-prefix", action="append", default=[],
        help="Path prefix (e.g. /report/) known to be an infinite trap. "
             "Sampled a limited number of times, never expanded. Can be "
             "passed multiple times.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show per-resource diagnostic dumps (JS/CSS bodies, EXIF "
             "tags, PNG chunk detail, etc.)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config()
    crawler = Crawler(config, exclude_prefixes=args.exclude_prefix)

    print(f"Starting crawl at {args.base_url} as user '{config.username}'...\n")
    crawler.crawl(args.base_url)
    crawler.print_stats()

    if not crawler.scanner.is_done() or args.dynamic:
        run_dynamic_pass(args.base_url, crawler)

    print("\n" + "=" * 60)
    print(f"Found {len(crawler.scanner.found)}/8 passwords:")
    for pw, src in crawler.scanner.found.items():
        print(f"  {pw}   (from {src})")
    print("=" * 60)

    if not crawler.scanner.is_done():
        print("\nStill missing some. Things worth double-checking manually:")
        print("  - View-source vs rendered DOM differences")
        print("  - robots.txt / sitemap.xml (even if not 'the trick', they can seed URLs)")
        print("  - WebSocket traffic (open browser devtools > Network > WS)")
        print("  - Font files, favicons, manifest.json, service workers")
        print("  - Query parameters or paths that differ only by case")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
