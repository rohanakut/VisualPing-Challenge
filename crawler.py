"""Fetches resources over HTTP (Basic Auth on every request), dispatches
each response to the right extractor, and drives the BFS crawl with
built-in trap protection.

This is the same crawl this script always did -- global mutable state
(found passwords, visited sets, pattern counts, inline-script hashes) is
now held on a Crawler instance instead of scattered module-level globals.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse

import requests

import extractors
from config import Config
from scanner import PasswordScanner
from utils import TrapTracker, is_page_url_guess, normalize_url, same_domain

log = logging.getLogger("crawler")

# A real browser requests these automatically even with no <a>/<link>
# pointing to them -- favicon in particular.
WELL_KNOWN_PATHS = (
    "/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
    "/manifest.json", "/site.webmanifest",
)


class Crawler:
    def __init__(self, config: Config, exclude_prefixes=None):
        self.config = config

        self.session = requests.Session()
        self.session.auth = (config.username, config.password)

        self.scanner = PasswordScanner()
        self.trap_tracker = TrapTracker(
            known_trap_prefixes=exclude_prefixes,
            full_expand_limit=config.full_expand_limit,
            sample_only_limit=config.sample_only_limit,
            known_trap_sample_limit=config.known_trap_sample_limit,
        )

        self.visited_pages: set[str] = set()
        self.visited_resources: set[str] = set()
        self.content_type_counts = defaultdict(int)
        self.content_type_samples = defaultdict(list)
        self.inline_script_hashes = defaultdict(list)
        self.inline_script_samples: dict[str, str] = {}
        self.pages_crawled = 0

    # -- fetching --------------------------------------------------------

    def fetch(self, url: str):
        try:
            resp = self.session.get(url, timeout=self.config.request_timeout)
        except requests.RequestException as e:
            log.warning("failed to fetch %s: %s", url, e)
            return None

        ctype = resp.headers.get("Content-Type", "unknown").split(";")[0].strip().lower()
        self.content_type_counts[ctype] += 1
        if len(self.content_type_samples[ctype]) < 5:
            self.content_type_samples[ctype].append(url)

        # Headers and cookies can hide passwords too.
        for k, v in resp.headers.items():
            self.scanner.scan_text(f"{k}: {v}", url)
        for k, v in resp.cookies.items():
            self.scanner.scan_text(f"{k}={v}", url)

        return resp

    def _record_inline_script(self, h: str, url: str, sample: str) -> None:
        self.inline_script_hashes[h].append(url)
        self.inline_script_samples[h] = sample

    def process_response(self, url: str, resp):
        ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()

        if "html" in ctype:
            return extractors.process_html(url, resp.text, self.scanner, self._record_inline_script)
        elif "css" in ctype:
            return extractors.process_css(url, resp.text, self.scanner)
        elif "javascript" in ctype or ctype == "application/x-javascript":
            return extractors.process_js(url, resp.text, self.scanner)
        elif "json" in ctype:
            return extractors.process_json(url, resp.text, self.scanner)
        elif ctype.startswith("image/"):
            return extractors.process_image(url, resp.content, self.scanner)
        elif ctype == "application/pdf" or url.lower().endswith(".pdf"):
            return extractors.process_pdf(url, resp.content, self.scanner)
        elif url.lower().endswith(".map"):
            # sourcemaps are JSON; sourcesContent holds the original unminified source
            return extractors.process_json(url, resp.text, self.scanner)
        elif ctype in ("application/octet-stream",) or not ctype:
            return extractors.process_generic_binary(url, resp.content, self.scanner)
        else:
            # Unknown type: try text first, fall back to binary scan.
            try:
                self.scanner.scan_text(resp.text, url)
            except Exception:
                extractors.process_generic_binary(url, resp.content, self.scanner)
            return [], False

    # -- crawl loop --------------------------------------------------------

    def crawl(self, base_url: str) -> None:
        base_netloc = urlparse(base_url).netloc
        queue_: deque[str] = deque([normalize_url(base_url)])

        for well_known in WELL_KNOWN_PATHS:
            queue_.append(normalize_url(urljoin(base_url, well_known)))

        while queue_ and not self.scanner.is_done() and self.pages_crawled < self.config.max_pages:
            url = queue_.popleft()
            if url in self.visited_resources:
                continue
            self.visited_resources.add(url)

            is_page_url = same_domain(url, base_netloc)
            if is_page_url:
                if url in self.visited_pages:
                    continue
                self.visited_pages.add(url)

            _pattern, should_skip, stop_expanding = self.trap_tracker.visit(url)
            if should_skip:
                continue

            resp = self.fetch(url)
            time.sleep(self.config.request_delay)
            if resp is None or resp.status_code >= 400:
                continue

            self.pages_crawled += 1
            new_links, is_html_page = self.process_response(url, resp)

            if self.pages_crawled % 50 == 0:
                top = sorted(self.trap_tracker.pattern_counts.items(), key=lambda kv: -kv[1])[:5]
                log.info(
                    "%d fetched, %d/8 found, queue=%d. Top URL patterns so far: %s",
                    self.pages_crawled, len(self.scanner.found), len(queue_), top,
                )

            if stop_expanding:
                # Sample this shape of URL for content, but don't let it
                # spawn more URLs of the same (or a new) shape.
                continue

            for link in new_links:
                link = normalize_url(link)
                if link in self.visited_resources:
                    continue
                # Always fetch new resources at least once (for password
                # scanning) regardless of domain, but only keep crawling
                # *pages* on-domain to avoid wandering off-site.
                if same_domain(link, base_netloc) or not is_page_url_guess(link):
                    queue_.append(link)
                elif is_html_page:
                    queue_.append(link)  # off-domain but linked: fetch once, don't recurse

        log.info(
            "Crawled %d resources across %d same-domain pages.",
            self.pages_crawled, len(self.visited_pages),
        )

    # -- reporting --------------------------------------------------------

    def print_stats(self) -> None:
        print("\nURL-pattern histogram (canonicalized path, top 15):")
        for pat, cnt in sorted(self.trap_tracker.pattern_counts.items(), key=lambda kv: -kv[1])[:15]:
            flag = "  <-- likely a trap" if cnt > self.config.full_expand_limit else ""
            print(f"  {cnt:5d}  {pat}{flag}")

        print("\nContent-Type breakdown (what kinds of resources we actually saw):")
        for ctype, cnt in sorted(self.content_type_counts.items(), key=lambda kv: -kv[1]):
            samples = ", ".join(self.content_type_samples[ctype][:3])
            print(f"  {cnt:5d}  {ctype:35s} e.g. {samples}")

        print("\nInline <script> variants across all pages (hash: count):")
        for h, urls in sorted(self.inline_script_hashes.items(), key=lambda kv: -len(kv[1])):
            flag = "  <-- RARE, worth checking manually!" if len(urls) <= 3 else ""
            print(f"  {h}: {len(urls)} page(s){flag}")
            if len(urls) <= 3:
                for u in urls:
                    print(f"      {u}")
                print(f"      content: {self.inline_script_samples[h]!r}")

        print("\nDistinct article pages reached per top-level section:")
        section_items = defaultdict(set)
        for u in self.visited_pages:
            path = urlparse(u).path
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                section_items[parts[0]].add(parts[1])
            elif len(parts) == 1:
                section_items[parts[0]].add("(index)")
        for section, items in sorted(section_items.items(), key=lambda kv: -len(kv[1])):
            print(f"  /{section}/ : {len(items)} distinct item(s)")
            for item in sorted(items)[:30]:
                print(f"      - {item}")
