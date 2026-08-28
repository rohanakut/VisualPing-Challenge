"""Optional second pass using a real, JS-executing browser to catch
content only reachable by running JavaScript: client-side-built nav,
XHR/fetch-triggered content, etc.
"""
import logging
from urllib.parse import urlparse

from utils import same_domain

log = logging.getLogger("dynamic")


def run_dynamic_pass(base_url: str, crawler) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.info(
            "playwright not installed; skipping dynamic pass. Run "
            "`pip install playwright && playwright install chromium` if "
            "some passwords are still missing after the static crawl."
        )
        return

    log.info("Re-visiting pages with a real browser to catch JS-only content and network calls...")

    scanner = crawler.scanner
    base_netloc = urlparse(base_url).netloc
    seen_network_bodies: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            http_credentials={"username": crawler.config.username, "password": crawler.config.password}
        )
        page = context.new_page()

        def on_response(response):
            try:
                url = response.url
                if url in seen_network_bodies:
                    return
                seen_network_bodies.add(url)
                ctype = response.headers.get("content-type", "")
                if any(t in ctype for t in ("text", "json", "javascript", "css")):
                    scanner.scan_text(response.text(), url)
            except Exception:
                pass

        page.on("response", on_response)

        # Check every visited page -- a low cap here would mean we might
        # never even render the one page where JS execution matters.
        pages_to_check = list(crawler.visited_pages) or [base_url]
        log.info("checking all %d visited pages (this will take a while)", len(pages_to_check))

        checked = 0
        for url in pages_to_check:
            if scanner.is_done():
                break
            checked += 1
            if checked % 50 == 0:
                log.info(
                    "%d/%d rendered, %d/8 found so far",
                    checked, len(pages_to_check), len(scanner.found),
                )
            try:
                page.goto(url, wait_until="load", timeout=8000)
                rendered_html = page.content()
                scanner.scan_text(rendered_html, url)

                # Pull hrefs that only exist after JS runs.
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                new_hrefs = [
                    h for h in hrefs
                    if h not in crawler.visited_pages and same_domain(h, base_netloc)
                ]
                if new_hrefs:
                    log.info("%s revealed %d JS-only link(s)", url, len(new_hrefs))
                for h in new_hrefs[:10]:  # cap fan-out here too
                    try:
                        page.goto(h, wait_until="load", timeout=8000)
                        scanner.scan_text(page.content(), h)
                        crawler.visited_pages.add(h)
                    except Exception:
                        pass
            except Exception as e:
                log.warning("%s: %s", url, e)

        browser.close()
