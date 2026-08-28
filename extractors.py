"""Content-type-aware processing. Given a fetched resource, scan it for
passwords (via the shared PasswordScanner) and return any new URLs it
references, so the crawler can decide whether to queue them.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from io import BytesIO
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

import image_forensics
from scanner import PasswordScanner

log = logging.getLogger("extractors")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import pytesseract
    HAVE_OCR = True
except ImportError:
    HAVE_OCR = False

HTML_LINK_ATTRS = ["href", "src", "action", "data-src", "data-href", "poster"]
CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)")
URL_LITERAL_RE = re.compile(r"""['"](/[^'"]+|https?://[^'"]+)['"]""")
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def process_html(url, text, scanner: PasswordScanner, on_inline_script=None):
    scanner.scan_text(text, url)  # catches comments, inline JSON, etc.

    soup = BeautifulSoup(text, "html.parser")

    # If the password is split across inline tags (e.g.
    # <b>0000dead</b><i>beef0000</i>), the raw-source regex above can't see
    # it because closing/opening tags sit in the middle of the hex run.
    # get_text() reconstructs text the way a browser renders it, joining
    # text nodes across tags.
    rendered_text = soup.get_text(separator="", strip=False)
    if rendered_text != text:
        scanner.scan_text(rendered_text, url + " [rendered-text]")

    new_links: list[str] = []

    # Standard + less-standard link-bearing attributes.
    for tag in soup.find_all(True):
        for attr in HTML_LINK_ATTRS:
            if tag.has_attr(attr):
                new_links.append(urljoin(url, tag[attr]))
        if tag.has_attr("srcset"):
            for part in tag["srcset"].split(","):
                candidate = part.strip().split(" ")[0]
                if candidate:
                    new_links.append(urljoin(url, candidate))
        # inline style="background: url(...)"
        if tag.has_attr("style"):
            for m in CSS_URL_RE.finditer(tag["style"]):
                new_links.append(urljoin(url, m.group(1)))

    # <meta http-equiv="refresh" content="0;url=...">
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        content = meta.get("content", "")
        m = re.search(r"url=([^;]+)", content, re.I)
        if m:
            new_links.append(urljoin(url, m.group(1).strip()))

    # HTML comments (already covered by the raw text scan above too, but
    # walking them explicitly is a good sanity check).
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        scanner.scan_text(str(c), url)

    # url(...) references inside inline <style> blocks.
    for style_tag in soup.find_all("style"):
        for m in CSS_URL_RE.finditer(style_tag.get_text()):
            new_links.append(urljoin(url, m.group(1)))

    # Inline <script> blocks (no src attr) can construct navigation links
    # via JS that never show up as a plain <a href> anywhere -- e.g. one
    # specific page dynamically linking to an orphan page not reachable
    # through normal pagination. Treat inline script text like a .js file
    # for link-discovery purposes.
    for script_tag in soup.find_all("script"):
        if script_tag.has_attr("src"):
            continue  # external scripts are crawled separately
        script_text = script_tag.get_text()
        if not script_text.strip():
            continue
        for m in URL_LITERAL_RE.finditer(script_text):
            new_links.append(urljoin(url, m.group(1)))
        scanner.scan_text(script_text, url + " [inline-script]")

        if on_inline_script:
            # Hash each page's inline-script content so the crawler can
            # spot any ONE page whose inline script differs from the
            # templated boilerplate shared by most other pages.
            h = hashlib.md5(script_text.encode("utf-8", errors="ignore")).hexdigest()[:12]
            on_inline_script(h, url, script_text[:500])

    return new_links, True


def process_css(url, text, scanner: PasswordScanner):
    scanner.scan_text(text, url)
    log.debug("[css] %s (%d bytes):\n%s", url, len(text), text[:3000])
    links = [urljoin(url, m.group(1)) for m in CSS_URL_RE.finditer(text)]
    return links, False


def process_js(url, text, scanner: PasswordScanner):
    scanner.scan_text(text, url)
    log.debug("[js] %s (%d bytes):\n%s", url, len(text), text[:4000])

    if "ws://" in text or "wss://" in text:
        idx = max(text.find("ws://"), text.find("wss://"))
        log.info(
            "[websocket-ref] %s references a websocket URL: ...%s...",
            url, text[max(0, idx - 50):idx + 100],
        )

    # Flag any tag types this crawler doesn't have first-class handling
    # for, in case a resource is referenced in a way that's never checked.
    for suspicious_tag in ("<iframe", "<object", "<embed", "<video", "<audio",
                            "<canvas", "<use ", "<picture", "<template", "xlink:href"):
        if suspicious_tag in text:
            idx = text.find(suspicious_tag)
            log.info(
                "[unhandled-tag] %s contains '%s': ...%s...",
                url, suspicious_tag.strip(), text[max(0, idx - 60):idx + 150],
            )

    links = [urljoin(url, m.group(1)) for m in URL_LITERAL_RE.finditer(text)]

    # Minified JS often references a .map file containing the original
    # unminified source (in a "sourcesContent" field) -- a string that was
    # never present in the minified bundle we already scanned.
    for m in SOURCEMAP_RE.finditer(text):
        links.append(urljoin(url, m.group(1)))

    return links, False


def process_json(url, text, scanner: PasswordScanner):
    new_links: list[str] = []
    try:
        data = json.loads(text)
    except ValueError:
        scanner.scan_text(text, url)
        return new_links, False

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            scanner.scan_text(node, url)
            if node.startswith("/") or node.startswith("http"):
                new_links.append(urljoin(url, node))

    walk(data)
    return new_links, False


def process_pdf(url, content, scanner: PasswordScanner):
    scanner.scan_bytes(content, url)  # cheap fallback (uncompressed streams, metadata)
    try:
        try:
            from pypdf import PdfReader
        except ImportError:
            from PyPDF2 import PdfReader  # fallback for older installs

        reader = PdfReader(BytesIO(content))

        # Document metadata (Title/Author/Subject/Keywords/custom fields).
        if reader.metadata:
            for k, v in dict(reader.metadata).items():
                scanner.scan_text(f"{k}={v}", url)

        # Decompressed page text -- the part raw byte scanning misses,
        # since PDF content streams are usually FlateDecode-compressed.
        for page in reader.pages:
            text = page.extract_text() or ""
            scanner.scan_text(text, url)
    except ImportError:
        log.warning(
            "pypdf/PyPDF2 not installed -- cannot decompress PDF text streams "
            "in %s. Run: pip install pypdf", url,
        )
    except Exception as e:
        log.warning("failed to parse PDF %s: %s", url, e)

    return [], False


def process_image(url, content, scanner: PasswordScanner):
    scanner.scan_bytes(content, url)

    for label, text in image_forensics.scan_png_chunks(url, content):
        scanner.scan_text(text, url + f" [{label}]")

    if HAVE_PIL:
        try:
            img = Image.open(BytesIO(content))
            log.debug("[image] %s format=%s size=%s mode=%s", url, img.format, img.size, img.mode)

            exif = img.getexif()
            if len(exif) == 0 and not getattr(img, "info", {}):
                log.debug("[image] %s no EXIF / no info chunks found", url)
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                log.debug("[image] %s EXIF %s = %r", url, tag, value)
                scanner.scan_text(f"{tag}={value}", url)
            for k, v in getattr(img, "info", {}).items():
                log.debug("[image] %s info[%s] = %r", url, k, v)
                scanner.scan_text(f"{k}={v}", url)

            # OCR pass: some images are actual photos/screenshots with the
            # password visually written/printed in them rather than stored
            # as metadata (e.g. a photographed whiteboard).
            if HAVE_OCR:
                try:
                    ocr_text = pytesseract.image_to_string(img)
                    if ocr_text.strip():
                        log.debug("[image] %s OCR text: %r", url, ocr_text.strip())
                        scanner.scan_text(ocr_text, url + " [ocr]")
                except Exception as e:
                    log.warning("OCR failed on %s: %s", url, e)
            else:
                log.debug(
                    "[image] %s pytesseract not installed -- skipping OCR "
                    "(pip install pytesseract, plus the tesseract binary, "
                    "e.g. `brew install tesseract` or `apt install tesseract-ocr`)",
                    url,
                )

            if img.format == "PNG":
                try:
                    hit, info = image_forensics.extract_lsb_text(img)
                    if hit:
                        log.info("[image] %s LSB steganography hit! (convention: %s)", url, info)
                        scanner.scan_text(hit, url + f" [lsb-stego:{info}]")
                    else:
                        log.debug(
                            "[image] %s LSB brute-force: %d conventions tried, no match. "
                            "Sample (RGB/msb-first): %r",
                            url, len(info), info.get("RGB/msb-first", "")[:60],
                        )
                except Exception as e:
                    log.warning("LSB extraction failed on %s: %s", url, e)
        except Exception as e:
            log.warning("failed to inspect image %s: %s", url, e)

    return [], False


def process_generic_binary(url, content, scanner: PasswordScanner):
    scanner.scan_bytes(content, url)
    return [], False
