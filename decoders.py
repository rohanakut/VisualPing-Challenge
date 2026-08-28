"""Detects passwords hidden via common obfuscations: base64, hex-encoded
ASCII, JS char-code arrays, reversed strings, percent/HTML/unicode
escapes, ROT13, zero-width-character insertion, and unicode confusable
normalization.

"Passwords are not always stored the way you'd first expect" -- these are
the cheap, common tricks worth checking on every blob of text the crawler
sees, regardless of where it came from.

find_encoded_passwords() is a pure function: given text, it returns every
decoding that happens to contain the VISUALPING{ marker, as (label,
decoded_text) pairs, for the caller to run the real password regex over.
"""
import base64
import codecs
import html
import re
import unicodedata
from urllib.parse import unquote

BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_ASCII_CANDIDATE_RE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")
CHARCODE_ARRAY_RE = re.compile(r"\[\s*(\d{1,3}\s*,\s*){5,}\d{1,3}\s*\]")
ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u200e\u200f\ufeff\u2060"

MARKER = "VISUALPING{"


def find_encoded_passwords(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []

    # base64
    for m in BASE64_CANDIDATE_RE.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0) + "===", validate=False).decode(
                "utf-8", errors="ignore"
            )
            if MARKER in decoded:
                hits.append(("base64-decoded", decoded))
        except Exception:
            pass

    # hex-encoded ASCII text (distinct from the password's own hex digits --
    # this looks for hex that decodes to readable text containing the
    # literal "VISUALPING{" string)
    for m in HEX_ASCII_CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
            if MARKER in decoded:
                hits.append(("hex-decoded", decoded))
        except Exception:
            pass

    # JS/JSON char-code arrays: [86, 73, 83, 85, 65, ...] -> chr() each
    for m in CHARCODE_ARRAY_RE.finditer(text):
        try:
            nums = [int(n) for n in re.findall(r"\d+", m.group(0))]
            decoded = "".join(chr(n) for n in nums if 0 <= n < 0x110000)
            if MARKER in decoded:
                hits.append(("charcode-decoded", decoded))
        except Exception:
            pass

    # reversed string, e.g. "}10edbaed0000{GNIPLAUSIV"
    reversed_text = text[::-1]
    if MARKER in reversed_text:
        hits.append(("reversed", reversed_text))

    # percent-encoding, e.g. VISUALPING%7B...%7D
    try:
        unescaped = unquote(text)
        if unescaped != text and MARKER in unescaped:
            hits.append(("url-decoded", unescaped))
    except Exception:
        pass

    # unicode escapes, e.g. \u0056\u0049\u0053...
    if "\\u00" in text or "\\x" in text:
        try:
            unescaped = text.encode("utf-8").decode("unicode_escape")
            if MARKER in unescaped:
                hits.append(("unicode-escape-decoded", unescaped))
        except Exception:
            pass

    # HTML entities, e.g. &#86;&#73;&#83;... or &#x56;&#x49;...
    if "&#" in text:
        try:
            unescaped = html.unescape(text)
            if MARKER in unescaped:
                hits.append(("html-entity-decoded", unescaped))
        except Exception:
            pass

    # ROT13 (unlikely but cheap to check)
    rot13d = codecs.encode(text, "rot_13")
    if MARKER in rot13d:
        hits.append(("rot13-decoded", rot13d))

    # Zero-width characters: a password can be made to LOOK completely
    # normal to a human while invisible chars are stitched between its
    # characters, silently breaking a naive regex match.
    stripped = text
    for zw in ZERO_WIDTH_CHARS:
        stripped = stripped.replace(zw, "")
    if stripped != text and MARKER in stripped:
        hits.append(("zero-width-stripped", stripped))

    # Unicode normalization: folds full-width / homoglyph lookalike chars
    # toward their ASCII equivalents where a canonical decomposition exists.
    try:
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text and MARKER in normalized:
            hits.append(("unicode-normalized", normalized))
    except Exception:
        pass

    return hits
