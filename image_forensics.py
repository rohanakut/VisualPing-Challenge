"""Binary-level image inspection that Pillow's normal API doesn't surface:

- scan_png_chunks: hand-parses the raw PNG chunk stream. Pillow's
  img.info only exposes chunk TYPES it recognizes, so a custom/
  non-standard ancillary chunk (which the PNG spec explicitly allows for
  extensibility) is silently skipped by Pillow even though it's sitting
  right there in the file bytes.
- extract_lsb_text: brute-forces a handful of common least-significant-bit
  steganography conventions (which channel(s), MSB-first vs LSB-first).
"""
import logging
import zlib

log = logging.getLogger("image_forensics")

STANDARD_PNG_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT",
    "sRGB", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs", "sPLT", "tIME",
}


def scan_png_chunks(url: str, content: bytes) -> list[tuple[str, str]]:
    """Returns [(label, text_to_scan), ...] for every non-standard PNG
    chunk found: the raw chunk bytes, and (if it happens to be
    zlib-compressed like zTXt) the inflated bytes too."""
    hits: list[tuple[str, str]] = []
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        return hits

    pos = 8
    found_unknown = False
    while pos + 8 <= len(content):
        length = int.from_bytes(content[pos:pos + 4], "big")
        ctype = content[pos + 4:pos + 8].decode("latin1", errors="replace")
        data_start = pos + 8
        data = content[data_start:data_start + length]

        if ctype not in STANDARD_PNG_CHUNKS:
            found_unknown = True
            log.info(
                "%s  UNKNOWN PNG chunk type '%s' (%d bytes) -- not something Pillow surfaces!",
                url, ctype, length,
            )
            hits.append((f"png-chunk:{ctype}", data.decode("latin1", errors="ignore")))
            try:
                inflated = zlib.decompress(data).decode("latin1", errors="ignore")
                log.debug("%s  inflated (%s): %r", url, ctype, inflated[:200])
                hits.append((f"png-chunk:{ctype}-inflated", inflated))
            except Exception:
                pass  # not zlib-compressed, that's fine

        pos = data_start + length + 4  # skip CRC
        if ctype == "IEND":
            break

    if not found_unknown:
        log.debug("%s  no non-standard PNG chunks found", url)
    return hits


def extract_lsb_text(img):
    """Tries a range of common LSB-steganography conventions -- which
    channel(s) to read the LSB from, and MSB-first vs LSB-first bit
    packing -- and returns (decoded_text, convention_label) for the first
    one whose output contains the password marker, or (None, samples) if
    nothing matched (samples is a dict of convention -> decoded text, for
    manual inspection)."""
    img = img.convert("RGB")
    pixels = list(img.getdata())

    channel_modes = {
        "RGB": lambda p: (p[0] & 1, p[1] & 1, p[2] & 1),
        "BGR": lambda p: (p[2] & 1, p[1] & 1, p[0] & 1),
        "R": lambda p: (p[0] & 1,),
        "G": lambda p: (p[1] & 1,),
        "B": lambda p: (p[2] & 1,),
    }

    results = {}
    for mode_name, extractor in channel_modes.items():
        bits = []
        for p in pixels:
            bits.extend(extractor(p))

        for bit_order in ("msb", "lsb"):
            chars = []
            for i in range(0, len(bits) - 7, 8):
                chunk = bits[i:i + 8]
                if bit_order == "lsb":
                    chunk = chunk[::-1]
                byte = 0
                for bit in chunk:
                    byte = (byte << 1) | bit
                chars.append(byte)
            decoded = bytes(chars).decode("latin1", errors="ignore")
            key = f"{mode_name}/{bit_order}-first"
            results[key] = decoded
            if "VISUALPING{" in decoded:
                return decoded, key

    return None, results
