
import logging
import re

from decoders import find_encoded_passwords

log = logging.getLogger("scanner")

PASSWORD_RE = re.compile(r"VISUALPING\{[0-9a-fA-F]{16}\}")
EXAMPLE_PASSWORD = "VISUALPING{0000deadbeef0000}"  # the worked example, not a real one


class PasswordScanner:
    def __init__(self):
        self.found: dict[str, str] = {}  # password -> first-seen url/label

    def record(self, password: str, url: str) -> None:
        if password == EXAMPLE_PASSWORD:
            return
        if password not in self.found:
            self.found[password] = url
            log.info("Found password (%d/8): %s  <- %s", len(self.found), password, url)

    def scan_text(self, text: str, url: str) -> None:
        for m in PASSWORD_RE.finditer(text):
            self.record(m.group(0), url)
        for label, decoded in find_encoded_passwords(text):
            for m in PASSWORD_RE.finditer(decoded):
                self.record(m.group(0), f"{url} [{label}]")

    def scan_bytes(self, data: bytes, url: str) -> None:
        # Try direct byte-pattern matching under a few encodings, since a
        # password embedded in binary metadata might not be plain
        # ASCII/latin1 -- e.g. EXIF UserComment fields are UTF-16 per spec.
        for encoding in ("latin1", "utf-16-le", "utf-16-be", "utf-8"):
            try:
                text = data.decode(encoding, errors="ignore")
                self.scan_text(text, f"{url} [{encoding}]")
            except Exception:
                pass

    def is_done(self) -> bool:
        return len(self.found) >= 8
