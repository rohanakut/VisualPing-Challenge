"""URL helpers plus crawler-trap protection to avoid infinte loop
"""
import re
from collections import defaultdict
from urllib.parse import urldefrag, urlparse

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
    ".woff2", ".ttf", ".ico", ".pdf", ".json", ".mp4", ".webp", ".map",
)


def normalize_url(url: str) -> str:
    url, _frag = urldefrag(url)
    return url


def same_domain(url: str, base_netloc: str) -> bool:
    return urlparse(url).netloc == base_netloc


def is_page_url_guess(url: str) -> bool:
    """Rough heuristic: does this look like an HTML page vs. a static asset?"""
    path = urlparse(url).path.lower()
    return not path.endswith(STATIC_EXTENSIONS)


class TrapTracker:
    def __init__(self, known_trap_prefixes=None, full_expand_limit=60,
                 sample_only_limit=200, known_trap_sample_limit=10):
        self.known_trap_prefixes = list(known_trap_prefixes or [])
        self.full_expand_limit = full_expand_limit
        self.sample_only_limit = sample_only_limit
        self.known_trap_sample_limit = known_trap_sample_limit
        self.pattern_counts = defaultdict(int)
        self.known_trap_counts = defaultdict(int)

    @staticmethod
    def canon_pattern(url: str) -> str:
        path = urlparse(url).path
        segs = path.split("/")
        canon_segs = []
        for s in segs:
            if re.fullmatch(r"\d+", s):
                canon_segs.append("#num")
            elif re.fullmatch(r"[0-9a-fA-F]{8,}", s):
                canon_segs.append("#hex")
            elif re.fullmatch(r"[0-9a-fA-F-]{20,}", s):
                canon_segs.append("#uuid")
            else:
                canon_segs.append(s)
        has_query = "?" in url
        return "/".join(canon_segs) + ("?*" if has_query else "")

    def matches_known_trap(self, url: str) -> str | None:
        path = urlparse(url).path
        for prefix in self.known_trap_prefixes:
            if path.startswith(prefix):
                return prefix
        return None

    def visit(self, url: str) -> tuple[str, bool, bool]:
        """Records a visit to `url` and returns (pattern, should_skip,
        stop_expanding). should_skip means: don't even fetch/scan it.
        stop_expanding means: fetch/scan it, but don't follow its links."""
        pattern = self.canon_pattern(url)
        self.pattern_counts[pattern] += 1
        count = self.pattern_counts[pattern]

        trap_prefix = self.matches_known_trap(url)
        if trap_prefix is not None:
            self.known_trap_counts[trap_prefix] += 1
            if self.known_trap_counts[trap_prefix] > self.known_trap_sample_limit:
                return pattern, True, True

        if count > self.sample_only_limit:
            # Almost certainly a trap (calendar, infinite pagination, random
            # slugs, session ids...). Skip entirely rather than burn budget.
            return pattern, True, True

        stop_expanding = trap_prefix is not None or count > self.full_expand_limit
        return pattern, False, stop_expanding
