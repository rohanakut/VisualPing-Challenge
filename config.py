"""Loads scraper configuration from environment variables / .env file.

The original script hardcoded the Basic Auth username/password as source
constants. Pulling them into .env means the credentials aren't sitting in
version control, while every tuning knob (crawl-trap limits, delays, etc.)
keeps the same defaults the original had.
"""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    username: str
    password: str
    request_delay: float = 0.15
    max_pages: int = 1000
    request_timeout: int = 15
    # Crawler-trap protection (see utils.TrapTracker)
    full_expand_limit: int = 60
    sample_only_limit: int = 200
    known_trap_sample_limit: int = 10


def load_config() -> Config:
    username = os.getenv("AUTH_USERNAME", "").strip()
    password = os.getenv("AUTH_PASSWORD", "").strip()
    if not username or not password:
        raise SystemExit(
            "AUTH_USERNAME / AUTH_PASSWORD are not set. Copy .env.example to "
            ".env and fill in your HTTP Basic Auth credentials."
        )
    return Config(
        username=username,
        password=password,
        request_delay=float(os.getenv("REQUEST_DELAY", "0.15")),
        max_pages=int(os.getenv("MAX_PAGES", "1000")),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT", "15")),
        full_expand_limit=int(os.getenv("FULL_EXPAND_LIMIT", "60")),
        sample_only_limit=int(os.getenv("SAMPLE_ONLY_LIMIT", "200")),
        known_trap_sample_limit=int(os.getenv("KNOWN_TRAP_SAMPLE_LIMIT", "10")),
    )
