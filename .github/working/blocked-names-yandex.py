#!/usr/bin/env python3
"""Generate a Yandex-focused blocked names list for dnscrypt-proxy."""

from __future__ import annotations

import fnmatch
import pathlib
import re
import sys
import urllib.error
import urllib.request
from typing import Iterable, List, Sequence, Set

REPO_ROOT = pathlib.Path(__file__).resolve().parent
EXAMPLE_PATH = REPO_ROOT / "example-blocked-names.txt"
OUTPUT_PATH = REPO_ROOT / "blocked-yandex.txt"
HOSTS_URL = "https://o0.pages.dev/Pro/hosts.txt"

_IP_ADDRESS_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_VALID_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z0-9-]+$")


def read_text_from_url(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        },
    )

    with urllib.request.urlopen(request) as response:  # type: ignore[call-arg]
        encoding = response.headers.get_content_charset("utf-8")
        return response.read().decode(encoding)


def load_example_lines() -> List[str]:
    try:
        text = EXAMPLE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Missing {EXAMPLE_PATH.name}. Place the file in the repository root."
        ) from exc

    return text.rstrip("\n").splitlines()


def extract_base_patterns(lines: Iterable[str]) -> Set[str]:
    patterns: Set[str] = set()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("="):
            stripped = stripped[1:]

        patterns.add(stripped.lower())

    return patterns


def extract_domains(hosts_text: str, excluded_patterns: Sequence[str]) -> List[str]:
    patterns = [pattern.lower() for pattern in excluded_patterns]
    results: List[str] = []
    seen: Set[str] = set()

    for raw_line in hosts_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        tokens = line.split()
        if not tokens:
            continue

        if _IP_ADDRESS_RE.match(tokens[0]):
            tokens = tokens[1:]

        for token in tokens:
            domain = token.strip().lower().strip(".")
            if not domain:
                continue

            if domain in seen:
                continue

            if "yandex" not in domain:
                continue

            if domain == "yandex.ru":
                continue

            if not _VALID_DOMAIN_RE.match(domain):
                continue

            if any(fnmatch.fnmatch(domain, pattern) for pattern in patterns):
                continue

            seen.add(domain)
            results.append(domain)

    return sorted(results)


def compose_output(header_lines: Sequence[str], domains: Iterable[str]) -> str:
    lines: List[str] = []
    lines.extend(header_lines)
    lines.append("")
    lines.append("# other yandex domains")
    lines.extend(domains)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    example_lines = load_example_lines()
    base_patterns = extract_base_patterns(example_lines)

    try:
        hosts_text = read_text_from_url(HOSTS_URL)
    except urllib.error.URLError as exc:  # pragma: no cover - depends on network
        raise RuntimeError(f"Unable to download {HOSTS_URL}: {exc}") from exc

    domains = extract_domains(hosts_text, sorted(base_patterns))
    output_text = compose_output(example_lines, domains)
    OUTPUT_PATH.write_text(output_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
