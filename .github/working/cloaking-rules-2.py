"""Create dnscrypt-proxy cloaking rules highlighting resolver disagreements."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping
from urllib import error, parse, request

# Keep the long URL readable; adjacent string literals concatenate in Python.
HOSTS_URL = (
    "https://raw.githubusercontent.com/ImMALWARE/"
    "dns.malw.link/refs/heads/master/hosts"
)
OUTPUT_FILENAME = "cloaking-rules-2.txt"
EXAMPLE_HEADER_NAME = "example-cloaking-rules.txt"
TIMEOUT = 10
USER_AGENT = "dnscrypt-proxy-cloaking-updater/3.0"

PROVIDERS: tuple[tuple[str, str], ...] = (
    ("comss", "https://dns.comss.one/dns-query"),
    ("google", "https://dns.google/dns-query"),
    ("cloudflare", "https://dns.cloudflare.com/dns-query"),
)
PRIMARY_PROVIDER = PROVIDERS[0][0]
SECONDARY_PROVIDERS = [name for name, _ in PROVIDERS[1:]]


class FetchError(RuntimeError):
    """Raised when an HTTP request fails."""


def fetch_text(url: str, params: Mapping[str, str] | None = None) -> str:
    """Return the HTTP response body as text."""

    if params:
        url = f"{url}?{parse.urlencode(params)}"
    request_obj = request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with request.urlopen(request_obj, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="replace")
    except error.URLError as exc:
        raise FetchError(f"failed to fetch {url}: {exc}") from exc


def parse_hosts(payload: str) -> Dict[str, List[str]]:
    """Parse a hosts file into ``host -> sorted list of IPs``."""

    hosts: Dict[str, set[str]] = defaultdict(set)
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip, host = parts[0], parts[1].lower()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        hosts[host].add(ip)
    return {host: sorted(ips) for host, ips in hosts.items()}


def download_hosts(url: str) -> Dict[str, List[str]]:
    logging.info("Downloading upstream hosts list from %s", url)
    text = fetch_text(url)
    parsed = parse_hosts(text)
    logging.info("Loaded %d unique hostnames from upstream list", len(parsed))
    return parsed


def query_provider(name: str, endpoint: str, host: str) -> List[str]:
    params = {"name": host, "type": "A"}
    try:
        payload = fetch_text(endpoint, params)
    except FetchError as exc:
        logging.warning("%s query for %s failed: %s", name, host, exc)
        return []

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        logging.warning("%s query for %s returned invalid JSON: %s", name, host, exc)
        return []

    answers = data.get("Answer") or []
    ips: set[str] = set()
    for answer in answers:
        if str(answer.get("type")) != "1":
            continue
        candidate = answer.get("data")
        if not candidate:
            continue
        try:
            ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        ips.add(candidate)

    result = sorted(ips)
    if result:
        logging.info("DNS %s -> %s: %s", name, host, ", ".join(result))
    else:
        logging.info("DNS %s -> %s: no data", name, host)
    return result


def query_providers(hosts: Iterable[str]) -> Dict[str, Dict[str, List[str]]]:
    cache: Dict[str, Dict[str, List[str]]] = {}
    for host in hosts:
        cache[host] = {}
        for name, endpoint in PROVIDERS:
            cache[host][name] = query_provider(name, endpoint, host)
    return cache


def registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def select_disagreements(
    hostnames: Iterable[str],
    answers: Mapping[str, Mapping[str, List[str]]],
) -> Dict[str, Dict[tuple[str, ...], List[str]]]:
    grouped: Dict[str, Dict[tuple[str, ...], List[str]]] = defaultdict(lambda: defaultdict(list))
    for host in hostnames:
        host_answers = answers.get(host, {})
        primary = host_answers.get(PRIMARY_PROVIDER, [])
        if not primary:
            continue
        if any(primary == host_answers.get(other, []) for other in SECONDARY_PROVIDERS):
            continue
        base = registrable_domain(host)
        grouped[base][tuple(primary)].append(host)
        others = {
            other: host_answers.get(other, []) for other in SECONDARY_PROVIDERS
        }
        summary = "; ".join(
            f"{name}={','.join(values) if values else 'no data'}"
            for name, values in sorted(others.items())
        )
        logging.info(
            "Using %s result for %s -> %s (others: %s)",
            PRIMARY_PROVIDER,
            host,
            ", ".join(primary),
            summary,
        )
    return grouped


def load_header(example_path: Path) -> List[str]:
    if not example_path.exists():
        raise SystemExit(f"Missing {example_path.name} next to the script")
    header: List[str] = []
    with example_path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                break
            header.append(line.rstrip("\n"))
    while header and not header[-1]:
        header.pop()
    return header


def render_lines(grouped: Mapping[str, Mapping[tuple[str, ...], List[str]]]) -> List[str]:
    header = load_header(Path(__file__).with_name(EXAMPLE_HEADER_NAME))
    lines = list(header)
    lines.extend(
        [
            "",
            "# Generated automatically from dns.malw.link hosts",
            "# Only includes hosts where dns.comss.one disagrees with dns.google and dns.cloudflare",
            "",
            "# comss dns results",
        ]
    )

    entries: list[tuple[str, str]] = []
    for base, ip_groups in sorted(grouped.items()):
        if len(ip_groups) == 1:
            ips = next(iter(ip_groups))
            for ip in ips:
                entries.append((base, ip))
        else:
            for ips, hosts in ip_groups.items():
                for host in sorted(hosts):
                    alias = f"={host}"
                    for ip in ips:
                        entries.append((alias, ip))

    for name, ip in sorted(entries):
        lines.append(f"{name} {ip}")
    return lines


def write_output(destination: Path, lines: Iterable[str]) -> None:
    materialised = list(lines)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(materialised) + "\n", encoding="utf-8")
    logging.info("Wrote %d lines to %s", len(materialised), destination)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hosts-url",
        default=HOSTS_URL,
        help="URL with the upstream hosts file (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name(OUTPUT_FILENAME),
        help="Destination path for the generated cloaking rules",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    options = parse_args()

    try:
        upstream_hosts = download_hosts(options.hosts_url)
    except FetchError as exc:
        logging.error("Unable to download hosts: %s", exc)
        raise SystemExit(1)

    hostnames = sorted(upstream_hosts)
    answers = query_providers(hostnames)
    grouped = select_disagreements(hostnames, answers)
    lines = render_lines(grouped)
    write_output(options.output, lines)
    records = sum(1 for line in lines if line and not line.startswith("#"))
    logging.info("Generated %d cloaking records", records)


if __name__ == "__main__":
    main()
