"""Generate dnscrypt-proxy cloaking rules where resolvers disagree."""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import logging
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Sequence
from urllib import error, parse, request


HOSTS_URL = (
    "https://raw.githubusercontent.com/ImMALWARE/"
    "dns.malw.link/refs/heads/master/hosts"
)
OUTPUT_FILENAME = "cloaking-rules-2.txt"
EXAMPLE_HEADER_NAME = "example-cloaking-rules.txt"
TIMEOUT = 15
MAX_WORKERS = 8
USER_AGENT = "dnscrypt-proxy-cloaking-updater/4.0"


@dataclasses.dataclass(frozen=True)
class Provider:
    """Representation of a DoH JSON provider."""

    name: str
    endpoint: str


PROVIDERS: tuple[Provider, ...] = (
    Provider("comss", "https://dns.comss.one/dns-query"),
    Provider("google", "https://dns.google/dns-query"),
    Provider("cloudflare", "https://dns.cloudflare.com/dns-query"),
)


class FetchError(RuntimeError):
    """Raised when an HTTP request fails."""


class ResponseFormatError(RuntimeError):
    """Raised when a DoH response is malformed."""


def fetch_text(
    url: str,
    params: Mapping[str, str] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
) -> str:
    """Return the HTTP response body decoded as text."""

    if params:
        url = f"{url}?{parse.urlencode(params)}"
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    request_obj = request.Request(url, headers=request_headers)
    try:
        with request.urlopen(request_obj, timeout=TIMEOUT) as response:
            body = response.read()
            encoding = response.headers.get_content_charset("utf-8")
            return body.decode(encoding, errors="replace")
    except error.HTTPError as exc:  # pragma: no cover - network failure
        raise FetchError(f"failed to fetch {url}: HTTP {exc.code}") from exc
    except error.URLError as exc:  # pragma: no cover - network failure
        raise FetchError(f"failed to fetch {url}: {exc}") from exc


def parse_hosts(payload: str) -> Dict[str, List[str]]:
    """Parse a hosts file into ``hostname -> sorted list of IPs``."""

    hosts: Dict[str, set[str]] = defaultdict(set)
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        candidate_ip, hostname = parts[0], parts[1].lower()
        try:
            ipaddress.ip_address(candidate_ip)
        except ValueError:
            continue
        hosts[hostname].add(candidate_ip)
    return {host: sorted(addresses) for host, addresses in hosts.items()}


def download_hosts(url: str) -> Dict[str, List[str]]:
    logging.info("Downloading upstream hosts list from %s", url)
    text = fetch_text(url)
    parsed = parse_hosts(text)
    logging.info("Loaded %d unique hostnames from upstream list", len(parsed))
    return parsed


def _parse_answers(payload: str) -> List[str]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:  # pragma: no cover - network failure
        raise ResponseFormatError(f"invalid JSON payload: {exc}") from exc

    status = int(data.get("Status", 0))
    if status != 0:
        raise ResponseFormatError(f"DoH query failed with status {status}")

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
    return sorted(ips)


def query_provider(provider: Provider, host: str) -> List[str]:
    params = {"name": host, "type": "A"}
    try:
        payload = fetch_text(
            provider.endpoint,
            params,
            headers={"Accept": "application/dns-json"},
        )
    except FetchError as exc:
        logging.warning("%s query for %s failed: %s", provider.name, host, exc)
        return []

    try:
        ips = _parse_answers(payload)
    except ResponseFormatError as exc:
        logging.warning("%s query for %s returned malformed data: %s", provider.name, host, exc)
        return []

    if ips:
        logging.info("DNS %s -> %s: %s", provider.name, host, ", ".join(ips))
    else:
        logging.info("DNS %s -> %s: no data", provider.name, host)
    return ips


def query_providers(
    hostnames: Sequence[str],
    providers: Sequence[Provider],
    *,
    max_workers: int = MAX_WORKERS,
) -> Dict[str, Dict[str, List[str]]]:
    """Resolve all hostnames against all providers."""

    def resolve_single(host: str) -> tuple[str, Dict[str, List[str]]]:
        results: Dict[str, List[str]] = {}
        for provider in providers:
            results[provider.name] = query_provider(provider, host)
        return host, results

    cache: Dict[str, Dict[str, List[str]]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map: Dict[Future[tuple[str, Dict[str, List[str]]]], str] = {
            executor.submit(resolve_single, host): host for host in hostnames
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                _, resolved = future.result()
            except Exception as exc:  # pragma: no cover - defensive programming
                logging.error("DNS lookups for %s failed: %s", host, exc)
                resolved = {}
            cache[host] = resolved
    return cache


def registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def select_disagreements(
    hostnames: Iterable[str],
    answers: Mapping[str, Mapping[str, List[str]]],
    primary_provider: str,
    secondary_providers: Iterable[str],
) -> Dict[str, Dict[tuple[str, ...], List[str]]]:
    grouped: Dict[str, Dict[tuple[str, ...], List[str]]] = defaultdict(lambda: defaultdict(list))
    secondary_list = list(secondary_providers)
    for host in hostnames:
        host_answers = answers.get(host, {})
        primary = host_answers.get(primary_provider, [])
        if not primary:
            continue
        if any(primary == host_answers.get(other, []) for other in secondary_list):
            continue
        base = registrable_domain(host)
        grouped[base][tuple(primary)].append(host)

        others = {other: host_answers.get(other, []) for other in secondary_list}
        summary = "; ".join(
            f"{name}={','.join(values) if values else 'no data'}"
            for name, values in sorted(others.items())
        )
        logging.info(
            "Using %s result for %s -> %s (others: %s)",
            primary_provider,
            host,
            ", ".join(primary),
            summary,
        )
    return grouped


def _iter_entries(grouped: Mapping[str, Mapping[tuple[str, ...], List[str]]]) -> Iterator[tuple[str, str]]:
    for base, ip_groups in sorted(grouped.items()):
        if len(ip_groups) == 1:
            ips = next(iter(ip_groups))
            for ip in ips:
                yield base, ip
            continue
        for ips, hosts in sorted(ip_groups.items()):
            for host in sorted(hosts):
                alias = f"={host}"
                for ip in ips:
                    yield alias, ip


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

    for name, ip in _iter_entries(grouped):
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
    parser.add_argument(
        "--max-workers",
        type=int,
        default=MAX_WORKERS,
        help="Number of concurrent workers for DNS lookups",
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
    answers = query_providers(hostnames, list(PROVIDERS), max_workers=options.max_workers)

    primary_provider = PROVIDERS[0].name
    secondary_providers = [provider.name for provider in PROVIDERS[1:]]
    grouped = select_disagreements(hostnames, answers, primary_provider, secondary_providers)
    lines = render_lines(grouped)
    write_output(options.output, lines)

    records = sum(1 for line in lines if line and not line.startswith("#"))
    logging.info("Generated %d cloaking records", records)


if __name__ == "__main__":
    main()

