#!/usr/bin/env python3
"""
Generate per-DNS hosts and cloaking-rules files.

Inputs:
- dns-targets.txt
- hosts.txt (list of URLs to hosts sources)

Outputs:
- <DNS_NAME>-hosts.txt
- <DNS_NAME>-cr.txt
- ReadME.md table
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    import dns.message
    import dns.query
    import dns.rdatatype
except ImportError:
    print("Install dnspython first: pip install dnspython", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[2]
DNS_TARGETS_FILE = ROOT / "dns-targets.txt"
HOSTS_LINKS_FILE = ROOT / "hosts.txt"
README_FILE = ROOT / "ReadME.md"
RAW_BASE_URL = os.environ.get("RAW_BASE_URL", "https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main")

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")

HEADER_CR = """################################
#        Cloaking rules        #
################################

# by sevcator <3
# Enjoy :D

"""

HEADER_HOSTS = """################################
#            Hosts             #
################################

# by sevcator <3
# Enjoy :D

"""

logger = logging.getLogger("build-lists")


@dataclass
class DnsTarget:
    name: str
    doh: str | None
    dot: str | None


def fetch_text(url: str, timeout: int = 25) -> str:
    req = Request(url, headers={"User-Agent": "dns-list-builder/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_dns_targets(text: str) -> list[DnsTarget]:
    targets: list[DnsTarget] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) == 2:
            endpoint, name = parts
            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                targets.append(DnsTarget(name=name, doh=endpoint, dot=None))
            else:
                targets.append(DnsTarget(name=name, doh=None, dot=endpoint))
        elif len(parts) == 3:
            doh, dot, name = parts
            targets.append(DnsTarget(name=name, doh=doh, dot=dot))
        else:
            print(f"Skip malformed dns-targets line: {raw}")
    return targets


def normalize_domain(value: str) -> str | None:
    d = value.strip().lower().rstrip(".")
    if not d or d.startswith("#"):
        return None
    if DOMAIN_RE.match(d):
        return d
    return None


def parse_host_line(line: str) -> tuple[str, str] | None:
    stripped = line.split("#", 1)[0].strip()
    if not stripped:
        return None
    parts = stripped.split()
    if len(parts) < 2:
        return None
    ip = parts[0]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    # skip local sinkhole entries
    if ip in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
        return None
    for candidate in parts[1:]:
        domain = normalize_domain(candidate)
        if domain:
            return str(ip_obj), domain
    return None


def extract_domains_from_sources(links_text: str) -> set[str]:
    domains: set[str] = set()
    links = [ln.strip() for ln in links_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    for link in links:
        try:
            content = fetch_text(link)
        except URLError as exc:
            logger.warning("Failed to fetch %s: %s", link, exc)
            continue
        for line in content.splitlines():
            parsed = parse_host_line(line)
            if parsed:
                _, domain = parsed
                domains.add(domain)
    return domains


def resolve_doh(doh_url: str, domain: str) -> set[str]:
    q = dns.message.make_query(domain, dns.rdatatype.A)
    wire = q.to_wire()
    req = Request(
        doh_url,
        data=wire,
        headers={
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
            "User-Agent": "dns-list-builder/1.0",
        },
        method="POST",
    )
    with urlopen(req, timeout=8) as resp_raw:
        resp = dns.message.from_wire(resp_raw.read())
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_dot(dot_host: str, domain: str) -> set[str]:
    q = dns.message.make_query(domain, dns.rdatatype.A)
    # dnspython handles TLS connection internally
    resp = dns.query.tls(q, dot_host, port=853, timeout=8, server_hostname=dot_host, ssl_context=ssl.create_default_context())
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_public(resolver_ip: str, domain: str) -> set[str]:
    q = dns.message.make_query(domain, dns.rdatatype.A)
    resp = dns.query.udp(q, resolver_ip, timeout=6)
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_target(target: DnsTarget, domain: str) -> set[str]:
    errors: list[str] = []

    if target.doh:
        try:
            return resolve_doh(target.doh, domain)
        except Exception as exc:
            errors.append(f"DoH failed: {exc}")

    if target.dot:
        try:
            return resolve_dot(target.dot, domain)
        except Exception as exc:
            errors.append(f"DoT failed: {exc}")

    if errors:
        raise RuntimeError("; ".join(errors))

    return set()


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(threadName)s | %(message)s",
    )


def should_skip_for_public_match(target_ips: set[str], cf_ips: set[str], gg_ips: set[str]) -> bool:
    if not target_ips:
        return True
    # Drop entry if any IP is shared by at least two of {target, cloudflare, google}
    all_sets = [target_ips, cf_ips, gg_ips]
    counter: Counter[str] = Counter()
    for ips in all_sets:
        for ip in ips:
            counter[ip] += 1
    return any(cnt >= 2 for cnt in counter.values())


def check_https_via_ip(domain: str, ip: str, timeout: float = 12.0) -> bool:
    context = ssl.create_default_context()
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        "User-Agent: dns-list-builder/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")

    try:
        with socket.create_connection((ip, 443), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=domain) as tls_socket:
                tls_socket.settimeout(timeout)
                tls_socket.sendall(request)
                response = tls_socket.recv(64)
        return response.startswith(b"HTTP/")
    except (OSError, ssl.SSLError):
        return False


def write_outputs(target: DnsTarget, records: list[tuple[str, str]]) -> tuple[Path, Path]:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", target.name)
    hosts_path = ROOT / f"{safe_name}-hosts.txt"
    cr_path = ROOT / f"{safe_name}-cr.txt"

    with hosts_path.open("w", encoding="utf-8") as f:
        f.write(HEADER_HOSTS)
        for ip, domain in records:
            f.write(f"{ip} {domain}\n")

    with cr_path.open("w", encoding="utf-8") as f:
        f.write(HEADER_CR)
        for ip, domain in records:
            f.write(f"{domain} {ip}\n")

    return hosts_path, cr_path


def update_readme(rows: list[tuple[str, str, str]]) -> None:
    lines = [
        "# DNS Builds",
        "",
        "DNS | Hosts (Raw) | Cloaking Rules (Raw) |",
        "--- | --- | --- |",
    ]
    for dns_name, hosts_file, cr_file in rows:
        hosts_link = f"[{hosts_file}]({RAW_BASE_URL}/{hosts_file})"
        cr_link = f"[{cr_file}]({RAW_BASE_URL}/{cr_file})"
        lines.append(f"{dns_name} | {hosts_link} | {cr_link} |")
    README_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_public_cache(domains: list[str], resolver: str, workers: int) -> dict[str, set[str]]:
    cache: dict[str, set[str]] = {}
    logger.info("Resolving baseline via %s in parallel (%s domains, %s workers)", resolver, len(domains), workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(resolve_public, resolver, domain): domain for domain in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                cache[domain] = future.result()
            except Exception as exc:
                cache[domain] = set()
                logger.debug("%s baseline lookup failed for %s: %s", resolver, domain, exc)
    return cache


def build_target_records(
    target: DnsTarget,
    domains: list[str],
    cf_cache: dict[str, set[str]],
    gg_cache: dict[str, set[str]],
    workers: int,
) -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    lock = Lock()

    def _process_domain(domain: str) -> None:
        logger.debug("%s: start %s", target.name, domain)
        try:
            target_ips = resolve_target(target, domain)
            if should_skip_for_public_match(target_ips, cf_cache.get(domain, set()), gg_cache.get(domain, set())):
                logger.debug("%s: skipped %s (public overlap/empty)", target.name, domain)
                return
            working_ip: str | None = None
            for ip in sorted(target_ips):
                logger.debug("%s: check %s via %s", target.name, domain, ip)
                if check_https_via_ip(domain, ip):
                    working_ip = ip
                    break

            if not working_ip:
                logger.debug("%s: skipped %s (no working HTTPS IP)", target.name, domain)
                return

            with lock:
                records.append((working_ip, domain))
            logger.debug("%s: accepted %s -> %s", target.name, domain, working_ip)
        except Exception as exc:
            logger.debug("%s: %s skipped (%s)", target.name, domain, exc)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_process_domain, domain) for domain in domains]
        for future in as_completed(futures):
            future.result()
    return sorted(records, key=lambda x: (x[1], x[0]))


def main() -> int:
    debug = os.environ.get("DEBUG", "").lower() in {"1", "true", "yes", "on"}
    workers = int(os.environ.get("WORKERS", "40"))
    configure_logging(debug)

    if not DNS_TARGETS_FILE.exists() or not HOSTS_LINKS_FILE.exists():
        logger.error("Need dns-targets.txt and hosts.txt in repo root")
        return 2

    targets = parse_dns_targets(DNS_TARGETS_FILE.read_text(encoding="utf-8"))
    if not targets:
        logger.error("No dns targets found")
        return 3

    domains = sorted(extract_domains_from_sources(HOSTS_LINKS_FILE.read_text(encoding="utf-8")))
    logger.info("Loaded domains: %s", len(domains))

    readme_rows: list[tuple[str, str, str]] = []
    cf_cache = build_public_cache(domains, "1.1.1.1", workers)
    gg_cache = build_public_cache(domains, "8.8.8.8", workers)

    for target in targets:
        logger.info("Processing target: %s", target.name)
        records = build_target_records(target, domains, cf_cache, gg_cache, workers)
        hosts_path, cr_path = write_outputs(target, records)
        readme_rows.append((target.name, hosts_path.name, cr_path.name))
        logger.info("%s: wrote %s records", target.name, len(records))

    update_readme(readme_rows)
    logger.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
