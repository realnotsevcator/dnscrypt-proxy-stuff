#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import base64
import logging
import os
import fnmatch
import random
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
WORKING_DIR = ROOT / ".github" / "working"
DNS_TARGETS_FILE = WORKING_DIR / "dns-targets.txt"
HOSTS_LINKS_FILE = WORKING_DIR / "hosts.txt"
BLACKLIST_FILE = WORKING_DIR / "blacklist.txt"
NO_SIMPLIFY_FILE = WORKING_DIR / "no-simpify.txt"
README_FILE = ROOT / "README.md"
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


@dataclass
class DnsTarget:
    name: str
    doh: str | None
    dot: str | None


@dataclass
class DotEndpoint:
    host: str
    port: int = 853


def fetch_text(url: str, timeout: int = 25) -> str:
    req = Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
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


def parse_dot_endpoint(dot_value: str) -> DotEndpoint:
    value = dot_value.strip()
    if not value:
        raise ValueError("DoT endpoint is empty")

    if value.startswith("tls://"):
        value = value[len("tls://"):]

    if not value:
        raise ValueError("DoT endpoint host is empty")

    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            raise ValueError("Malformed IPv6 DoT endpoint")
        host = value[1:closing]
        remainder = value[closing + 1 :]
        if remainder.startswith(":"):
            port = int(remainder[1:])
        elif remainder:
            raise ValueError("Malformed IPv6 DoT endpoint")
        else:
            port = 853
    else:
        host_port = value.rsplit(":", 1)
        if len(host_port) == 2 and host_port[1].isdigit():
            host, port_raw = host_port
            port = int(port_raw)
        else:
            host = value
            port = 853

    host = host.strip().rstrip(".")
    if not host:
        raise ValueError("DoT endpoint host is empty")
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid DoT port: {port}")

    return DotEndpoint(host=host, port=port)


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
    common_headers = {
        "Accept": "application/dns-message",
        "User-Agent": random.choice(USER_AGENTS),
    }
    try:
        req = Request(
            doh_url,
            data=wire,
            headers={
                **common_headers,
                "Content-Type": "application/dns-message",
            },
            method="POST",
        )
        with urlopen(req, timeout=8) as resp_raw:
            resp = dns.message.from_wire(resp_raw.read())
    except Exception:
        encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
        separator = "&" if "?" in doh_url else "?"
        get_url = f"{doh_url}{separator}dns={encoded}"
        req = Request(get_url, headers=common_headers, method="GET")
        with urlopen(req, timeout=8) as resp_raw:
            resp = dns.message.from_wire(resp_raw.read())
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_dot(dot_host: str, domain: str, timeout: float = 8.0) -> set[str]:
    endpoint = parse_dot_endpoint(dot_host)
    q = dns.message.make_query(domain, dns.rdatatype.A)
    wire = q.to_wire()
    context = ssl.create_default_context()
    packet = len(wire).to_bytes(2, "big") + wire

    with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as tcp_socket:
        with context.wrap_socket(tcp_socket, server_hostname=endpoint.host) as tls_socket:
            tls_socket.settimeout(timeout)
            tls_socket.sendall(packet)

            length_raw = tls_socket.recv(2)
            if len(length_raw) < 2:
                raise RuntimeError("DoT server closed connection before response length")
            expected = int.from_bytes(length_raw, "big")
            payload = b""
            while len(payload) < expected:
                chunk = tls_socket.recv(expected - len(payload))
                if not chunk:
                    raise RuntimeError("DoT server closed connection before full response")
                payload += chunk

    resp = dns.message.from_wire(payload)
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_public(resolver_ip: str, domain: str) -> set[str]:
    q = dns.message.make_query(domain, dns.rdatatype.A)
    resp = dns.query.udp(q, resolver_ip, timeout=6)
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_target(target: DnsTarget, domain: str) -> set[str]:
    collected: set[str] = set()
    errors: list[str] = []

    if target.doh:
        try:
            collected.update(resolve_doh(target.doh, domain))
        except Exception as exc:
            errors.append(f"DoH failed ({type(exc).__name__}): {exc}")

    if target.dot:
        try:
            collected.update(resolve_dot(target.dot, domain))
        except Exception as exc:
            errors.append(f"DoT failed ({type(exc).__name__}): {exc}")

    if collected:
        return collected

    if errors:
        raise RuntimeError("; ".join(errors))

    return set()


def configure_logging(debug: bool) -> None:
    # Console output should include only warnings and errors.
    logging.basicConfig(
        level=logging.WARNING,
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
        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
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


def load_patterns(path: Path) -> list[str]:
    if not path.exists():
        return []
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lower()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def matches_patterns(domain: str, patterns: list[str]) -> bool:
    d = domain.lower()
    return any(fnmatch.fnmatch(d, p) for p in patterns)


def simplify_cloaking_records(records: list[tuple[str, str]], no_simplify_patterns: list[str]) -> list[tuple[str, str]]:
    grouped: dict[tuple[str, str], list[str]] = {}
    passthrough: list[tuple[str, str]] = []
    for ip, domain in records:
        if matches_patterns(domain, no_simplify_patterns):
            passthrough.append((ip, domain))
            continue
        parts = domain.split(".")
        if len(parts) < 2:
            passthrough.append((ip, domain))
            continue
        root_domain = ".".join(parts[-2:])
        grouped.setdefault((ip, root_domain), []).append(domain)

    simplified: list[tuple[str, str]] = list(passthrough)
    for (ip, root_domain), domains in grouped.items():
        unique = sorted(set(domains))
        # keep only root-domain rule when we have enough subdomain variants
        if root_domain in unique and len(unique) >= 4 and not matches_patterns(root_domain, no_simplify_patterns):
            simplified.append((ip, root_domain))
            continue
        for domain in unique:
            simplified.append((ip, f"={domain}"))
    return sorted(simplified, key=lambda x: (x[1], x[0]))


def write_outputs(
    target: DnsTarget,
    records: list[tuple[str, str]],
    blacklist_patterns: list[str],
    no_simplify_patterns: list[str],
) -> tuple[Path, Path]:
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", target.name)
    hosts_dir = ROOT / "hosts"
    cr_dir = ROOT / "cr"
    hosts_dir.mkdir(parents=True, exist_ok=True)
    cr_dir.mkdir(parents=True, exist_ok=True)

    filtered_records = [(ip, domain) for ip, domain in records if not matches_patterns(domain, blacklist_patterns)]
    hosts_path = hosts_dir / f"{safe_name}.txt"
    cr_path = cr_dir / f"{safe_name}.txt"

    with hosts_path.open("w", encoding="utf-8") as f:
        f.write(HEADER_HOSTS)
        for ip, domain in filtered_records:
            f.write(f"{ip} {domain}\n")

    cloaking_records = simplify_cloaking_records(filtered_records, no_simplify_patterns)
    with cr_path.open("w", encoding="utf-8") as f:
        f.write(HEADER_CR)
        for ip, domain in cloaking_records:
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
        hosts_link = f"[{hosts_file}]({RAW_BASE_URL}/hosts/{hosts_file})"
        cr_link = f"[{cr_file}]({RAW_BASE_URL}/cr/{cr_file})"
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
        except RuntimeError as exc:
            logger.warning("%s: %s skipped (%s)", target.name, domain, exc)
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
        logger.error("Need dns-targets.txt and hosts.txt in .github/working")
        return 2

    targets = parse_dns_targets(DNS_TARGETS_FILE.read_text(encoding="utf-8"))
    if not targets:
        logger.error("No dns targets found")
        return 3

    domains = sorted(extract_domains_from_sources(HOSTS_LINKS_FILE.read_text(encoding="utf-8")))
    blacklist_patterns = load_patterns(BLACKLIST_FILE)
    no_simplify_patterns = load_patterns(NO_SIMPLIFY_FILE)
    logger.info("Loaded domains: %s", len(domains))

    readme_rows: list[tuple[str, str, str]] = []
    cf_cache = build_public_cache(domains, "1.1.1.1", workers)
    gg_cache = build_public_cache(domains, "8.8.8.8", workers)

    for target in targets:
        logger.info("Processing target: %s", target.name)
        records = build_target_records(target, domains, cf_cache, gg_cache, workers)
        hosts_path, cr_path = write_outputs(target, records, blacklist_patterns, no_simplify_patterns)
        readme_rows.append((target.name, hosts_path.name, cr_path.name))
        logger.info("%s: wrote %s records", target.name, len(records))

    update_readme(readme_rows)
    logger.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
