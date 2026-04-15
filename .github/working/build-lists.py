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
import subprocess
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

ROOT = Path(__file__).resolve().parent
WORKING_DIR = ROOT
DNS_TARGETS_FILE = WORKING_DIR / "dns-targets.txt"
HOSTS_LINKS_FILE = WORKING_DIR / "hosts.txt"
BLACKLIST_FILE = WORKING_DIR / "blacklist.txt"
NO_SIMPLIFY_FILE = WORKING_DIR / "no-simplify.txt"
CUSTOM_FILE = WORKING_DIR / "custom.txt"
README_FILE = ROOT / "README.md"
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "sevcator/dnscrypt-proxy-stuff")
GITHUB_REF_NAME = os.environ.get("GITHUB_REF_NAME", "main")
RAW_BASE_URL = os.environ.get("RAW_BASE_URL", f"https://raw.githubusercontent.com/{GITHUB_REPOSITORY}/{GITHUB_REF_NAME}")
ZAPRET_HOSTS_URL = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"

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

MAX_DNS_FAILURES = 3
PROGRESS_LOG_EVERY = 10
DOH_TIMEOUT = float(os.environ.get("DOH_TIMEOUT", "5"))
DOT_TIMEOUT = float(os.environ.get("DOT_TIMEOUT", "5"))
PUBLIC_DNS_TIMEOUT = float(os.environ.get("PUBLIC_DNS_TIMEOUT", "4"))
HTTPS_TIMEOUT = float(os.environ.get("HTTPS_TIMEOUT", "5"))
MAX_FALLBACK_IPS = int(os.environ.get("MAX_FALLBACK_IPS", "12"))
FALLBACK_PROGRESS_LOG_EVERY = int(os.environ.get("FALLBACK_PROGRESS_LOG_EVERY", "5"))


@dataclass
class DnsTarget:
    name: str
    doh: str | None
    dot: str | None


@dataclass
class DotEndpoint:
    host: str
    port: int = 853


@dataclass
class TargetFailureState:
    failures: int = 0
    disabled: bool = False


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
    records = parse_host_line_records(line)
    if not records:
        return None
    return records[0]


def parse_host_line_records(line: str) -> list[tuple[str, str]]:
    stripped = line.split("#", 1)[0].strip()
    if not stripped:
        return []
    parts = stripped.split()
    if len(parts) < 2:
        return []
    ip = parts[0]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return []
    # skip local sinkhole entries
    if ip in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
        return []
    records: list[tuple[str, str]] = []
    for candidate in parts[1:]:
        domain = normalize_domain(candidate)
        if domain:
            records.append((str(ip_obj), domain))
    return records


def extract_domains_from_sources(links_text: str) -> set[str]:
    domains: set[str] = set()
    links = [ln.strip() for ln in links_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    for link in links:
        try:
            content = fetch_text(link)
        except URLError as exc:
            logger.warning("Failed to fetch %s: %s", link, exc)
            continue
        for ip, domain in extract_records_from_text(content):
            domains.add(domain)
    return domains


def extract_source_records(links_text: str) -> dict[str, set[str]]:
    records_by_domain: dict[str, set[str]] = {}
    links = [ln.strip() for ln in links_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    for link in links:
        try:
            content = fetch_text(link)
        except URLError as exc:
            logger.warning("Failed to fetch %s: %s", link, exc)
            continue
        for ip, domain in extract_records_from_text(content):
            records_by_domain.setdefault(domain, set()).add(ip)
    return records_by_domain


def extract_records_from_text(text: str) -> list[tuple[str, str]]:
    records: set[tuple[str, str]] = set()
    for line in text.splitlines():
        records.update(parse_host_line_records(line))
    return sorted(records, key=lambda x: (x[1], x[0]))


def extract_records_from_url(url: str) -> list[tuple[str, str]]:
    try:
        content = fetch_text(url)
    except URLError as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return []
    return extract_records_from_text(content)


def resolve_doh(doh_url: str, domain: str, timeout: float = DOH_TIMEOUT) -> set[str]:
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
        with urlopen(req, timeout=timeout) as resp_raw:
            resp = dns.message.from_wire(resp_raw.read())
    except Exception:
        encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
        separator = "&" if "?" in doh_url else "?"
        get_url = f"{doh_url}{separator}dns={encoded}"
        req = Request(get_url, headers=common_headers, method="GET")
        with urlopen(req, timeout=timeout) as resp_raw:
            resp = dns.message.from_wire(resp_raw.read())
    return {rr.to_text() for ans in resp.answer for rr in ans if rr.rdtype == dns.rdatatype.A}


def resolve_dot(dot_host: str, domain: str, timeout: float = DOT_TIMEOUT) -> set[str]:
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
    resp = dns.query.udp(q, resolver_ip, timeout=PUBLIC_DNS_TIMEOUT)
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
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(threadName)s | %(message)s",
    )


def should_skip_for_public_match(
    target_ips: set[str],
    cf_ips: set[str],
    gg_ips: set[str],
    q9_ips: set[str],
) -> bool:
    if not target_ips:
        return True
    # Drop entry if any IP is shared by at least two of {target, cloudflare, google, quad9}
    all_sets = [target_ips, cf_ips, gg_ips, q9_ips]
    counter: Counter[str] = Counter()
    for ips in all_sets:
        for ip in ips:
            counter[ip] += 1
    return any(cnt >= 2 for cnt in counter.values())


def check_https_via_ip(domain: str, ip: str, timeout: float = HTTPS_TIMEOUT) -> bool:
    check_domain = domain[2:] if domain.startswith("*.") else domain
    if not check_domain:
        return False

    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "NUL",
        "--head",
        "--location",
        "--ipv4",
        "--resolve",
        f"{check_domain}:443:{ip}",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
        f"https://{check_domain}/",
    ]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=max(timeout + 1, 1),
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
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


def load_custom_domains(path: Path) -> list[str]:
    if not path.exists():
        return []

    custom_domains: list[str] = []
    seen_domains: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        custom_domains.append(domain)
    return custom_domains


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
        unique: list[str] = []
        seen_domains: set[str] = set()
        for domain in domains:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            unique.append(domain)
        # keep only root-domain rule when we have enough subdomain variants
        if root_domain in unique and len(unique) >= 4 and not matches_patterns(root_domain, no_simplify_patterns):
            simplified.append((ip, root_domain))
            continue
        for domain in unique:
            simplified.append((ip, f"={domain}"))
    return simplified


def merge_records_preserving_order(*record_groups: list[tuple[str, str]]) -> list[tuple[str, str]]:
    merged: list[tuple[str, str]] = []
    seen_domains: set[str] = set()
    for group in record_groups:
        for ip, domain in group:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            merged.append((ip, domain))
    return merged


def extend_records_with_custom_domains(
    records: list[tuple[str, str]],
    custom_domains: list[str],
) -> list[tuple[str, str]]:
    if not custom_domains:
        return list(records)

    extended = list(records)
    seen_pairs = set(records)
    seen_ips: set[str] = set()
    ordered_ips: list[str] = []

    for ip, _domain in records:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        ordered_ips.append(ip)

    for ip in ordered_ips:
        for custom_domain in custom_domains:
            pair = (ip, custom_domain)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            extended.append(pair)

    return extended


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


def cleanup_output_dirs() -> None:
    for directory in (ROOT / "hosts", ROOT / "cr"):
        if not directory.exists():
            continue
        for path in directory.glob("*.txt"):
            path.unlink()


def update_readme(rows: list[tuple[str, str, str, str, str]]) -> None:
    lines = [
        "# DNS Builds",
        "",
        "DNS | Hosts | Cloaking Rules | Hosts (+ Flowseal) | Cloaking Rules (+ Flowseal) |",
        "--- | --- | --- | --- | --- |",
    ]
    for dns_name, hosts_file, cr_file, flow_hosts_file, flow_cr_file in rows:
        hosts_link = f"[{hosts_file}]({RAW_BASE_URL}/hosts/{hosts_file})"
        cr_link = f"[{cr_file}]({RAW_BASE_URL}/cr/{cr_file})"
        flow_hosts_link = f"[{flow_hosts_file}]({RAW_BASE_URL}/hosts/{flow_hosts_file})"
        flow_cr_link = f"[{flow_cr_file}]({RAW_BASE_URL}/cr/{flow_cr_file})"
        lines.append(f"{dns_name} | {hosts_link} | {cr_link} | {flow_hosts_link} | {flow_cr_link} |")
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


def extend_public_cache(
    cache: dict[str, set[str]],
    domains: list[str],
    resolver: str,
    workers: int,
) -> dict[str, set[str]]:
    missing_domains = [domain for domain in domains if domain not in cache]
    if not missing_domains:
        return cache
    extended = dict(cache)
    extended.update(build_public_cache(missing_domains, resolver, workers))
    return extended


def build_target_records(
    target: DnsTarget,
    source_records_by_domain: dict[str, set[str]],
    workers: int,
) -> tuple[list[tuple[str, str]], set[str], set[str]]:
    domains = sorted(source_records_by_domain)
    records: list[tuple[str, str]] = []
    unresolved_domains: set[str] = set()
    discovered_ips: set[str] = set()
    lock = Lock()
    failure_state = TargetFailureState()
    total_domains = len(domains)
    processed_count = 0

    def _log_progress(force: bool = False) -> None:
        with lock:
            processed = processed_count
            accepted = len(records)
            unresolved = len(unresolved_domains)
            failures = failure_state.failures
            disabled = failure_state.disabled

        if force or processed == total_domains or (processed > 0 and processed % PROGRESS_LOG_EVERY == 0):
            suffix = " [disabled]" if disabled else ""
            logger.info(
                "%s: progress %s/%s, accepted=%s, unresolved=%s, dns_failures=%s%s",
                target.name,
                processed,
                total_domains,
                accepted,
                unresolved,
                failures,
                suffix,
            )

    def _register_dns_failure(domain: str, exc: Exception) -> None:
        with lock:
            if failure_state.disabled:
                return
            failure_state.failures += 1
            failures = failure_state.failures
            if failures >= MAX_DNS_FAILURES:
                failure_state.disabled = True
                logger.warning(
                    "%s: disabled after %s DNS failures, removing from queue (%s on %s)",
                    target.name,
                    failures,
                    exc,
                    domain,
                )

    def _finish_domain() -> None:
        nonlocal processed_count
        with lock:
            processed_count += 1
        _log_progress()

    def _process_domain(domain: str) -> tuple[str, str | None, set[str]]:
        logger.debug("%s: start %s", target.name, domain)

        source_ips = sorted(source_records_by_domain.get(domain, set()))
        target_ips: set[str] = set()

        with lock:
            dns_disabled = failure_state.disabled

        if not dns_disabled:
            try:
                target_ips = resolve_target(target, domain)
            except RuntimeError as exc:
                _register_dns_failure(domain, exc)
                logger.warning("%s: %s DNS skipped (%s)", target.name, domain, exc)
            except Exception as exc:
                _register_dns_failure(domain, exc)
                logger.debug("%s: %s DNS skipped (%s)", target.name, domain, exc)

        candidate_ips: list[str] = []
        seen_ips: set[str] = set()
        for ip in source_ips + sorted(target_ips):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            candidate_ips.append(ip)

        working_ip: str | None = None
        for ip in candidate_ips:
            logger.debug("%s: check %s via %s", target.name, domain, ip)
            if check_https_via_ip(domain, ip):
                working_ip = ip
                break

        if not working_ip:
            logger.debug("%s: skipped %s (no working source/DNS IP)", target.name, domain)
        else:
            logger.debug("%s: accepted %s -> %s", target.name, domain, working_ip)

        return domain, working_ip, target_ips

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_process_domain, domain): domain for domain in domains}
        for future in as_completed(futures):
            domain, working_ip, target_ips = future.result()
            if target_ips:
                with lock:
                    discovered_ips.update(target_ips)
            if working_ip:
                with lock:
                    records.append((working_ip, domain))
            else:
                with lock:
                    unresolved_domains.add(domain)
            _finish_domain()

    _log_progress(force=True)

    return sorted(records, key=lambda x: (x[1], x[0])), unresolved_domains, discovered_ips


def apply_known_ip_fallback(
    target_name: str,
    records: list[tuple[str, str]],
    unresolved_domains: set[str],
    target_known_ips: set[str],
    workers: int,
) -> list[tuple[str, str]]:
    if not unresolved_domains:
        return sorted(records, key=lambda x: (x[1], x[0]))

    resolved_domains = {domain for _, domain in records}
    updated_records = list(records)
    fallback_domains = sorted(unresolved_domains)
    candidate_ips = sorted(target_known_ips)

    if not candidate_ips:
        logger.info("%s: fallback skipped, no recognized IPs collected", target_name)
        return sorted(records, key=lambda x: (x[1], x[0]))

    logger.info(
        "%s: starting fallback for %s unresolved domains using %s recognized IPs",
        target_name,
        len(fallback_domains),
        len(candidate_ips),
    )

    def _log_fallback_progress(processed: int, resolved_now: int, force: bool = False) -> None:
        if force or processed == len(fallback_domains) or (
            processed > 0 and processed % FALLBACK_PROGRESS_LOG_EVERY == 0
        ):
            logger.info(
                "%s: fallback progress %s/%s, added=%s",
                target_name,
                processed,
                len(fallback_domains),
                resolved_now,
            )

    fallback_added = 0
    lock = Lock()

    def _process_domain(domain: str) -> tuple[str, str] | None:
        if domain in resolved_domains:
            return None
        for ip in candidate_ips:
            logger.debug("%s: fallback check %s via %s", target_name, domain, ip)
            if not check_https_via_ip(domain, ip):
                continue
            logger.debug("%s: fallback accepted %s -> %s", target_name, domain, ip)
            return (ip, domain)
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_process_domain, domain): domain for domain in fallback_domains}
        for index, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            if result is not None:
                with lock:
                    ip, domain = result
                    if domain not in resolved_domains:
                        updated_records.append((ip, domain))
                        resolved_domains.add(domain)
                        fallback_added += 1
            _log_fallback_progress(index, fallback_added)

    _log_fallback_progress(len(fallback_domains), fallback_added, force=True)

    return sorted(updated_records, key=lambda x: (x[1], x[0]))


def main() -> int:
    debug = os.environ.get("DEBUG", "").lower() in {"1", "true", "yes", "on"}
    workers = int(os.environ.get("WORKERS", "40"))
    configure_logging(debug)

    if not DNS_TARGETS_FILE.exists() or not HOSTS_LINKS_FILE.exists():
        logger.error("Need dns-targets.txt and hosts.txt in %s", WORKING_DIR)
        return 2

    targets = parse_dns_targets(DNS_TARGETS_FILE.read_text(encoding="utf-8"))
    if not targets:
        logger.error("No dns targets found")
        return 3

    source_records_by_domain = extract_source_records(HOSTS_LINKS_FILE.read_text(encoding="utf-8"))
    domains = sorted(source_records_by_domain)
    blacklist_patterns = load_patterns(BLACKLIST_FILE)
    no_simplify_patterns = load_patterns(NO_SIMPLIFY_FILE)
    custom_domains = load_custom_domains(CUSTOM_FILE)
    logger.info("Loaded domains: %s", len(domains))
    if custom_domains:
        logger.info("Loaded custom domains: %s", len(custom_domains))

    cleanup_output_dirs()

    target_records: dict[str, list[tuple[str, str]]] = {}
    target_unresolved: dict[str, set[str]] = {}
    target_known_ips: dict[str, set[str]] = {}

    for target in targets:
        logger.info("Processing target: %s", target.name)
        records, unresolved, discovered_ips = build_target_records(
            target,
            source_records_by_domain,
            workers,
        )
        target_records[target.name] = records
        target_unresolved[target.name] = unresolved
        target_known_ips[target.name] = discovered_ips

    final_records_by_target: dict[str, list[tuple[str, str]]] = {}
    readme_rows: list[tuple[str, str, str, str, str]] = []
    for target in targets:
        records = apply_known_ip_fallback(
            target_name=target.name,
            records=target_records.get(target.name, []),
            unresolved_domains=target_unresolved.get(target.name, set()),
            target_known_ips=target_known_ips.get(target.name, set()),
            workers=workers,
        )
        records = extend_records_with_custom_domains(records, custom_domains)
        final_records_by_target[target.name] = records
        hosts_path, cr_path = write_outputs(target, records, blacklist_patterns, no_simplify_patterns)
        logger.info("%s: wrote %s records", target.name, len(records))

    logger.info("Preparing -zapret builds")
    zapret_records = extract_records_from_url(ZAPRET_HOSTS_URL)

    for target in targets:
        zapret_target = DnsTarget(
            name=f"{target.name}-zapret",
            doh=target.doh,
            dot=target.dot,
        )
        records = merge_records_preserving_order(
            final_records_by_target.get(target.name, []),
            zapret_records,
        )
        hosts_path, cr_path = write_outputs(zapret_target, records, blacklist_patterns, no_simplify_patterns)
        base_target_hosts = f"{re.sub(r'[^A-Za-z0-9._-]+', '_', target.name)}.txt"
        base_target_cr = f"{re.sub(r'[^A-Za-z0-9._-]+', '_', target.name)}.txt"
        readme_rows.append((target.name, base_target_hosts, base_target_cr, hosts_path.name, cr_path.name))
        logger.info("%s: wrote %s records", zapret_target.name, len(records))

    update_readme(readme_rows)
    logger.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
