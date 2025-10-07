#!/usr/bin/env python3
import base64
import json
import logging
import os
import re
import ssl
import struct
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HOSTS_URL = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
OUTPUT_FILE = "cloaking-rules-2.txt"
BASE_FILE = "example-cloaking-rules.txt"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

COMSS_DOH_ENDPOINTS = [
    "https://dns.comss.one/dns-query",
    "https://router.comss.one/dns-query",
]
ALT_DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]

IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
WHITESPACE_SPLIT_RE = re.compile(r"\s+")


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
LOG = logging.getLogger(__name__)


def fetch(url, headers=None, data=None):
    LOG.info("Requesting resource from %s", url)
    req = Request(url, data=data, headers=headers or {"User-Agent": DEFAULT_USER_AGENT})
    ctx = ssl.create_default_context()
    with urlopen(req, context=ctx) as resp:
        payload = resp.read()
        LOG.info("Retrieved %d bytes from %s", len(payload), url)
        return payload

def get_hosts_from_repo():
    LOG.info("Downloading hosts manifest from upstream repository")
    raw = fetch(HOSTS_URL).decode("utf-8", errors="ignore")
    parsed_hosts = []
    host_redirect_map = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            continue
        parts = WHITESPACE_SPLIT_RE.split(line)
        mapped_ipv4 = None
        if parts and IPV4_REGEX.match(parts[0]):
            candidate_ip = parts[0]
            if not candidate_ip.startswith("0.0.0.0") and not candidate_ip.startswith("127."):
                mapped_ipv4 = candidate_ip
            parts = parts[1:]
        for part in parts:
            if not part:
                continue
            if part.startswith("#"):
                break
            if IPV4_REGEX.match(part):
                continue
            host = part.strip().lower().rstrip(".")
            if host:
                parsed_hosts.append(host)
                if mapped_ipv4:
                    host_redirect_map.setdefault(host, mapped_ipv4)
    seen, uniq = set(), []
    for h in parsed_hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    LOG.info("Collected %d unique host entries from upstream", len(uniq))
    return uniq, host_redirect_map

def to_idna(name):
    try:
        return name.encode("idna").decode("ascii")
    except Exception:
        return name

def encode_qname(name):
    out = b""
    for label in name.split("."):
        b = label.encode("ascii", errors="ignore")
        out += bytes([len(b)]) + b
    return out + b"\x00"

def build_dns_query(name):
    tid = int.from_bytes(os.urandom(2), "big")
    flags = 0x0100
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = encode_qname(to_idna(name))
    qtail = struct.pack(">HH", 1, 1)
    return header + qname + qtail

def read_name(data, offset):
    labels = []
    pos = offset
    jumped = False
    end_pos = None
    while True:
        if pos >= len(data):
            return "", offset
        length = data[pos]
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                return "", offset
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end_pos = pos + 2
            pos = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                end_pos = pos + 1
            break
        pos += 1
        if pos + length > len(data):
            return "", offset
        labels.append(data[pos:pos + length].decode("ascii", errors="ignore"))
        pos += length
    return ".".join(labels), end_pos

def parse_dns_message(data):
    if len(data) < 12:
        return set()
    _, _, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    pos = 12
    for _ in range(qdcount):
        _, pos = read_name(data, pos)
        pos += 4
    ips = set()
    for _ in range(ancount):
        _, pos = read_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ips.add(".".join(str(b) for b in rdata))
    return ips

def doh_wire(base_url, name):
    LOG.info("Sending DoH request to %s for host %s", base_url, name)
    q = build_dns_query(name)
    b64 = base64.urlsafe_b64encode(q).decode().rstrip("=")
    url = f"{base_url}?dns={b64}"
    headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/dns-message"}
    try:
        data = fetch(url, headers=headers)
        ips = parse_dns_message(data)
        LOG.info("DoH response from %s for %s returned: %s", base_url, name, ", ".join(sorted(ips)) or "<none>")
        return ips
    except Exception:
        LOG.exception("DoH request to %s for %s failed", base_url, name)
        return set()

def google_json(name):
    LOG.info("Sending Google DNS JSON request for host %s", name)
    params = {"name": to_idna(name), "type": "A", "cd": "false"}
    url = f"https://dns.google/resolve?{urlencode(params)}"
    headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/dns-json"}
    try:
        data = fetch(url, headers=headers)
        j = json.loads(data.decode("utf-8", errors="ignore"))
        ips = set()
        for ans in j.get("Answer") or []:
            if ans.get("type") == 1:
                d = ans.get("data", "")
                if IPV4_REGEX.match(d):
                    ips.add(d)
        LOG.info("Google DNS response for %s yielded: %s", name, ", ".join(sorted(ips)) or "<none>")
        return ips
    except Exception:
        LOG.exception("Google DNS JSON request for %s failed", name)
        return set()

def resolver_sets(name):
    LOG.info("Aggregating resolver responses for %s", name)
    comss_addresses = set()
    for base in COMSS_DOH_ENDPOINTS:
        comss_addresses |= doh_wire(base, name)
    google_addresses = google_json(name)
    alternate_doh_addresses = set()
    for base in ALT_DOH_ENDPOINTS:
        alternate_doh_addresses |= doh_wire(base, name)
    LOG.info(
        "Resolver summary for %s -> comss: %s | google: %s | alternate DoH: %s",
        name,
        ", ".join(sorted(comss_addresses)) or "<none>",
        ", ".join(sorted(google_addresses)) or "<none>",
        ", ".join(sorted(alternate_doh_addresses)) or "<none>",
    )
    return {
        "comss": comss_addresses,
        "google": google_addresses,
        "yandex_google": alternate_doh_addresses,
    }

def apex_of(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def main():
    LOG.info("Beginning cloaking rule generation")
    all_hosts, host_redirects = get_hosts_from_repo()
    LOG.info("Loaded %d hosts slated for evaluation", len(all_hosts))
    output_lines = []
    if os.path.isfile(BASE_FILE):
        LOG.info("Including base file contents from %s", BASE_FILE)
        with open(BASE_FILE, "r", encoding="utf-8", errors="ignore") as header_file:
            header_contents = header_file.read().rstrip("\n")
            output_lines.append(header_contents)
        output_lines.append("")
    else:
        LOG.info("Base file %s not located", BASE_FILE)
    output_lines.append("# comss dns results")

    rules_written = 0
    for host in all_hosts:
        LOG.info("Evaluating host %s", host)
        resolver_results = resolver_sets(host)
        comss_ips, google_ips, yandex_google_ips = (
            resolver_results["comss"],
            resolver_results["google"],
            resolver_results["yandex_google"],
        )
        if not comss_ips:
            if not (google_ips or yandex_google_ips):
                mapped_ip = host_redirects.get(host)
                if mapped_ip:
                    label = host if host == apex_of(host) else f"={host}"
                    output_lines.append(f"{label} {mapped_ip}")
                    rules_written += 1
                    LOG.info(
                        "Inserted cloaking rule from local mapping: %s -> %s",
                        label,
                        mapped_ip,
                    )
                else:
                    LOG.info("Skipping %s: no resolver returned an address", host)
            else:
                LOG.info(
                    "Skipping %s: COMSS empty while alternative resolvers returned data",
                    host,
                )
            continue
        alternate_ips = google_ips | yandex_google_ips
        differing = comss_ips - alternate_ips if alternate_ips else comss_ips
        if not differing:
            LOG.info(
                "Skipping %s: COMSS answers match alternative resolvers", host
            )
            continue
        chosen_ip = sorted(differing)[0]
        label = host if host == apex_of(host) else f"={host}"
        output_lines.append(f"{label} {chosen_ip}")
        rules_written += 1
        LOG.info("Inserted cloaking rule: %s -> %s", label, chosen_ip)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_handle:
        payload = "\n".join(output_lines).rstrip() + "\n"
        output_handle.write(payload)
        LOG.info(
            "Wrote %d lines (%d rules) to %s",
            len(output_lines),
            rules_written,
            OUTPUT_FILE,
        )

if __name__ == "__main__":
    main()
