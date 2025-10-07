#!/usr/bin/env python3
import base64
import json
import logging
import os
import re
import ssl
import socket
import struct
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HOSTS_URL = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
OUTPUT_FILE = "cloaking-rules-2.txt"
OPTIONAL_HEADER_FILE = "example-cloaking-rules.txt"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger("cloaking-rules-2")

COMSS_DOH = [
    "https://dns.comss.one/dns-query",
    "https://router.comss.one/dns-query",
]
COMSS_DNS_IPS = ["83.220.169.155", "212.109.195.93"]

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SPACE_SPLIT = re.compile(r"\s+")

def fetch(url, headers=None, data=None):
    LOGGER.debug("Fetching URL %s", url)
    req = Request(url, data=data, headers=headers or {"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urlopen(req, context=ctx) as resp:
        payload = resp.read()
        LOGGER.debug(
            "Fetched %s bytes from %s with status %s",
            len(payload),
            url,
            getattr(resp, "status", "unknown"),
        )
        return payload

def get_hosts_from_repo():
    LOGGER.info("Downloading hosts list from %s", HOSTS_URL)
    raw = fetch(HOSTS_URL).decode("utf-8", errors="ignore")
    LOGGER.debug("Processing hosts file with %s bytes", len(raw))
    hosts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = SPACE_SPLIT.split(line)
        if parts and parts[0] in {"0.0.0.0", "127.0.0.1"}:
            logging.debug("Skipping hosts entry with local IP %s: %s", parts[0], line)
            continue
        for part in parts:
            if not part:
                continue
            if part.startswith("#"):
                break
            if IPV4_RE.match(part):
                continue
            host = part.strip().lower().rstrip(".")
            if host:
                LOGGER.debug("Adding host entry %s", host)
                hosts.append(host)
    seen, uniq = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    LOGGER.info("Collected %s unique host entries", len(uniq))
    return uniq

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
    LOGGER.debug("Querying DoH resolver %s for %s", base_url, name)
    q = build_dns_query(name)
    b64 = base64.urlsafe_b64encode(q).decode().rstrip("=")
    url = f"{base_url}?dns={b64}"
    headers = {"User-Agent": UA, "Accept": "application/dns-message"}
    try:
        data = fetch(url, headers=headers)
        ips = parse_dns_message(data)
        LOGGER.debug("Received %s IPs from %s for %s", len(ips), base_url, name)
        return ips
    except Exception as exc:
        LOGGER.warning("Failed DoH query to %s for %s: %s", base_url, name, exc)
        return set()

def google_json(name):
    LOGGER.debug("Querying Google DoH JSON API for %s", name)
    params = {"name": to_idna(name), "type": "A", "cd": "false"}
    url = f"https://dns.google/resolve?{urlencode(params)}"
    headers = {"User-Agent": UA, "Accept": "application/dns-json"}
    try:
        data = fetch(url, headers=headers)
        j = json.loads(data.decode("utf-8", errors="ignore"))
        ips = set()
        for ans in j.get("Answer") or []:
            if ans.get("type") == 1:
                d = ans.get("data", "")
                if IPV4_RE.match(d):
                    ips.add(d)
        LOGGER.debug("Google returned %s IPs for %s", len(ips), name)
        return ips
    except Exception as exc:
        LOGGER.warning("Failed Google query for %s: %s", name, exc)
        return set()

def udp_dns_query(server_ip, name):
    try:
        LOGGER.debug("Sending UDP DNS query to %s for %s", server_ip, name)
        q = build_dns_query(name)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(q, (server_ip, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
        ips = parse_dns_message(data)
        LOGGER.debug(
            "Received %s IPs from UDP resolver %s for %s", len(ips), server_ip, name
        )
        return ips
    except Exception as exc:
        LOGGER.warning("Failed UDP query to %s for %s: %s", server_ip, name, exc)
        return set()

def resolver_sets(name):
    LOGGER.info("Resolving host %s", name)
    comss_ips = set()
    for base in COMSS_DOH:
        comss_ips |= doh_wire(base, name)
    for ip in COMSS_DNS_IPS:
        comss_ips |= udp_dns_query(ip, name)
    google_ips = google_json(name)
    LOGGER.debug(
        "Combined resolver results for %s - comss: %s, google: %s",
        name,
        comss_ips,
        google_ips,
    )
    return {"comss": comss_ips, "google": google_ips}

def apex_of(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def main():
    LOGGER.info("Starting cloaking rules generation")
    all_hosts = get_hosts_from_repo()
    LOGGER.info("Fetched %s hosts to evaluate", len(all_hosts))
    output_lines = []
    if os.path.isfile(OPTIONAL_HEADER_FILE):
        LOGGER.info("Reading optional header from %s", OPTIONAL_HEADER_FILE)
        with open(OPTIONAL_HEADER_FILE, "r", encoding="utf-8", errors="ignore") as f:
            output_lines.append(f.read().rstrip("\n"))
        output_lines.append("")
    else:
        LOGGER.debug("Optional header file %s not found", OPTIONAL_HEADER_FILE)
    output_lines.append("# comss dns results")

    rules_count = 0
    for host in all_hosts:
        sets = resolver_sets(host)
        comss_ips, google_ips = sets["comss"], sets["google"]
        if not comss_ips:
            LOGGER.debug("Skipping %s because comss returned no IPs", host)
            continue
        differing = comss_ips - google_ips if google_ips else comss_ips
        if not differing:
            LOGGER.debug("Skipping %s because results matched Google", host)
            continue
        chosen_ip = sorted(differing)[0]
        label = host if host == apex_of(host) else f"={host}"
        output_lines.append(f"{label} {chosen_ip}")
        LOGGER.debug("Added cloaking rule for %s -> %s", label, chosen_ip)
        rules_count += 1

    LOGGER.info("Writing %s cloaking rules to %s", rules_count, OUTPUT_FILE)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines).rstrip() + "\n")
    LOGGER.info("Finished cloaking rules generation")

if __name__ == "__main__":
    main()
