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

COMSS_DOH = [
    "https://dns.comss.one/dns-query",
    "https://router.comss.one/dns-query",
]
COMSS_DNS_IPS = ["83.220.169.155", "212.109.195.93"]

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SPACE_SPLIT = re.compile(r"\s+")


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
LOGGER = logging.getLogger(__name__)


def fetch(url, headers=None, data=None):
    LOGGER.info("Fetching URL: %s", url)
    req = Request(url, data=data, headers=headers or {"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urlopen(req, context=ctx) as resp:
        payload = resp.read()
        LOGGER.info("Received %d bytes from %s", len(payload), url)
        return payload

def get_hosts_from_repo():
    LOGGER.info("Downloading hosts list from repository")
    raw = fetch(HOSTS_URL).decode("utf-8", errors="ignore")
    hosts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            continue
        parts = SPACE_SPLIT.split(line)
        for part in parts:
            if not part:
                continue
            if part.startswith("#"):
                break
            if IPV4_RE.match(part):
                continue
            host = part.strip().lower().rstrip(".")
            if host:
                hosts.append(host)
    seen, uniq = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    LOGGER.info("Collected %d unique hosts from repository", len(uniq))
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
    LOGGER.info("Querying DoH endpoint %s for %s", base_url, name)
    q = build_dns_query(name)
    b64 = base64.urlsafe_b64encode(q).decode().rstrip("=")
    url = f"{base_url}?dns={b64}"
    headers = {"User-Agent": UA, "Accept": "application/dns-message"}
    try:
        data = fetch(url, headers=headers)
        ips = parse_dns_message(data)
        LOGGER.info("DoH response from %s for %s: %s", base_url, name, ", ".join(sorted(ips)) or "<none>")
        return ips
    except Exception:
        LOGGER.exception("Failed DoH query against %s for %s", base_url, name)
        return set()

def google_json(name):
    LOGGER.info("Querying Google DNS JSON API for %s", name)
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
        LOGGER.info("Google DNS response for %s: %s", name, ", ".join(sorted(ips)) or "<none>")
        return ips
    except Exception:
        LOGGER.exception("Failed Google DNS query for %s", name)
        return set()

def udp_dns_query(server_ip, name):
    try:
        LOGGER.info("Sending UDP DNS query to %s for %s", server_ip, name)
        q = build_dns_query(name)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(q, (server_ip, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
        ips = parse_dns_message(data)
        LOGGER.info("UDP DNS response from %s for %s: %s", server_ip, name, ", ".join(sorted(ips)) or "<none>")
        return ips
    except Exception:
        LOGGER.exception("Failed UDP DNS query to %s for %s", server_ip, name)
        return set()

def resolver_sets(name):
    LOGGER.info("Aggregating resolver responses for %s", name)
    comss_ips = set()
    for base in COMSS_DOH:
        comss_ips |= doh_wire(base, name)
    for ip in COMSS_DNS_IPS:
        comss_ips |= udp_dns_query(ip, name)
    google_ips = google_json(name)
    LOGGER.info(
        "Resolver results for %s -> comss: %s | google: %s",
        name,
        ", ".join(sorted(comss_ips)) or "<none>",
        ", ".join(sorted(google_ips)) or "<none>",
    )
    return {
        "comss": comss_ips,
        "google": google_ips,
    }

def apex_of(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def main():
    LOGGER.info("Starting cloaking rules generation")
    all_hosts = get_hosts_from_repo()
    LOGGER.info("Loaded %d hosts to evaluate", len(all_hosts))
    output_lines = []
    if os.path.isfile(OPTIONAL_HEADER_FILE):
        LOGGER.info("Reading optional header from %s", OPTIONAL_HEADER_FILE)
        with open(OPTIONAL_HEADER_FILE, "r", encoding="utf-8", errors="ignore") as f:
            header_contents = f.read().rstrip("\n")
            output_lines.append(header_contents)
        output_lines.append("")
    else:
        LOGGER.info("Optional header file %s not found", OPTIONAL_HEADER_FILE)
    output_lines.append("# comss dns results")

    added_entries = 0
    for host in all_hosts:
        LOGGER.info("Processing host: %s", host)
        sets = resolver_sets(host)
        comss_ips, google_ips = sets["comss"], sets["google"]
        if not comss_ips:
            LOGGER.info("Skipping %s: no COMSS IPs returned", host)
            continue
        differing = comss_ips - google_ips if google_ips else comss_ips
        if not differing:
            LOGGER.info("Skipping %s: COMSS and Google results identical", host)
            continue
        chosen_ip = sorted(differing)[0]
        label = host if host == apex_of(host) else f"={host}"
        output_lines.append(f"{label} {chosen_ip}")
        added_entries += 1
        LOGGER.info("Added cloaking rule: %s -> %s", label, chosen_ip)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        payload = "\n".join(output_lines).rstrip() + "\n"
        f.write(payload)
        LOGGER.info(
            "Wrote %d lines (%d rules) to %s", len(output_lines), added_entries, OUTPUT_FILE
        )

if __name__ == "__main__":
    main()
