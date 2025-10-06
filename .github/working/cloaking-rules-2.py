#!/usr/bin/env python3
import json
import os
import re
import ssl
from collections import defaultdict
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HOSTS_URL = "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
OUTPUT_FILE = "comss_dns_results.txt"
OPTIONAL_HEADER_FILE = "example-cloaking-rules.txt"
UA = "Mozilla/5.0 (compatible; comss-doh-check/1.0)"

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SPACE_SPLIT = re.compile(r"\s+")

def fetch(url: str, headers: dict = None):
    req = Request(url, headers=headers or {"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urlopen(req, context=ctx) as resp:
        return resp.read()

def get_hosts_from_repo() -> list[str]:
    raw = fetch(HOSTS_URL).decode("utf-8", errors="ignore")
    hosts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = SPACE_SPLIT.split(line)
        if len(parts) < 2:
            continue
        ip = parts[0]
        if not IPV4_RE.match(ip):
            continue
        for host in parts[1:]:
            host = host.strip().lower().rstrip(".")
            if host and not host.startswith("#"):
                hosts.append(host)
    seen, uniq = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq

def to_idna(name: str) -> str:
    try:
        return name.encode("idna").decode("ascii")
    except Exception:
        return name

def doh_json(url_base: str, name: str) -> set[str]:
    params = {"name": to_idna(name), "type": "A", "cd": "false"}
    url = f"{url_base}?{urlencode(params)}"
    headers = {"User-Agent": UA, "Accept": "application/dns-json"}
    try:
        data = fetch(url, headers=headers)
        j = json.loads(data.decode("utf-8", errors="ignore"))
        answers = j.get("Answer") or []
        ips = set()
        for ans in answers:
            if ans.get("type") == 1:
                d = ans.get("data", "")
                if IPV4_RE.match(d):
                    ips.add(d)
        return ips
    except Exception:
        return set()

def resolver_sets(name: str) -> dict:
    return {
        "comss": doh_json("https://dns.comss.one/dns-query", name),
        "google": doh_json("https://dns.google/resolve", name),
        "cloudflare": doh_json("https://dns.cloudflare.com/dns-query", name),
    }

def apex_of(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def main():
    all_hosts = get_hosts_from_repo()
    interesting = {}

    def work(host: str):
        sets = resolver_sets(host)
        comss, g, cf = sets["comss"], sets["google"], sets["cloudflare"]
        if comss == g == cf:
            return None
        if comss != g and comss != cf and len(comss) > 0:
            return (host, comss)
        return None

    for host in all_hosts:
        res = work(host)
        if res:
            h, comss_ips = res
            interesting[h] = comss_ips

    groups = defaultdict(dict)
    for host, ips in interesting.items():
        groups[apex_of(host)][host] = ips

    output_lines = []
    if os.path.isfile(OPTIONAL_HEADER_FILE):
        with open(OPTIONAL_HEADER_FILE, "r", encoding="utf-8", errors="ignore") as f:
            output_lines.append(f.read().rstrip("\n"))
        output_lines.append("")
    output_lines.append("# comss dns results")

    for apex in sorted(groups.keys()):
        members = groups[apex]
        ip_sets = {tuple(sorted(v)) for v in members.values()}
        if len(ip_sets) == 1:
            ips = next(iter(members.values()))
            ip_str = ",".join(sorted(ips))
            output_lines.append(f"{apex} {ip_str}")
        else:
            for host in sorted(members.keys()):
                ip_str = ",".join(sorted(members[host]))
                output_lines.append(f"={host} {ip_str}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines).rstrip() + "\n")

if __name__ == "__main__":
    main()
