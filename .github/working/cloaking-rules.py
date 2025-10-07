import logging
from collections import defaultdict, Counter
import fnmatch

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

URL = 'https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts'
remove_domains = ['*xbox*', '*instagram*', '*proton*', '*facebook*', '*torrent*', '*twitch*', '*deezer*', '*dzcdn*', '*weather*', '*fitbit*', '*ggpht*', '*github*', '*tiktok*', '*imgur*', '*4pda*', '*malw.link*']
adblock_ips = {'127.0.0.1', '0.0.0.0'}
no_simplify_domains = ['*microsoft*', '*bing*', '*goog*', '*github*', '*parsec*', '*oai*', '*archive.org*', '*ttvnw*', '*spotify*', '*scdn.co*', '*clashroyale*', '*clashofclans*', '*brawlstars*', '*supercell*']
example_file = 'example-cloaking-rules.txt'
output_file = 'cloaking-rules.txt'

best_domain = 'chatgpt.com'
base_ip = None
custom_domains = ['soundcloud.com', 'genius.com']

logger.info("Fetching hosts data from %s", URL)
response = requests.get(URL)
logger.info("Received response with status %s and %d bytes", response.status_code, len(response.content))
response.raise_for_status()
lines = response.text.splitlines()
logger.info("Fetched %d lines from upstream list", len(lines))

entries = []
skipped_comments = 0
skipped_short = 0
skipped_adblock = 0
skipped_removed = 0
for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        skipped_comments += 1
        continue
    parts = line.split()
    if len(parts) < 2:
        skipped_short += 1
        continue
    ip, host = parts[0], parts[1]
    if ip in adblock_ips:
        skipped_adblock += 1
        continue
    if any(pattern.strip('*') in host for pattern in remove_domains):
        skipped_removed += 1
        continue
    if host == best_domain and base_ip is None:
        base_ip = ip
    entries.append((host, ip))

logger.info(
    "Processed upstream entries: %d kept, %d comments/blank, %d too short, %d adblock, %d removed",
    len(entries),
    skipped_comments,
    skipped_short,
    skipped_adblock,
    skipped_removed,
)
if base_ip:
    logger.info("Detected base IP %s for best domain %s", base_ip, best_domain)
else:
    logger.warning("Base IP for %s not found in upstream data", best_domain)

host_to_ip = defaultdict(set)
subdomains_by_root = defaultdict(list)

for host, ip in entries:
    host_to_ip[host].add(ip)
    parts = host.split('.')
    if len(parts) >= 2:
        root = '.'.join(parts[-2:])
        subdomains_by_root[root].append((host, ip))

final_hosts = {}

for root, items in subdomains_by_root.items():
    domain_ips = Counter()
    all_hosts = set(host for host, _ in items)
    no_simplify = any(fnmatch.fnmatch(host, pattern) for host in all_hosts for pattern in no_simplify_domains)

    if no_simplify:
        for host, ip in items:
            final_hosts.setdefault(host, set()).add(ip)
    else:
        for host, ip in items:
            if host == root:
                domain_ips[ip] += 5
            else:
                domain_ips[ip] += 1

        most_common_ip, count = domain_ips.most_common(1)[0]

        root_in_items = any(h == root for h, _ in items)
        if root_in_items or any(h.endswith('.' + root) for h, _ in items):
            final_hosts[root] = {most_common_ip}

        for host, ip in items:
            if host != root and ip != most_common_ip:
                final_hosts.setdefault(host, set()).add(ip)

if base_ip:
    for custom_domain in custom_domains:
        final_hosts.setdefault(custom_domain, set()).add(base_ip)
        logger.info("Added custom domain %s with base IP %s", custom_domain, base_ip)

logger.info("Reading example entries from %s", example_file)
with open(example_file, 'r', encoding='utf-8') as f:
    base = f.read()
logger.info("Loaded %d characters of example entries", len(base))

total_host_entries = sum(len(ips) for ips in final_hosts.values())
logger.info(
    "Writing %d hosts across %d domains to %s",
    total_host_entries,
    len(final_hosts),
    output_file,
)
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(base.rstrip() + '\n\n')
    f.write('# t.me/immalware hosts\n')
    for host in sorted(final_hosts):
        if host not in custom_domains:
            is_no_simplify = any(fnmatch.fnmatch(host, pattern) for pattern in no_simplify_domains)
            prefix = '=' if is_no_simplify else ''
            for ip in sorted(final_hosts[host]):
                f.write(f"{prefix}{host} {ip}\n")

    f.write('\n# custom t.me/immalware hosts\n')
    for host in sorted(custom_domains):
        if host in final_hosts:
            for ip in sorted(final_hosts[host]):
                f.write(f"{host} {ip}\n")

logger.info("Saved cloaking rules to %s", output_file)




