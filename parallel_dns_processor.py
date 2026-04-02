#!/usr/bin/env python3
"""Parallel DNS requester with debug logging to console."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("parallel_dns")


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(threadName)s | %(message)s",
    )


def load_domains(path: Path, limit: int | None = None) -> list[str]:
    domains: list[str] = []
    with path.open("r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.isdigit():
                continue
            domains.append(line)
            if limit and len(domains) >= limit:
                break

    unique_domains = sorted(set(domains))
    logger.debug("Loaded %s domains (%s unique) from %s", len(domains), len(unique_domains), path)
    return unique_domains


def resolve_domain(domain: str, timeout: float) -> dict[str, object]:
    started = time.perf_counter()
    logger.debug("DNS request started for %s", domain)

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.debug("DNS request completed for %s in %sms -> %s", domain, duration_ms, ips)
        return {"domain": domain, "ok": True, "ips": ips, "duration_ms": duration_ms}
    except socket.gaierror as error:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.debug("DNS request failed for %s in %sms -> %s", domain, duration_ms, error)
        return {
            "domain": domain,
            "ok": False,
            "ips": [],
            "error": f"{error.__class__.__name__}: {error}",
            "duration_ms": duration_ms,
        }
    finally:
        socket.setdefaulttimeout(old_timeout)


def run_parallel_resolution(domains: Iterable[str], workers: int, timeout: float) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    domains_list = list(domains)
    logger.info("Starting parallel processing: %s domains, %s workers", len(domains_list), workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(resolve_domain, domain, timeout): domain for domain in domains_list}
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)

    ok_count = sum(1 for item in results if item["ok"])
    logger.info("Completed processing. Success=%s, Failed=%s", ok_count, len(results) - ok_count)
    return sorted(results, key=lambda item: str(item["domain"]))


def save_results(path: Path, results: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(results, file, ensure_ascii=False, indent=2)
    logger.info("Saved %s results to %s", len(results), path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parallel DNS requests + processing with console debug logs.")
    parser.add_argument("--input", default="blocked-names.txt", help="Input file with domain list.")
    parser.add_argument("--workers", type=int, default=30, help="Number of parallel DNS workers.")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds.")
    parser.add_argument("--limit", type=int, default=200, help="How many domains to process from the file.")
    parser.add_argument("--output", default="dns-results.json", help="Output JSON file path.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logs in the console.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(args.debug)

    input_path = Path(args.input)
    output_path = Path(args.output)

    domains = load_domains(input_path, args.limit)
    results = run_parallel_resolution(domains, args.workers, args.timeout)
    save_results(output_path, results)


if __name__ == "__main__":
    main()
