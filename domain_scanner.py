#!/usr/bin/env python3
"""Two-step .com availability scanner: fast DNS filter, then Verisign WHOIS verification."""

import argparse
import csv
import itertools
import socket
import string
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone

WHOIS_SERVER = "whois.verisign-grs.com"
WHOIS_PORT = 43
WHOIS_MIN_INTERVAL = 0.5
BACKOFF_BASE = 10
BACKOFF_MAX = 160
MAX_WHOIS_ATTEMPTS = 5
THROTTLE_MARKERS = ("throttled", "rate limit", "limit exceeded")

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


class WhoisRateLimiter:
    """Enforces a global gap between WHOIS queries across all threads, plus a shared backoff pause."""

    def __init__(self, min_interval):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._paused_until = 0.0

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                if now >= self._paused_until and now >= self._next_slot:
                    self._next_slot = now + self.min_interval
                    return
                wait_for = max(self._paused_until, self._next_slot) - now
            time.sleep(min(wait_for, 0.5))

    def pause(self, seconds):
        with self._lock:
            self._paused_until = max(self._paused_until, time.monotonic() + seconds)


def generate_domains(length):
    for combo in itertools.product(string.ascii_lowercase, repeat=length):
        yield "".join(combo) + ".com"


def bounded_as_completed(executor, fn, items, max_in_flight):
    """Like as_completed over executor.submit, but keeps only max_in_flight futures alive."""
    items = iter(items)
    pending = {executor.submit(fn, item) for item in itertools.islice(items, max_in_flight)}
    while pending:
        done, pending = wait(pending, return_when=FIRST_COMPLETED)
        for fut in done:
            nxt = next(items, None)
            if nxt is not None:
                pending.add(executor.submit(fn, nxt))
            yield fut.result()


def check_dns(domain):
    """Step 1: returns (domain, True) if the name does not resolve (WHOIS candidate)."""
    try:
        socket.gethostbyname(domain)
        return domain, False
    except OSError:
        return domain, True


_whois_ip = None


def whois_address():
    # Resolved once: per-query lookups would queue behind the DNS scan threads
    global _whois_ip
    if _whois_ip is None:
        _whois_ip = socket.gethostbyname(WHOIS_SERVER)
    return _whois_ip


def query_whois(domain, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        # Raw connect to an IP skips getaddrinfo, which Windows queues behind the DNS scan
        s.connect((whois_address(), WHOIS_PORT))
        # "domain" keyword restricts the lookup to domain records (not nameservers/registrars)
        s.sendall(f"domain {domain}\r\n".encode("ascii"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def classify_whois(text):
    lower = text.lower()
    if "no match for" in lower:
        return "AVAILABLE"
    if "domain name:" in lower:
        return "TAKEN"
    if any(marker in lower for marker in THROTTLE_MARKERS):
        return "THROTTLED"
    return "UNKNOWN"


def check_whois(domain, limiter, timeout=10):
    """Step 2: registry verification with global pacing and exponential backoff on throttling."""
    backoff = BACKOFF_BASE
    for attempt in range(1, MAX_WHOIS_ATTEMPTS + 1):
        limiter.acquire()
        try:
            status = classify_whois(query_whois(domain, timeout))
        except OSError as exc:
            status = "ERROR"
            log(f"[!] WHOIS error on {domain} (attempt {attempt}): {exc}")

        if status in ("AVAILABLE", "TAKEN"):
            return domain, status

        if status == "THROTTLED":
            log(f"[!] Throttled on {domain} (attempt {attempt}). Backing off {backoff}s for all threads...")
            limiter.pause(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)
        else:
            time.sleep(min(2 ** attempt, 30))
    return domain, "FAILED"


def run_scanner(length=3, max_dns_threads=200, max_whois_threads=3, output="results.csv"):
    total = 26 ** length
    print(f"[*] Scanning {total:,} domains: DNS ({max_dns_threads} threads) -> WHOIS "
          f"({max_whois_threads} threads, >= {WHOIS_MIN_INTERVAL}s between queries), pipelined.")

    print(f"[*] WHOIS server {WHOIS_SERVER} -> {whois_address()}")
    limiter = WhoisRateLimiter(WHOIS_MIN_INTERVAL)
    state_lock = threading.Lock()
    counts = {"candidates": 0, "whois_done": 0}
    available, failed = [], []
    checked = 0
    start = time.monotonic()

    with open(output, "w", newline="", encoding="utf-8") as f, \
            ThreadPoolExecutor(max_workers=max_whois_threads) as whois_executor, \
            ThreadPoolExecutor(max_workers=max_dns_threads) as dns_executor:
        writer = csv.writer(f)
        writer.writerow(["domain", "checked_at_utc"])
        f.flush()

        def on_whois_done(future):
            domain, status = future.result()
            with state_lock:
                counts["whois_done"] += 1
                prefix = f"[WHOIS {counts['whois_done']}/{counts['candidates']}]"
                if status == "AVAILABLE":
                    available.append(domain)
                    writer.writerow([domain, datetime.now(timezone.utc).isoformat(timespec="seconds")])
                    f.flush()
                elif status != "TAKEN":
                    failed.append(domain)
            if status == "AVAILABLE":
                log(f"{prefix} [$$$ AVAILABLE $$$] {domain}")
            elif status == "TAKEN":
                log(f"{prefix} [TAKEN] {domain}")
            else:
                log(f"{prefix} [FAILED] {domain} (gave up after {MAX_WHOIS_ATTEMPTS} attempts)")

        for domain, is_candidate in bounded_as_completed(
            dns_executor, check_dns, generate_domains(length), max_dns_threads * 4
        ):
            checked += 1
            if is_candidate:
                with state_lock:
                    counts["candidates"] += 1
                log(f"[DNS-NX] {domain} -> queued for WHOIS")
                whois_executor.submit(check_whois, domain, limiter).add_done_callback(on_whois_done)
            if checked % 1000 == 0 or checked == total:
                log(f"[*] DNS progress: {checked:,}/{total:,} | candidates: {counts['candidates']:,} "
                    f"| WHOIS done: {counts['whois_done']:,} | {time.monotonic() - start:.0f}s")

        log("[*] DNS phase complete. Waiting for remaining WHOIS checks...")

    print(f"[*] Done. {len(available)} available domain(s) saved to {output}.")
    if failed:
        print(f"[!] {len(failed)} domain(s) could not be verified: {', '.join(failed)}")


def main():
    parser = argparse.ArgumentParser(description="3/4-letter .com availability scanner")
    parser.add_argument("-l", "--length", type=int, choices=(3, 4), default=3)
    parser.add_argument("--dns-threads", type=int, default=200)
    parser.add_argument("--whois-threads", type=int, choices=range(1, 6), default=3,
                        metavar="{1-5}")
    parser.add_argument("-o", "--output", default="results.csv")
    args = parser.parse_args()

    try:
        run_scanner(args.length, args.dns_threads, args.whois_threads, args.output)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Partial results are in", args.output)


if __name__ == "__main__":
    main()
