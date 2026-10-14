#!/usr/bin/env python3
"""Letters-only .com availability hunter.

  generate: write every a-z combination to domains_<L>.csv, split into task batches,
            and import results from earlier scan logs so they are skipped.
  run:      process batches. Stage 1 asks the 13 .com TLD nameservers directly (fast);
            stage 2 verifies NXDOMAIN names on all registry backends in parallel
            (2 Verisign WHOIS IPs + Verisign RDAP), each with its own pacing/backoff.
"""

import argparse
import csv
import glob
import itertools
import os
import queue
import random
import re
import socket
import string
import struct
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# From https://www.iana.org/domains/root/db/com.html
GTLD_SERVERS = [
    "192.5.6.30", "192.33.14.30", "192.26.92.30", "192.31.80.30", "192.12.94.30",
    "192.35.51.30", "192.42.93.30", "192.54.112.30", "192.43.172.30", "192.48.79.30",
    "192.52.178.30", "192.41.162.30", "192.55.83.30",
]
WHOIS_HOST = "whois.verisign-grs.com"
RDAP_URL = "https://rdap.verisign.com/com/v1/domain/"

MIN_INTERVAL = 0.5
BACKOFF_BASE = 10
BACKOFF_MAX = 160
MAX_ATTEMPTS = 5
THROTTLE_MARKERS = ("throttled", "rate limit", "limit exceeded")

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def paths(length):
    return {
        "domains": f"domains_{length}.csv",
        "checked": f"checked_{length}.csv",
        "available": f"available_{length}.csv",
        "tasks": os.path.join("tasks", str(length)),
    }


# ---------------------------------------------------------------- state files

class Recorder:
    """Append-only, thread-safe result log; makes every run resumable."""

    def __init__(self, length):
        p = paths(length)
        self._lock = threading.Lock()
        self._checked = self._open(p["checked"], ["domain", "status", "source", "checked_at"])
        self._available = self._open(p["available"], ["domain", "source", "checked_at"])

    @staticmethod
    def _open(path, header):
        new = not os.path.exists(path)
        f = open(path, "a", newline="", encoding="utf-8")
        if new:
            csv.writer(f).writerow(header)
            f.flush()
        return f

    def record(self, domain, status, source):
        ts = now_iso()
        with self._lock:
            csv.writer(self._checked).writerow([domain, status, source, ts])
            self._checked.flush()
            if status == "AVAILABLE":
                csv.writer(self._available).writerow([domain, source, ts])
                self._available.flush()

    def close(self):
        self._checked.close()
        self._available.close()


def load_checked(length):
    """Domains with a final status (TAKEN/AVAILABLE); FAILED ones get retried."""
    done = {}
    path = paths(length)["checked"]
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["status"] in ("TAKEN", "AVAILABLE"):
                    done[row["domain"]] = row["status"]
    return done


# ---------------------------------------------------------------- generate

LOG_RESULT = re.compile(r"\[(TAKEN|\$\$\$ AVAILABLE \$\$\$)\] ([a-z]+\.com)")


def import_logs(length, recorder, already):
    imported = 0
    for log_path in glob.glob("scan_*.log"):
        with open(log_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = LOG_RESULT.search(line)
                if not m:
                    continue
                domain = m.group(2)
                if len(domain) - 4 != length or domain in already:
                    continue
                status = "TAKEN" if m.group(1) == "TAKEN" else "AVAILABLE"
                recorder.record(domain, status, f"import:{log_path}")
                already[domain] = status
                imported += 1
    return imported


def cmd_generate(length, batch_size):
    p = paths(length)
    domains = ["".join(c) + ".com" for c in itertools.product(string.ascii_lowercase, repeat=length)]

    with open(p["domains"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain"])
        w.writerows([d] for d in domains)
    print(f"[*] Wrote {len(domains):,} domains to {p['domains']}")

    os.makedirs(p["tasks"], exist_ok=True)
    for old in glob.glob(os.path.join(p["tasks"], "batch_*.csv")):
        os.remove(old)
    batches = [domains[i:i + batch_size] for i in range(0, len(domains), batch_size)]
    for i, chunk in enumerate(batches):
        with open(os.path.join(p["tasks"], f"batch_{i:04d}.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["domain"])
            w.writerows([d] for d in chunk)
    print(f"[*] Split into {len(batches)} task batches of up to {batch_size} in {p['tasks']}/")

    recorder = Recorder(length)
    already = load_checked(length)
    imported = import_logs(length, recorder, already)
    recorder.close()
    print(f"[*] Imported {imported} results from earlier scan logs. "
          f"{len(domains) - len(already):,} domains still to check.")


# ---------------------------------------------------------------- stage 1: TLD zone

def _dns_query(qid, name):
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 2, 1)  # QTYPE=NS, QCLASS=IN


def zone_status(domain, timeout=2.0, attempts=3):
    """'NX' if the name is absent from the .com zone, 'DELEGATED' if present, None on failure."""
    servers = random.sample(GTLD_SERVERS, attempts)
    for server in servers:
        qid = random.randint(0, 0xFFFF)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(_dns_query(qid, domain), (server, 53))
                data, _ = s.recvfrom(4096)
        except OSError:
            continue
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
            continue
        rcode = struct.unpack(">H", data[2:4])[0] & 0xF
        if rcode == 3:
            return "NX"
        if rcode == 0:
            return "DELEGATED"
    return None


# ---------------------------------------------------------------- stage 2: registry backends

def _classify_whois(text):
    lower = text.lower()
    if "no match for" in lower:
        return "AVAILABLE"
    if "domain name:" in lower:
        return "TAKEN"
    if any(m in lower for m in THROTTLE_MARKERS):
        return "THROTTLED"
    return "UNKNOWN"


def whois_backend(ip):
    def check(domain):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((ip, 43))
            s.sendall(f"domain {domain}\r\n".encode("ascii"))
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return _classify_whois(b"".join(chunks).decode("utf-8", errors="ignore"))
    return f"whois@{ip}", check


def rdap_backend():
    def check(domain):
        req = urllib.request.Request(RDAP_URL + domain, headers={"Accept": "application/rdap+json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return "TAKEN" if r.status == 200 else "UNKNOWN"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "AVAILABLE"
            if e.code == 429:
                return "THROTTLED"
            return "UNKNOWN"
    return "rdap", check


def registry_backends():
    ips = sorted({a[4][0] for a in socket.getaddrinfo(WHOIS_HOST, 43, socket.AF_INET, socket.SOCK_STREAM)})
    return [whois_backend(ip) for ip in ips] + [rdap_backend()]


class RegistryPool:
    """One worker per backend pulling from a shared queue; each backend paces and backs off on its own."""

    def __init__(self, recorder):
        self.recorder = recorder
        self.queue = queue.Queue()
        self.stats = {"AVAILABLE": 0, "TAKEN": 0, "FAILED": 0}
        self._stats_lock = threading.Lock()
        self.backends = registry_backends()
        for name, check in self.backends:
            threading.Thread(target=self._worker, args=(name, check), daemon=True).start()

    def submit(self, domain):
        self.queue.put((domain, 1))

    def wait(self):
        self.queue.join()

    def _finish(self, domain, status, source):
        self.recorder.record(domain, status, source)
        with self._stats_lock:
            self.stats[status] += 1
        tag = "[$$$ AVAILABLE $$$]" if status == "AVAILABLE" else f"[{status}]"
        log(f"  {tag} {domain}  ({source})")

    def _worker(self, name, check):
        backoff = BACKOFF_BASE
        while True:
            domain, attempt = self.queue.get()
            start = time.monotonic()
            try:
                status = check(domain)
            except OSError:
                status = "ERROR"

            if status in ("AVAILABLE", "TAKEN"):
                self._finish(domain, status, name)
                backoff = BACKOFF_BASE
            elif attempt >= MAX_ATTEMPTS:
                self._finish(domain, "FAILED", name)
            else:
                # Requeue before task_done so queue.join() keeps waiting for it
                self.queue.put((domain, attempt + 1))
                if status == "THROTTLED":
                    log(f"  [!] {name} throttled; pausing it {backoff}s (others keep going)")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, BACKOFF_MAX)
            self.queue.task_done()
            time.sleep(max(0.0, MIN_INTERVAL - (time.monotonic() - start)))


# ---------------------------------------------------------------- run

def read_batch(path):
    with open(path, newline="", encoding="utf-8") as f:
        return [row["domain"] for row in csv.DictReader(f)]


def cmd_run(length, only_batch, dns_threads):
    p = paths(length)
    batch_files = sorted(glob.glob(os.path.join(p["tasks"], "batch_*.csv")))
    if not batch_files:
        print(f"[!] No task batches found. Run: python domain_hunter.py generate -l {length}")
        return
    if only_batch is not None:
        batch_files = [f for f in batch_files if f.endswith(f"batch_{only_batch:04d}.csv")]

    done = load_checked(length)
    recorder = Recorder(length)
    pool = RegistryPool(recorder)
    print(f"[*] Registry backends in parallel: {', '.join(n for n, _ in pool.backends)}")
    print(f"[*] {len(batch_files)} batch(es); {len(done):,} domains already checked will be skipped.")

    try:
        for batch_path in batch_files:
            todo = [d for d in read_batch(batch_path) if d not in done]
            name = os.path.basename(batch_path)
            if not todo:
                log(f"[=] {name}: already complete")
                continue

            t0 = time.monotonic()
            nx, delegated, dns_failed = [], 0, 0
            with ThreadPoolExecutor(max_workers=dns_threads) as ex:
                for domain, status in zip(todo, ex.map(zone_status, todo)):
                    if status == "DELEGATED":
                        recorder.record(domain, "TAKEN", "tld-zone")
                        done[domain] = "TAKEN"
                        delegated += 1
                    elif status == "NX":
                        nx.append(domain)
                    else:
                        dns_failed += 1
            log(f"[>] {name}: {len(todo)} to check | in .com zone (taken): {delegated} | "
                f"not in zone -> registry: {len(nx)} | DNS failed (retry next run): {dns_failed} "
                f"| {time.monotonic() - t0:.1f}s")

            for domain in nx:
                pool.submit(domain)
            pool.wait()
            for domain in nx:
                done[domain] = True
            log(f"[+] {name} done. Totals so far: {pool.stats}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Progress is saved; rerun to resume.")
    finally:
        recorder.close()

    print(f"[*] Finished. Available domains are in {p['available']}")


def main():
    parser = argparse.ArgumentParser(description="Letters-only .com availability hunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write all combinations and split into task batches")
    g.add_argument("-l", "--length", type=int, choices=(3, 4), default=3)
    g.add_argument("--batch-size", type=int, default=1000)

    r = sub.add_parser("run", help="check pending domains batch by batch (resumable)")
    r.add_argument("-l", "--length", type=int, choices=(3, 4), default=3)
    r.add_argument("--batch", type=int, help="run only this batch number")
    r.add_argument("--dns-threads", type=int, default=50)

    args = parser.parse_args()
    if args.cmd == "generate":
        cmd_generate(args.length, args.batch_size)
    else:
        cmd_run(args.length, args.batch, args.dns_threads)


if __name__ == "__main__":
    main()
