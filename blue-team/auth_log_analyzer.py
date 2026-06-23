#!/usr/bin/env python3
"""
auth_log_analyzer.py - SSH authentication log analyzer (Linux /var/log/auth.log).

Flags: failed attempts, brute force (IPs above a threshold) and successful
logins from an IP that had already accumulated failures.

Usage:
    python auth_log_analyzer.py data/sample_auth.log
    python auth_log_analyzer.py /var/log/auth.log --threshold 10
"""
import argparse
import re
from collections import defaultdict, Counter

# Regex: capture only the user and IP from failed/accepted login lines.
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse(path):
    """Read the log file and collect the raw data."""
    failed = defaultdict(list)   # ip -> list of attempted users
    accepted = []                # list of (user, ip) successful logins
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                failed[m.group("ip")].append(m.group("user"))
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                accepted.append((m.group("user"), m.group("ip")))
    return failed, accepted


def report(failed, accepted, threshold):
    """Analyze the data and print the alerts."""
    print("=" * 62)
    print("AUTH LOG ANALYSIS REPORT")
    print("=" * 62)

    total_failed = sum(len(v) for v in failed.values())
    print(f"\nTotal failed attempts: {total_failed}")
    print(f"Total successful logins: {len(accepted)}")

    # Brute force: IPs whose number of failures is >= threshold.
    bruteforce = {ip: u for ip, u in failed.items() if len(u) >= threshold}
    print(f"\n[!] IPs above threshold ({threshold}+ failures) - possible brute force:")
    if not bruteforce:
        print("    none")
    for ip, users in sorted(bruteforce.items(), key=lambda x: len(x[1]), reverse=True):
        top = ", ".join(f"{u}({n})" for u, n in Counter(users).most_common(3))
        print(f"    {ip:<16} {len(users):>3} attempts | most targeted users: {top}")

    # Most severe case: a successful login from an IP that also had failures
    # (brute force that succeeded).
    print("\n[!] SUCCESSFUL logins from an IP that also had failures:")
    suspicious = [(u, ip) for u, ip in accepted if ip in failed]
    if not suspicious:
        print("    none")
    for user, ip in suspicious:
        print(f"    user '{user}' from {ip} (this IP had {len(failed[ip])} failures)")

    print("\n" + "=" * 62)


def main():
    ap = argparse.ArgumentParser(description="Analyze auth.log for suspicious SSH activity")
    ap.add_argument("logfile", help="path to the log file")
    ap.add_argument("--threshold", type=int, default=5,
                    help="minimum failures to flag an IP (default 5)")
    args = ap.parse_args()

    failed, accepted = parse(args.logfile)
    report(failed, accepted, args.threshold)


if __name__ == "__main__":
    main()
