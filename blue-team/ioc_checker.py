#!/usr/bin/env python3
"""
ioc_checker.py - Match a file (log/text) against a list of IoCs.

IoC = Indicators of Compromise (IPs, domains, hashes of known malicious files).
Reports any matches found along with their line number.

Usage:
    python ioc_checker.py --iocs data/sample_iocs.csv data/sample_auth.log
"""
import argparse
import csv


def load_iocs(path):
    """Load IoCs from a CSV with columns: type,value,description."""
    iocs = {}  # value -> (type, description)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            value = row["value"].strip()
            if value:
                iocs[value] = (row.get("type", "").strip(),
                               row.get("description", "").strip())
    return iocs


def scan(target, iocs):
    """Search each IoC inside the target file; return the matches found."""
    hits = []  # (line_number, value, type, description, line_text)
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            for value, (ioc_type, desc) in iocs.items():
                if value in line:
                    hits.append((n, value, ioc_type, desc, line.strip()))
    return hits


def main():
    ap = argparse.ArgumentParser(description="Search for IoCs inside a file")
    ap.add_argument("target", help="file to analyze")
    ap.add_argument("--iocs", required=True, help="CSV with the IoC list")
    args = ap.parse_args()

    iocs = load_iocs(args.iocs)
    hits = scan(args.target, iocs)

    print(f"IoCs loaded: {len(iocs)} | File analyzed: {args.target}")
    print("-" * 62)
    if not hits:
        print("No matches found.")
        return
    for n, value, ioc_type, desc, text in hits:
        print(f"[MATCH] line {n}: {value} ({ioc_type}) - {desc}")
        print(f"        > {text}")
    print("-" * 62)
    print(f"Total matches: {len(hits)}")


if __name__ == "__main__":
    main()
