#!/usr/bin/env python3
"""
win_event_triage.py - Triage a CSV export of the Windows "Security" log.

Picks out the Event IDs that matter to a blue team and sorts them by priority,
so the analyst looks at the serious things first.

Sample export (PowerShell):
    Get-WinEvent -LogName Security | Select TimeCreated,Id,Message |
        Export-Csv -NoTypeInformation export.csv

Usage:
    python win_event_triage.py data/sample_win_security.csv
"""
import argparse
import csv
from collections import Counter

# Event IDs that really matter -> (description, priority).
KEY_EVENTS = {
    "4624": ("Successful logon", "info"),
    "4625": ("Failed logon", "medium"),                              # many 4625 = brute force
    "4720": ("A new user account was created", "high"),
    "4726": ("A user account was deleted", "medium"),
    "4672": ("Special privileges (admin) assigned to logon", "high"),  # privilege escalation
    "4732": ("Member added to a privileged local group", "high"),
    "1102": ("The security log was cleared", "critical"),            # destroys evidence
    "4688": ("A new process was created", "info"),
}

# Level -> number (smaller = more severe), used for sorting.
PRIORITY = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def load(path):
    """Load the CSV as a list of dicts {column: value}."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser(description="Triage Windows security events")
    ap.add_argument("csvfile", help="CSV export of the Security log")
    args = ap.parse_args()

    rows = load(args.csvfile)
    counter = Counter()      # count per Event ID
    relevant = []            # only events present in KEY_EVENTS

    for row in rows:
        eid = str(row.get("EventID", "")).strip()
        counter[eid] += 1
        if eid in KEY_EVENTS:
            desc, prio = KEY_EVENTS[eid]
            relevant.append((prio, eid, desc, row))

    relevant.sort(key=lambda x: PRIORITY.get(x[0], 9))  # most severe first

    print("=" * 62)
    print("WINDOWS SECURITY EVENT TRIAGE")
    print("=" * 62)
    print(f"Total events: {len(rows)}\n")

    print("Relevant events (sorted by priority):")
    for prio, eid, desc, row in relevant:
        acct = row.get("Account", "-")
        ip = row.get("SourceIP", "-")
        when = row.get("TimeCreated", "-")
        print(f"  [{prio.upper():<8}] {when}  EID {eid} - {desc}")
        print(f"             account={acct} ip={ip}")

    print("\nCount per Event ID:")
    for eid, n in counter.most_common():
        name = KEY_EVENTS.get(eid, ("(unmapped)", ""))[0]
        print(f"  {eid:<6} x{n:<4} {name}")


if __name__ == "__main__":
    main()
