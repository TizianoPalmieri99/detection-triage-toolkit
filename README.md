# Detection & Triage Toolkit

A small collection of scripts to analyze security logs and artifacts, together
with incident response playbooks. Built as a hands-on project while studying SOC
and blue team fundamentals: I wanted simple tools to do the first triage of an
alert without spinning up a full SIEM.

Everything uses the Python standard library — no dependencies to install.

## What it does

| Script | Purpose |
|--------|---------|
| `blue-team/auth_log_analyzer.py` | Analyzes a Linux `auth.log`: failed SSH attempts, brute force, successful logins from suspicious IPs |
| `blue-team/ioc_checker.py` | Searches for Indicators of Compromise (IPs, domains, hashes) inside a file |
| `blue-team/win_event_triage.py` | Triage of a CSV export of the Windows Security log by relevant Event IDs |

The `playbooks/` folder contains two incident response procedures (compromised
account, malware on an endpoint) based on the NIST SP 800-61 lifecycle.

## Requirements

- Python 3.8 or newer. Nothing else.

## Usage

The sample data in `data/` lets you try the scripts right away.

```bash
# SSH authentication log analysis
python blue-team/auth_log_analyzer.py data/sample_auth.log

# Same analysis with a lower brute-force threshold
python blue-team/auth_log_analyzer.py data/sample_auth.log --threshold 3

# Search for IoCs inside a log
python blue-team/ioc_checker.py --iocs data/sample_iocs.csv data/sample_auth.log

# Triage of Windows security events
python blue-team/win_event_triage.py data/sample_win_security.csv
```

## Example output

Running the SSH log analyzer on the sample data:

```
$ python blue-team/auth_log_analyzer.py data/sample_auth.log
==============================================================
AUTH LOG ANALYSIS REPORT
==============================================================

Total failed attempts: 18
Total successful logins: 4

[!] IPs above threshold (5+ failures) - possible brute force:
    203.0.113.45       9 attempts | most targeted users: root(4), admin(2), test(1)
    45.137.21.9        7 attempts | most targeted users: root(3), ubuntu(2), git(2)

[!] SUCCESSFUL logins from an IP that also had failures:
    user 'root' from 203.0.113.45 (this IP had 9 failures)

==============================================================
```

The successful login from `203.0.113.45` — an IP that had just brute-forced its
way in — is the alert worth escalating.

## Structure

```
detection-triage-toolkit/
├── blue-team/      # the tools
├── data/           # sample data to try them
├── playbooks/      # incident response procedures
└── README.md
```

## The story hidden in the sample data

The three sample files describe **the same attack** seen from different angles:
an SSH brute force from `203.0.113.45` that succeeds, the same pattern on Windows
(failed logons 4625 → successful logon 4624), then the attacker creates a
persistence account (4720), escalates privileges (4732/4672), runs a command
(4688) and finally clears the security log (1102) to hide the tracks. The
`ioc_checker` confirms that IP is already on a known IoC list.

Chain: brute force → access → persistence account → privilege escalation →
execution → anti-forensics.

## Notes

- The data in `data/` is fictitious. The IPs belong to the ranges reserved for
  documentation (RFC 5737), so they are not real addresses.
- Never commit logs or credentials from real systems: see `.gitignore`.

## Possible future improvements

- JSON output to integrate with a SIEM.
- Automatic IP reputation lookup against an API (e.g. AbuseIPDB).
- Support for the journald JSON log format.
```
