# Blue Team — triage utilities

Three Python scripts (standard library only, no dependencies) for the first
triage of a security alert. Clean version with essential comments.

| Script | Purpose |
|--------|---------|
| `auth_log_analyzer.py` | Analyzes a Linux `auth.log`: failed SSH attempts, brute force, successful logins from suspicious IPs |
| `ioc_checker.py` | Searches for Indicators of Compromise (IPs, domains, hashes) inside a file |
| `win_event_triage.py` | Triage of a CSV export of the Windows Security log by relevant Event IDs |

## Usage

Sample data lives in the project's `../data/` folder.

```bash
# SSH log analysis (brute-force threshold configurable with --threshold)
python auth_log_analyzer.py ../data/sample_auth.log
python auth_log_analyzer.py ../data/sample_auth.log --threshold 3

# Search for IoCs inside a log
python ioc_checker.py --iocs ../data/sample_iocs.csv ../data/sample_auth.log

# Triage of Windows security events
python win_event_triage.py ../data/sample_win_security.csv
```
