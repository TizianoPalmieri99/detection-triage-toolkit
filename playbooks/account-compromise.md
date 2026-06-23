# IR Playbook — Compromised account

Operational procedure to handle a user account suspected of compromise
(e.g. stolen credentials, login from an anomalous IP, successful brute force).
Structure based on the NIST SP 800-61 incident response lifecycle.

## 1. Identification
- Where does the signal come from? (SIEM alert, EDR, user report)
- Review the authentication logs: timestamps, source IP, geolocation.
  - Linux: `auth.log` → use `auth_log_analyzer.py`
  - Windows: Event ID 4624 (successful logon) / 4625 (failed) → `win_event_triage.py`
- Key questions: is the timing plausible? Is the IP known/corporate? Are there
  repeated failures followed by a success (brute force that succeeded)?

## 2. Containment
- Disable the account (do NOT delete it: it is needed for the investigation).
- Force logout of all active sessions / revoke tokens.
- Block the source IP on the firewall if hostile.
- Notify the real user through an alternative channel.

## 3. Eradication
- Reset the password and, if possible, enable/enforce MFA.
- Look for post-access activity: new accounts created, mail rules, persistence.
  (On Windows check 4720 account created, 4732 added to an admin group.)
- Check whether the same credentials are used elsewhere (password reuse).

## 4. Recovery
- Re-enable the account only after cleanup and a new password + MFA.
- Monitor the account for a few days with increased attention.

## 5. Lessons learned
- How did the attack succeed? (weak password, no MFA, no rate limiting)
- Preventive actions: mandatory MFA, password policy, fail2ban/lockout,
  automatic alert on "N failures + 1 success from the same IP".

## Useful indicators to collect
- Source IP, user-agent, timestamp, logon type, affected assets.
