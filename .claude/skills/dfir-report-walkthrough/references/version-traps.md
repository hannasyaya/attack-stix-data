# Version traps

This repository tracks the latest ATT&CK release. Most published reports were
written against an older one, so a report's own technique IDs are a strong
starting point but not ground truth. Checking them is a habit, not a special
step:

```bash
python3 util/attack_lookup.py validate T1562.001 T1574.002
cat report.txt | python3 util/attack_lookup.py validate     # reads IDs from stdin
python3 util/attack_lookup.py extract report.md             # resolve every ID in a file
```

## The tactic rename

**Defense Evasion no longer exists as a tactic.** It split into:

- **Stealth** (`stealth`) — hiding: side-loading, injection, masquerading,
  file deletion, command obfuscation
- **Defense Impairment** (`defense-impairment`) — breaking things: killing AV,
  clearing logs, disabling firewalls, code-signing abuse

A report's "Defense Evasion" section usually spans both. It is older, not
wrong — translate it and say that you did.

The full current tactic list:

```
reconnaissance · resource-development · initial-access · execution ·
persistence · privilege-escalation · stealth · defense-impairment ·
credential-access · discovery · lateral-movement · collection ·
command-and-control · exfiltration · impact
```

## The T1562 restructure

The entire Impair Defenses family was revoked and rebuilt as top-level
techniques under Defense Impairment. This is the trap that bites most often,
because AV-killer and BYOVD activity is common in ransomware reports and
T1562.001 was its natural home.

| Revoked | Name | Use instead |
|---|---|---|
| T1070.001 | Clear Windows Event Logs | **T1685.005** Clear Windows Event Logs |
| T1070.002 | Clear Linux or Mac System Logs | **T1685.006** Clear Linux or Mac System Logs |
| T1547.011 | Plist Modification | **T1647** Plist File Modification |
| T1562 | Impair Defenses | **T1685** Disable or Modify Tools |
| T1562.001 | Disable or Modify Tools | **T1685** Disable or Modify Tools |
| T1562.002 | Disable Windows Event Logging | **T1685.001** Disable or Modify Windows Event Log |
| T1562.003 | Impair Command History Logging | **T1690** Prevent Command History Logging |
| T1562.004 | Disable or Modify System Firewall | **T1686** Disable or Modify System Firewall |
| T1562.006 | Indicator Blocking | **T1685** Disable or Modify Tools |
| T1562.007 | Disable or Modify Cloud Firewall | **T1686.001** Cloud Firewall |
| T1562.008 | Disable or Modify Cloud Logs | **T1685.002** Disable or Modify Cloud Log |
| T1562.009 | Safe Mode Boot | **T1688** Safe Mode Boot |
| T1562.010 | Downgrade Attack | **T1689** Downgrade Attack |
| T1562.011 | Spoof Security Alerting | **T1685.003** Modify or Spoof Tool UI |
| T1562.012 | Disable or Modify Linux Audit System | **T1685.004** Disable or Modify Linux Audit System Log |
| T1562.013 | Disable or Modify Network Device Firewall | **T1686.002** Network Device Firewall |
| T1574.002 | DLL Side-Loading | **T1574.001** DLL |

## Side-loading merged

**T1574.002 DLL Side-Loading is revoked.** Both search-order hijacking and
side-loading now map to **T1574.001 DLL**. Reports distinguishing the two are
using pre-v19 IDs — worth knowing, since side-loading appears in a large share
of loader-delivered intrusions.

## Detection objects replaced free text

Detection guidance moved off the technique's `x_mitre_detection` field into
first-class objects:

- **Detection Strategy** (`DET####`) — grouped detection approach per technique
- **Analytic** (`AN####`) — platform-specific logic with structured log sources
  naming the exact channel and event ID
- **Data Component** (`DC####`) — now carries its own ATT&CK ID

`attack_lookup.py technique <ID> -d` prints whichever the bundle has, falling
back to the legacy field for older releases.

## Comparing against an older release

When you want to see a report the way its authors did, query the release they
wrote against:

```bash
python3 util/attack_lookup.py --attack-version 16.1 technique T1562.001
python3 util/attack_lookup.py --attack-version 16.1 search impair defenses
```

Every release since v1.0 is in `enterprise-attack/`, so you can reproduce any
report's contemporary mapping and diff it against current.

## The general habit

There are 149 revoked Enterprise techniques with defined replacements
in this bundle, plus deprecated ones with none. You will not memorise them, and
you do not need to — run `validate` over any table you are handed. The point is
not that reports are careless; it is that ATT&CK moves, and a citation that was
correct in 2024 can name an ID that no longer exists.
