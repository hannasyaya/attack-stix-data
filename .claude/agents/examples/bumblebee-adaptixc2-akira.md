# Worked example: Bumblebee and AdaptixC2 deliver Akira

Example output from the `dfir-report-analyst` agent, mapped against
**Enterprise ATT&CK v19.1** as shipped in this repository.

Source: The DFIR Report, ["From Bing Search to Ransomware: Bumblebee and
AdaptixC2 Deliver Akira"](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/)
(published 2026-06-29, in partnership with Swisscom B2B CSIRT; the intrusion
occurred July 2025 and was first covered in the 2025-08-05 flash alert).

> **Sourcing caveat.** thedfirreport.com returns HTTP 403 to automated fetches
> and is blocked by this environment's network policy, so this example was
> built from the published summary plus secondary coverage, not the full
> report body. Steps below are marked *reported* or *inferred* accordingly.
> Re-run the agent with the pasted report text to fill in the host-level
> evidence, IOCs, and the report's own ATT&CK table.

## What happened

A user searching Bing for "ManageEngine OpManager" was steered by SEO
poisoning to a look-alike domain and downloaded a trojanized MSI installer.
The installer side-loaded `msimg32.dll`, the Bumblebee loader, on the
beachhead host. Bumblebee dropped an AdaptixC2 beacon, which the actor used to
pivot to a domain controller and dump `NTDS.dit`. The actor returned the next
day, stood up an SSH proxy for lateral movement, and exfiltrated over 75 GB —
file shares, credentials, and SYSVOL domain configuration — via FileZilla over
SFTP to a server in Ukraine. Akira ransomware was deployed roughly **44 hours**
after initial access.

## Attack chain

| # | Phase | Action | ATT&CK | Basis |
|---|---|---|---|---|
| 1 | Resource Development | Look-alike domain ranked in Bing for a sysadmin software query | T1608.006 SEO Poisoning | reported |
| 2 | Initial Access | User visits the poisoned result and downloads a trojanized installer | T1189 Drive-by Compromise | reported |
| 3 | Execution | User runs the malicious MSI | T1204.002 Malicious File | reported |
| 4 | Stealth | MSI installed via msiexec | T1218.007 Msiexec | inferred from MSI delivery |
| 5 | Stealth / Execution | `msimg32.dll` side-loaded to run the Bumblebee loader | T1574.001 DLL | reported |
| 6 | Command and Control | Bumblebee beacons out, drops an AdaptixC2 beacon | T1071.001 Web Protocols | inferred |
| 7 | Discovery | Domain and host enumeration ahead of the DC pivot | T1087.002 Domain Account, T1018 Remote System Discovery | inferred |
| 8 | Credential Access | `NTDS.dit` dumped from the domain controller | T1003.003 NTDS | reported |
| 9 | Persistence | Privileged domain accounts created | T1136.002 Domain Account | reported |
| 10 | Lateral Movement | SSH proxy established; movement to DCs and backup servers | T1021.004 SSH, T1090.001 Internal Proxy, T1572 Protocol Tunneling | reported |
| 11 | Collection | File shares and SYSVOL staged for exfiltration | T1039 Data from Network Shared Drive | inferred |
| 12 | Exfiltration | 75 GB+ pushed via FileZilla over SFTP to an actor-controlled host | T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | reported |
| 13 | Impact | Akira ransomware deployed domain-wide at ~44h | T1486 Data Encrypted for Impact | reported |
| 14 | Impact | Shadow copy deletion / recovery inhibition typical of Akira | T1490 Inhibit System Recovery, T1489 Service Stop | inferred from ATT&CK's Akira profile |

Tactic names follow v19: **Stealth** and **Defense Impairment** replace the
older **Defense Evasion**.

## Tooling

| Tool | Role | ATT&CK coverage |
|---|---|---|
| Bumblebee | First-stage loader, side-loaded as `msimg32.dll` | **S1039** — 39 techniques linked |
| AdaptixC2 | Post-exploitation C2 beacon | **Not tracked.** Map its observed behaviors individually |
| FileZilla | SFTP client used for bulk exfiltration | **Not tracked.** Legitimate software abused |
| Akira | Ransomware payload | **S1129** (plus S1194 Akira_v2, S1191 Megazord); actor **G1024** |

ATT&CK's S1039 Bumblebee entry corroborates behaviors the summary does not
spell out — process injection (T1055, T1055.001, T1055.004), scheduled tasks
(T1053.005), WMI execution (T1047), and system/owner discovery. Treat these as
capability of the malware family, not as confirmed observations in this
intrusion, until the full report is read.

## Detection opportunities

Ranked by where this chain is most reliably caught. Log sources are taken from
the v19 Detection Strategy objects (`technique <ID> -d`).

1. **NTDS.dit access on a domain controller** — DET0586 / AN1611. Watch
   `WinEventLog:Security` 4688 for `ntdsutil.exe`, Sysmon 11 for file writes
   under `%SystemRoot%\NTDS\`, and `Microsoft-Windows-VSS` shadow-copy
   creation. This is the highest-value chokepoint in the chain: it sits before
   the 44-hour clock ran out and has few benign causes.
2. **DLL side-loading from a user-writable path** — a signed or
   ordinary-looking binary loading `msimg32.dll` out of its own install
   directory rather than `System32`. Sysmon 7 (image load) with a path filter.
3. **Outbound SSH from a Windows workstation or server** — the actor's proxy
   was the pivot for everything after day one. Egress on 22/tcp from hosts that
   have no business speaking SSH is a strong, low-volume signal.
4. **Bulk SFTP egress** — 75 GB to a single external host over hours. Netflow
   volume thresholds per destination ASN catch this even when the protocol is
   encrypted and the client is legitimate software.
5. **New privileged domain accounts** — Security 4720/4728 correlated with
   creation outside a change window.
6. **MSI execution from a browser download path** — noisiest of the set;
   useful for hunting rather than alerting.

## Gaps and caveats

- The full report's own ATT&CK table has not been validated against v19. Run
  `python3 util/attack_lookup.py extract <report.txt>` once the text is
  available — reports written in 2025-2026 predate the Defense Evasion split
  and may cite IDs that have since been deprecated or revoked.
- No hashes, C2 IPs, or domains are reproduced here; the summary did not carry
  them. Pull IOCs from the report body directly.
- Steps 4, 6, 7, 11, and 14 are analyst inference from the described behavior
  and ATT&CK's profiles for Bumblebee and Akira, not statements from the
  report.
- AdaptixC2 is an open-source framework with no ATT&CK software entry, so its
  specific capabilities (beacon protocols, lateral-movement modules) must be
  mapped from observation rather than looked up.
