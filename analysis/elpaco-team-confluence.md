# ELPACO-team ransomware via Confluence (CVE-2023-22527)

Analysis of The DFIR Report, ["Another Confluence Bites the Dust: Falling to
ELPACO-team Ransomware"](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/)
— published 2025-05-19, intrusion late June 2024, originally issued as a private
Threat Brief in October 2024 and used as the December 2024 DFIR Labs CTF.
Report analysts: pcsc0ut, IrishDeath, Tornado. Internal case `#TB30043 #PR35928`.

Every ATT&CK ID below was resolved against **Enterprise ATT&CK v19.1** as
shipped in this repository, using `util/attack_lookup.py` — not from memory.
Two of the IDs the report itself cites have since been revoked; see
[Validating the report's own mapping](#validating-the-reports-own-mapping).

---

## The short version

An unpatched, internet-facing Atlassian Confluence server was exploited via
**CVE-2023-22527** (OGNL template injection → RCE). The web server ran as
`NETWORK SERVICE`, so the actor's first job was privilege escalation; they used
Metasploit's `getsystem`, failed twice, and succeeded on the third method. From
SYSTEM they created a local admin (`noname`), installed AnyDesk as a service
with a fixed unattended password, and then largely abandoned Metasploit —
**AnyDesk became the primary hands-on-keyboard channel for the rest of the
intrusion**.

Over the next two days they scanned the network with SoftPerfect NetScan,
failed at Zerologon and PrintNightmare, dumped LSASS with Mimikatz, validated
the stolen NTLM hashes with Impacket `secretsdump`, and used Impacket `wmiexec`
with pass-the-hash to get an interactive shell on a domain controller — where
they created a domain account `NONAME` and put it in **Domain Admins** *and*
**Enterprise Admins**. They then RDP'd to a backup server and a file server,
turned off Defender, and ran the ransomware.

**Time from first exploit to encryption: ~62 hours.** No meaningful data
exfiltration — under 70 MB moved in *both* directions across the whole
intrusion, screen frames included. This was encryption-only extortion, not
double extortion.

### Why this case is worth studying

- **The entry point is boring and that's the point.** A known CVE with a public
  PoC, on a server that had been getting scanned and exploited for `whoami` by
  unrelated parties for *months* before the real intrusion. Patch latency, not
  actor sophistication, is the story.
- **The tooling is entirely off-the-shelf.** Metasploit, AnyDesk, Mimikatz,
  Impacket, SoftPerfect NetScan, ProcessHacker, Defender Control. Nothing
  bespoke except the ransomware, and that's a Mimic variant.
- **Repetition suggests automation.** The install-AnyDesk / add-admin /
  enable-RDP sequence ran three separate times with the same passwords. The
  report reads this as a playbook or script, not improvisation.
- **Two of the actor's three escalation attempts and both of their exploit
  attempts against DCs failed** — and the failures are documented as carefully
  as the successes. That's rare and useful: it tells you what a *partially*
  hardened environment looks like under attack.

---

## Timeline

Times are relative to the first Metasploit delivery (T0). Day numbering follows
the report body.

| When | What |
|---|---|
| T−20 min | `45.227.254[.]124` exploits CVE-2023-22527, runs `whoami`, leaves. This IP later becomes the actor's self-hosted AnyDesk server. |
| **T0 (day 1)** | `91.191.209[.]46` exploits the same bug, uses `curl` to fetch `HAHLGiDDb.exe` into `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\` and runs it. |
| T0 + ~30 s | Loader pulls a Meterpreter DLL over raw TCP `91.191.209[.]46:12385`, drops `nbjlop.dll`, opens named pipe `\\nbjlop`, injects a remote thread into `lsass.exe`. |
| T0 + minutes | `getsystem`: named-pipe impersonation (DLL dropper variant) **fails**, token duplication **fails**, RPCSS named-pipe impersonation **succeeds** → two SYSTEM `cmd.exe` children. |
| T0 + minutes | `u1.bat` creates local admin `noname` / `Slepoy_123`, password set to never expire. |
| T0 + ~3 min | AnyDesk downloaded into `C:\Program Files\Atlassian\Confluence\`, installed as a service, unattended password `P@ssword1` set, `--get-id` run to capture the AnyDesk ID. |
| T0 + ~4 min | Second loader `RfHBBgXXYF.exe` delivered the same way. |
| T0 + ~12 min | Third loader `ZqYeqEZtohD.exe`. |
| T0 + ~13 min | Metasploit C2 closes. Everything from here runs over AnyDesk. |
| **Day 2** | Several AnyDesk sessions lasting seconds to under two minutes, no commands run. Separately, `109.160.16.68` exploits Confluence for ~20 min (`dir C:\Users\`, `net localgroup administrators`, and a hand-typed `whaomi` typo) — the report assesses this as a **likely unrelated actor**. Two more IPs run `whoami` only. |
| **Day 3** | AnyDesk file transfer of an `Attacker\share\` folder (contains `spider.dll`). Mimikatz dropped and run 4×; `secretsdump.exe` run 8× in under 2 min; NetScan sweeps the subnet; `zero.exe` (Zerologon) fails against the DCs; `CheckVuln.bat` + `rpcdump.exe` find no PrintNightmare surface; `wmiexec.exe` pass-the-hash → interactive shell on a DC → domain account `NONAME` added to Domain Admins and Enterprise Admins. SMB share `share` created on the beachhead; host rebooted. |
| **~T0 + 62 h** | `ELPACO-team.exe` dropped on Confluence host, copied to a **backup server** over RDP as `noname`, executed. Ransom note `C:\Decryption_INFO.txt` opened in Notepad to verify. Repeated on a **file server** after Defender Control and ProcessHacker were installed. Files renamed `.ELPACO-team`. Event logs and files deleted on the beachhead. |

---

## The attack chain, mapped

| # | Phase | What the actor did | ATT&CK (v19.1) |
|---|---|---|---|
| 1 | Resource Development | Self-hosted AnyDesk server on `45.227.254[.]124:443`; Metasploit handler on `91.191.209[.]46:12385` | T1583.004 Server |
| 2 | Resource Development | Off-the-shelf offensive tooling: Mimikatz, Impacket, NetScan, ProcessHacker, Defender Control | T1588.002 Tool |
| 3 | Initial Access | CVE-2023-22527 OGNL template injection against internet-facing Confluence (Suricata sid 2050543) | **T1190** Exploit Public-Facing Application |
| 4 | Execution | `cmd.exe /c` children of `tomcat9.exe` — `whoami`, `dir`, `curl` | **T1059.003** Windows Command Shell |
| 5 | Command and Control | `curl` fetches the loader from the exploiting host | **T1105** Ingress Tool Transfer |
| 6 | Stealth | Loader imports only `VirtualAlloc` + `ExitProcess`; resolves the rest by API-name hash at runtime | T1027.007 Dynamic API Resolution |
| 7 | Stealth | Meterpreter DLL loaded into memory / injected into other processes; process access `0x1F3FFF` on `tomcat9.exe`, `conhost.exe`, `mysqld.exe`, `java.exe`, `svchost.exe` | T1055 Process Injection; T1055.001 Dynamic-link Library Injection; T1620 Reflective Code Loading |
| 8 | Command and Control | Raw TCP sockets to `91.191.209[.]46:12385` — explicitly *not* HTTP | T1095 Non-Application Layer Protocol; T1571 Non-Standard Port |
| 9 | Credential Access | Remote thread created in `lsass.exe` 30 s after loader start (Sysmon EID 8) | **T1003.001** LSASS Memory |
| 10 | Privilege Escalation | `getsystem` — named-pipe impersonation (`\\nbjlop`, DLL dropper variant) failed; token duplication failed (x86-only); **RPCSS named-pipe impersonation succeeded** | T1134.001 Token Impersonation/Theft; **T1134.002** Create Process with Token *(the failed duplication attempt)* |
| 11 | Persistence | `u1.bat`: `net user noname Slepoy_123 /add`, WMIC lookup of SID `S-1-5-32-544`, `net localgroup` add, password never expires (Security 4720/4722/4738/4724) | **T1136.001** Local Account; T1098.007 Additional Local or Domain Groups |
| 12 | Persistence / C2 | AnyDesk installed as a service into `ProgramData`; `--start-service`; unattended password `P@ssword1` piped via `echo`; `--get-id`. Done three times. | **T1543.003** Windows Service; T1219.002 Remote Desktop Software |
| 13 | Command and Control | AnyDesk **Direct Connection** to the actor's own server, bypassing AnyDesk relay infrastructure | T1219.002 Remote Desktop Software |
| 14 | Persistence *(staged, never run)* | `spider.dll` / `spider_32.dll` — hardcoded `Crackenn` / `*aaa111Cracke` added via `NetUserAdd` to Administrators and Remote Desktop Users. No evidence it executed. | T1136.001 *(capability only)* |
| 15 | Discovery | `whoami` (repeatedly, from multiple IPs) | T1033 System Owner/User Discovery |
| 16 | Discovery | `dir C:\Users\` to enumerate account names; `net localgroup administrators` | T1083 File and Directory Discovery; T1087.001 Local Account |
| 17 | Discovery | `!start.cmd` branches on OS architecture; ransomware runs `Get-VM` / `Get-VHD` | T1082 System Information Discovery |
| 18 | Discovery | NetScan sweep of the local subnet: TCP 88, 137, 445, 3389, **6160 (Veeam agent)** | **T1046** Network Service Discovery; **T1018** Remote System Discovery |
| 19 | Discovery | NetScan SMB read/write checks, dropping `delete.me` on shares (Security 5145) | T1135 Network Share Discovery |
| 20 | Discovery | `reg query "...\Terminal Server\WinStations\RDP-Tcp" /v PortNumber` | **T1012** Query Registry |
| 21 | Discovery | `CheckVuln.bat` → `rpcdump.exe` + `findstr /C:"MS-RPRN" /C:"MS-PAR"` against two DCs, hunting PrintNightmare surface (473 endpoints returned, neither present) | **T1057** Process Discovery *(as the report maps it)*; T1018 Remote System Discovery |
| 22 | Privilege Escalation | `zero.exe <DC> <DC$> administrator -c "whoami"` — **Zerologon (CVE-2020-1472) failed**; only Suricata phases 1 and 2 of 3 fired | **T1068** Exploitation for Privilege Escalation; T1210 Exploitation of Remote Services |
| 23 | Privilege Escalation | PrintNightmare (CVE-2021-34527) tooling staged — `sharpprintnightmare.exe`, `spn.exe` — never viable | T1068; T1210 |
| 24 | Defense Impairment | `DC.exe` (Defender Control) sets `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1` | **T1685** Disable or Modify Tools *(report cites the revoked T1562.001)*; **T1112** Modify Registry |
| 25 | Defense Impairment | `reg add ... fDenyTSConnections /t REG_DWORD /d 0` | T1112 Modify Registry |
| 26 | Defense Impairment | `netsh advfirewall firewall set rule group="remote desktop" new enable=yes` and `add rule name="allow RDP" dir=in protocol=TCP localport=3389 action=allow` | **T1686** Disable or Modify System Firewall *(report cites the revoked T1562.004)* |
| 27 | Credential Access | `mimikatz.exe "privilege::debug" "log .\!logs\Result.txt" "sekurlsa::logonPasswords" "token::elevate" "lsadump::sam" exit` — 4 executions, `lsass.exe` access `0x1010`; output read in Notepad each time | **T1003.001** LSASS Memory; T1003.002 Security Account Manager |
| 28 | Credential Access | ProcessHacker installed on backup and file servers, `lsass.exe` access `0x1010` as SYSTEM (no dump file observed) | T1003.001 *(attempted)* |
| 29 | Credential Access | `secretsdump.exe -hashes :<HASH> <USER>@<IP>` — PyInstaller-packed Impacket `secretsdump.py`, 8 runs in <2 min across 2 users / 2 IPs / 2 hashes; leaves `sessionresume_XXXXXXXX` artifacts | **T1003.003** NTDS *(see caveats)*; T1003.002 Security Account Manager |
| 30 | Lateral Movement | `wmiexec.exe :<NTLM_HASH> <domain_admin>@<dc_ip>` — authentication with the hash, no password | **T1550.002** Pass the Hash |
| 31 | Lateral Movement | Impacket `wmiexec` gives an interactive prompt on the DC; all commands appear as `wmiprvse.exe` children with output redirected to epoch-named files in `ADMIN$` | **T1047** Windows Management Instrumentation; T1021.002 SMB/Windows Admin Shares |
| 32 | Persistence / Priv Esc | On the DC: `NET1 USER NONAME SLEPOY_123 /DOMAIN /ADD`, then `/DOMAIN /ADD` into `DOMAIN ADMINS` and `ENTERPRISE ADMINS` | T1136.002 Domain Account; T1098.007 Additional Local or Domain Groups |
| 33 | Lateral Movement | Compromised domain admin account reused for RDP and AnyDesk sessions | T1078.002 Domain Accounts |
| 34 | Lateral Movement | Batch script creates SMB share `share` on the beachhead, fixes permissions, starts LanManServer/LanManWorkstation, reboots (Security 5142) | T1021.002 SMB/Windows Admin Shares |
| 35 | Lateral Movement | RDP to file server and backup server — in at least one case launched straight from the NetScan GUI (`netscan.exe` → `mstsc.exe`) | **T1021.001** Remote Desktop Protocol |
| 36 | Lateral Movement | Tools and `ELPACO-team.exe` copied host-to-host over SMB and the RDP session | T1570 Lateral Tool Transfer |
| 37 | Stealth | 7-Zip SFX unpacks the ransomware bundle; `Everything64.dll` extracted with password `7595128543001923103` | T1027.013 Encrypted/Encoded File; T1140 Deobfuscate/Decode Files or Information |
| 38 | Stealth | Payload copied to `C:\Users\noname\AppData\Local\<GUID>\svhostss.exe` — same hash as `ELPACO-team.exe`, named to blend with `svchost.exe` | T1036.005 Match Legitimate Resource Name or Location |
| 39 | Persistence | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\svhostss` → the payload path | **T1547.001** Registry Run Keys / Startup Folder |
| 40 | Execution | `powershell.exe -ExecutionPolicy Bypass` running `Get-VM`, `Get-VHD`, `Get-DiskImage -ImagePath $_.Path`, `Dismount-DiskImage`, `Get-VM \| Stop-VM` | **T1059.001** PowerShell |
| 41 | Impact | Virtual machines stopped and VHDs dismounted so their files can be encrypted | T1489 Service Stop |
| 42 | Impact | `ELPACO-team.exe` / `svhostss.exe` encrypts files, appends `.ELPACO-team`, writes `C:\Decryption_INFO.txt`; `Everything.exe` used to index files fast; 12,000+ process accesses in under 10 minutes | **T1486** Data Encrypted for Impact; T1083 File and Directory Discovery |
| 43 | Stealth | `logs_delete.cmd`; event logs cleared | **T1685.005** Clear Windows Event Logs |
| 44 | Stealth | `xdel.exe` bundled with the ransomware; file deletions on the beachhead before the actor left | T1070.004 File Deletion |
| 45 | Exfiltration | *Not observed.* <70 MB total both directions over AnyDesk, including screen frames | — |

**Bold** IDs are ones the report's own ATT&CK table also lists.

---

## Validating the report's own mapping

The report cites **23 techniques**. Run against this repository's v19.1 bundle:

```bash
python3 util/attack_lookup.py extract report.txt
```

**21 resolve cleanly. Two are revoked** — not because the report was wrong, but
because ATT&CK v19 split the old `T1562 Impair Defenses` tree into a new
**Defense Impairment** tactic and renumbered its children:

| Report cites | Status | Current ID |
|---|---|---|
| T1562.001 Disable or Modify Tools | **REVOKED** | **T1685** Disable or Modify Tools |
| T1562.004 Disable or Modify System Firewall | **REVOKED** | **T1686** Disable or Modify System Firewall |

Two more shifted without breaking:

- **T1219** was renamed *Remote Access Software* → **Remote Access Tools**, and
  gained sub-techniques. AnyDesk is squarely **T1219.002 Remote Desktop
  Software**.
- **T1070.001 Clear Windows Event Logs** (which the report *doesn't* cite, but
  which its `logs_delete.cmd` indicator calls for) is now **T1685.005**.

If you are re-using this report's mapping in a current Navigator layer or
detection backlog, those are the four to fix.

### Where the report's table is thinner than its own evidence

These are described in the report prose but absent from its ATT&CK list:

1. **T1550.002 Pass the Hash.** The single largest omission. The report shows
   `wmiexec.exe :<NTLM_HASH> <user>@<ip>` and says outright that hashes from
   Mimikatz were used to authenticate. Pass-the-hash is *how* the domain fell,
   and it isn't mapped.
2. **T1547.001 Registry Run Keys.** The ransomware's own persistence — the
   `Run\svhostss` value — is documented with the full key path and not mapped.
3. **T1046 / T1135 Network Service and Share Discovery.** NetScan's port sweep
   and its SMB read/write checks (with the `delete.me` artifact and Event 5145)
   get a full section and a Sigma rule, but no technique.
4. **T1021.002 SMB/Windows Admin Shares.** `ADMIN$` output redirection is
   shown in screenshots; the `share` creation script has its own subsection.
5. **T1098.007 Additional Local or Domain Groups.** `NONAME` going into Domain
   Admins *and* Enterprise Admins is the moment of total domain compromise.
   T1136 Create Account covers the creation, not the elevation.
6. **T1136.002 Domain Account.** Only the local variant (`.001`) is listed,
   though `NET1 USER NONAME ... /DOMAIN /ADD` is quoted verbatim.
7. **T1055 Process Injection.** Meterpreter's reflective DLL injection and the
   `0x1F3FFF` process-access events across five processes have their own
   Defense Evasion subsection.
8. **T1685.005 Clear Windows Event Logs / T1070.004 File Deletion.** The Key
   Takeaways say "some event logs were deleted"; `logs_delete.cmd` is an
   indicator with three hashes.
9. **T1036.005 Match Legitimate Resource Name or Location.** `svhostss.exe`.
10. **T1570 Lateral Tool Transfer.** T1105 Ingress Tool Transfer is listed —
    that covers external→internal, not the host-to-host copies of
    `ELPACO-team.exe` onto the backup and file servers.

### Where the report's table is arguably wrong

**T1071 Application Layer Protocol** is the questionable one. The report's own
Command and Control section states: *"The Command and Control traffic to the
Metasploit server used raw TCP sockets, not HTTP or other common protocols."*
That is the textbook definition of **T1095 Non-Application Layer Protocol**, and
port 12385 adds **T1571 Non-Standard Port**. T1071 could be defended for the
AnyDesk channel on 443, but nothing in the report characterises that traffic at
the protocol layer beyond a certificate exchange.

**T1134.002 Create Process with Token** describes the token-duplication attempt
that *failed*. The method that actually worked — RPCSS named-pipe impersonation
— is **T1134.001 Token Impersonation/Theft**. Both belong in the table; only
`.002` is there.

**T1016 System Network Configuration Discovery** has no clear supporting
evidence in the report. There is no `ipconfig`, `route`, `arp`, or `netsh
interface` in any quoted command line. NetScan's activity is network *service*
and *system* discovery (T1046/T1018), which are the IDs that are missing.

### Where the evidence is weaker than the mapping

**T1003.003 NTDS.** The report shows `secretsdump.exe` invoked with `-hashes`
against remote IPs and notes that Impacket's `secretsdump` *can* extract
`NTDS.dit`. It does not show NTDS extraction happening — no DRSGetNCChanges
traffic, no `vssadmin`, no `ntds.dit` file artifact. The eight rapid executions
across two users and two IPs read more like **hash validation** than
replication. T1003.002 Security Account Manager is better supported (Mimikatz
ran `lsadump::sam` explicitly). Treat T1003.003 as plausible-not-proven.

**T1490 Inhibit System Recovery** is *not* mapped by the report, and this
analysis does not add it. Mimic-family ransomware normally deletes shadow
copies, but the report never shows it. The PowerShell that *is* shown stops VMs
and dismounts VHDs — that's T1489 Service Stop, a different behavior.

---

## Reading the failures

Three attacks in this intrusion did not work, and each failure tells you
something about the environment:

| Attempt | Why it failed | What that means for you |
|---|---|---|
| `getsystem` named-pipe impersonation, DLL dropper variant | Requires the shell to *already* be running as Administrator; it was `NETWORK SERVICE` | Running Confluence/Tomcat under a low-privilege service account genuinely cost the actor time and generated three sets of loud artifacts |
| `getsystem` token duplication | Rapid7's implementation only works on x86; the host was x64 | Same — and each failed attempt dropped a named DLL and opened a matching named pipe |
| Zerologon (`zero.exe`) against two DCs | Patched. Only 2 of the 3 Suricata phases fired | The DCs were patched for CVE-2020-1472; the Confluence server was not patched for a CVE with a public PoC. Patch coverage was uneven, not absent |
| PrintNightmare (`rpcdump.exe` + `CheckVuln.bat`) | Neither `MS-RPRN` nor `MS-PAR` was among 473 registered RPC endpoints — Print Spooler wasn't exposed | Disabling the Print Spooler on DCs worked exactly as intended |

The actor still won, via credential theft and pass-the-hash. **Every hardening
control in this environment held except the one that mattered: patching the
internet-facing application, and preventing LSASS from being read by SYSTEM.**

---

## Detection opportunities

The report's own detection sections are unusually good. A few that generalise:

**The Metasploit loader's DLL/pipe pairing.** Every loader dropped a
randomly-named DLL and opened a named pipe with the *same* name minus `.dll`:

| DLL (Sysmon EID 11) | Pipe (Sysmon EID 17) |
|---|---|
| `...\Temp\nbjlop.dll` | `\\nbjlop` |
| `...\Temp\npixmw.dll` | `\\npixmw` |
| `...\Temp\cjlodi.dll` | `\\cjlodi` |
| `...\Temp\wucnic.dll` | `\\wucnic` |

Sigma can't express a cross-event string join, but any SIEM with `JOIN` and
string functions can — strip the extension from the DLL name, strip the
backslashes from the pipe name, correlate on a short time window. The report
says this query returned **only** the Metasploit activity across the whole case.
That is a very high-signal hunt, and it's free.

**Web server processes spawning shells.** `tomcat9.exe` → `cmd.exe` → `whoami`
is the entire initial-access detection. Sigma
`8202070f-edeb-4d31-a010-a26c72ac5600` (*Suspicious Process By Web Server
Process*) covers it. Applies to any T1190 case, not just Confluence.

**NetScan's `delete.me`.** SoftPerfect's share write-access check creates and
deletes a file called `delete.me`. Windows Security **Event 5145** records it by
name. Near-zero false positives.

**LSASS access flags.** `0x1010` (`PROCESS_QUERY_LIMITED_INFORMATION` +
`PROCESS_VM_READ`) from a non-system binary is the credential-dumping signature
here — it fired identically for Mimikatz *and* ProcessHacker. `0x1F3FFF`
(full access) preceded injection. ATT&CK's detection strategy for T1003.001
(DET0363) keys on exactly this access-then-dump sequence.

**Impacket's fingerprints.** `wmiprvse.exe` spawning `cmd.exe` with output
redirected to `\\127.0.0.1\ADMIN$\<epoch>` is Impacket `wmiexec` and almost
nothing else. Four public Sigma rules in the report cover it. `secretsdump`
additionally leaves `sessionresume_` + 8 random letters on disk.

**NetScan → mstsc.** `netscan.exe` spawning `mstsc.exe` means someone clicked
"Remote Desktop" in the NetScan GUI. Legitimate admins rarely pivot that way.

Pull the full v19.1 detection strategies and log sources for any of these:

```bash
python3 util/attack_lookup.py technique T1003.001 T1550.002 T1046 --detections --mitigations
```

---

## Indicators

**Network**

| Indicator | Role |
|---|---|
| `45.227.254[.]124` | First exploit (`whoami`); actor-hosted AnyDesk On-Prem server, port 443. Later seen presenting a self-signed cert on 3389, CN `D-422`, serial `104770999709883145161872575332968665437` |
| `91.191.209[.]46` | Metasploit delivery + Meterpreter C2 on TCP **12385** |
| `109.160.16.68` | Day-2 Confluence exploitation — assessed as a **separate** actor |
| `185.228.19[.]244`, `185.220.101[.]185` | Day-2 `whoami`-only exploitation; attribution unknown |

**Host artifacts**

- `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\` — loader and
  Meterpreter DLL drop location
- `C:\Program Files\Atlassian\Confluence\` — `AnyDesk.exe`, `u1.bat`
- `C:\Users\noname\AppData\Local\<GUID>\svhostss.exe` — ransomware copy
- `C:\temp\MIMIC_LOG.txt`, `C:\temp\session.tmp` — written on every encrypted host
- `C:\Decryption_INFO.txt` — ransom note; `.ELPACO-team` file extension
- `sessionresume_<8 letters>` — Impacket `secretsdump` artifact
- `delete.me` — NetScan share write-check artifact

**Credentials the actor created** (fixed across all three runs — strong
indicator of a scripted playbook)

| Account | Password | Where |
|---|---|---|
| `noname` | `Slepoy_123` | Local admin on beachhead, then **domain** account in Domain Admins + Enterprise Admins |
| AnyDesk unattended | `P@ssword1` | Set three times, same value |
| `Crackenn` | `*aaa111Cracke` | Hardcoded in `spider.dll` — **never created**; same pair appears in a SentinelOne Black Basta report |
| 7-Zip SFX | `7595128543001923103` | `Everything64.dll` extraction |

**Key file hashes (SHA256)** — full list in the report:

| File | SHA256 |
|---|---|
| `elpaco-team.exe` | `a710ed9e008326b981ff0fadb1c75d89deca2b52451d4677a8fd808b4ac0649b` |
| `elpaco-team.exe` (2nd) | `0b83f2667abff814bb724808c404396e6ad417591165f1762a8e99ec108d4996` |
| `hahlgiddb.exe` (Metasploit loader) | `abbe5619e1d7a08f807b57d0949a7f97108a546a415778f25ed35f31ee2cd2f5` |
| `u1.bat` | `15348e1401fe18b83e30a7e7f6b4de40b9981a0e133c22958324a89c188f2c49` |
| `secretsdump.exe` | `c3405d9c9d593d75d773c0615254e69d0362954384058ee970a3ec0944519c37` |
| `wmiexec.exe` | `14f0c4ce32821a7d25ea5e016ea26067d6615e3336c3baa854ea37a290a462a8` |
| `spider.dll` | `90cdcf54bbaeb9c5c4afc9b74b48b13e293746ee8858c033fc9d365fd4074018` |
| `checkvuln.bat` | `2c656109db6d2059c41a50e623ceb5e656ff764c44b1e1dbf41131f0206f8238` |
| `defendercontrol.exe` | `6606d759667fbdfaa46241db7ffb4839d2c47b88a20120446f41e916cad77d0b` |
| `logs_delete.cmd` | `36d3b20e9380aaaac9151280b4ac3e047a0871efbb158f04344946ff67176a48` |
| `netscan.exe` | `5748bfb17e662fb6d197886a69df47f1071052c3381eb1c609a2bc5dba8c2992` |

---

## Caveats and open questions

- **The report's day numbering is internally inconsistent.** The Case Summary
  places privilege escalation on "the fourth day", while the Privilege
  Escalation section shows `getsystem` happening within minutes of initial
  access on day one, and every other section (Credential Access, Discovery,
  Impact) says "day three". The 62-hour figure is consistent with day three.
  The timeline above follows the body, not the summary.
- **Day-2 activity is probably a different actor.** The report says so
  explicitly for `109.160.16.68` (the `whaomi` typo suggests hand-typed input),
  and cannot attribute the two `whoami`-only IPs at all. This server was being
  opportunistically exploited by multiple unrelated parties. Don't merge those
  IPs into a single actor profile.
- **`spider.dll` was staged but never executed.** No `Crackenn` account, no
  `rundll32`/`regsvr32` invocation. Mapping it as achieved persistence would
  overstate the evidence — it's a capability the actor carried, and a link to
  Black Basta tooling, nothing more.
- **The AnyDesk `--get-id` step is a persistence tell, not a technique.** It
  exists so the actor can reconnect later without re-exploiting. Worth
  recording as tradecraft even though ATT&CK has no ID for it.
- **T1583.004 and T1588.002 are PRE-ATT&CK inferences.** The report doesn't
  describe how the infrastructure was acquired; the self-hosted AnyDesk server
  and the tool inventory imply it.
- **`ELPACO-team` is a Mimic variant** (per Cyfirma, November 2024), and Mimic
  itself descends from Phobos — which is why the report's YARA hits include
  `ELASTIC_Windows_Ransomware_Phobos_11Ea7Be5` and
  `SEKOIA_Ransomware_Win_Eking_Rich_Header`. It abuses the legitimate
  **Everything** search engine (`Everything.exe`, `Everything64.dll`) to index
  target files quickly — a Mimic family signature.
- **No exfiltration means no leak-site leverage.** Under 70 MB moved in total.
  If you are modelling this actor, they were betting entirely on backup
  destruction — which is why the *backup server* was the first encryption
  target.

---

## Reproducing this analysis

```bash
# validate the IDs the report cites against the current bundle
python3 util/attack_lookup.py extract /path/to/report.txt

# confirm the two revocations and their successors
python3 util/attack_lookup.py validate T1562.001 T1562.004 T1070.001

# look up anything above in full
python3 util/attack_lookup.py technique T1550.002 --full --detections --mitigations

# the Navigator layer for this intrusion is checked in alongside this file
#   analysis/elpaco-team-layer.json
# to regenerate it (note: skip the four IDs this file cites *as revoked* --
# T1562, T1562.001, T1562.004, T1070.001 -- they are discussed, not mapped)
python3 util/attack_lookup.py layer $(grep -oE 'T1[0-9]{3}(\.[0-9]{3})?' \
  analysis/elpaco-team-confluence.md | sort -u \
  | grep -vE '^(T1562(\.00[14])?|T1070\.001)$') \
  --out analysis/elpaco-team-layer.json
```
