# Glossary for report readers

Terms that stop beginners mid-report. Each entry gives the plain definition,
then why it matters for mapping or detection. Explain the term, then connect it
to whatever the learner is actually reading — definitions stick when attached
to something concrete.

## Malware roles

**Loader** — a small program whose only job is to get other malware running. It
does no damage itself. Loaders stay small because small is cheap to rebuild
when detected, and because the valuable payload should stay hidden until the
environment is checked (locale, sandbox). The split also matches the criminal
economy: one crew runs loaders and sells access, another buys it and deploys
their own tooling. A multi-hour gap between loader and hands-on activity is
usually that handoff.

**Dropper** — carries its payload inside itself rather than downloading it.

**Payload** — the thing that finally does harm (ransomware, a stealer).

**Implant / agent / beacon** — the component giving the operator interactive
control. Used more or less interchangeably.

**C2 (command and control)** — the adversary's server infrastructure, and the
channel to it.

**RAT** — remote access trojan; an implant with interactive control features.

## Access and control

**Beacon** — an implant that periodically calls out asking "any commands?"
rather than the attacker connecting in. Two reasons: firewalls block inbound
connections, so the victim must initiate; and a persistent open connection is
conspicuous where short periodic requests look like ordinary web traffic.

Governed by **sleep** (interval between check-ins) and **jitter** (random
variation on it, to defeat periodicity detection). The rhythm is a forensic
artifact — gaps in beacon traffic show when the operator was away.

**Reverse shell / reverse tunnel** — same principle: the inside machine
initiates outbound, and the connection is then used backwards to carry the
adversary's traffic in. `ssh -R` is the canonical example.

**Beachhead host** — the first machine an adversary controls, from which they
expand.

**Dwell time** — how long the adversary was present before detection or impact.

## Techniques you will meet constantly

**DLL side-loading** — placing a legitimate signed executable in a folder you
control, next to a malicious DLL it genuinely imports. Windows searches the
program's own directory before `System32`, so the malicious DLL wins and
adversary code runs inside a trusted process.

Two conditions make it work: the DLL must be one the binary actually imports
(you cannot hijack a DLL that is never loaded), and it must not be in
**KnownDLLs** — a protected list of core libraries (`kernel32.dll`,
`user32.dll` and others) always loaded from `System32` regardless. This is why
adversaries hunt for specific binary/DLL pairs.

The relocation is the detection: a `System32` binary running from `%TEMP%` or
`%APPDATA%` has no legitimate explanation.

**Process injection** — writing code into another *running* process's memory
and starting a thread on it. The host process is a victim, not a participant:
it never loads or imports anything. Typical API sequence is `OpenProcess`,
`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.

Forensic fingerprints: **unbacked thread entry point** (code from no file on
disk) and **private RWX regions** (memory both writable and executable, which
legitimate programs rarely need). The file on disk stays clean, which is why
static analysis finds nothing and memory analysis finds everything.

**LOLBin / living off the land** — using tools already on the system
(`wbadmin`, `rundll32`, `wmic`, `certutil`, `comsvcs.dll`) instead of bringing
malware. Nothing to download, nothing for a file scanner to catch, and the
binaries are signed by Microsoft. Detection has to be behavioral: the binary is
legitimate, the *use* is not.

**Masquerading** — making something look benign. Renaming a legitimate utility
(`WAB.exe` → `AdgNsy.exe`) defeats name-based rules, but the PE
`OriginalFilename` field survives renaming, so an Image/OriginalFilename
mismatch is a reliable catch.

**DGA (domain generation algorithm)** — malware and adversary both run the same
algorithm, usually date-seeded, producing many candidate domains. The adversary
registers one or two; the malware tries them until one answers.

The failed lookups are *not* decoys — the malware genuinely does not know which
domain is live, so it searches. That noise is a cost the adversary accepts for
resilience, and it is the detection: a burst of NXDOMAIN responses for
high-entropy names is not something normal software produces.

The point is movable C2. The adversary changes servers by registering a
different domain from tomorrow's list; already-deployed malware follows with no
update.

**BYOVD (bring your own vulnerable driver)** — deploying a legitimate but
vulnerable signed driver to gain kernel-level access, then using it to kill
security products from below. Maps to **T1685** (not the revoked T1562.001)
plus T1068.

**Geofencing** — malware checking system locale, keyboard layout or language
packs and exiting if it matches certain regions, usually CIS. Legal
self-preservation for the operators, and a weak attribution signal. It also
means a sandbox with the wrong locale sees nothing happen.

**UAC (User Account Control)** — the Windows prompt asking permission for
admin rights. A signed binary shows a publisher name; unsigned shows "Unknown
Publisher", which is why abused code-signing certificates matter. `consent.exe`
is the binary that displays this prompt.

**Code signing** — a signature asserting who published a binary and that it is
unmodified. Adversaries register shell companies, buy genuine certificates, and
sign malware; the signature is valid, the company is fake. A signer name is a
far better hunting indicator than a hash, because it is reused across many
samples until revoked. "Revoked certificate" in a report usually describes the
state at analysis time, not at execution time.

**Pass the hash** — authenticating with a stolen password hash without ever
knowing the password.

**DPAPI** — the Windows Data Protection API, used to encrypt saved credentials.
Extracting the *domain backup key* is far more serious than local DPAPI abuse:
it decrypts any domain user's DPAPI secrets and survives password resets.
Enterprise ATT&CK has no dedicated DPAPI technique; closest are T1552.004 and
T1555.004.

## Detection vocabulary

**YARA** — rules matching patterns (strings, byte sequences) inside files or
memory. Useful when malware carries distinctive strings that collide with
nothing benign. Scans memory too, which matters for injected code that never
touched disk.

**Sigma** — rules matching *log events* (process creation, network
connections). Vendor-neutral, translated into whatever SIEM you run.

**Suricata / ET rules** — rules matching network traffic on the wire.

Reports often ship all three. They inspect different things: files, logs,
packets.

**Sysmon** — a Windows logging tool producing the telemetry most host rules
depend on. Events worth recognising: **1** process creation, **3** network
connection, **7** image (DLL) load, **10** process access, **11** file create,
**22** DNS query, **23** file delete.

**Correlation rule** — fires on a *pattern* across events rather than a single
event. Necessary where no individual event is suspicious (a DGA burst, or LSASS
enumeration followed by a dump).

**Pyramid of Pain** (David Bianco) — indicators ranked by how much it costs the
adversary to change them. Hashes are free to change, domains and IPs cheap,
tools moderate, **TTPs expensive**. This is the entire argument for mapping
behavior instead of collecting IOCs: the domains in any report are dead by
publication, but "a domain controller opened an outbound SSH connection" still
detects the next crew.

**Detection vs prevention vs response** — three different things, and reports
usually show prevention failing while detection quietly worked. If a report
reconstructs an intrusion in forensic detail, the telemetry existed; what was
missing was someone acting on it.
