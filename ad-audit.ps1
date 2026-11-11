<#
  ad-audit.ps1 - Active Directory hardening audit from a domain-joined host.

  The BLUE-TEAM counterpart to ade.ps1 / ad-enum.sh. Same attack surface,
  opposite lens: everything the attacker scripts go looking for to ABUSE, this
  one inventories so you can FIX it first. For every weakness it prints the
  offending objects and a concrete remediation (an attribute to clear, a GPO to
  set, a command to run) - not an exploitation hint.

  USE CASE: run it under any account that can read the directory (a read-only
  auditor account is enough for most checks; a few ACL/registry checks read more
  if you run it on a DC). It never writes to the directory and never requests a
  Kerberos ticket, so it is safe to run in production and leaves no roast events.

  Pure ADSI / .NET: no RSAT, no PowerView, nothing downloaded.

    powershell -ep bypass -f ad-audit.ps1
    powershell -ep bypass -f ad-audit.ps1 -OutDir C:\Audit\ad
    powershell -ep bypass -f ad-audit.ps1 -Domain corp.com -StaleDays 60

  Findings are built from the returned objects, not by grepping the output
  files, so the command text can never be mistaken for a result.
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$Domain,                 # override the naming context, e.g. corp.com
    [int]$StaleDays   = 90,          # "stale" = no logon / no pwd change in this many days
    [int]$KrbtgtDays  = 180,         # krbtgt password older than this is flagged
    [switch]$SkipAcl,                # the domain-wide DACL scan is the slowest part
    [switch]$Quiet                   # summary only, no per-check lines
)

$ErrorActionPreference = 'Stop'
$script:Data     = @{}               # slug -> objects
$script:Findings = @()               # ordered list of {Sev,Title,Body,Fix}
$script:N_OK=0; $script:N_EMPTY=0; $script:N_FAIL=0

# ---------------------------------------------------------------- output ---
function Say([string]$s,[string]$c='Gray'){ if(-not $Quiet){ Write-Host $s -ForegroundColor $c } }
function Section([string]$s){ Say "`n[=== $s ===]" 'Cyan' }

# well-known GUIDs: an ExtendedRight ACE carrying one of these is dangerous
$G_ReplGet    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
$G_ReplGetAll = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # ...-Get-Changes-All  (DCSync = both)
$G_ReplGetFil = '89e95b76-444d-4c62-991a-0facbeda640c'   # ...-Get-Changes-In-Filtered-Set
$G_ForcePwd   = '00299570-246d-11d0-a768-00aa006e0529'   # User-Force-Change-Password
$G_WriteMember= 'bf9679c0-0de6-11d0-a285-00aa003049e2'   # add self/others to a group

# ----------------------------------------------------------- domain bind ---
try {
    $rootDSE = [ADSI]'LDAP://RootDSE'
    $script:DefaultNC = [string]$rootDSE.Properties['defaultNamingContext'].Value
    $script:DcName    = [string]$rootDSE.Properties['dnsHostName'].Value
    $script:ConfigNC  = [string]$rootDSE.Properties['configurationNamingContext'].Value   # ADCS lives here
    $script:SchemaNC  = [string]$rootDSE.Properties['schemaNamingContext'].Value
    if (-not $DefaultNC) { throw 'RootDSE returned no defaultNamingContext' }
} catch {
    Write-Host "[-] Cannot reach a Domain Controller over LDAP: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Are you on a domain-joined host? Try: nltest /dsgetdc:$env:USERDNSDOMAIN" -ForegroundColor Yellow
    exit 1
}
if ($Domain) { $script:DefaultNC = 'DC=' + ($Domain -replace '\.',',DC=') }

if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ("ad-audit-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# domain SID - lets us build/recognise well-known RIDs (512 DA, 516 DCs, ...)
try {
    $domObj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DefaultNC")
    $script:DomSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$domObj.Properties['objectSid'][0]),0)).Value
} catch { $script:DomSid = $null }

Section 'PRE-FLIGHT'
Say ("[*] Auditing as : {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name)) 'Cyan'
Say ("[*] Domain      : {0}" -f $DefaultNC) 'Cyan'
Say ("[*] Domain SID  : {0}" -f $DomSid) 'Cyan'
Say ("[*] DC          : {0}" -f $DcName) 'Cyan'
Say ("[*] Output       : {0}" -f $OutDir) 'Cyan'
Say  "[!] Read-only audit: no directory writes, no Kerberos tickets requested." 'Yellow'

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
    $s.FindAll()
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

# UAC bits worth naming on sight (same set ade.ps1 reports, plus reversible-enc)
function Decode-UAC([int]$uac){
    $f=@(); if($uac -band 0x2){$f+='DISABLED'}; if($uac -band 0x10){$f+='LOCKOUT'}
    if($uac -band 0x20){$f+='PASSWD_NOTREQD'}; if($uac -band 0x80){$f+='REVERSIBLE_PWD'}
    if($uac -band 0x10000){$f+='DONT_EXPIRE'}
    if($uac -band 0x80000){$f+='TRUSTED_FOR_DELEGATION'}; if($uac -band 0x400000){$f+='DONT_REQ_PREAUTH'}
    if($uac -band 0x1000000){$f+='TRUSTED_TO_AUTH_FOR_DELEGATION'}; $f -join ','
}

# FileTime long (pwdLastSet, lastLogonTimestamp, ...) -> DateTime, or $null
function ConvertTo-Date($v){
    try { $n=[int64]$v; if($n -le 0 -or $n -eq 9223372036854775807){ return $null }; [DateTime]::FromFileTimeUtc($n) } catch { $null }
}
function Days-Since($dt){ if($dt){ [int]((Get-Date).ToUniversalTime() - $dt).TotalDays } else { $null } }

# resolve a SID string to DOMAIN\name, falling back to the raw SID
function Resolve-Sid([string]$sid){
    try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $sid }
}

# SIDs that legitimately hold directory-replication (DCSync) rights
$script:ReplOk = @('S-1-5-9','S-1-5-18','S-1-5-32-544')
if ($DomSid) { foreach($r in 512,516,518,519,498,521){ $script:ReplOk += "$DomSid-$r" } }

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
        Say ("  [FAIL] {0,-50} {1}" -f $Desc,$errMsg) 'Red'
        return
    }
    $arr = @($objs | Where-Object { $null -ne $_ })
    $script:Data[$Slug] = $arr
    if ($arr.Count) {
        $names = @($arr[0].psobject.Properties.Name)
        if ($names.Count -eq 1 -and $names[0] -eq 'Line') {
            Add-Content $file ($arr.Line -join "`n")
        } else {
            Add-Content $file (($arr | Format-List | Out-String).Trim())
        }
    }

    if ($arr.Count -eq 0) {
        $script:N_EMPTY++; Say ("  [----] {0,-50} no results" -f $Desc) 'DarkYellow'
    } else {
        $script:N_OK++;   Say ("  [ OK ] {0,-50} {1} object(s)" -f $Desc,$arr.Count) 'Green'
    }
}

function Add-Finding([string]$Sev,[string]$Title,$Body,[string]$Fix){
    $script:Findings += [pscustomobject]@{ Sev=$Sev; Title=$Title; Body=$Body; Fix=$Fix }
}

# ============================================================ COLLECTION ===

# --- password & lockout policy -------------------------------------------
Section 'PASSWORD & LOCKOUT POLICY'
$polProps = @('minPwdLength','lockoutThreshold','pwdProperties','maxPwdAge','minPwdAge','pwdHistoryLength','lockoutDuration','msDS-Behavior-Version')
$pol = $null
Run '01-passpol' 'domain password / lockout policy' {
    $r = @(Search-AD "(distinguishedName=$DefaultNC)" $polProps -Base $DefaultNC)[0]
    if (-not $r) { return }
    $maxAge = $null
    try { $raw=[int64]$r.Properties['maxpwdage'][0]; if($raw -ne 0){ $maxAge=[int]([math]::Abs($raw)/864000000000) } } catch {}
    $script:pol = [pscustomobject]@{
        minPwdLength     = [int]("$($r.Properties['minpwdlength'][0])")
        lockoutThreshold = [int]("$($r.Properties['lockoutthreshold'][0])")
        pwdHistoryLength = [int]("$($r.Properties['pwdhistorylength'][0])")
        maxPwdAgeDays    = $maxAge
        complexity       = (([int]("$($r.Properties['pwdproperties'][0])")) -band 0x1) -ne 0
        reversibleDomain = (([int]("$($r.Properties['pwdproperties'][0])")) -band 0x10) -ne 0
    }
    $script:pol
}
if ($pol) {
    if ($pol.minPwdLength -lt 14) {
        Add-Finding 'HIGH' "Minimum password length is $($pol.minPwdLength) (want >= 14)" $pol `
            "Raise 'Minimum password length' to 14+ in the Default Domain Policy (Computer Config > Policies > Windows Settings > Security Settings > Account Policies > Password Policy). Consider a Fine-Grained Password Policy (PSO) of 15+ for privileged accounts."
    }
    if (-not $pol.complexity) {
        Add-Finding 'HIGH' 'Password complexity is DISABLED domain-wide' $pol `
            "Enable 'Password must meet complexity requirements' in the Default Domain Policy. Pair it with a banned-password list (Azure AD Password Protection on-prem agent) to stop 'Winter2026!'-style passwords."
    }
    if ($pol.reversibleDomain) {
        Add-Finding 'CRIT' 'Reversible encryption enabled DOMAIN-WIDE (passwords recoverable in plaintext)' $pol `
            "Disable 'Store passwords using reversible encryption' in the Default Domain Policy immediately, then force a password reset so the cleartext-equivalent copies are purged."
    }
    if ($pol.lockoutThreshold -eq 0) {
        Add-Finding 'HIGH' 'Account lockout threshold is 0 (unlimited password guessing / spraying)' $pol `
            "Set 'Account lockout threshold' to 5-10 bad attempts with a 15-30 min window+duration. This is the single control that defeats the password spraying ad-enum.sh/kerbrute perform."
    }
    if ($pol.maxPwdAgeDays -eq $null -or $pol.maxPwdAgeDays -gt 365) {
        Add-Finding 'MEDIUM' "Maximum password age is $($pol.maxPwdAgeDays) days (never-expiring or > 1 year)" $pol `
            "Modern guidance allows long max-age ONLY with MFA + banned-password screening + breach monitoring. Without those, cap it (e.g. 365 days) so a leaked hash eventually dies."
    }
}

# --- krbtgt age ------------------------------------------------------------
Section 'KRBTGT'
Run '02-krbtgt' 'krbtgt password age (golden-ticket lifetime)' {
    Search-AD '(sAMAccountName=krbtgt)' @('sAMAccountName','pwdLastSet','whenChanged') | ForEach-Object {
        $pls = ConvertTo-Date $_.Properties['pwdlastset'][0]
        [pscustomobject]@{ Account='krbtgt'; PwdLastSet=$pls; AgeDays=(Days-Since $pls) }
    }
}
$kt = $Data['02-krbtgt'] | Select-Object -First 1
if ($kt -and $kt.AgeDays -ne $null -and $kt.AgeDays -gt $KrbtgtDays) {
    Add-Finding 'HIGH' "krbtgt password is $($kt.AgeDays) days old (> $KrbtgtDays)" $kt `
        "Rotate the krbtgt password TWICE (second rotation >10h after the first, to clear the N-1 key) on a schedule (e.g. every 180 days) and after any suspected DC compromise. Use Microsoft's New-KrbtgtKeys.ps1 - a stale krbtgt means a stolen hash forges Golden Tickets indefinitely."
}

# --- Kerberos attack surface ----------------------------------------------
Section 'KERBEROS ATTACK SURFACE'
# accounts with no pre-auth = AS-REP roastable (offline crackable, no lockout)
Run '03-asrep' 'AS-REP roastable accounts (DONT_REQ_PREAUTH)' {
    Search-AD '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('sAMAccountName','userAccountControl','adminCount') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','userAccountControl','adminCount') }
}
if ($Data['03-asrep'].Count) {
    $sev = if ($Data['03-asrep'] | Where-Object { $_.adminCount -eq '1' }) { 'CRIT' } else { 'HIGH' }
    Add-Finding $sev 'AS-REP roastable accounts (Kerberos pre-auth disabled)' $Data['03-asrep'] `
        "Clear 'Do not require Kerberos preauthentication' on each account (uncheck in ADUC Account tab, or: Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth `$false). If an app truly needs it, give that account a 25+ char random password and add it to Protected Users."
}
# user accounts (not computers, not krbtgt) carrying an SPN = kerberoastable
Run '04-spn' 'kerberoastable accounts (SPN on a user object)' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))' @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','msDS-SupportedEncryptionTypes') |
        ForEach-Object {
            $row = Convert-Row $_ @('sAMAccountName','servicePrincipalName','adminCount','msDS-SupportedEncryptionTypes')
            $pls = ConvertTo-Date $_.Properties['pwdlastset'][0]
            $row | Add-Member -NotePropertyName 'PwdAgeDays' -NotePropertyValue (Days-Since $pls) -PassThru
        }
}
if ($Data['04-spn'].Count) {
    $privRoast = $Data['04-spn'] | Where-Object { $_.adminCount -eq '1' }
    if ($privRoast) {
        Add-Finding 'CRIT' 'Kerberoastable PRIVILEGED account (SPN on an admin user)' $privRoast `
            "A privileged account with an SPN is a crackable path straight to admin. Move the service to a group Managed Service Account (gMSA): its 120-char password rotates automatically and cannot be roasted offline. Until then, give it a 25+ char password and remove it from privileged groups."
    }
    $other = $Data['04-spn'] | Where-Object { $_.adminCount -ne '1' }
    if ($other) {
        Add-Finding 'HIGH' 'Kerberoastable service accounts (SPN on user objects)' $other `
            "Convert each service to a gMSA (New-ADServiceAccount ... -PrincipalsAllowedToRetrieveManagedPassword). Where that is impossible, set a 25+ char random password and force AES only (Set-ADUser <u> -KerberosEncryptionType AES128,AES256) so a captured ticket is far harder to crack."
    }
}
# accounts whose AES is not enforced -> RC4 tickets, trivially crackable
Run '05-rc4' 'accounts still allowing RC4 Kerberos (no AES enforced)' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=24)))' @('sAMAccountName','servicePrincipalName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','servicePrincipalName') }
}
if ($Data['05-rc4'].Count) {
    Add-Finding 'MEDIUM' 'Service accounts without AES enforced (RC4 tickets allowed)' $Data['05-rc4'] `
        "Set msDS-SupportedEncryptionTypes to AES128+AES256 (Set-ADUser <u> -KerberosEncryptionType AES128,AES256) after confirming the service supports AES. RC4 service tickets are what hashcat -m 13100 cracks in seconds."
}

# --- delegation ------------------------------------------------------------
Section 'DELEGATION'
Run '06-unconstrained' 'unconstrained delegation (non-DC accounts)' {
    Search-AD '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))' @('sAMAccountName','userAccountControl','servicePrincipalName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','userAccountControl','servicePrincipalName') }
}
if ($Data['06-unconstrained'].Count) {
    Add-Finding 'CRIT' 'Unconstrained delegation on non-DC accounts' $Data['06-unconstrained'] `
        "Any coerced privileged logon to these hosts leaks a usable TGT (incl. a DC's). Replace with constrained delegation or RBCD. If the host must keep it, mark sensitive accounts 'Account is sensitive and cannot be delegated' and add admins to Protected Users (members cannot be delegated)."
}
Run '07-constrained' 'constrained delegation (msDS-AllowedToDelegateTo)' {
    Search-AD '(msDS-AllowedToDelegateTo=*)' @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl') }
}
if ($Data['07-constrained'].Count) {
    Add-Finding 'MEDIUM' 'Constrained delegation configured (review targets)' $Data['07-constrained'] `
        "Verify each delegation target is intended and that 'protocol transition' (TRUSTED_TO_AUTH_FOR_DELEGATION) is not enabled unless required - it lets the account impersonate anyone to the target. Prefer RBCD (configured on the resource, easier to scope and revoke)."
}
Run '08-rbcd' 'resource-based constrained delegation (RBCD)' {
    Search-AD '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' @('sAMAccountName','distinguishedName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','distinguishedName') }
}
if ($Data['08-rbcd'].Count) {
    Add-Finding 'MEDIUM' 'RBCD configured (confirm every entry is intentional)' $Data['08-rbcd'] `
        "Review the principals allowed to act on behalf of each object (Get-ADComputer <c> -Properties PrincipalsAllowedToDelegateToAccount). An attacker who can write this attribute on an object grants themselves impersonation; see the MachineAccountQuota finding - the two combine into a takeover."
}

# --- MachineAccountQuota ---------------------------------------------------
Section 'MACHINE ACCOUNT QUOTA'
Run '09-maq' 'ms-DS-MachineAccountQuota' {
    $r = @(Search-AD "(distinguishedName=$DefaultNC)" @('ms-DS-MachineAccountQuota') -Base $DefaultNC)[0]
    if ($r) { [pscustomobject]@{ MachineAccountQuota = [int]("$($r.Properties['ms-ds-machineaccountquota'][0])") } }
}
$maq = $Data['09-maq'] | Select-Object -First 1
if ($maq -and $maq.MachineAccountQuota -gt 0) {
    Add-Finding 'HIGH' "ms-DS-MachineAccountQuota = $($maq.MachineAccountQuota) (any user can join 10 computers)" $maq `
        "Set it to 0: Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}. A non-zero quota is the fuel for noPac (CVE-2021-42278/87), RBCD takeover and shadow-credential attacks. Delegate machine-join to a specific group via an OU ACL instead."
}

# --- who holds DCSync / dangerous ACEs on the domain root -----------------
if (-not $SkipAcl) {
    Section 'REPLICATION (DCSYNC) RIGHTS'
    Run '10-dcsync' 'non-default principals holding replication rights on the domain' {
        $r = @(Search-AD "(distinguishedName=$DefaultNC)" @('distinguishedname') -Base $DefaultNC -WithAcl)[0]
        if (-not $r) { return }
        $sdBytes = $r.Properties['ntsecuritydescriptor']
        if (-not $sdBytes -or -not $sdBytes.Count) { return }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($sdBytes[0])
        $hits = @{}
        foreach ($ace in $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            $ot = $ace.ObjectType.ToString()
            $rights = $ace.ActiveDirectoryRights.ToString()
            $isRepl = ($ot -eq $G_ReplGet -or $ot -eq $G_ReplGetAll -or $ot -eq $G_ReplGetFil -or ($rights -match 'GenericAll'))
            if (-not $isRepl) { continue }
            $trustee = $ace.IdentityReference.Value
            if ($script:ReplOk -contains $trustee) { continue }   # expected holder
            $key = "$trustee|$ot"
            if (-not $hits.ContainsKey($key)) {
                $hits[$key] = [pscustomobject]@{ Trustee=(Resolve-Sid $trustee); Sid=$trustee; Right=$rights; ObjectTypeGuid=$ot }
            }
        }
        $hits.Values
    }
    if ($Data['10-dcsync'].Count) {
        Add-Finding 'CRIT' 'Non-default principals hold replication (DCSync) rights' $Data['10-dcsync'] `
            "DCSync = full credential theft (incl. krbtgt) without touching a DC. Remove the replication ACE from each unexpected trustee (dsacls, or the AD ACL editor on the domain root). Only Domain Controllers, Administrators and Enterprise/Domain Admins should hold DS-Replication-Get-Changes[-All]."
    }

    Section 'ADMINSDHOLDER'
    Run '11-adminsdholder' 'write-class ACEs on AdminSDHolder (persistence vector)' {
        $base = "CN=AdminSDHolder,CN=System,$DefaultNC"
        $r = @(Search-AD "(distinguishedName=$base)" @('distinguishedname') -Base $base -WithAcl)[0]
        if (-not $r) { return }
        $sdBytes = $r.Properties['ntsecuritydescriptor']
        if (-not $sdBytes -or -not $sdBytes.Count) { return }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($sdBytes[0])
        $danger = 'GenericAll','WriteDacl','WriteOwner','WriteProperty'
        foreach ($ace in $sd.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            if (-not ($danger | Where-Object { $rights -match $_ })) { continue }
            $trustee = $ace.IdentityReference.Value
            if ($script:ReplOk -contains $trustee) { continue }
            [pscustomobject]@{ Trustee=(Resolve-Sid $trustee); Sid=$trustee; Right=$rights }
        }
    }
    if ($Data['11-adminsdholder'].Count) {
        Add-Finding 'HIGH' 'Unexpected write rights on AdminSDHolder' $Data['11-adminsdholder'] `
            "AdminSDHolder's DACL is stamped onto every protected (adminCount=1) account hourly by SDProp - a write ACE here is self-healing domain persistence. Verify each trustee against a known-good baseline and remove any you cannot account for."
    }
}

# --- LAPS deployment -------------------------------------------------------
Section 'LAPS (LOCAL ADMIN PASSWORDS)'
Run '12-laps' 'LAPS schema presence + coverage' {
    $legacy = @(Search-AD '(cn=ms-Mcs-AdmPwd)' @('cn') -Base $SchemaNC).Count -gt 0
    $winlaps= @(Search-AD '(cn=ms-LAPS-Password)' @('cn') -Base $SchemaNC).Count -gt 0
    $covered = 0
    if ($legacy) { $covered += @(Search-AD '(ms-Mcs-AdmPwdExpirationTime=*)' @('cn')).Count }
    if ($winlaps){ $covered += @(Search-AD '(msLAPS-PasswordExpirationTime=*)' @('cn')).Count }
    $comps = @(Search-AD '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' @('cn')).Count
    [pscustomobject]@{ LegacyLAPS=$legacy; WindowsLAPS=$winlaps; ComputersCovered=$covered; MemberComputers=$comps }
}
$laps = $Data['12-laps'] | Select-Object -First 1
if ($laps) {
    if (-not $laps.LegacyLAPS -and -not $laps.WindowsLAPS) {
        Add-Finding 'HIGH' 'LAPS is not deployed (no LAPS attributes in the schema)' $laps `
            "Deploy Windows LAPS (built into current Windows; Update-LapsADSchema then a GPO) so every machine has a unique, rotating local Administrator password. Without it one cracked/dumped local admin hash pivots across every host (pass-the-hash)."
    } elseif ($laps.ComputersCovered -lt $laps.MemberComputers) {
        Add-Finding 'MEDIUM' "LAPS present but only $($laps.ComputersCovered)/$($laps.MemberComputers) member computers are covered" $laps `
            "Extend the LAPS GPO to the OUs holding the uncovered machines and confirm the policy applies (gpresult). Also review who can READ the LAPS password attribute - it should be limited to tier-0/helpdesk, not Authenticated Users."
    }
}

# --- AD CS (certificate template abuse surface) ---------------------------
Section 'AD CS (CERTIFICATE SERVICES)'
Run '13-adcs-ca' 'enterprise Certificate Authorities' {
    $base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    Search-AD '(objectClass=pKIEnrollmentService)' @('cn','dNSHostName','certificateTemplates') -Base $base |
        ForEach-Object { Convert-Row $_ @('cn','dNSHostName','certificateTemplates') }
}
Run '14-adcs-esc1' 'certificate templates allowing requester-supplied subject + client auth (ESC1-style)' {
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $authEku = '1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4','2.5.29.37.0'   # client-auth / smartcard / PKINIT / any
    Search-AD '(objectClass=pKICertificateTemplate)' @('cn','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature','pKIExtendedKeyUsage') -Base $base | ForEach-Object {
        $nameFlag = [int]("$($_.Properties['mspki-certificate-name-flag'][0])")
        $enrFlag  = [int]("$($_.Properties['mspki-enrollment-flag'][0])")
        $raSig    = [int]("$($_.Properties['mspki-ra-signature'][0])")
        $ekus     = @($_.Properties['pkiextendedkeyusage'] | ForEach-Object { "$_" })
        $suppliesSubject = ($nameFlag -band 0x1) -ne 0           # ENROLLEE_SUPPLIES_SUBJECT
        $mgrApproval     = ($enrFlag -band 0x2) -ne 0            # PEND_ALL_REQUESTS
        $hasAuthEku      = ($ekus.Count -eq 0) -or ($ekus | Where-Object { $authEku -contains $_ })
        if ($suppliesSubject -and $hasAuthEku -and -not $mgrApproval -and $raSig -le 0) {
            [pscustomobject]@{
                Template      = [string]$_.Properties['cn'][0]
                SuppliesSAN   = $true
                ManagerApprov = $mgrApproval
                RASignatures  = $raSig
                EKUs          = ($ekus -join ' ; ')
            }
        }
    }
}
if ($Data['14-adcs-esc1'].Count) {
    Add-Finding 'CRIT' 'Certificate template(s) vulnerable to ESC1 (requester names any subject + client auth)' $Data['14-adcs-esc1'] `
        "Any user who can enroll can mint a cert as a Domain Admin. On each template: turn ON 'CA certificate manager approval' OR require authorized signatures, and turn OFF 'Supply in the request' (use 'Build from this Active Directory information' for the subject). Then tighten Enroll permissions to a specific group. Also set the CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 OFF (certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2). Audit the full ESC1-8 set with Certify/certipy 'find'."
}
if ($Data['13-adcs-ca'].Count) {
    Add-Finding 'INFO' 'AD CS is present - audit the full ESC1-ESC16 surface' $Data['13-adcs-ca'] `
        "Run 'certipy find -vulnerable' (or Certify.exe find /vulnerable) against this CA, enable CA audit logging, and restrict web enrollment / enforce Extended Protection (EPA) + require-SSL to close ESC8 NTLM relay to the CA."
}

# --- dangerous account states ---------------------------------------------
Section 'ACCOUNT HYGIENE'
Run '15-nopassreq' 'accounts with PASSWD_NOTREQD' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' @('sAMAccountName','userAccountControl') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','userAccountControl') }
}
if ($Data['15-nopassreq'].Count) {
    Add-Finding 'HIGH' 'Accounts flagged PASSWD_NOTREQD (may have an empty password)' $Data['15-nopassreq'] `
        "Clear the flag (Set-ADAccountControl <u> -PasswordNotRequired `$false) and set a real password. These accounts can authenticate with a blank password regardless of the domain minimum-length policy."
}
Run '16-reversible' 'accounts with reversible encryption set' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' @('sAMAccountName') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName') }
}
if ($Data['16-reversible'].Count) {
    Add-Finding 'CRIT' 'Per-account reversible encryption (plaintext-recoverable password)' $Data['16-reversible'] `
        "Clear the flag (Set-ADUser <u> -AllowReversiblePasswordEncryption `$false) and reset the password. The DC stores a reversibly-encrypted copy that a DCSync/NTDS dump yields in cleartext."
}
Run '17-pwnotexpire' 'enabled accounts with password-never-expires' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName','adminCount') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','adminCount') }
}
if ($Data['17-pwnotexpire'].Count) {
    $sev = if ($Data['17-pwnotexpire'] | Where-Object { $_.adminCount -eq '1' }) { 'HIGH' } else { 'MEDIUM' }
    Add-Finding $sev 'Enabled accounts whose password never expires' $Data['17-pwnotexpire'] `
        "Review each: human accounts should expire. Service accounts that need it should become gMSAs. Clear the flag (Set-ADUser <u> -PasswordNeverExpires `$false) where possible - never-expiring passwords are the ones still set to the value from a years-old breach."
}
Run '18-desc-pw' 'possible passwords in description / info fields' {
    Search-AD '(&(objectCategory=person)(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*pw:*)(info=*pass*)))' @('sAMAccountName','description','info') |
        ForEach-Object { Convert-Row $_ @('sAMAccountName','description','info') }
}
if ($Data['18-desc-pw'].Count) {
    Add-Finding 'HIGH' 'Possible cleartext passwords in account description/info' $Data['18-desc-pw'] `
        "Review and wipe these fields (the description attribute is readable by every authenticated user). Rotate any password that was stored there and move secrets to a vault."
}

# --- privileged accounts ---------------------------------------------------
Section 'PRIVILEGED ACCOUNTS'
Run '19-priv-members' 'members of tier-0 / privileged groups' {
    $names = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners'
    foreach ($g in $names) {
        foreach ($r in (Search-AD "(&(objectCategory=group)(cn=$g))" @('member','cn'))) {
            $m = $r.Properties['member']
            if ($m -and $m.Count) { $m | ForEach-Object { [pscustomobject]@{ Group=$g; Member=$_ } } }
        }
    }
}
if ($Data['19-priv-members'].Count) {
    $da = @($Data['19-priv-members'] | Where-Object { $_.Group -eq 'Domain Admins' })
    if ($da.Count -gt 5) {
        Add-Finding 'MEDIUM' "Domain Admins has $($da.Count) members (keep it small)" $da `
            "Trim Domain Admins to a handful of named, dedicated tier-0 accounts. Remove service accounts and day-to-day user accounts; use just-in-time elevation (PAM / time-bound group membership) instead of standing membership."
    }
    $op = @($Data['19-priv-members'] | Where-Object { $_.Group -in 'Account Operators','Print Operators','DnsAdmins' })
    if ($op.Count) {
        Add-Finding 'MEDIUM' 'Members in often-overlooked privileged groups (Account/Print Operators, DnsAdmins)' $op `
            "These groups grant near-tier-0 power (DnsAdmins can load a DLL on the DC; Account Operators can edit most accounts). Empty them unless there is a hard requirement, and treat remaining members as tier-0."
    }
}
Run '20-orphan-admincount' 'adminCount=1 accounts no longer in a privileged group' {
    $privMembersDN = @($Data['19-priv-members'] | ForEach-Object { $_.Member })
    Search-AD '(&(objectCategory=person)(objectClass=user)(adminCount=1))' @('sAMAccountName','distinguishedName') | ForEach-Object {
        $dn = [string]$_.Properties['distinguishedname'][0]
        if ($privMembersDN -notcontains $dn) { Convert-Row $_ @('sAMAccountName','distinguishedName') }
    }
}
if ($Data['20-orphan-admincount'].Count) {
    Add-Finding 'INFO' 'Accounts with adminCount=1 but no current privileged membership (SDProp leftovers)' $Data['20-orphan-admincount'] `
        "These were privileged once; SDProp left them with a locked-down ACL and adminCount=1. Confirm they are no longer meant to be privileged, then clear adminCount and re-enable inheritance so normal delegation applies."
}
Run '21-protected-users' 'Protected Users group membership' {
    foreach ($r in (Search-AD '(&(objectCategory=group)(cn=Protected Users))' @('member'))) {
        $m = $r.Properties['member']
        [pscustomobject]@{ ProtectedUsersMembers = if ($m) { $m.Count } else { 0 } }
    }
}
$pu = $Data['21-protected-users'] | Select-Object -First 1
if ($pu -and $pu.ProtectedUsersMembers -eq 0) {
    Add-Finding 'MEDIUM' 'Protected Users group is empty' $pu `
        "Add tier-0 accounts (Domain/Enterprise Admins) to Protected Users: it forces Kerberos AES, blocks NTLM/RC4/DES for those accounts, and prevents their credentials from being delegated or cached - defeating most pass-the-hash and delegation abuse against admins. Test first (members cannot use NTLM-only services)."
}

# --- stale objects (attack surface reduction) -----------------------------
Section 'STALE OBJECTS'
$cut = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
Run '22-stale-users' "enabled users inactive > $StaleDays days" {
    Search-AD '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName','lastLogonTimestamp') | ForEach-Object {
        $ll = ConvertTo-Date $_.Properties['lastlogontimestamp'][0]
        if ($ll -eq $null -or $ll -lt $cut) { [pscustomobject]@{ User=[string]$_.Properties['samaccountname'][0]; LastLogon=$ll; DaysIdle=(Days-Since $ll) } }
    }
}
if ($Data['22-stale-users'].Count) {
    Add-Finding 'MEDIUM' "$($Data['22-stale-users'].Count) enabled but inactive user account(s)" ($Data['22-stale-users'] | Sort-Object DaysIdle -Descending | Select-Object -First 25) `
        "Disable (then later delete) accounts idle beyond your threshold. Dormant enabled accounts are prime spray/roast targets no one is watching. Note lastLogonTimestamp lags up to ~14 days, so confirm before acting."
}
Run '23-stale-computers' "enabled computers inactive > $StaleDays days" {
    Search-AD '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('name','lastLogonTimestamp','operatingSystem') | ForEach-Object {
        $ll = ConvertTo-Date $_.Properties['lastlogontimestamp'][0]
        if ($ll -eq $null -or $ll -lt $cut) { [pscustomobject]@{ Computer=[string]$_.Properties['name'][0]; OS=[string]$_.Properties['operatingsystem'][0]; LastLogon=$ll; DaysIdle=(Days-Since $ll) } }
    }
}
if ($Data['23-stale-computers'].Count) {
    Add-Finding 'INFO' "$($Data['23-stale-computers'].Count) stale computer object(s)" ($Data['23-stale-computers'] | Sort-Object DaysIdle -Descending | Select-Object -First 25) `
        "Disable/remove stale computer accounts. Flag any legacy OS still present (Server 2008/2012, Windows 7) - unsupported OSes keep RC4/weak protocols alive and are the usual coercion/relay launch points."
}

# --- guest / builtin administrator -----------------------------------------
Section 'BUILT-IN ACCOUNTS'
Run '24-guest' 'built-in Guest account state' {
    if ($DomSid) {
        Search-AD "(objectSid=$DomSid-501)" @('sAMAccountName','userAccountControl') | ForEach-Object {
            $uac=[int]("$($_.Properties['useraccountcontrol'][0])")
            [pscustomobject]@{ Account=[string]$_.Properties['samaccountname'][0]; Enabled=(($uac -band 0x2) -eq 0) }
        }
    }
}
$guest = $Data['24-guest'] | Select-Object -First 1
if ($guest -and $guest.Enabled) {
    Add-Finding 'MEDIUM' 'Built-in Guest account is ENABLED' $guest `
        "Disable the domain Guest account (it should be off by default). An enabled Guest allows anonymous-ish access to resources that permit the Guests group."
}

# --- domain trusts ---------------------------------------------------------
Section 'TRUSTS'
Run '25-trusts' 'domain/forest trusts' {
    Search-AD '(objectClass=trustedDomain)' @('name','trustDirection','trustType','trustAttributes') |
        ForEach-Object { Convert-Row $_ @('name','trustDirection','trustAttributes') }
}
if ($Data['25-trusts'].Count) {
    # trustAttributes 0x40 = TREAT_AS_EXTERNAL, 0x8 = FOREST_TRANSITIVE; SID filtering off is the risk
    $risky = $Data['25-trusts'] | Where-Object { $a=0; [void][int]::TryParse("$($_.trustAttributes)",[ref]$a); ($a -band 0x8) -ne 0 }
    if ($risky) {
        Add-Finding 'INFO' 'Forest/transitive trusts present - verify SID filtering' $risky `
            "Confirm SID filtering (quarantine) is enabled on inbound trusts (netdom trust ... /quarantine). Without it, SID history across the trust can smuggle privileged SIDs. Review whether each trust is still needed and whether selective authentication should be enforced."
    } else {
        Add-Finding 'INFO' 'Domain trusts present' $Data['25-trusts'] `
            "Inventory each trust's direction and type; remove any that are no longer needed, and ensure SID filtering is on for external trusts."
    }
}

# --- functional level ------------------------------------------------------
if ($pol -and $pol.'minPwdLength' -ne $null) {
    Run '26-funclevel' 'domain functional level' {
        $r = @(Search-AD "(distinguishedName=$DefaultNC)" @('msDS-Behavior-Version') -Base $DefaultNC)[0]
        if ($r) { [pscustomobject]@{ 'msDS-Behavior-Version' = [int]("$($r.Properties['msds-behavior-version'][0])") } }
    }
    $fl = $Data['26-funclevel'] | Select-Object -First 1
    if ($fl -and $fl.'msDS-Behavior-Version' -lt 7) {
        Add-Finding 'INFO' "Domain functional level is low (msDS-Behavior-Version=$($fl.'msDS-Behavior-Version'))" $fl `
            "Raise the domain/forest functional level (7 = Server 2016) once all DCs support it. Newer levels unlock security features (e.g. Server 2016 enables Credential Guard-friendly defaults and better Kerberos behaviour)."
    }
}

# =============================================================== SUMMARY ===
# Everything below reads $script:Data objects, never the output files, so a
# banner or a command line can never be mistaken for a result.

$sumFile = Join-Path $OutDir 'SUMMARY.txt'
$order = @{ 'CRIT'=0; 'HIGH'=1; 'MEDIUM'=2; 'INFO'=3 }
$sorted = $Findings | Sort-Object { $order[$_.Sev] }
"AD hardening audit - $DefaultNC - $(Get-Date -Format s)" | Set-Content -Encoding UTF8 $sumFile
foreach ($f in $sorted) {
    $tag = switch($f.Sev){ 'CRIT'{'[CRITICAL]'} 'HIGH'{'[HIGH]    '} 'MEDIUM'{'[MEDIUM]  '} default{'[INFO]    '} }
    $col = switch($f.Sev){ 'CRIT'{'Red'} 'HIGH'{'Yellow'} 'MEDIUM'{'DarkYellow'} default{'Green'} }
    $bodyText = ($f.Body | Format-List | Out-String).Trim()
    Add-Content $sumFile "`n### $tag $($f.Title)`n$bodyText`n`n>> FIX: $($f.Fix)"
    Say "`n$tag $($f.Title)" $col
    ($bodyText -split "`n") | Select-Object -First 8 | ForEach-Object { Say "    $_" }
    if (($bodyText -split "`n").Count -gt 8) { Say "    ... more in SUMMARY.txt" 'DarkYellow' }
    Say "    >> FIX: $($f.Fix)" 'Cyan'
}

Section 'RUN REPORT'
Say ("  OK {0}   no results {1}   failed {2}" -f $N_OK,$N_EMPTY,$N_FAIL) 'Gray'
if ($sorted) {
    Section 'TOP FINDINGS - fix in this order'
    foreach ($f in $sorted | Where-Object { $_.Sev -in 'CRIT','HIGH' }) {
        $col = if($f.Sev -eq 'CRIT'){'Red'}else{'Yellow'}
        Say ("  [{0}] {1}" -f $f.Sev,$f.Title) $col
    }
}
Say ("`n[+] done. Full output in {0}  (summary: SUMMARY.txt)" -f $OutDir) 'Green'
Say  "[*] Re-run after each fix to confirm the finding clears." 'Cyan'
Say  "[*] For attack-path mapping (who is admin where), pair this with BloodHound run read-only under an auditor account." 'Cyan'
