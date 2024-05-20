<#
.SYNOPSIS
    inject_misconfigs.ps1 — injects the vulnerable state of the CORP.LOCAL lab.

.DESCRIPTION
    Consumes configs/lab-config.json and configs/vulnerable-acls.json to place
    the lab into a deliberately weak state:

        * Kerberoastable SPNs on Tier-1 service accounts (MSSQLSvc, HTTP, cifs)
        * AS-REP roastable user (PRE-AUTH NOT REQUIRED on the asrep-user canary)
        * Unconstrained delegation on svc-unconst
        * Constrained / RBCD primitive (msDS-AllowedToActOnBehalfOfOtherIdentity)
          on svc-rbcd -> DC01$
        * ADCS is provisioned with an ESC1-style template and web enrollment
          is enabled (ESC8 surface) when the CA role is installed
        * Every ACL in vulnerable-acls.json is applied (GenericAll, WriteDacl,
          ForceChangePassword, RBCD)

    Safe to re-run: each primitive is applied only if not already present.

.PARAMETER ConfigJson
    Path to configs/lab-config.json

.PARAMETER AclsJson
    Path to configs/vulnerable-acls.json

.PARAMETER SkipAdcs
    Skips ADCS/CA provisioning (useful on non-ADCS VMs during development).

.EXAMPLE
    .\inject_misconfigs.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigJson = (Join-Path $PSScriptRoot '..\configs\lab-config.json'),

    [Parameter(Mandatory = $false)]
    [string]$AclsJson = (Join-Path $PSScriptRoot '..\configs\vulnerable-acls.json'),

    [switch]$SkipAdcs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Write-InjectLog { param([string]$Message) Write-Host "[inject] $Message" -ForegroundColor Magenta }
function Read-Json { param([string]$Path) if (-not (Test-Path $Path)) { throw "Missing $Path" }; Get-Content $Path -Raw | ConvertFrom-Json }

$config = Read-Json $ConfigJson
$acls   = Read-Json $AclsJson

# ---------------------------------------------------------------------------
# 1. Kerberoastable SPNs (T1558.003)
# ---------------------------------------------------------------------------
foreach ($user in $config.users) {
    if (-not $user.spns) { continue }
    $exists = Get-ADUser -Filter { SamAccountName -eq $user.sam } -ErrorAction SilentlyContinue
    if (-not $exists) {
        Write-Warning "SPN target missing: $($user.sam) (run provision.ps1 first)"
        continue
    }
    foreach ($spn in $user.spns) {
        $current = (Get-ADUser $user.sam -Properties servicePrincipalName).servicePrincipalName
        if ($current -notcontains $spn) {
            Set-ADUser $user.sam -ServicePrincipalNames @{Add = $spn}
            Write-InjectLog "SPN added:  $spn  (user=$($user.sam))"
        } else {
            Write-InjectLog "SPN present: $spn"
        }
    }
}

# ---------------------------------------------------------------------------
# 2. AS-REP roastable user (T1558.004)
# ---------------------------------------------------------------------------
foreach ($user in $config.users) {
    if ($user.does_not_require_preauth -eq $true) {
        $flag = Get-ADUser $user.sam -Properties userAccountControl
        if (($flag.userAccountControl -band 0x400000) -eq 0) {
            Set-ADAccountControl -Identity $user.sam -DoesNotRequirePreAuth $true
            Write-InjectLog "AS-REP flag (0x400000) set on: $($user.sam)"
        } else {
            Write-InjectLog "AS-REP flag already set: $($user.sam)"
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Unconstrained delegation (T1098)
# ---------------------------------------------------------------------------
foreach ($entry in $config.delegation) {
    if ($entry.type -eq 'unconstrained') {
        Set-ADUser -Identity $entry.sam -TrustedForDelegation $true
        Write-InjectLog "Unconstrained delegation set: $($entry.sam)"
    }
    if ($entry.type -eq 'constrained') {
        Set-ADUser -Identity $entry.sam -TrustedForDelegation $true
        Write-InjectLog "Constrained(RBCD-ready) user flagged: $($entry.sam)"
    }
}

# ---------------------------------------------------------------------------
# 4. RBCD — msDS-AllowedToActOnBehalfOfOtherIdentity on DC01 for svc-rbcd
#     Right GUID: 3e0f7e18-2c7a-4c10-ba16-1f9d4bd8fc43 (AllowedToAct)
# ---------------------------------------------------------------------------
$rbcdEntry = $config.delegation | Where-Object { $_.type -eq 'constrained' }
if ($rbcdEntry) {
    try {
        $trusteeName = 'CORP\' + $rbcdEntry.sam
        $trustee = New-Object System.Security.Principal.NTAccount($trusteeName)
        $trusteeSid = $trustee.Translate([System.Security.Principal.SecurityIdentifier]).Value

        $sdString = "O:BA:BA(OA;;CR;3e0f7e18-2c7a-4c10-ba16-1f9d4bd8fc43;;;$trusteeSid)"
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdString)
        $binary = New-Object byte[] ($raw.BinaryLength)
        $raw.GetBinaryForm($binary, 0)

        foreach ($computer in $rbcdEntry.allowed_to_act_on) {
            Set-ADComputer -Identity $computer -Replace @{
                'msDS-AllowedToActOnBehalfOfOtherIdentity' = $binary
            }
            Write-InjectLog "RBCD set: $trusteeSid can act on behalf of $computer"
        }
    } catch {
        Write-Warning "RBCD injection failed (machine may be mid-provisioning): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 5. ADCS — ESC1-style template + web enrollment (ESC8 surface)
# ---------------------------------------------------------------------------
function Assert-AdcsInstalled {
    try { $null = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' }; return $true }
    catch { return $false }
}

if (-not $SkipAdcs -and -not (Assert-AdcsInstalled)) {
    Write-InjectLog 'Installing AD CS (Certificate Services CA) — this may reboot.'

    $caFeatures = Get-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment
    if ($caFeatures | Where-Object { $_.InstallState -ne 'Installed' }) {
        Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools |
            Out-Null
    }

    try {
        Install-AdcsCertificationAuthority `
            -CAType EnterpriseRootCA `
            -CACommonName 'CORP-LAB-CA' `
            -CADistinguishedNameSuffix 'DC=corp,DC=local' `
            -ValidityPeriod Years -ValidityPeriodUnits 10 `
            -Force `
            -Confirm:$false
        Write-InjectLog 'Enterprise Root CA configured.'
    } catch {
        Write-Warning "CA configuration pending reboot: $($_.Exception.Message)"
    }

    try {
        Install-AdcsWebEnrollment -Force -Confirm:$false
        Write-InjectLog 'Certification Authority Web Enrollment enabled (ESC8 surface).'
    } catch {
        Write-Warning "Web enrollment enablement pending reboot: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 5b. ESC1-style template (enrollee supplies subject + client auth EKU)
#     Recreated as a copy of the WebServer template for a predictable CN.
# ---------------------------------------------------------------------------
$templateName = 'CorpLab-ESC1'
try {
    $t = Get-ADObject -Filter { (objectClass -eq 'pKICertificateTemplate') -and (name -eq $templateName) }
} catch { $t = $null }

if (-not $t) {
    try {
        $caCs = Get-CACertificateTemplate -ErrorAction SilentlyContinue
        if ($caCs) {
            Copy-ItemProperty "Cert:\LocalMachine\My\*" -ErrorAction SilentlyContinue | Out-Null
            # Use the ADSI certsrv snap-in to duplicate WebServer with weak flags:
            $dn = 'CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local'
            $src = [adsi]("LDAP://$dn")
            $newDn = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
            $new = [adsi]::Create('pKICertificateTemplate', "CN=$templateName," +
                'CN=Certificate Templates,CN=Public Key Services,CN=Services,' +
                'CN=Configuration,DC=corp,DC=local')
            foreach ($prop in $src.Properties.PropertyNames) {
                if ($prop -in @('cn', 'distinguishedname', 'instanceType')) { continue }
                $new.Properties[$prop].Value = $src.Properties[$prop].Value
            }
            # Enable enrollee-supplied subject (ESC1) + keep ClientAuth EKU.
            $new.Properties['msPKI-Certificate-Name-Flag'].Value = 0x1
            $new.Properties['pKIExtendedKeyUsage'].Value = @(
                '1.3.6.1.5.5.7.3.2',           # Client Authentication
                '1.3.6.1.5.5.7.3.4'            # Email protection (kept for realism)
            )
            $new.Properties['msPKI-Template-Schema-Version'].Value = 2
            $new.SetInfo()
            # Grant Authenticated Users Enroll on the new template.
            $tdn = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services," +
                   'CN=Services,CN=Configuration,DC=corp,DC=local'
            $tpl = [System.DirectoryServices.DirectoryEntry]("LDAP://$tdn")
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                (New-Object System.Security.Principal.NTAccount('NT AUTHORITY\Authenticated Users')),
                ([System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight'),
                'Allow',
                ([System.DirectoryServices.ActiveDirectorySchemaProperty]::new('Enroll').SchemaGuid))

            $tpl.ObjectSecurity.SecurityDescriptor = $null
            $tpl.CommitChanges()
            Write-InjectLog "ESC1 template created: $templateName"
        } else {
            Write-Warning 'No CA certificate template available yet — run again after the reboot.'
        }
    } catch {
        Write-Warning "ESC1 template provisioning incomplete: $($_.Exception.Message)"
    }
} else {
    Write-InjectLog "ESC1 template present: $templateName"
}

# ---------------------------------------------------------------------------
# 6. ACL catalogue from vulnerable-acls.json
# ---------------------------------------------------------------------------
function Grant-GenericAll {
    param([string]$TargetDn, [string]$Trustee)
    $entry = [System.DirectoryServices.DirectoryEntry]("LDAP://$TargetDn")
    $trusteeObj = New-Object System.Security.Principal.NTAccount($Trustee)
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $trusteeObj, 'GenericAll', 'Allow')
    $entry.ObjectSecurity.AddAccessRule($rule)
    $entry.CommitChanges()
}

function Grant-WriteDacl {
    param([string]$TargetDn, [string]$Trustee)
    $entry = [System.DirectoryServices.DirectoryEntry]("LDAP://$TargetDn")
    $trusteeObj = New-Object System.Security.Principal.NTAccount($Trustee)
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $trusteeObj, 'WriteDacl', 'Allow')
    $entry.ObjectSecurity.AddAccessRule($rule)
    $entry.CommitChanges()
}

function Grant-ForceChangePassword {
    param([string]$TargetDn, [string]$Trustee)
    $entry = [System.DirectoryServices.DirectoryEntry]("LDAP://$TargetDn")
    $trusteeObj = New-Object System.Security.Principal.NTAccount($Trustee)
    # User-Force-Change-Password extended right GUID
    $guid = [System.Guid]'00299570-246d-11d0-a768-00aa006e0529'
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $trusteeObj, 'ExtendedRight', 'Allow', $guid)
    $entry.ObjectSecurity.AddAccessRule($rule)
    $entry.CommitChanges()
}

function Resolve-ObjectDn {
    param([string]$Target, [string]$Type, [string]$Container)
    if ($Type -eq 'group') {
        $g = Get-ADGroup -Filter { Name -eq $Target } -ErrorAction SilentlyContinue
        return $g.DistinguishedName
    }
    if ($Type -eq 'user') {
        $u = Get-ADUser -Filter { SamAccountName -eq $Target } -ErrorAction SilentlyContinue
        return $u.DistinguishedName
    }
    if ($Type -eq 'computer') {
        $m = Get-ADComputer -Filter { SamAccountName -eq $Target } -ErrorAction SilentlyContinue
        return $m.DistinguishedName
    }
    throw "Unknown target type: $Type"
}

foreach ($acl in $acls.acls) {
    try {
        $targetDn = Resolve-ObjectDn -Target $acl.target -Type $acl.target_type
        $trusteeSam = $acl.trustee
        switch ($acl.right) {
            'GenericAll'     { Grant-GenericAll -TargetDn $targetDn -Trustee "CORP\$trusteeSam" }
            'WriteDacl'      { Grant-WriteDacl -TargetDn $targetDn -Trustee "CORP\$trusteeSam" }
            'ForceChangePassword' { Grant-ForceChangePassword -TargetDn $targetDn -Trustee "CORP\$trusteeSam" }
            'RBCD'           {
                # Pre-created in step 4 (msDS-AllowedToActOnBehalfOfOtherIdentity)
                Write-InjectLog "RBCD already handled for $($acl.target) -> $trusteeSam"
            }
            default { Write-Warning "Unsupported ACL right: $($acl.right)" }
        }
        Write-InjectLog "Applied $($acl.right) on $($acl.target) for $trusteeSam"
    } catch {
        Write-Warning "Failed to apply $($acl.id): $($_.Exception.Message)"
    }
}

Write-Host @'
────────────────────────────────────────────────────────────
Injection complete. Verify with:
    Get-ADUser svc-sql -Properties servicePrincipalName | select -ExpandProperty servicePrincipalName
    Setspn -L CORP\svc-sql
    Get-ADUser asrep-user -Properties userAccountControl
Run .\cleanup.ps1 -ResetLab to revert every primitive.
────────────────────────────────────────────────────────────
'@ -ForegroundColor Yellow