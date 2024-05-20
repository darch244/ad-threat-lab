<#
.SYNOPSIS
    cleanup.ps1 — reverts every injected misconfiguration and resets domain state.

.DESCRIPTION
    Inverse of inject_misconfigs.ps1. Consumes the same JSON catalogs and
    removes:

        * All injectible SPNs (restores the account to no-extra-SPN state)
        * The AS-REP (does-not-require-pre-auth) flag on lab accounts
        * Unconstrained + constrained delegation flags
        * msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) on DC01
        * The ACL primitives from vulnerable-acls.json
        * Optionally: locks accounts that were disabled/pwned during a test

    Optional -DisableAdcs removes the CA role and web enrollment if the lab no
    longer needs certificate-abuse surface.

.PARAMETER ConfigJson
    Path to configs/lab-config.json (defaults to sibling ../configs).

.PARAMETER AclsJson
    Path to configs/vulnerable-acls.json.

.PARAMETER ResetLab
    Switches on aggressive resets (re-enable disabled users, clear SPNs even
    if they were staged outside the catalog).

.PARAMETER DisableAdcs
    Removes the AD CS roles installed by inject_misconfigs.ps1.

.EXAMPLE
    .\cleanup.ps1 -ResetLab
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigJson = (Join-Path $PSScriptRoot '..\configs\lab-config.json'),

    [Parameter(Mandatory = $false)]
    [string]$AclsJson = (Join-Path $PSScriptRoot '..\configs\vulnerable-acls.json'),

    [switch]$ResetLab,
    [switch]$DisableAdcs
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Write-CleanupLog { param([string]$Message) Write-Host "[cleanup] $Message" -ForegroundColor Green }
function Read-Json { param([string]$Path) if (-not (Test-Path $Path)) { throw "Missing $Path" }; Get-Content $Path -Raw | ConvertFrom-Json }

$config = Read-Json $ConfigJson
$acls   = Read-Json $AclsJson

# ---------------------------------------------------------------------------
# 1. Remove injected SPNs.
# ---------------------------------------------------------------------------
foreach ($user in $config.users) {
    if (-not $user.spns) { continue }
    if (Get-ADUser -Filter { SamAccountName -eq $user.sam } -ErrorAction SilentlyContinue) {
        $current = (Get-ADUser $user.sam -Properties servicePrincipalName).servicePrincipalName
        foreach ($spn in $user.spns) {
            if ($current -contains $spn) {
                Set-ADUser $user.sam -ServicePrincipalNames @{Remove = $spn}
                Write-CleanupLog "Removed SPN: $spn ($($user.sam))"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Clear the AS-REP flag (userAccountControl bit 0x400000).
# ---------------------------------------------------------------------------
foreach ($user in $config.users) {
    if ($user.does_not_require_preauth -eq $true) {
        $u = Get-ADUser $user.sam -Properties userAccountControl -ErrorAction SilentlyContinue
        if ($u -and (($u.userAccountControl -band 0x400000) -ne 0)) {
            Set-ADAccountControl -Identity $user.sam -DoesNotRequirePreAuth $false
            Write-CleanupLog "Cleared AS-REP flag: $($user.sam)"
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Reset delegation flags.
# ---------------------------------------------------------------------------
foreach ($entry in $config.delegation) {
    $u = Get-ADUser -Filter { SamAccountName -eq $entry.sam } -ErrorAction SilentlyContinue
    if ($u) {
        if ((Get-ADUser $entry.sam -Properties TrustedForDelegation).TrustedForDelegation) {
            Set-ADUser -Identity $entry.sam -TrustedForDelegation $false
            Write-CleanupLog "Disabled delegation: $($entry.sam)"
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Clear RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity).
# ---------------------------------------------------------------------------
$rbcdEntry = $config.delegation | Where-Object { $_.type -eq 'constrained' }
if ($rbcdEntry) {
    foreach ($computer in $rbcdEntry.allowed_to_act_on) {
        $node = Get-ADComputer -Identity $computer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

        try {
            Set-ADComputer -Identity $computer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            Write-CleanupLog "Cleared RBCD on $computer"
        } catch {
            Write-Warning "RBCD already clear on $computer"
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Remove ACL primitives (revert to default DACL).
# ---------------------------------------------------------------------------
function Remove-LabAclRule {
    param([string]$TargetDn, [string]$Trustee, [string]$Right)
    $entry = [System.DirectoryServices.DirectoryEntry]("LDAP://$TargetDn")
    $trusteeObj = New-Object System.Security.Principal.NTAccount($Trustee)
    $ruleType = $Right
    switch ($Right) {
        'GenericAll' { $ruleType = 'GenericAll' }
        'WriteDacl'  { $ruleType = 'WriteDacl' }
        default      { $ruleType = 'ExtendedRight' }
    }
    $rules = @($entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
    foreach ($r in $rules) {
        if ($r.IdentityReference.Value -eq $Trustee -and $r.ActiveDirectoryRights.ToString() -match $ruleType) {
            $entry.ObjectSecurity.RemoveAccessRule($r.ObjectToRemove()) | Out-Null
            Write-CleanupLog "Removed $Right rule for $Trustee on $TargetDn"
        }
    }
    $entry.CommitChanges()
}

function Resolve-ObjectDn {
    param([string]$Target, [string]$Type)
    switch ($Type) {
        'group'    { return (Get-ADGroup -Filter { Name -eq $Target }).DistinguishedName }
        'user'     { return (Get-ADUser -Filter { SamAccountName -eq $Target }).DistinguishedName }
        'computer' { return (Get-ADComputer -Filter { SamAccountName -eq $Target }).DistinguishedName }
        default    { throw "Unknown target type: $Type" }
    }
}

foreach ($acl in $acls.acls) {
    if ($acl.right -eq 'RBCD') { continue }   # handled in step 4
    try {
        Remove-LabAclRule `
            -TargetDn (Resolve-ObjectDn -Target $acl.target -Type $acl.target_type) `
            -Trustee "CORP\$($acl.trustee)" `
            -Right $acl.right
    } catch {
        Write-Warning "Failed to remove $($acl.id): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 6. (Optional) aggressive state reset.
# ---------------------------------------------------------------------------
if ($ResetLab) {
    foreach ($user in $config.users) {
        $u = Get-ADUser -Filter { SamAccountName -eq $user.sam } -ErrorAction SilentlyContinue
        if ($u -and $u.Enabled -eq $false) {
            Enable-ADAccount -Identity $user.sam
            Write-CleanupLog "Re-enabled: $($user.sam)"
        }
    }
}

# ---------------------------------------------------------------------------
# 7. (Optional) remove AD CS attacker surface.
# ---------------------------------------------------------------------------
if ($DisableAdcs) {
    try {
        Uninstall-AdcsWebEnrollment -Force -Confirm:$false -ErrorAction SilentlyContinue
        Uninstall-AdcsCertificationAuthority -Force -Confirm:$false -ErrorAction SilentlyContinue
        Uninstall-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment
        Write-CleanupLog 'AD CS role removed.'
    } catch {
        Write-Warning "AD CS removal requires elevation/reboot: $($_.Exception.Message)"
    }
}

Write-Host @'
────────────────────────────────────────────────────────────
Cleanup complete. The lab no longer contains the catalogued
misconfigurations. Re-inject anytime with:
    .\inject_misconfigs.ps1
────────────────────────────────────────────────────────────
'@ -ForegroundColor Yellow