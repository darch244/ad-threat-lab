<#
.SYNOPSIS
    provision.ps1 — CORP.LOCAL forest build, AD DS, OUs and tiered structure.

.DESCRIPTION
    Idempotent provisioning runbook for the ad-threat-lab domain controller
    (DC01). Stages:

      1. Promote to Domain Controller (CORP.LOCAL, WinThreshold functional level,
         DNS installed) — causes a reboot on first run.
      2. Create the Tier-0/1/2, ServiceAccounts and PrivilegedAccess OUs.
      3. Create the tiered groups and users defined in configs/lab-config.json.
      4. Join high-value metadata (descriptions) so acl_scanner/spn_collector can
         rank objects.

    Run repeatedly with Vagrant: `vagrant provision dc01`. Each stage is guarded
    so a re-run is a no-op. SPNs, pre-auth flags, delegation and ACLs are left
    for inject_misconfigs.ps1.

.PARAMETER DsrmPassword
    SafeModeAdministratorPassword (DSRM) set at promotion time.

.PARAMETER ConfigJson
    Path to configs/lab-config.json (CORP.LOCAL schema).

.PARAMETER InitialPassword
    Default password assigned to lab accounts on creation.

.EXAMPLE
    .\provision.ps1 -DsrmPassword 'Dsrc!Corp2k22'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DsrmPassword = 'Dsrc!Corp2k22',

    [Parameter(Mandatory = $false)]
    [string]$ConfigJson = (Join-Path $PSScriptRoot '..\configs\lab-config.json'),

    [Parameter(Mandatory = $false)]
    [string]$InitialPassword = 'LabStart!22445'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Test-IsDomainController {
    try {
        $null = Get-ADDomainController -Filter * -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Write-ProgressLog {
    param([string]$Message)
    Write-Host "[provision] $Message" -ForegroundColor Cyan
}

function Import-LabConfig {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Config not found: $Path"
    }
    return Get-Content $Path -Raw | ConvertFrom-Json
}

# ---------------------------------------------------------------------------
# Stage 1 — Domain Controller promotion (reboots once).
# ---------------------------------------------------------------------------
if (-not (Test-IsDomainController)) {
    Write-ProgressLog 'DC role not present. Installing AD DS + DNS, then promoting.'

    $features = Get-WindowsFeature AD-Domain-Services, DNS, RSAT-AD-PowerShell,
                 RSAT-ADDS -Name
    if ($features | Where-Object { $_.InstallState -ne 'Installed' }) {
        Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-PowerShell,
            RSAT-ADDS -IncludeManagementTools
    }

    $secureDsrm = ConvertTo-SecureString $DsrmPassword -AsPlainText -Force

    try {
        Install-ADDSForest `
            -DomainName 'corp.local' `
            -DomainNetbiosName 'CORP' `
            -SafeModeAdministratorPassword $secureDsrm `
            -InstallDns:$true `
            -ForestMode 'WinThreshold' `
            -DomainMode 'WinThreshold' `
            -NoRebootOnCompletion:$true `
            -Force `
            -WarningAction SilentlyContinue
    } catch {
        Write-Error "Forest promotion failed: $($_.Exception.Message)"
        exit 1
    }

    Write-ProgressLog 'Forest created. Rebooting to finish promotion...'
    Restart-Computer -Force
    exit 0
}

Write-ProgressLog 'DC role detected. Skipping promotion.'

# ---------------------------------------------------------------------------
# Stage 2 — OU hierarchy.
# ---------------------------------------------------------------------------
$config = Import-LabConfig -Path $ConfigJson
$baseDn = $config.domain.base_dn
$rootDn = "DC=corp,DC=local"

foreach ($ou in $config.ous) {
    $ouName = $ou.name
    $ouPath = $ou.path
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $ouPath } -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ouName -Path $ouPath.Substring($ouPath.IndexOf(','))
        Write-ProgressLog "Created OU $ouPath"
    } else {
        Write-ProgressLog "OU exists: $ouPath"
    }
}

# ---------------------------------------------------------------------------
# Stage 3 — Groups.
# ---------------------------------------------------------------------------
foreach ($group in $config.groups) {
    $sam = $group.name
    if (-not (Get-ADGroup -Filter { Name -eq $sam } -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $sam -GroupScope 'Global' -Path $group.ou_path
        Write-ProgressLog "Created group $sam"
    } else {
        Write-ProgressLog "Group exists: $sam"
    }
}

# ---------------------------------------------------------------------------
# Stage 4 — Tiered users.
# ---------------------------------------------------------------------------
function New-LabUser {
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$BaseDn
    )

    $sam = $User.sam
    if (Get-ADUser -Filter { SamAccountName -eq $sam } -ErrorAction SilentlyContinue) {
        Write-ProgressLog "User exists: $sam"
        return
    }

    $display = $User.display_name
    $nameParts = $display -split ' '
    $given = if ($nameParts.Length -gt 1) { $nameParts[0] } else { $sam }
    $surname = if ($nameParts.Length -gt 1) { $nameParts[-1] } else { '' }

    New-ADUser `
        -Name $display `
        -SamAccountName $sam `
        -UserPrincipalName "$sam@corp.local" `
        -GivenName $given `
        -Surname $surname `
        -DisplayName $display `
        -Path $User.ou_path `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -Enabled $true `
        -Description ("Tier-" + $User.tier + " lab account") `
        -ChangePasswordAtLogon $false

    if ($User.high_value -eq $true) {
        Set-ADUser -Identity $sam -Replace @{ 'extensionAttribute1' = 'high-value' }
    }

    foreach ($groupName in $User.group_membership) {
        if (Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue) {
            Add-ADPrincipalGroupMembership -Identity $sam -MemberOf $groupName
        } else {
            Write-Warning "Group $groupName not found — skipping membership for $sam"
        }
    }

    if ($User.does_not_require_preauth -eq $true) {
        Set-ADAccountControl -Identity $sam -DoesNotRequirePreAuth $true
        Write-ProgressLog "Pre-auth disabled (canary): $sam"
    }

    Write-ProgressLog "Created user $sam (Tier-$($User.tier))"
}

foreach ($user in $config.users) {
    New-LabUser -User $user -Password $InitialPassword -BaseDn $baseDn
}

Write-ProgressLog 'Provisioning complete.'
Write-Host @'
────────────────────────────────────────────────────────────
Next step (on a fresh user-session, from automation/):
    .\inject_misconfigs.ps1
Re-run `vagrant provision dc01` to finish any interrupted
promotion, or run cleanup.ps1 to reset the lab state.
────────────────────────────────────────────────────────────
'@ -ForegroundColor Yellow