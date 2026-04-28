<#
.SYNOPSIS
    [RECOMMENDED] Locks the KEV-Remediate Logic App's Mail.Send permission to a
    single mailbox using Exchange Online RBAC for Applications - the modern
    replacement for Application Access Policy.

.DESCRIPTION
    Mail.Send is a tenant-wide application permission. By default, the Logic App's
    managed identity can send mail as ANY user in the tenant. This script restricts
    it to ONE mailbox using the modern RBAC for Applications model.

    Microsoft Learn explicitly states (Apr 2026):
      "Application Access Policies are replaced by Role Based Access Control for
       Applications. Don't create new App Access Policies as these policies will
       eventually require migration to Role Based Access Control for Applications."
    Source: https://learn.microsoft.com/exchange/permissions-exo/application-rbac

    This script implements the recommended path. The legacy script
    Lock-MailSendScope.ps1 is kept for backward compatibility only.

    What this script does:
      1. Creates a dedicated shared mailbox for KEV notifications
      2. Creates an Exchange Management Scope targeting only that mailbox
      3. Creates a Service Principal pointer for the Logic App's MI
      4. Creates a New-ManagementRoleAssignment binding the 'Application Mail.Send'
         role to the Service Principal, scoped via the Management Scope
      5. Tests the assignment

    After running this script, the Logic App can send from kev-remediate@<domain>
    and nothing else, even though it still holds the Mail.Send Graph permission.

.PARAMETER TenantDomain
    The primary tenant domain (e.g., contoso.onmicrosoft.com or contoso.com).

.PARAMETER LogicAppName
    Name of the KEV-Remediate Logic App. Default: KEV-Remediate

.PARAMETER MailboxAddress
    SMTP address for the dedicated sender mailbox.
    Default: kev-remediate@<TenantDomain>

.PARAMETER ScopeName
    Name of the Management Scope. Default: KEV-Remediate-MailScope

.PARAMETER AssignmentName
    Name of the role assignment. Default: KEV-Remediate-MailSend

.EXAMPLE
    .\Lock-MailSendScope-RBAC.ps1 -TenantDomain contoso.com

.NOTES
    Requires:
      - Az PowerShell module
      - ExchangeOnlineManagement module
      - Exchange Administrator or Organization Management role
      - The KEV-Remediate Logic App must already be deployed (with system-assigned MI)

    References:
      - https://learn.microsoft.com/exchange/permissions-exo/application-rbac
      - https://learn.microsoft.com/powershell/module/exchangepowershell/new-managementscope
      - https://learn.microsoft.com/powershell/module/exchangepowershell/new-serviceprincipal
      - https://learn.microsoft.com/powershell/module/exchangepowershell/new-managementroleassignment

    Cache note (from Microsoft Learn): "Changes to app permissions are subject to
    cache maintenance that varies between 30 minutes and 2 hours." Use the
    Test-ServicePrincipalAuthorization cmdlet to bypass cache for verification.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TenantDomain,

    [string]$LogicAppName = 'KEV-Remediate',

    [string]$MailboxAddress = "kev-remediate@$TenantDomain",

    [string]$ScopeName = 'KEV-Remediate-MailScope',

    [string]$AssignmentName = 'KEV-Remediate-MailSend'
)

$ErrorActionPreference = 'Stop'

# ── Pre-checks ──
foreach ($mod in 'Az.Resources','ExchangeOnlineManagement') {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        throw "Required module '$mod' not installed. Install with: Install-Module $mod -Scope CurrentUser"
    }
}

# ── Get the Logic App MI ──
Write-Host '[1/5] Resolving Logic App managed identity...' -ForegroundColor Cyan
$mi = Get-AzADServicePrincipal -DisplayName $LogicAppName
if (-not $mi) {
    throw "Could not find managed identity for Logic App '$LogicAppName'. Ensure it is deployed with a system-assigned MI."
}
Write-Host "  Found MI: $($mi.DisplayName)" -ForegroundColor Green
Write-Host "    AppId   : $($mi.AppId)" -ForegroundColor Gray
Write-Host "    ObjectId: $($mi.Id)" -ForegroundColor Gray

# ── Connect to Exchange Online ──
Write-Host '[2/5] Connecting to Exchange Online...' -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

# ── Step 1: Ensure the dedicated mailbox exists ──
Write-Host '[3/5] Ensuring dedicated mailbox + management scope...' -ForegroundColor Cyan

$existingMbx = Get-Mailbox -Identity $MailboxAddress -ErrorAction SilentlyContinue
if ($existingMbx) {
    Write-Host "  Mailbox $MailboxAddress already exists." -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($MailboxAddress, 'Create shared mailbox')) {
        New-Mailbox -Shared `
            -Name 'kev-remediate-noreply' `
            -DisplayName 'KEV Remediation Notifications' `
            -PrimarySmtpAddress $MailboxAddress | Out-Null
        Write-Host "  Created mailbox $MailboxAddress" -ForegroundColor Green
    }
}

# ── Step 2: Create the Management Scope (targets that one mailbox) ──
$existingScope = Get-ManagementScope -Identity $ScopeName -ErrorAction SilentlyContinue
if ($existingScope) {
    Write-Host "  Management Scope '$ScopeName' already exists." -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($ScopeName, 'Create Management Scope')) {
        # RecipientRestrictionFilter targets a single mailbox by SMTP address
        New-ManagementScope -Name $ScopeName `
            -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$MailboxAddress'" | Out-Null
        Write-Host "  Created Management Scope '$ScopeName'" -ForegroundColor Green
    }
}

# ── Step 3: Create Service Principal pointer in Exchange ──
Write-Host '[4/5] Ensuring Exchange Service Principal + role assignment...' -ForegroundColor Cyan

$existingSp = Get-ServicePrincipal -Identity $mi.AppId -ErrorAction SilentlyContinue
if ($existingSp) {
    Write-Host "  Exchange Service Principal for AppId $($mi.AppId) already exists." -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($mi.AppId, 'Create Exchange Service Principal pointer')) {
        New-ServicePrincipal `
            -AppId $mi.AppId `
            -ObjectId $mi.Id `
            -DisplayName $LogicAppName | Out-Null
        Write-Host "  Created Service Principal pointer." -ForegroundColor Green
    }
}

# ── Step 4: Create the Role Assignment (Application Mail.Send, scoped) ──
$existingAssignment = Get-ManagementRoleAssignment -Identity $AssignmentName -ErrorAction SilentlyContinue
if ($existingAssignment) {
    Write-Host "  Role assignment '$AssignmentName' already exists." -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($AssignmentName, 'Create Role Assignment')) {
        New-ManagementRoleAssignment -Name $AssignmentName `
            -App $mi.AppId `
            -Role 'Application Mail.Send' `
            -CustomResourceScope $ScopeName | Out-Null
        Write-Host "  Created role assignment '$AssignmentName'." -ForegroundColor Green
        Write-Host '  Cache note: changes can take 30 min - 2 hours to reflect in app permissions.' -ForegroundColor Yellow
    }
}

# ── Step 5: Verify with Test-ServicePrincipalAuthorization (bypasses cache) ──
Write-Host '[5/5] Testing the assignment...' -ForegroundColor Cyan

Write-Host "`nApproved sender ($MailboxAddress) - should show 'Application Mail.Send':" -ForegroundColor White
try {
    Test-ServicePrincipalAuthorization -Identity $mi.AppId -Resource $MailboxAddress |
        Select-Object RoleName, GrantedPermissions, AllowedResourceScope |
        Format-Table -AutoSize
} catch {
    Write-Warning "Test-ServicePrincipalAuthorization failed: $_"
}

# Try a random user to confirm denial
$otherMailbox = Get-Mailbox -ResultSize 5 |
    Where-Object { $_.PrimarySmtpAddress -ne $MailboxAddress } |
    Select-Object -First 1
if ($otherMailbox) {
    Write-Host "`nAny other user ($($otherMailbox.PrimarySmtpAddress)) - should NOT show Mail.Send:" -ForegroundColor White
    try {
        Test-ServicePrincipalAuthorization -Identity $mi.AppId -Resource $otherMailbox.PrimarySmtpAddress |
            Select-Object RoleName, GrantedPermissions, AllowedResourceScope |
            Format-Table -AutoSize
    } catch {
        Write-Host "  (No matching grant - expected.)" -ForegroundColor Green
    }
}

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "Update the Logic App's NotificationEmail parameter to: $MailboxAddress" -ForegroundColor White
Write-Host "If you previously ran Lock-MailSendScope.ps1 (legacy), remove that policy with:" -ForegroundColor White
Write-Host "  Remove-ApplicationAccessPolicy -Identity '<policy-id-from-Get-ApplicationAccessPolicy>'" -ForegroundColor Gray
