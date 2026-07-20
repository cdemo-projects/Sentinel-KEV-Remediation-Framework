<#
.SYNOPSIS
    [LEGACY] Locks the KEV-Remediate Logic App's Mail.Send permission to a single mailbox.

.DEPRECATED
    Microsoft is migrating Application Access Policies to Role Based Access Control
    for Applications in Exchange Online. Per Microsoft Learn (verified Apr 2026):

      "Don't create new App Access Policies as these policies will eventually require
       migration to Role Based Access Control for Applications."

    Source: https://learn.microsoft.com/exchange/permissions-exo/application-rbac

    USE Lock-MailSendScope-RBAC.ps1 INSTEAD for new deployments. This script remains
    available for tenants where RBAC for Apps cannot be used yet (e.g., specific gov
    clouds where the feature has not rolled out). Both scripts produce equivalent
    runtime behavior - the only difference is the underlying Exchange model.

.DESCRIPTION
    Mail.Send is a tenant-wide application permission - by default, the Logic App's
    managed identity can send mail as ANY user in the tenant. This script:

      1. Creates a dedicated shared mailbox for KEV notifications
      2. Creates a mail-enabled security group containing only that mailbox
      3. Applies an Exchange Application Access Policy that restricts the Logic App
         MI to ONLY send mail from that group's members
      4. Tests the policy

    After running this script, the Logic App can send from kev-remediate@<domain>
    and nothing else, even though it still holds the Mail.Send permission.

.PARAMETER TenantDomain
    The primary tenant domain (e.g., contoso.onmicrosoft.com or contoso.com).

.PARAMETER LogicAppName
    Name of the KEV-Remediate Logic App. Default: KEV-Remediate

.PARAMETER MailboxAddress
    SMTP address for the dedicated sender mailbox.
    Default: kev-remediate@<TenantDomain>

.PARAMETER GroupAddress
    SMTP address for the mail-enabled security group used as policy scope.
    Default: kev-remediate-senders@<TenantDomain>

.EXAMPLE
    .\Lock-MailSendScope.ps1 -TenantDomain contoso.com

.NOTES
    Requires:
      - Az PowerShell module
      - ExchangeOnlineManagement module
      - Exchange Administrator or Global Administrator role
      - The KEV-Remediate Logic App must already be deployed (with system-assigned MI)

    Reference:
      https://learn.microsoft.com/graph/auth-limit-mailbox-access
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TenantDomain,

    [string]$LogicAppName = 'KEV-Remediate',

    [string]$MailboxAddress = "kev-remediate@$TenantDomain",

    [string]$GroupAddress = "kev-remediate-senders@$TenantDomain"
)

$ErrorActionPreference = 'Stop'

# ── Pre-checks ──
foreach ($mod in 'Az.Resources','ExchangeOnlineManagement') {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        throw "Required module '$mod' not installed. Install with: Install-Module $mod -Scope CurrentUser"
    }
}

# ── Get the Logic App MI's Application (client) ID ──
Write-Host "[1/4] Resolving Logic App managed identity..." -ForegroundColor Cyan
$mi = Get-AzADServicePrincipal -DisplayName $LogicAppName
if (-not $mi) {
    throw "Could not find managed identity for Logic App '$LogicAppName'. Ensure it is deployed with a system-assigned MI."
}
Write-Host "  Found MI: $($mi.DisplayName) [AppId: $($mi.AppId)]" -ForegroundColor Green

# ── Connect to Exchange Online ──
Write-Host "[2/4] Connecting to Exchange Online..." -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

# ── Step 1: Create the dedicated shared mailbox (idempotent) ──
Write-Host "[3/4] Ensuring dedicated mailbox + security group..." -ForegroundColor Cyan

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

# ── Step 2: Create the mail-enabled security group (idempotent) ──
$existingGroup = Get-DistributionGroup -Identity $GroupAddress -ErrorAction SilentlyContinue
if ($existingGroup) {
    Write-Host "  Group $GroupAddress already exists." -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($GroupAddress, 'Create mail-enabled security group')) {
        New-DistributionGroup -Name 'KEV-Remediate-Senders' `
            -Type Security `
            -PrimarySmtpAddress $GroupAddress | Out-Null
        Write-Host "  Created security group $GroupAddress" -ForegroundColor Green
    }
}

# Add the mailbox to the group
$members = Get-DistributionGroupMember -Identity $GroupAddress -ErrorAction SilentlyContinue
if ($members.PrimarySmtpAddress -notcontains $MailboxAddress) {
    if ($PSCmdlet.ShouldProcess("$MailboxAddress -> $GroupAddress", 'Add mailbox to group')) {
        Add-DistributionGroupMember -Identity $GroupAddress -Member $MailboxAddress
        Write-Host "  Added $MailboxAddress to $GroupAddress" -ForegroundColor Green
    }
} else {
    Write-Host "  $MailboxAddress already in $GroupAddress." -ForegroundColor Yellow
}

# ── Step 3: Apply the Application Access Policy (idempotent) ──
Write-Host "[4/4] Applying Exchange Application Access Policy..." -ForegroundColor Cyan

$existingPolicies = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue |
    Where-Object { $_.AppId -eq $mi.AppId -and $_.ScopeName -eq $GroupAddress }

if ($existingPolicies) {
    Write-Host "  Policy already exists for AppId $($mi.AppId) -> $GroupAddress" -ForegroundColor Yellow
} else {
    if ($PSCmdlet.ShouldProcess($mi.AppId, "Restrict Mail.Send to $GroupAddress")) {
        New-ApplicationAccessPolicy `
            -AppId $mi.AppId `
            -PolicyScopeGroupId $GroupAddress `
            -AccessRight RestrictAccess `
            -Description "Restrict $LogicAppName Logic App to send from approved address only" | Out-Null
        Write-Host "  Policy applied." -ForegroundColor Green
    }
}

# ── Verify ──
Write-Host "`n=== Verification ===" -ForegroundColor Cyan

Write-Host "`nApproved sender ($MailboxAddress) - should return Granted:" -ForegroundColor White
$grant = Test-ApplicationAccessPolicy -Identity $MailboxAddress -AppId $mi.AppId
Write-Host "  Result: $($grant.AccessCheckResult)" -ForegroundColor $(if ($grant.AccessCheckResult -eq 'Granted') { 'Green' } else { 'Red' })

# Try a random user to confirm denial - skip if no other mailboxes
$otherMailbox = Get-Mailbox -ResultSize 5 |
    Where-Object { $_.PrimarySmtpAddress -ne $MailboxAddress } |
    Select-Object -First 1
if ($otherMailbox) {
    Write-Host "`nAny other user ($($otherMailbox.PrimarySmtpAddress)) - should return Denied:" -ForegroundColor White
    $deny = Test-ApplicationAccessPolicy -Identity $otherMailbox.PrimarySmtpAddress -AppId $mi.AppId
    Write-Host "  Result: $($deny.AccessCheckResult)" -ForegroundColor $(if ($deny.AccessCheckResult -eq 'Denied') { 'Green' } else { 'Red' })
}

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "Update the Logic App's NotificationEmail parameter to: $MailboxAddress" -ForegroundColor White
Write-Host "Example: az resource update -g <rg> --name $LogicAppName --resource-type Microsoft.Logic/workflows --set properties.parameters.NotificationEmail.value=$MailboxAddress" -ForegroundColor Gray
