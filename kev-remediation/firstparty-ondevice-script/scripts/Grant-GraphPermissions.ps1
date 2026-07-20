<#
.SYNOPSIS
    Grants the KEV Patch Automation Logic App's managed identity the Graph + Defender
    app-role (application) permissions it needs. Resolves role IDs by NAME at runtime,
    so there are no hard-coded permission GUIDs to drift.

.NOTES
    MUST be run by a Global Administrator or Privileged Role Administrator
    (app-role assignment for high-privilege permissions requires admin consent).
    Idempotent - safe to re-run.

.PARAMETER ManagedIdentityPrincipalId
    The Object (principal) ID of the Logic App system-assigned identity.
    This is the 'managedIdentityPrincipalId' output from the Bicep deployment.

.EXAMPLE
    ./Grant-GraphPermissions.ps1 -ManagedIdentityPrincipalId <guid>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ManagedIdentityPrincipalId
)

# --- Permission map: resource appId -> required application app-role values ---
$wellKnown = @{
    MicrosoftGraph    = '00000003-0000-0000-c000-000000000000'
    WindowsDefenderATP = 'fc780465-2017-40d4-a0c5-307022471b92'  # Defender for Endpoint API
}

$required = @{
    $wellKnown.MicrosoftGraph = @(
        'DeviceManagementManagedDevices.PrivilegedOperations.All', # initiateOnDemandProactiveRemediation
        'DeviceManagementConfiguration.ReadWrite.All',             # quality/feature/driver/expedite policies
        'WindowsUpdates.ReadWrite.All',                            # /admin/windows/updates deployment service
        'Mail.Send'                                               # notifications (lock down with App Access Policy)
    )
    $wellKnown.WindowsDefenderATP = @(
        'Vulnerability.Read.All'                                  # SoftwareVulnerabilityChangesByMachine (MDVM)
        # ,'Machine.Isolate'         # uncomment to enable immediate containment
        # ,'Machine.RestrictExecution'
    )
}

Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Connect-MgGraph -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All' -NoWelcome

# Existing assignments (for idempotency)
$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityPrincipalId -All

foreach ($resourceAppId in $required.Keys) {
    $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'"
    if (-not $resourceSp) { Write-Warning "Resource SP not found for appId $resourceAppId - skipping"; continue }

    foreach ($roleValue in $required[$resourceAppId]) {
        $appRole = $resourceSp.AppRoles | Where-Object { $_.Value -eq $roleValue -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $appRole) { Write-Warning "Role '$roleValue' not found on $($resourceSp.DisplayName) - skipping"; continue }

        $already = $existing | Where-Object { $_.ResourceId -eq $resourceSp.Id -and $_.AppRoleId -eq $appRole.Id }
        if ($already) { Write-Host "[=] $($resourceSp.DisplayName) / $roleValue already assigned" -ForegroundColor DarkGray; continue }

        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityPrincipalId `
            -PrincipalId $ManagedIdentityPrincipalId -ResourceId $resourceSp.Id -AppRoleId $appRole.Id | Out-Null
        Write-Host "[+] Granted $($resourceSp.DisplayName) / $roleValue" -ForegroundColor Green
    }
}

Write-Host "`nDone. Allow a few minutes for the grants to propagate before the Logic App runs." -ForegroundColor Cyan
