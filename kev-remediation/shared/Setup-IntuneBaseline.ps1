<#
.SYNOPSIS
    Sets up the Intune tenant bootstrap baseline for KEV remediation.

.DESCRIPTION
    Creates:
      - MDM auto-enrollment scoped to Intune-Enrollment-Pilot-Users
      - Windows enrollment restriction for pilot users
      - Windows Update Ring - Pilot (assigned to Intune-Windows-Pilot-Devices)
      - Windows Update Ring - Broad (assigned to Intune-Windows-Broad-Devices, excludes Intune-Windows-Update-Exclusions)
      - Windows Compliance - Pilot (assigned to Intune-Windows-Pilot-Devices)
      - IME Bootstrap platform script (assigned to Intune-Windows-Pilot-Devices)

    Prerequisites:
      - Groups already created in Entra ID (run the group creation step first)
      - User with Global Administrator or Intune Administrator role
      - No Graph SDK required; uses raw OAuth2 device code flow

.EXAMPLE
    .\Setup-IntuneBaseline.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$tenantId = '<tenant-id>'
# Microsoft Graph Command Line Tools - well-known public client
$clientId = '<client-id>'

# ── Authenticate via OAuth2 device code flow ──
Write-Host 'Requesting device code for Microsoft Graph...'
$deviceCodeBody = @{
    client_id = $clientId
    scope     = 'https://graph.microsoft.com/DeviceManagementServiceConfig.ReadWrite.All https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All https://graph.microsoft.com/DeviceManagementManagedDevices.ReadWrite.All https://graph.microsoft.com/Group.ReadWrite.All offline_access'
}
$deviceCode = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" -Body $deviceCodeBody
Write-Host $deviceCode.message

# Poll for token
$tokenBody = @{
    client_id   = $clientId
    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
    device_code = $deviceCode.device_code
}
$token = $null
$deadline = [datetime]::UtcNow.AddSeconds($deviceCode.expires_in)
while ([datetime]::UtcNow -lt $deadline) {
    try {
        $token = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $tokenBody
        break
    } catch {
        $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($err.error -eq 'authorization_pending') {
            Start-Sleep -Seconds $deviceCode.interval
        } else {
            throw "Token acquisition failed: $($err.error_description)"
        }
    }
}
if (-not $token) { throw 'Device code authentication timed out.' }
$headers = @{ Authorization = "Bearer $($token.access_token)"; 'Content-Type' = 'application/json' }

$me = Invoke-RestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName' -Headers $headers
Write-Host "Authenticated as: $($me.displayName) ($($me.userPrincipalName))"

# ── Helper: Graph REST call ──
function Invoke-MgRest {
    param(
        [string]$Method,
        [string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = $Uri; Headers = $script:headers }
    if ($Body) {
        $params.Body = $Body
        $params.ContentType = 'application/json'
    }
    Invoke-RestMethod @params
}

# ── Resolve group IDs ──
Write-Host "`n=== Resolving groups ==="
$groupNames = @{
    PilotUsers      = 'Intune-Enrollment-Pilot-Users'
    PilotDevices    = 'Intune-Windows-Pilot-Devices'
    BroadDevices    = 'Intune-Windows-Broad-Devices'
    UpdateExclusions = 'Intune-Windows-Update-Exclusions'
}

$groupIds = @{}
foreach ($key in $groupNames.Keys) {
    $name = $groupNames[$key]
    $result = Invoke-MgRest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$name'&`$select=id,displayName"
    if ($result.value.Count -eq 0) {
        Write-Error "Group '$name' not found. Create groups first."
        return
    }
    $groupIds[$key] = $result.value[0].id
    Write-Host "  $name = $($groupIds[$key])"
}

# ── 1. MDM Auto-Enrollment ──
Write-Host "`n=== Policy 1: MDM Auto-Enrollment ==="
Write-Host "  Checking current MDM mobility management policies..."

try {
    $mdmPolicies = Invoke-MgRest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies'
    $intuneMdm = $mdmPolicies.value | Where-Object { $_.displayName -match 'Microsoft Intune' -or $_.id -match 'Microsoft Intune Enrollment' }

    if ($intuneMdm) {
        $policyId = $intuneMdm.id
        Write-Host "  Found MDM policy: $($intuneMdm.displayName) (appliesTo: $($intuneMdm.appliesTo))"

        if ($intuneMdm.appliesTo -ne 'selected') {
            if ($PSCmdlet.ShouldProcess('MDM Auto-Enrollment', 'Set appliesTo=selected')) {
                Invoke-MgRest -Method PATCH -Uri "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/$policyId" -Body (@{
                    appliesTo = 'selected'
                } | ConvertTo-Json)
                Write-Host "  Updated appliesTo to 'selected'"
            }
        }

        # Add pilot users group to the included groups
        $includedGroups = Invoke-MgRest -Method GET -Uri "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/$policyId/includedGroups"
        $alreadyIncluded = $includedGroups.value | Where-Object { $_.id -eq $groupIds.PilotUsers }
        if (-not $alreadyIncluded) {
            if ($PSCmdlet.ShouldProcess('MDM Auto-Enrollment', "Add Intune-Enrollment-Pilot-Users to included groups")) {
                $ref = @{ '@odata.id' = "https://graph.microsoft.com/beta/groups/$($groupIds.PilotUsers)" } | ConvertTo-Json
                Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/$policyId/includedGroups/`$ref" -Body $ref
                Write-Host "  Added Intune-Enrollment-Pilot-Users to MDM enrollment scope"
            }
        } else {
            Write-Host "  Intune-Enrollment-Pilot-Users already in MDM enrollment scope"
        }
    } else {
        Write-Host "  No Microsoft Intune MDM policy found. Configure manually:"
        Write-Host "    Intune admin center > Devices > Device onboarding > Enrollment > Windows > Automatic Enrollment"
        Write-Host "    Set MDM user scope to 'Some' and select Intune-Enrollment-Pilot-Users"
    }
} catch {
    Write-Warning "Could not configure MDM auto-enrollment via API: $($_.Exception.Message)"
    Write-Host "  Configure manually in Intune admin center:"
    Write-Host "    Devices > Device onboarding > Enrollment > Windows > Automatic Enrollment"
    Write-Host "    MDM user scope = Some, group = Intune-Enrollment-Pilot-Users"
}

# ── 2. Windows Enrollment Restriction ──
Write-Host "`n=== Policy 2: Windows Enrollment Restriction ==="

try {
    $existingRestrictions = Invoke-MgRest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'singlePlatformRestriction'"
    $existing = $existingRestrictions.value | Where-Object { $_.displayName -eq 'Windows Enrollment - KEV Pilot' }

    if ($existing) {
        Write-Host "  Already exists: $($existing.displayName) (ID: $($existing.id))"
    } else {
        if ($PSCmdlet.ShouldProcess('Enrollment Restriction', 'Create Windows Enrollment - KEV Pilot')) {
            $restriction = @{
                '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'
                displayName   = 'Windows Enrollment - KEV Pilot'
                description   = 'Allows Windows enrollment for KEV remediation pilot users'
                priority      = 1
                platformRestriction = @{
                    platformBlocked       = $false
                    personalDeviceEnrollmentBlocked = $false
                }
                platformType = 'windows'
            } | ConvertTo-Json -Depth 5

            $created = Invoke-MgRest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' -Body $restriction
            Write-Host "  Created: $($created.displayName) (ID: $($created.id))"

            # Assign to pilot users group
            $assignment = @{
                enrollmentConfigurationAssignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId       = $groupIds.PilotUsers
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5

            Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($created.id)/assign" -Body $assignment
            Write-Host "  Assigned to Intune-Enrollment-Pilot-Users"
        }
    }
} catch {
    Write-Warning "Could not create enrollment restriction: $($_.Exception.Message)"
    Write-Host "  Create manually: Intune admin center > Devices > Device onboarding > Enrollment > Device platform restriction"
}

# ── 3. Windows Update Ring - Pilot ──
Write-Host "`n=== Policy 3: Windows Update Ring - Pilot ==="

try {
    $existingRings = Invoke-MgRest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"
    $existingPilot = $existingRings.value | Where-Object { $_.displayName -eq 'Windows Update Ring - Pilot' }

    if ($existingPilot) {
        Write-Host "  Already exists: $($existingPilot.displayName) (ID: $($existingPilot.id))"
    } else {
        if ($PSCmdlet.ShouldProcess('Update Ring', 'Create Windows Update Ring - Pilot')) {
            $pilotRing = @{
                '@odata.type'                          = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
                displayName                            = 'Windows Update Ring - Pilot'
                description                            = 'Pilot update ring - 0 day quality deferral, 30 day feature deferral'
                microsoftUpdateServiceAllowed           = $true
                driversExcluded                         = $true
                qualityUpdatesDeferralPeriodInDays      = 0
                featureUpdatesDeferralPeriodInDays      = 30
                qualityUpdatesPaused                    = $false
                featureUpdatesPaused                    = $false
                businessReadyUpdatesOnly                = 'userDefined'
                automaticUpdateMode                     = 'autoInstallAtMaintenanceTime'
                activeHoursStart                        = '08:00:00'
                activeHoursEnd                          = '17:00:00'
                installationSchedule                    = $null
                qualityUpdatesPauseExpiryDateTime       = '0001-01-01T00:00:00Z'
                featureUpdatesPauseExpiryDateTime       = '0001-01-01T00:00:00Z'
                featureUpdatesRollbackWindowInDays      = 10
                deadlineForQualityUpdatesInDays         = 2
                deadlineForFeatureUpdatesInDays         = 7
                deadlineGracePeriodInDays               = 1
                postponeRebootUntilAfterDeadline        = $false
                updateNotificationLevel                 = 'defaultNotifications'
                engagedRestartDeadlineInDays             = $null
                engagedRestartSnoozeScheduleInDays       = $null
                engagedRestartTransitionScheduleInDays   = $null
                autoRestartNotificationDismissal         = 'notConfigured'
                skipChecksBeforeRestart                 = $false
                allowWindows11Upgrade                   = $false
            } | ConvertTo-Json -Depth 5

            $createdRing = Invoke-MgRest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' -Body $pilotRing
            Write-Host "  Created: $($createdRing.displayName) (ID: $($createdRing.id))"

            # Assign to pilot devices group
            $ringAssignment = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId       = $groupIds.PilotDevices
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5

            Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($createdRing.id)/assign" -Body $ringAssignment
            Write-Host "  Assigned to Intune-Windows-Pilot-Devices"
        }
    }
} catch {
    Write-Warning "Could not create pilot update ring: $($_.Exception.Message)"
    Write-Host "  Create manually: Intune admin center > Devices > By platform > Windows > Manage updates > Update rings"
}

# ── 4. Windows Update Ring - Broad ──
Write-Host "`n=== Policy 4: Windows Update Ring - Broad ==="

try {
    $existingBroad = $existingRings.value | Where-Object { $_.displayName -eq 'Windows Update Ring - Broad' }

    if ($existingBroad) {
        Write-Host "  Already exists: $($existingBroad.displayName) (ID: $($existingBroad.id))"
    } else {
        if ($PSCmdlet.ShouldProcess('Update Ring', 'Create Windows Update Ring - Broad')) {
            $broadRing = @{
                '@odata.type'                          = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
                displayName                            = 'Windows Update Ring - Broad'
                description                            = 'Broad update ring - 3 day quality deferral, 30 day feature deferral'
                microsoftUpdateServiceAllowed           = $true
                driversExcluded                         = $true
                qualityUpdatesDeferralPeriodInDays      = 3
                featureUpdatesDeferralPeriodInDays      = 30
                qualityUpdatesPaused                    = $false
                featureUpdatesPaused                    = $false
                businessReadyUpdatesOnly                = 'userDefined'
                automaticUpdateMode                     = 'autoInstallAtMaintenanceTime'
                activeHoursStart                        = '08:00:00'
                activeHoursEnd                          = '17:00:00'
                installationSchedule                    = $null
                qualityUpdatesPauseExpiryDateTime       = '0001-01-01T00:00:00Z'
                featureUpdatesPauseExpiryDateTime       = '0001-01-01T00:00:00Z'
                featureUpdatesRollbackWindowInDays      = 10
                deadlineForQualityUpdatesInDays         = 5
                deadlineForFeatureUpdatesInDays         = 14
                deadlineGracePeriodInDays               = 2
                postponeRebootUntilAfterDeadline        = $false
                updateNotificationLevel                 = 'defaultNotifications'
                engagedRestartDeadlineInDays             = $null
                engagedRestartSnoozeScheduleInDays       = $null
                engagedRestartTransitionScheduleInDays   = $null
                autoRestartNotificationDismissal         = 'notConfigured'
                skipChecksBeforeRestart                 = $false
                allowWindows11Upgrade                   = $false
            } | ConvertTo-Json -Depth 5

            $createdBroad = Invoke-MgRest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' -Body $broadRing
            Write-Host "  Created: $($createdBroad.displayName) (ID: $($createdBroad.id))"

            # Assign to broad devices, exclude update-exclusions
            $broadAssignment = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId       = $groupIds.BroadDevices
                        }
                    },
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'
                            groupId       = $groupIds.UpdateExclusions
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5

            Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($createdBroad.id)/assign" -Body $broadAssignment
            Write-Host "  Assigned to Intune-Windows-Broad-Devices (excludes Intune-Windows-Update-Exclusions)"
        }
    }
} catch {
    Write-Warning "Could not create broad update ring: $($_.Exception.Message)"
    Write-Host "  Create manually: Intune admin center > Devices > By platform > Windows > Manage updates > Update rings"
}

# ── 5. Pilot Compliance Policy ──
Write-Host "`n=== Policy 5: Pilot Compliance Policy ==="

try {
    $existingCompliance = Invoke-MgRest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
    $existingPilotCompliance = $existingCompliance.value | Where-Object { $_.displayName -eq 'Windows Compliance - Pilot' }

    if ($existingPilotCompliance) {
        Write-Host "  Already exists: $($existingPilotCompliance.displayName) (ID: $($existingPilotCompliance.id))"
    } else {
        if ($PSCmdlet.ShouldProcess('Compliance Policy', 'Create Windows Compliance - Pilot')) {
            $compliance = @{
                '@odata.type'                  = '#microsoft.graph.windows10CompliancePolicy'
                displayName                    = 'Windows Compliance - Pilot'
                description                    = 'Light compliance policy for KEV remediation pilot'
                defenderEnabled                = $true
                defenderRealtimeMonitoringEnabled = $true  # Added for real-time protection
                firewallEnabled                = $true
                scheduledActionsForRule         = @(
                    @{
                        ruleName               = 'PasswordRequired'
                        scheduledActionConfigurations = @(
                            @{
                                actionType                 = 'block'
                                gracePeriodHours           = 24
                                notificationTemplateId     = ''
                                notificationMessageCCList  = @()
                            }
                        )
                    }
                )
            } | ConvertTo-Json -Depth 6

            $createdCompliance = Invoke-MgRest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies' -Body $compliance
            Write-Host "  Created: $($createdCompliance.displayName) (ID: $($createdCompliance.id))"

            # Assign to pilot devices
            $complianceAssignment = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                            groupId       = $groupIds.PilotDevices
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5

            Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($createdCompliance.id)/assign" -Body $complianceAssignment
            Write-Host "  Assigned to Intune-Windows-Pilot-Devices"
        }
    }
} catch {
    Write-Warning "Could not create compliance policy: $($_.Exception.Message)"
    Write-Host "  Create manually: Intune admin center > Devices > Compliance policies"
}

# ── 6. IME Bootstrap Platform Script ──
Write-Host "`n=== Policy 6: IME Bootstrap Platform Script ==="

try {
    $existingScripts = Invoke-MgRest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
    $existingIME = $existingScripts.value | Where-Object { $_.displayName -eq 'IME Bootstrap - Windows Pilot' }

    if ($existingIME) {
        Write-Host "  Already exists: $($existingIME.displayName) (ID: $($existingIME.id))"
    } else {
        if ($PSCmdlet.ShouldProcess('Platform Script', 'Create IME Bootstrap - Windows Pilot')) {
            $scriptContent = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('Write-Output "IME bootstrap complete"'))

            $imeScript = @{
                '@odata.type'              = '#microsoft.graph.deviceManagementScript'
                displayName                = 'IME Bootstrap - Windows Pilot'
                description                = 'Low-risk script to trigger Intune Management Extension installation on pilot devices'
                scriptContent              = $scriptContent
                runAsAccount               = 'system'
                enforceSignatureCheck      = $false
                runAs32BitOn64BitHost      = $false
                fileName                   = 'IME-Bootstrap.ps1'
            } | ConvertTo-Json -Depth 5

            $createdScript = Invoke-MgRest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -Body $imeScript
            Write-Host "  Created: $($createdScript.displayName) (ID: $($createdScript.id))"

            # Assign to pilot devices
            $scriptAssignment = @{
                deviceManagementScriptGroupAssignments = @(
                    @{
                        '@odata.type' = '#microsoft.graph.deviceManagementScriptGroupAssignment'
                        targetGroupId = $groupIds.PilotDevices
                        id            = $createdScript.id
                    }
                )
            } | ConvertTo-Json -Depth 5

            Invoke-MgRest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($createdScript.id)/assign" -Body $scriptAssignment
            Write-Host "  Assigned to Intune-Windows-Pilot-Devices"
        }
    }
} catch {
    Write-Warning "Could not create IME bootstrap script: $($_.Exception.Message)"
    Write-Host "  Create manually: Intune admin center > Devices > Scripts and remediations > Platform scripts"
}

# ── Summary ──
Write-Host "`n=== Intune Baseline Setup Summary ==="
Write-Host @"
Groups:
  Intune-Enrollment-Pilot-Users   = $($groupIds.PilotUsers)
  Intune-Windows-Pilot-Devices    = $($groupIds.PilotDevices)
  Intune-Windows-Broad-Devices    = $($groupIds.BroadDevices)
  Intune-Windows-Update-Exclusions = $($groupIds.UpdateExclusions)

Next steps:
  1. Enroll cdemo: Settings > Accounts > Access work or school > Enroll only in device management
  2. Add cdemo device object to Intune-Windows-Pilot-Devices
  3. Sync the device and verify:
       dsregcmd /status | Select-String 'MdmUrl'
       Get-Service IntuneManagementExtension
  4. Once MdmUrl is populated and IME is running, test KEV remediation
"@
