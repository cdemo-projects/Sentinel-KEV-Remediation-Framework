<#
.SYNOPSIS
    Sends a test KEV CVE payload to the KEV-ServiceNow-v1 Logic App.

.EXAMPLE
    .\Test-KEVServiceNow.gcc.ps1 -TriggerUrl "<value-from-deploy-output>"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TriggerUrl,
    [string]$CveId               = "CVE-2024-11477",
    [string]$AppName             = "7-Zip",
    [string]$AppPublisher        = "Igor Pavlov",
    [string]$AppVersion          = "24.09",
    [int]   $ManagedDeviceCount  = 3,
    [string]$Remediation         = "Update 7-Zip to 24.09 or later. Use Intune Win32 LOB deployment of the packaged 7z2409-x64.intunewin, or push via the Enterprise App Catalog.",
    [string]$Insights            = "CISA KEV: heap-buffer-overflow in 7-Zip RAR5 parser allows arbitrary code execution. Update available via Win32 LOB.",
    [string]$SentinelIncidentId  = "test-incident-001"
)

$ErrorActionPreference = "Stop"

$body = [pscustomobject]@{
    cveId               = $CveId
    appName             = $AppName
    appPublisher        = $AppPublisher
    appVersion          = $AppVersion
    managedDeviceCount  = $ManagedDeviceCount
    remediation         = $Remediation
    insights            = $Insights
    sentinelIncidentId  = $SentinelIncidentId
} | ConvertTo-Json

Write-Host "POST -> $TriggerUrl" -ForegroundColor Cyan
Write-Host "Body:" -ForegroundColor DarkGray
Write-Host $body -ForegroundColor DarkGray
Write-Host ""

$response = Invoke-RestMethod -Method Post -Uri $TriggerUrl -Body $body -ContentType "application/json"

Write-Host "Response:" -ForegroundColor Green
$response | ConvertTo-Json -Depth 10

if ($response.ticketNumber) {
    Write-Host ""
    Write-Host "ServiceNow ticket created:" -ForegroundColor Yellow
    Write-Host "  Number: $($response.ticketNumber)" -ForegroundColor White
    Write-Host "  URL:    $($response.ticketUrl)" -ForegroundColor White
}
