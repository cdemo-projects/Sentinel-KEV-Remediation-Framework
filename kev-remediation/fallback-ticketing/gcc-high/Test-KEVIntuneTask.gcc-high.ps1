<#
.SYNOPSIS
    Sends a test payload to KEV-IntuneTask-v1 to create an Intune Security Task for a CVE.

.EXAMPLE
    .\Test-KEVIntuneTask.gcc-high.ps1 -TriggerUrl "<value-from-Deploy-output>"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TriggerUrl,
    [string]$CveId           = "CVE-2024-11477",
    [string]$AppName         = "7-Zip",
    [string]$AppPublisher    = "Igor Pavlov",
    [string]$AppVersion      = "24.09",
    [int]   $ManagedDeviceCount = 3,
    [string]$Remediation     = "Update 7-Zip to 24.09 or later. Use Intune Win32 LOB deployment of the packaged 7z2409-x64.intunewin.",
    [string]$Insights        = "CISA KEV: heap-buffer-overflow in 7-Zip RAR5 parser. Update available via Win32 LOB."
)

$ErrorActionPreference = "Stop"

$body = @{
    cveId               = $CveId
    appName             = $AppName
    appPublisher        = $AppPublisher
    appVersion          = $AppVersion
    managedDeviceCount  = $ManagedDeviceCount
    remediation         = $Remediation
    insights            = $Insights
} | ConvertTo-Json

Write-Host "POST -> $TriggerUrl" -ForegroundColor Cyan
Write-Host "Body:" -ForegroundColor DarkGray
Write-Host $body -ForegroundColor DarkGray
Write-Host ""

$response = Invoke-RestMethod -Method Post -Uri $TriggerUrl -Body $body -ContentType "application/json"

Write-Host "Response:" -ForegroundColor Green
$response | ConvertTo-Json -Depth 10

if ($response.taskId) {
    Write-Host ""
    Write-Host "Task created. View it in Intune admin center:" -ForegroundColor Yellow
    Write-Host "  https://intune.microsoft.us > Endpoint security > Security tasks" -ForegroundColor White
    Write-Host "  Task ID: $($response.taskId)" -ForegroundColor White
}
