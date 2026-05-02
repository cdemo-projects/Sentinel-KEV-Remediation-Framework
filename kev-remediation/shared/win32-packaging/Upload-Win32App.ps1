<#
.SYNOPSIS
    Uploads an .intunewin file to Microsoft Intune as a Win32 LOB app via Microsoft Graph.

.DESCRIPTION
    Implements the multi-step Intune Win32 LOB upload protocol:
      1. Create mobileApp (win32LobApp) with metadata, install/uninstall, detection rules, MSI info
      2. Create contentVersion
      3. Create file record (name, size, sizeEncrypted, manifest)
      4. Poll until Azure Storage SAS URI is provisioned
      5. Upload encrypted payload to blob storage in chunks (~6 MB blocks), each tagged with a blockId
      6. PUT block list to commit the blob
      7. POST file commit with fileEncryptionInfo (from .intunewin Detection.xml)
      8. Poll until uploadState = commitFileSuccess
      9. PATCH mobileApp committedContentVersion = new contentVersion id

    Does NOT assign the app. Assignment is the Logic App's job at runtime per CVE incident.
    After upload, the script prints the Intune app ID — paste that into Win32-App-Mapping.json.

.PARAMETER Config
    Path to the JSON config file (see examples/7zip-2409.json).

.PARAMETER IntuneWinPath
    Optional override of the .intunewin path. Defaults to the file produced by Build-Win32Package.ps1.

.PARAMETER Cloud
    Commercial or Gov. Determines Graph endpoint and Connect-MgGraph environment.

.PARAMETER TenantId
    Optional tenant GUID for Connect-MgGraph. If omitted, uses the default for current sign-in.

.EXAMPLE
    .\Upload-Win32App.ps1 -Config .\examples\7zip-2409.json -Cloud Gov

.EXAMPLE
    .\Upload-Win32App.ps1 -Config .\examples\7zip-2409.json -Cloud Gov -TenantId <guid>

.NOTES
    Requires PowerShell 7.0+ and Microsoft.Graph.Authentication module:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

    Required Graph scope (delegated for an interactive admin run):
        DeviceManagementApps.ReadWrite.All

    For unattended automation (CI), use a service principal with the same application permission.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Config,
    [string]$IntuneWinPath = '',
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [string]$TenantId = ''
)

$ErrorActionPreference = 'Stop'

# ---------- 0. Config + cloud setup ----------
if (-not (Test-Path $Config)) { throw "Config file not found: $Config" }
$cfg = Get-Content -Raw -Path $Config | ConvertFrom-Json -Depth 12

if (-not $IntuneWinPath) {
    $intunewinName = [IO.Path]::ChangeExtension($cfg.source.fileName, '.intunewin')
    $IntuneWinPath = Join-Path $cfg.package.outputFolder $intunewinName
}
if (-not (Test-Path $IntuneWinPath)) { throw ".intunewin not found: $IntuneWinPath  - run Build-Win32Package.ps1 first" }

$mgEnv      = if ($Cloud -eq 'Gov') { 'USGov' }                 else { 'Global' }
$graphBase  = if ($Cloud -eq 'Gov') { 'https://graph.microsoft.us' } else { 'https://graph.microsoft.com' }
$apiVersion = 'beta'   # Win32LobApp upload subresources are stable on beta

# ---------- 1. Connect to Graph ----------
Write-Host "[1/9] Connecting to Microsoft Graph ($Cloud cloud)..." -ForegroundColor Cyan
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Environment -ne $mgEnv -or ($TenantId -and $ctx.TenantId -ne $TenantId)) {
    if ($ctx) { Disconnect-MgGraph | Out-Null }
    $connectArgs = @{
        Environment = $mgEnv
        Scopes      = 'DeviceManagementApps.ReadWrite.All'
        NoWelcome   = $true
    }
    if ($TenantId) { $connectArgs.TenantId = $TenantId }
    Connect-MgGraph @connectArgs | Out-Null
    $ctx = Get-MgContext
}
Write-Host "      Tenant: $($ctx.TenantId)  Account: $($ctx.Account)" -ForegroundColor Green

# Helper: call Graph with retry on throttling
function Invoke-Graph {
    param([string]$Method, [string]$Url, $Body = $null, [int]$RetryMax = 3)
    $attempt = 0
    while ($true) {
        try {
            $params = @{ Method = $Method; Uri = $Url }
            if ($Body -ne $null) { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $params.ContentType = 'application/json' }
            return Invoke-MgGraphRequest @params
        } catch {
            $attempt++
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($attempt -ge $RetryMax -or $code -notin 429,503) { throw }
            $delay = [int]([math]::Pow(2, $attempt))
            Write-Warning "Graph $Method $Url returned $code, retrying in ${delay}s (attempt $attempt/$RetryMax)"
            Start-Sleep -Seconds $delay
        }
    }
}

# ---------- 2. Read Detection.xml from .intunewin ----------
Write-Host "[2/9] Extracting Detection.xml from .intunewin ..." -ForegroundColor Cyan
Add-Type -AssemblyName System.IO.Compression.FileSystem
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("intunewin-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $zip = [IO.Compression.ZipFile]::OpenRead($IntuneWinPath)
    $detEntry = $zip.Entries | Where-Object { $_.FullName -like '*Detection.xml' } | Select-Object -First 1
    $payloadEntry = $zip.Entries | Where-Object { $_.FullName -like '*IntunePackage.intunewin' } | Select-Object -First 1
    if (-not $detEntry -or -not $payloadEntry) { throw ".intunewin is malformed (missing Detection.xml or IntunePackage.intunewin)" }
    $detPath = Join-Path $tempRoot 'Detection.xml'
    $payloadPath = Join-Path $tempRoot 'payload.bin'
    [IO.Compression.ZipFileExtensions]::ExtractToFile($detEntry, $detPath, $true)
    [IO.Compression.ZipFileExtensions]::ExtractToFile($payloadEntry, $payloadPath, $true)
} finally {
    if ($zip) { $zip.Dispose() }
}
[xml]$det = Get-Content $detPath -Raw
$enc = $det.ApplicationInfo.EncryptionInfo
$encryptedSize    = (Get-Item $payloadPath).Length
$unencryptedSize  = [int64]$det.ApplicationInfo.UnencryptedContentSize
Write-Host "      payload bytes encrypted=$encryptedSize unencrypted=$unencryptedSize" -ForegroundColor Green

# ---------- 3. Build mobileApp body ----------
Write-Host "[3/9] Creating mobileApp (win32LobApp) ..." -ForegroundColor Cyan
$app = $cfg.intuneApp
$detectionRules = @()
foreach ($r in $app.detectionRules) {
    switch ($r.type) {
        'msi' {
            $detectionRules += @{
                '@odata.type' = '#microsoft.graph.win32LobAppProductCodeDetection'
                productCode   = $r.productCode
                productVersionOperator = $r.productVersionOperator
                productVersion = $r.productVersion
            }
        }
        default { throw "Unsupported detection rule type: $($r.type) (extend Upload-Win32App.ps1 to add support)" }
    }
}
$msiInfo = $app.msiInformation
$mobileAppBody = @{
    '@odata.type'                    = '#microsoft.graph.win32LobApp'
    displayName                      = $app.displayName
    description                      = $app.description
    publisher                        = $app.publisher
    notes                            = $app.notes
    owner                            = $app.owner
    developer                        = $app.developer
    informationUrl                   = $app.informationUrl
    privacyInformationUrl            = $app.privacyInformationUrl
    isFeatured                       = $app.isFeatured
    fileName                         = $cfg.source.fileName
    setupFilePath                    = $cfg.source.fileName
    installCommandLine               = $app.installCommandLine
    uninstallCommandLine             = $app.uninstallCommandLine
    applicableArchitectures          = $app.applicableArchitectures
    minimumSupportedWindowsRelease   = $app.minimumSupportedWindowsRelease
    installExperience                = @{
        runAsAccount           = $app.installExperience.runAsAccount
        deviceRestartBehavior  = $app.installExperience.deviceRestartBehavior
    }
    msiInformation                   = @{
        productCode     = $msiInfo.productCode
        productVersion  = $msiInfo.productVersion
        upgradeCode     = $msiInfo.upgradeCode
        requiresReboot  = $msiInfo.requiresReboot
        packageType     = $msiInfo.packageType
    }
    detectionRules                   = $detectionRules
    requirementRules                 = @()
    returnCodes                      = @(
        @{ returnCode = 0;    type = 'success' },
        @{ returnCode = 1707; type = 'success' },
        @{ returnCode = 3010; type = 'softReboot' },
        @{ returnCode = 1641; type = 'hardReboot' },
        @{ returnCode = 1618; type = 'retry' }
    )
}
$mobileApp = Invoke-Graph -Method POST -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps" -Body $mobileAppBody
$appId = $mobileApp.id
Write-Host "      mobileApp id: $appId" -ForegroundColor Green

# ---------- 4. Create contentVersion ----------
Write-Host "[4/9] Creating contentVersion ..." -ForegroundColor Cyan
$cv = Invoke-Graph -Method POST -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions" -Body @{}
$cvId = $cv.id
Write-Host "      contentVersion id: $cvId" -ForegroundColor Green

# ---------- 5. Create file record ----------
Write-Host "[5/9] Creating file record ..." -ForegroundColor Cyan
$fileBody = @{
    '@odata.type'    = '#microsoft.graph.mobileAppContentFile'
    name             = $cfg.source.fileName
    size             = $unencryptedSize
    sizeEncrypted    = $encryptedSize
    manifest         = $null
    isDependency     = $false
}
$file = Invoke-Graph -Method POST -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files" -Body $fileBody
$fileId = $file.id

# ---------- 6. Poll for SAS URI ----------
Write-Host "[6/9] Waiting for Azure Storage SAS URI ..." -ForegroundColor Cyan
$sas = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    $f = Invoke-Graph -Method GET -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$fileId"
    if ($f.uploadState -eq 'azureStorageUriRequestSuccess') { $sas = $f.azureStorageUri; break }
    if ($f.uploadState -like '*Failed*') { throw "SAS URI provisioning failed: $($f.uploadState)" }
}
if (-not $sas) { throw "Timed out waiting for SAS URI." }
Write-Host "      SAS issued." -ForegroundColor Green

# ---------- 7. Upload payload in chunks ----------
Write-Host "[7/9] Uploading encrypted payload in chunks ..." -ForegroundColor Cyan
$chunkSize = 6MB
$blockIds = New-Object System.Collections.Generic.List[string]
$fs = [IO.File]::OpenRead($payloadPath)
try {
    $buffer = New-Object byte[] $chunkSize
    $idx = 0
    while ($true) {
        $read = $fs.Read($buffer, 0, $chunkSize)
        if ($read -le 0) { break }
        $chunk = if ($read -eq $chunkSize) { $buffer } else { $buffer[0..($read-1)] }
        $blockIdRaw = '{0:D6}' -f $idx
        $blockId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($blockIdRaw))
        $blockIds.Add($blockId) | Out-Null
        $putUri = "$sas&comp=block&blockid=$([Uri]::EscapeDataString($blockId))"
        $maxRetry = 3
        for ($r = 0; $r -lt $maxRetry; $r++) {
            try {
                Invoke-WebRequest -Method PUT -Uri $putUri -Body $chunk -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -UseBasicParsing | Out-Null
                break
            } catch {
                if ($r -eq $maxRetry-1) { throw }
                Start-Sleep -Seconds (2 * ($r+1))
            }
        }
        $idx++
        if ($idx % 5 -eq 0) { Write-Host "      uploaded $idx chunks ($([math]::Round($fs.Position / 1MB,1)) MB)" }
    }
} finally {
    $fs.Dispose()
}

# Renew SAS if upload took close to its expiry (rare for small apps; skipped here)

# Commit block list
$blocksXml = ($blockIds | ForEach-Object { "<Latest>$_</Latest>" }) -join ''
$blockListXml = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + $blocksXml + '</BlockList>'
Invoke-WebRequest -Method PUT -Uri "$sas&comp=blocklist" -Body $blockListXml -ContentType 'application/xml' -UseBasicParsing | Out-Null
Write-Host "      block list committed ($($blockIds.Count) blocks)." -ForegroundColor Green

# ---------- 8. Commit file with encryption info ----------
Write-Host "[8/9] Committing file with encryption info ..." -ForegroundColor Cyan
$commitBody = @{
    fileEncryptionInfo = @{
        encryptionKey        = $enc.EncryptionKey
        macKey               = $enc.MacKey
        initializationVector = $enc.InitializationVector
        mac                  = $enc.Mac
        profileIdentifier    = $enc.ProfileIdentifier
        fileDigest           = $enc.FileDigest
        fileDigestAlgorithm  = $enc.FileDigestAlgorithm
    }
}
Invoke-Graph -Method POST -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$fileId/commit" -Body $commitBody | Out-Null

# Poll commit
$committed = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    $f = Invoke-Graph -Method GET -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$fileId"
    if ($f.uploadState -eq 'commitFileSuccess') { $committed = $true; break }
    if ($f.uploadState -like '*Failed*') { throw "File commit failed: $($f.uploadState)" }
}
if (-not $committed) { throw "Timed out waiting for commitFileSuccess." }
Write-Host "      commit succeeded." -ForegroundColor Green

# ---------- 9. PATCH mobileApp committedContentVersion ----------
Write-Host "[9/9] Setting committedContentVersion on the app ..." -ForegroundColor Cyan
$patchBody = @{
    '@odata.type'              = '#microsoft.graph.win32LobApp'
    committedContentVersion    = $cvId
}
Invoke-Graph -Method PATCH -Url "$graphBase/$apiVersion/deviceAppManagement/mobileApps/$appId" -Body $patchBody | Out-Null
Write-Host "      Done." -ForegroundColor Green

# ---------- Cleanup ----------
Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue

# ---------- Summary ----------
Write-Host ""
Write-Host "Upload complete." -ForegroundColor Green
Write-Host "  appKey       : $($cfg.appKey)"
Write-Host "  Intune appId : $appId"
Write-Host "  Cloud        : $Cloud"
Write-Host ""
Write-Host "Next:"
Write-Host "  1. (Optional) Configure supersedence in the Intune portal against any prior version of this app."
Write-Host "  2. Add this entry to kev-remediation/shared/Win32-App-Mapping.json:"
Write-Host ""
Write-Host "     {"
Write-Host "       `"cveId`": `"<CVE-XXXX-XXXXX>`","
Write-Host "       `"softwareVendor`": `"<vendor-token-from-MDETVM_CL>`","
Write-Host "       `"softwareName`":   `"<software-token-from-MDETVM_CL>`","
Write-Host "       `"intuneAppId`":    `"$appId`","
Write-Host "       `"intuneAppDisplayName`": `"$($app.displayName)`","
Write-Host "       `"minRemediatedVersion`": `"$($app.msiInformation.productVersion)`""
Write-Host "     }"
Write-Host ""
