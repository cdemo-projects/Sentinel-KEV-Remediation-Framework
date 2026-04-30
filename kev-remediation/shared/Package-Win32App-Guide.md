# Package a Third-Party App for KEV Remediation (Gov-safe)

This guide is for the Intune admin who needs to add or update an app the **KEV-Remediate** Logic App can push when MDE flags a KEV-listed CVE.

Two paths. Pick whichever fits the app:

| Path | Use when | Effort | Gov-safe |
|---|---|---|---|
| **A. Microsoft Enterprise App Management** | App is in the curated Microsoft catalog (7-Zip, Notepad++, VLC, PuTTY, Chrome Enterprise, Firefox ESR, etc.) | ~5 minutes per app | Yes - GA in GCC and GCC High |
| **B. Custom Win32 (.intunewin) package** | Vendor MSI/EXE not in the catalog, or you need custom install args | ~30-60 minutes per app | Yes - installer lives in Intune CDN, not pulled from internet at runtime |

Both produce a `mobileApps` resource with a GUID. That GUID goes in [Win32-App-Mapping.json](./Win32-App-Mapping.json) so the Logic App can look it up by CVE.

---

## Path A: Microsoft Enterprise App Management

1. Open the **Intune admin center** (`intune.microsoft.us` for GCC High, `endpoint.microsoft.us` for GCC).
2. **Apps > Windows > Add > Enterprise App Catalog app**.
3. Search the app, pick the version. Microsoft has already validated, packaged, and signed it.
4. Set **Notes** to: `KEV-mapping: <CVE-ID-or-vendor/name>` (helps a human auditor cross-reference).
5. Configure **install behavior**: silent install, system context.
6. **Assignments**: leave empty. The Logic App creates per-device assignments at runtime.
7. **Review + create**.
8. Copy the **App ID** (GUID in URL after creation) into `Win32-App-Mapping.json`.

That is it. Microsoft handles supersedence when newer versions are added.

---

## Path B: Custom Win32 (.intunewin)

### Prerequisites

- Internet-connected Windows admin workstation (your dev box, NOT a gov-isolated server).
- [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool/releases) (`IntuneWinAppUtil.exe`).
- The vendor installer (MSI preferred, EXE acceptable).

### Steps

#### 1. Get the vendor installer

Download from the official vendor site on your admin box. Verify the SHA256 hash against the vendor publication. Save to a clean folder, e.g. `C:\Win32Source\7zip\7z2409-x64.msi`.

> Do this **once per app version**. The installer never touches a target device or the internet at runtime - Intune redistributes from its own CDN.

#### 2. Package as `.intunewin`

```powershell
.\IntuneWinAppUtil.exe `
    -c "C:\Win32Source\7zip" `
    -s "7z2409-x64.msi" `
    -o "C:\Win32Output"
```

Output: `C:\Win32Output\7z2409-x64.intunewin`.

#### 3. Upload to Intune

1. **Apps > Windows > Add > Windows app (Win32)**.
2. **App package file**: select the `.intunewin`.
3. **Name / Description / Publisher**: fill in.
4. **Notes**: `KEV-mapping: <CVE-ID-or-vendor/name>`.
5. **Program**:
    - Install: `msiexec /i "7z2409-x64.msi" /qn`
    - Uninstall: `msiexec /x "{PRODUCT-GUID}" /qn`
    - Install behavior: **System**.
6. **Requirements**: 64-bit Windows 10 1809+ (or whatever applies).
7. **Detection rules**:
    - For MSI, use **MSI product code** detection.
    - For EXE, use **registry version check** under `HKLM:\SOFTWARE\...\Uninstall\*`.
8. **Dependencies / Supersedence**:
    - **Supersedence**: select the previous version of the same app, set **Uninstall previous version: No** (msiexec MSI handles in-place upgrade). Mark the new app as superseding.
    - This is what lets the Logic App push the new version cleanly.
9. **Assignments**: leave empty. The Logic App creates per-device assignments at runtime.
10. **Review + create**.

#### 4. Capture the App ID

After creation, the URL is `.../mobileApps/{GUID}`. Copy that GUID.

#### 5. Add to the mapping file

Edit [Win32-App-Mapping.json](./Win32-App-Mapping.json):

```json
{
  "cveId": "CVE-2024-12345",
  "softwareVendor": "igor_pavlov",
  "softwareName": "7-zip",
  "intuneAppId": "<paste-GUID-here>",
  "intuneAppDisplayName": "7-Zip 24.09 (x64)",
  "minRemediatedVersion": "24.09",
  "supersedesAppIds": ["<previous-version-GUID>"],
  "notes": "Vendor MSI packaged via IntuneWinAppUtil.exe."
}
```

`softwareVendor` and `softwareName` MUST match the values MDE returns in `MDETVM_CL`. Confirm with:

```kql
MDETVM_CL
| where cveId == "CVE-2024-12345"
| project softwareVendor, softwareName, softwareVersion
| distinct softwareVendor, softwareName
```

#### 6. Test the assign call manually before relying on the Logic App

Replace `{appId}` and `{groupId}` (a single-device test group works well):

```powershell
$body = @{
  '@odata.type' = '#microsoft.graph.mobileAppAssignment'
  intent = 'required'
  target = @{
    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
    groupId = '<test-device-group-id>'
  }
  settings = @{
    '@odata.type' = '#microsoft.graph.win32LobAppAssignmentSettings'
    notifications = 'showAll'
    deliveryOptimizationPriority = 'foreground'
  }
} | ConvertTo-Json -Depth 5

# Gov-cloud Graph endpoint
Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.us/v1.0/deviceAppManagement/mobileApps/{appId}/assignments" `
    -Body $body
```

Expected: HTTP 201 Created. The test device should pick up the install at next IME check-in (force with `Get-ScheduledTask -TaskName PushLaunch | Start-ScheduledTask`).

---

## Lifecycle

- **New CVE for an app already mapped:** add a row to the mapping with the same `intuneAppId` and the new `cveId`. No repackaging needed if the existing version already remediates.
- **New version of an existing app:** Path A or B again, mark new app as **superseding** the old in Intune, swap the `intuneAppId` value in the mapping (or add a new row and remove the old).
- **Vendor goes EOL:** remove the mapping row. Logic App will fall through to notification-only.

---

## What the Logic App does with this

1. Sentinel detects a KEV-listed CVE on devices.
2. Logic App reads `MDETVM_CL`, gets `cveId + deviceList`.
3. Looks up `cveId` in `Win32-App-Mapping.json`.
4. **Hit:** calls `POST /deviceAppManagement/mobileApps/{intuneAppId}/assignments` for the pilot device(s). Intune handles delivery, retries, install-state. Proof of remediation comes from the next MDETVM snapshot showing `CveRows == 0`.
5. **Miss:** falls through to the existing email + Teams notification path. Admin gets notified to package the app, then re-runs.

No public internet egress. No WinGet. No SYSTEM-context downloads. Suitable for GCC, GCC High, and DoD provided the app itself is allowed in the environment.
