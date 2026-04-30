# Win32 packaging workflow

Two-step workflow to package a third-party app and ship it to Intune (commercial or gov) for use by the KEV-Remediate Logic App.

```
examples\<app>.json   <-- one config per app, both scripts read it
Build-Win32Package.ps1  -- run on a VM with internet, produces .intunewin
Upload-Win32App.ps1     -- run with Graph access, ships to Intune
```

After upload, paste the printed app GUID into [`../Win32-App-Mapping.json`](../Win32-App-Mapping.json) so the Logic App can find it.

---

## 1. Prerequisites

### On the packaging VM
- Windows 10/11 or Server 2019+
- PowerShell 7.0+
- Internet access to the vendor and to GitHub (for IntuneWinAppUtil.exe)

### On the upload box (can be the same VM or your normal admin workstation)
- PowerShell 7.0+
- Module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- Network reach to the right Graph endpoint:
  - Commercial: `graph.microsoft.com`
  - Gov: `graph.microsoft.us`
- An Entra account with `Intune Service Administrator` (or the granular delegated scope `DeviceManagementApps.ReadWrite.All`)

---

## 2. Configure the app

Copy [`examples/7zip-2409.json`](examples/7zip-2409.json) to a new file for your app and edit:

| Field | What to set |
|---|---|
| `appKey` | Short stable id, e.g. `notepad-plus-plus-869` |
| `source.vendorUrl` | Direct HTTPS download URL of the vendor MSI/EXE |
| `source.sha256` | The vendor's published checksum. **Build script aborts if mismatch.** Leave the placeholder on the first run; the script will print the actual hash so you can verify it manually against the vendor's hash, then update the file. |
| `source.fileName` | Just the filename (no path) |
| `package.stagingFolder` / `outputFolder` | Working directories on the VM |
| `intuneApp.displayName` | What admins see in Intune |
| `intuneApp.notes` | Convention: `KEV-mapping: <vendor>/<software>` |
| `intuneApp.installCommandLine` | `msiexec /i "<file>.msi" /qn` for MSI; vendor-specific silent flag for EXE |
| `intuneApp.uninstallCommandLine` | `msiexec /x {PRODUCT-CODE} /qn` for MSI |
| `intuneApp.msiInformation.productCode` | The MSI ProductCode GUID. Get it via `msiexec /a <msi> TARGETDIR=C:\extracted` then read Product.wxs, or [Orca](https://learn.microsoft.com/windows/win32/msi/orca-exe). |
| `intuneApp.msiInformation.productVersion` / `upgradeCode` | From the MSI |
| `intuneApp.detectionRules[0]` | For an MSI app, leave the `msi` type with the same `productCode` and `productVersion` |

---

## 3. Build the .intunewin (on the VM)

```powershell
cd <path-to>\kev-remediation\shared\win32-packaging
.\Build-Win32Package.ps1 -Config .\examples\7zip-2409.json
```

What it does:
1. Downloads `IntuneWinAppUtil.exe` from Microsoft's GitHub if not cached
2. Downloads the vendor installer to `package.stagingFolder`
3. Verifies SHA256 (aborts on mismatch)
4. Runs `IntuneWinAppUtil.exe -c <staging> -s <file> -o <output>`
5. Prints the path to the resulting `.intunewin`

Re-run with `-Force` to redownload the installer and rebuild.

---

## 4. Upload to Intune

```powershell
.\Upload-Win32App.ps1 -Config .\examples\7zip-2409.json -Cloud Gov
# or:
.\Upload-Win32App.ps1 -Config .\examples\7zip-2409.json -Cloud Commercial -TenantId <guid>
```

The script implements the full Win32 LOB upload protocol:

| Step | What |
|---|---|
| 1 | `Connect-MgGraph` to the right cloud, scope `DeviceManagementApps.ReadWrite.All` |
| 2 | Open the `.intunewin` (it's a ZIP), extract `Detection.xml` and `IntunePackage.intunewin` (the encrypted payload) |
| 3 | `POST /deviceAppManagement/mobileApps` with `@odata.type = #microsoft.graph.win32LobApp` + all metadata, MSI info, detection rules, return codes |
| 4 | `POST /microsoft.graph.win32LobApp/contentVersions` |
| 5 | `POST /contentVersions/{cv}/files` with name + size + sizeEncrypted |
| 6 | Poll until Intune provisions an Azure Storage SAS URI |
| 7 | Upload the encrypted payload to blob storage in 6 MB blocks (each tagged with a Base64 blockId), then PUT the block list to commit the blob |
| 8 | `POST /files/{f}/commit` with `fileEncryptionInfo` from `Detection.xml`. Poll until `uploadState = commitFileSuccess`. |
| 9 | `PATCH /mobileApps/{id}` with `committedContentVersion = {cv}` |

The script prints the new Intune app GUID at the end. **Copy that GUID** into the mapping file (next step).

---

## 5. Wire it into the Logic App mapping

Edit [`../Win32-App-Mapping.json`](../Win32-App-Mapping.json) and add a row:

```json
{
  "cveId": "CVE-XXXX-XXXXX",
  "softwareVendor": "<token from MDETVM_CL>",
  "softwareName":   "<token from MDETVM_CL>",
  "intuneAppId":    "<paste GUID here>",
  "intuneAppDisplayName": "7-Zip 24.09 (x64)",
  "minRemediatedVersion": "24.09.00.0"
}
```

To confirm the vendor + software tokens for a given CVE in your tenant:

```kql
MDETVM_CL
| where cveId == "CVE-XXXX-XXXXX"
| project softwareVendor, softwareName, softwareVersion
| distinct softwareVendor, softwareName
```

That's it. Next time the Sentinel automation rule fires for that CVE, the Logic App will look up the GUID and call `POST /deviceAppManagement/mobileApps/{guid}/assignments` against the affected device(s).

---

## 6. Updating an app

When the vendor releases a new version that fixes another CVE:

1. Edit the JSON config: bump `vendorUrl`, `sha256`, `displayName`, `productCode`, `productVersion`, `installCommandLine`, etc.
2. Re-run `Build-Win32Package.ps1 -Force`
3. Re-run `Upload-Win32App.ps1` (you'll get a new app GUID)
4. In the Intune portal: edit the new app -> Supersedence -> add the previous version as superseded
5. Update `Win32-App-Mapping.json` with the new GUID; remove or repoint the old row

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `SHA256 mismatch!` on build | Vendor changed the installer or you copied the wrong hash. Compare against the vendor's published checksum, never trust a hash from a third-party page. |
| `Refusing to package an unverified installer` | The config still has the placeholder hash. Run once, copy the `actual` hash the script prints, verify it against the vendor's published value, then update the JSON. |
| `Timed out waiting for SAS URI` | Tenant throttling or transient Intune service issue. Re-run; the partially-created mobileApp will be a duplicate -- delete it from the portal. |
| `commitFileSuccess` never returns | Encryption info from `Detection.xml` didn't match the payload (rare unless the .intunewin is corrupt). Re-run `Build-Win32Package.ps1 -Force`. |
| HTTP 403 on POST mobileApps | Account is missing `Intune Service Administrator` or scope wasn't granted. Confirm with `(Get-MgContext).Scopes`. |
| HTTP 401 in gov | You signed into the commercial cloud. The script auto-corrects environments, but check `(Get-MgContext).Environment` is `USGov`. |

## References

- [Add a Win32 app to Intune](https://learn.microsoft.com/intune/intune-service/apps/apps-win32-add)
- [Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)
- [Intune Win32 LOB upload protocol (community write-up)](https://oceanleaf.ch/intune-win32-app-upload-with-graph-api/)
