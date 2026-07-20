# KEV Remediation Framework &mdash; Operator Runbook

End-to-end operator playbook for the production-scale Win32 app remediation path. Pairs with the Win32 packaging guide (`win32-packaging/README.md`).

## Lifecycle overview

```
ONE-TIME PER TENANT:
  1. Setup-KEVRingGroups.ps1            -> creates 3 universal ring groups
  2. Deploy-MappingHost.ps1             -> creates Storage container + uploads mapping
  3. Assign-KEVRemediatePermissions.ps1 -> grants Logic App MI the right Graph perms
  4. Patch-KEVRemediate-Win32.ps1       -> splices Win32 snippet into deployed Logic App

PER APP (~5 min each):
  5. Build-Win32Package.ps1 OR Intune portal upload  -> get mobileApps GUID
  6. Onboard-AppToFramework.ps1        -> creates AppPatch group + standing assignment
  7. Append the printed JSON block to Win32-App-Mapping.json
  8. Add CVE IDs to that app's cveIds[] as KEV publishes them
  9. Deploy-MappingHost.ps1            -> re-upload mapping JSON to Storage

PER INCIDENT (Logic App, fully automated):
  - Sentinel detects KEV-listed CVE
  - Logic App reads mapping, finds app, intersects affected devices with rings
  - Wave 1: Pilot ring members get added to AppPatch group
  - Wait 24h, poll install state, halt if failure rate > threshold
  - Wave 2: Early ring
  - Wait 48h, poll, halt if failure
  - Wave 3: Broad ring
  - Wait until MDETVM_CL CveRows == 0 for these devices
  - Cleanup: remove devices from AppPatch group
  - Close incident
```

---

## Tenant setup (do once)

### 1. Create the universal ring groups

```powershell
# Hybrid pattern: Pilot+Early are admin-curated, Broad is dynamic ("all Windows devices")
.\Setup-KEVRingGroups.ps1 -Cloud Gov
```

Output prints the three group GUIDs. Paste them into `Win32-App-Mapping.json` -> `ringStrategy`.

**Then populate Pilot and Early manually** (Entra portal or PowerShell):
- Pilot: ~50 devices owned by IT/security team
- Early: ~500 devices that customer designates as friendly users
- Broad: auto-populated dynamically (no action)

### 2. Deploy the mapping host

```powershell
.\Deploy-MappingHost.ps1 -Cloud Gov -ResourceGroup <your-rg>
```

Provisions a Storage account + private container `kev-config`, grants the Logic App MI Storage Blob Data Reader, uploads the current `Win32-App-Mapping.json`. Prints the blob URL.

### 3. Grant Logic App permissions

```powershell
.\Assign-KEVRemediatePermissions.gov.ps1 `
    -ResourceGroupName <your-rg> `
    -WorkspaceName <your-sentinel-workspace> `
    -WorkspaceResourceGroup <workspace-rg> `
    -TenantId <your-gcc-tenant-guid>
```

Grants the MI:
- Sentinel Responder + Log Analytics Reader on the workspace
- 8 Graph application permissions (Group + GroupMember + DeviceManagementApps + others)
- Windows Update Deployment Administrator Entra role

### 4. Patch the Logic App with the Win32 snippet

```powershell
# Dry-run first (always)
.\Patch-KEVRemediate-Win32.ps1 -Cloud Gov -ResourceGroup <your-rg> -Win32MappingUrl https://<storage>.blob.core.usgovcloudapi.net/kev-config/Win32-App-Mapping.json

# Review backup file + planned diff, then:
.\Patch-KEVRemediate-Win32.ps1 -Cloud Gov -ResourceGroup <your-rg> -Win32MappingUrl https://... -Apply
```

---

## Per-app onboarding (do once per app)

### 1. Get the app into Intune

Either:
- **Portal upload** (recommended for first-time admins): `intune.microsoft.us` -> Apps -> Windows -> + Create -> Windows app (Win32)
- **Script upload**: `Build-Win32Package.ps1` then `Upload-Win32App.ps1` (BETA)

Capture the resulting `mobileApps` GUID from the URL.

### 2. Verify softwareVendor + softwareName tokens in MDETVM_CL

```kql
// Run in Sentinel Logs
MDETVM_CL
| where cveId in ("CVE-XXXX-XXXXX", "CVE-YYYY-YYYYY")
| project softwareVendor, softwareName, softwareVersion
| distinct softwareVendor, softwareName
```

You'll get the exact lowercase tokens MDE uses. **The Logic App matches against these exactly** &mdash; case-sensitive, character-for-character.

### 3. Onboard the app

```powershell
.\Onboard-AppToFramework.ps1 -Cloud Gov `
    -IntuneAppId <mobileApps-guid> `
    -AppKey 7zip `
    -SoftwareVendor igor_pavlov `
    -SoftwareName 7-zip
```

What it does:
- Verifies the Intune app is in `published` state
- Creates Entra group `AAD-KEV-AppPatch-7zip`
- Creates the standing Intune assignment (app -> group, intent=required)
- Prints a JSON block to copy into the mapping

### 4. Update the mapping file

Append the printed block to `Win32-App-Mapping.json` apps[] array. Add CVE IDs to `cveIds[]`:

```json
{
  "appKey": "7zip",
  "intuneAppId": "81b14843-...",
  "intuneAppDisplayName": "7-Zip 24.09 (x64 edition)",
  "minRemediatedVersion": "24.09.00.0",
  "intuneAppPatchGroupId": "<group-guid-from-onboard-script>",
  "softwareVendor": "igor_pavlov",
  "softwareName": "7-zip",
  "cveIds": ["CVE-2024-XXXXX"],
  "ringOverrides": null,
  "excludeFromAutomation": false
}
```

### 5. Re-upload the mapping

```powershell
.\Deploy-MappingHost.ps1 -Cloud Gov -ResourceGroup <your-rg>
```

The Logic App reads from this URL at every incident, so changes are picked up immediately.

---

## Per-incident behavior (Logic App, fully automated)

When Sentinel detects a KEV-listed CVE on managed devices:

1. **Lookup**: Logic App reads `Win32-App-Mapping.json` -> finds the matching app entry by `cveIds[]` (or by `softwareVendor`+`softwareName` if no CVE match).
2. **Exclusion check**: if `excludeFromAutomation: true`, fall through to notification.
3. **Affected device intersection**: pulls Pilot/Early/Broad ring members, intersects with the affected device list.
4. **Wave 1 - Pilot**: adds intersected Pilot devices to the AppPatch group. Intune begins install.
5. **Wait**: `pilotToEarlyHours` (default 24) before checking pilot health.
6. **Halt-or-promote**: if pilot failure rate > threshold, post Sentinel comment and exit. Else proceed.
7. **Wave 2 - Early**: adds intersected Early devices.
8. **Wait + check**: `earlyToBroadHours` (default 48).
9. **Wave 3 - Broad**: adds intersected Broad devices. (For >1,000 broad devices, the Foreach pattern in the snippet should be replaced with `$batch` per the operator pacing notes &mdash; planned upgrade.)
10. **Cleanup**: when `MDETVM_CL` shows `CveRows == 0` for the affected set, the auto-close Logic App runs and removes devices from the AppPatch group.

---

## Failure scenarios and what happens

| Scenario | Logic App behavior |
|---|---|
| App not in mapping | Falls through to notification. Audit log records `no-mapping-found`. |
| App `excludeFromAutomation: true` | Falls through to notification. Audit log records `excluded-from-automation`. |
| Pilot failure rate > threshold | Halts. Posts comment to Sentinel incident. Devices already in group stay (admin decides). |
| Pilot succeeds but Early fails | Same halt at Early. |
| Device offline at incident time | Stays in group. Receives the install on next maintenance sync (~8 hr). |
| Concurrent incidents for same app | Both runs add to the same AppPatch group. Group write is idempotent. Cleanup may need locking (Phase 6 work). |
| Group write throttled (429) | Retry policy on the Foreach action handles transient 429s. Sustained throttling needs $batch + pacing (Phase 6 work). |

---

## Day-2 operations

### Add a new CVE for an existing app

Edit `Win32-App-Mapping.json`, append to that app's `cveIds[]`, re-run `Deploy-MappingHost.ps1`. No Logic App or Intune changes needed.

### Update an app to a new version

1. Package + upload the new version to Intune (gets a new mobileApps GUID)
2. In Intune portal: configure supersedence on the new app pointing at the old one
3. Update `Win32-App-Mapping.json`: replace `intuneAppId` and `minRemediatedVersion`, optionally clear stale `cveIds[]`
4. Re-upload mapping

### Remove an app from the framework

1. Remove the entry from `Win32-App-Mapping.json`
2. Re-upload mapping
3. Optionally delete the AppPatch group from Entra (or leave it &mdash; empty groups are harmless)
4. Optionally delete the Intune assignment to the AppPatch group

### Adjust ring delays globally

Edit `ringStrategy.defaultPilotToEarlyHours` and `defaultEarlyToBroadHours`. Re-upload. Applies to all subsequent incidents.

### Adjust ring delays for one app only

Set `ringOverrides` on that app:
```json
"ringOverrides": {
  "pilotToEarlyHours": 4,
  "earlyToBroadHours": 12,
  "failureThreshold": 0.05
}
```

Useful for high-criticality apps (browsers, mail clients) where slower ring discipline is unacceptable for active KEV exploitation.

### Pause the framework entirely

Disable the KEV-Remediate Logic App in the Azure portal. WUfB Path A (Windows quality updates) keeps running independently if it's a separate Logic App.

---

## Verification queries

### Has any KEV remediation actually happened?

```kql
// Sentinel Logs
KEVRemediation_CL  // (when Phase 6 audit table is built)
| where TimeGenerated > ago(7d)
| summarize Devices = dcount(deviceId), Apps = dcount(appKey) by Wave, Outcome
```

### Are devices stuck in an AppPatch group after CveRows == 0?

```powershell
# Should be empty between incidents
$tok = (az account get-access-token --resource https://graph.microsoft.us --query accessToken -o tsv)
Invoke-RestMethod -Uri "https://graph.microsoft.us/v1.0/groups/<AppPatch-group-id>/members?`$count=true" `
    -Headers @{ Authorization="Bearer $tok"; ConsistencyLevel="eventual" }
```

### Any apps with no CVEs ever (candidates for removal)?

Eyeball the mapping JSON for entries where `cveIds: []` and the app has been there 6+ months.

---

## Known gaps (Phase 6+ roadmap)

| Item | Why it's not done yet |
|---|---|
| `$batch` for >50-device Foreach steps | Foreach with parallelism + retry policy works to ~1,000 devices; $batch is the upgrade for cleaner throttle pacing at 5K+ |
| Sentinel custom table audit writer | Audit log accumulates in Logic App variable; persisting to a custom table is Phase 6 |
| Concurrent-incident lock | Multi-CVE-same-app race condition theoretical; Storage table lease pattern designed but not coded |
| Broad ring subtraction logic | Currently the snippet treats Broad = AffectedDevices (overlap with Pilot/Early is benign for additive ops, but adds noise) |
| Sub-page (>999) ring member fetch | Add `@odata.nextLink` follow loop in steps 5/6 |
| `syncDevice` nudge per device for sub-hour SLAs | Snippet relies on natural sync; nudge is one extra Graph call per device, optional |

---

## References

- [Logic App snippet (commercial)](../commercial/KEV-Remediate-Win32-Snippet.json)
- [Logic App snippet (gov)](../gov/KEV-Remediate-Win32-Snippet.gov.json)
- [Mapping JSON schema](Win32-App-Mapping.json)
- [Mapping host Bicep](mapping-host-storage.bicep)
- [Win32 packaging guide](win32-packaging/README.md)
- [Microsoft: Intune throttling limits](https://learn.microsoft.com/graph/throttling-limits#intune-service-limits)
- [Microsoft: Graph $batch](https://learn.microsoft.com/graph/json-batching)
- [Microsoft: Intune device sync intervals](https://learn.microsoft.com/intune/device-configuration/troubleshoot-device-profiles#policy-refresh-intervals)
