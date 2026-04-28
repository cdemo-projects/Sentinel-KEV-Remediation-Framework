# Sentinel KEV Remediation Framework

Modular solution for detecting and remediating [CISA Known Exploited Vulnerabilities (KEVs)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) using Microsoft Defender Vulnerability Management (MDVM), Microsoft Sentinel, and Intune/WUfB.

**Each component is independent.** Deploy only what you need:

| Component | What it does | Requires |
|---|---|---|
| **TVM Data Ingest** | Daily pipeline: MDE API → `MDETVM_CL` custom table in Sentinel | Sentinel, MDE P2 |
| **Sentinel Analytics** | KQL rule correlates `MDETVM_CL` against CISA KEV catalog → incidents | TVM Data Ingest |
| **Sentinel Workbooks** | Visual dashboards for KEV exposure and remediation tracking | TVM Data Ingest |
| **KEV Remediation** | SOAR playbook: auto-remediate via WUfB (Windows KBs) or Intune (third-party) | Sentinel Analytics + Intune |

---

## Architecture

### Pipeline 1 · Data Ingest

![Pipeline 1 - Data Ingest](docs/pipeline-1-ingest.png)

---

### Pipeline 2 · KEV Detection

![Pipeline 2 - KEV Detection](docs/pipeline-2-detection.png)

---

### Pipeline 3 · Automated Remediation

![Pipeline 3 - Automated Remediation](docs/pipeline-3-remediation.png)

---

## Repo Layout

```text
Sentinel-KEV-Remediation-Framework/
├── README.md
├── DEPLOY-GUIDE.md
├── LICENSE
│
├── tvm-data-ingest/                 ← Daily data pipeline (independent)
│   ├── MDETVM-LogicApp.json
│   ├── MDETVM-LogicApp.gov.json
│   ├── Assign-MDVMPermissions.ps1
│   ├── Verify-MDVMTables.kql
│   └── Pipeline-Health-Alerts.json
│
├── sentinel-analytics/              ← KEV detection rules (requires tvm-data-ingest)
│   ├── CISA-KEV-MDVM-Correlation.kql
│   ├── CISA-KEV-MDVM-AnalyticsRule.json
│   └── KEV-Exceptions-Watchlist.json
│
├── sentinel-workbooks/              ← Dashboards (requires tvm-data-ingest)
│   ├── MDETVM-KEV-Workbook.json
│   └── KEV-Workbook-GalleryTemplate.json
│
└── kev-remediation/                 ← Automated remediation (requires sentinel-analytics)
    ├── KEV-Remediate-LogicApp.json
    ├── KEV-Remediate-AutomationRule.json
    ├── Assign-KEVRemediatePermissions.ps1
    ├── Patch-ThirdPartyApprovalPath.ps1
    ├── Update-KEVRemediateThirdPartyPath.ps1
    ├── Verify-Remediation.ps1
    ├── Setup-IntuneBaseline.ps1
    ├── Intune-KEV-Starter-Policy.md
    ├── AutoClose-KEVIncidents-LogicApp.json
    └── AutoClose-KEVIncidents-LogicApp.gov.json
```

---

## Quick Start

### Option 1: Just the workbook (visibility only)

```powershell
# Deploy the data pipeline
az deployment group create -g <rg> `
  --template-file tvm-data-ingest/MDETVM-LogicApp.json `
  --parameters PlaybookName=MDETVM WorkspaceName=<ws>

# Grant permissions
./tvm-data-ingest/Assign-MDVMPermissions.ps1 `
  -TenantId <tenant> -ResourceGroupName <rg> -WorkspaceName <ws> -PlaybookName MDETVM

# Deploy workbook
az deployment group create -g <rg> `
  --template-file sentinel-workbooks/MDETVM-KEV-Workbook.json `
  --parameters workspaceId=<workspace-resource-id>
```

### Option 2: Detection + incidents (add alerting)

```powershell
# After Option 1, add the analytics rule
az deployment group create -g <rg> `
  --template-file sentinel-analytics/CISA-KEV-MDVM-AnalyticsRule.json `
  --parameters workspace=<ws>
```

### Option 3: Full automation (add remediation)

```powershell
# After Option 2, deploy the remediation playbook
az deployment group create -g <rg> `
  --template-file kev-remediation/KEV-Remediate-LogicApp.json `
  --parameters WorkspaceName=<ws> GraphApiBase=https://graph.microsoft.com

# Grant permissions (includes Intune + WUfB roles)
./kev-remediation/Assign-KEVRemediatePermissions.ps1 `
  -ResourceGroupName <rg> -WorkspaceName <ws>

# Wire incidents to the playbook
az deployment group create -g <rg> `
  --template-file kev-remediation/KEV-Remediate-AutomationRule.json `
  --parameters WorkspaceName=<ws> PlaybookResourceId=<logic-app-resource-id>
```

> **Intune baseline:** If the tenant doesn't have Intune update rings or MDM enrollment configured, see [Intune-KEV-Starter-Policy.md](kev-remediation/Intune-KEV-Starter-Policy.md).

---

## About `MDETVM_CL`

`MDETVM_CL` is a single custom Sentinel table containing data from two native Defender tables:

| Native Table | What it provides |
|---|---|
| `DeviceTvmSoftwareVulnerabilities` | CVEs per device, software info, recommended KB |
| `DeviceTvmSoftwareVulnerabilitiesKB` | CVSS score, exploit availability, severity level |

The MDE REST API returns this data flattened — no joins needed in Sentinel KQL.

---

## How Patching Actually Works

This framework only **automates a slice** of patching. Most updates are still delivered by Intune / Windows Update for Business (WUfB) on their normal cadence. This section spells out exactly what this project does, what it doesn't do, and what your tenant must already have configured for the rest.

### What this framework does

| Update type | What this framework does | Underlying mechanism |
|---|---|---|
| **Windows quality updates (KBs)** | Expedites the KB to affected devices when a KEV is detected | Graph `windowsUpdates/deploymentAudiences` → `expedite` ([docs](https://learn.microsoft.com/graph/windowsupdates-deploy-expedited-update)) |
| **Third-party apps (Intune-managed)** ⚠️ *Lab/POC only* | Triggers an on-demand proactive remediation script that downloads the vendor installer and runs it silently | Graph `deviceManagement/managedDevices/{id}/initiateOnDemandProactiveRemediation` |
| **Third-party apps (MECM-managed)** | Sends an email + Teams notification with the CVE, devices, and required version. No automated push | Manual hand-off |

> ⚠️ **The third-party Intune path is a reference implementation for non-prod environments only.** It pulls vendor installers from the public internet, which is not appropriate for production or government tenants. For prod, pair this framework with **Intune Win32 apps + supersedence** or **MECM application deployment** for third-party patching. See the *Known gaps* table below for details.

### What this framework does **not** do

| Update type | Why not | Where it actually gets handled |
|---|---|---|
| **Windows feature updates** (e.g., 23H2 → 24H2) | No expedite API exists for feature updates ([Autopatch capabilities table](https://learn.microsoft.com/graph/windowsupdates-concept-overview#capabilities-of-windows-autopatch)) | Intune **Feature update policy** ([docs](https://learn.microsoft.com/intune/device-updates/windows/)) |
| **Driver / firmware updates** | No expedite API exists for drivers (same capabilities table) | Intune **Windows driver update policy** ([docs](https://learn.microsoft.com/intune/device-updates/windows/manage-driver-updates)) |
| **Microsoft 365 Apps (Office)** | Office uses Click-to-Run channels, not Windows Update | M365 Apps **update channels** + Office Deployment Tool / Cloud Update / Config Mgr ([docs](https://learn.microsoft.com/microsoft-365-apps/updates/overview-update-channels)) |
| **Microsoft Edge** | Edge has its own updater (auto-updates by default) | Allow Edge to self-update **OR** manage via Autopatch / Edge Update policies ([docs](https://learn.microsoft.com/deployedge/microsoft-edge-update-policies)) |
| **.NET Framework / Visual C++ runtimes** | These ride on Windows monthly cumulative updates | Already covered by your **Quality update ring** |
| **Win32 LOB / non-Intune-managed apps** | No standard install method to call | Package as Win32 app with **supersedence** ([docs](https://learn.microsoft.com/intune/app-management/deployment/add-win32)) |

### Why a KEV can still be detected after Intune rings have done their job

- **Detection runs daily.** A device must check in, install the KB, and report back to MDE before MDVM stops flagging it. There's normally a 24–72 hour window where a KEV looks "open" even though the patch is already on the way.
- **Patch may exist in the catalog before your ring deploys it.** Quality update rings ship in waves (pilot → broad). Devices in a later wave still show the CVE until their wave runs.
- **Ring deferral may exceed CISA due date.** CISA gives ~21 days for KEVs. If your broad ring is deferred 14 days plus a 7-day deadline, you'll miss the window for some devices unless you expedite — which is exactly what this framework does.

### Configuration required per update type

Before the framework can do its job, your tenant should already be set up for the categories below. None of this is created by the framework.

| Update type | Required config | Where it lives |
|---|---|---|
| **Windows quality updates** | Update ring with `Allow Microsoft product updates = Allow` so .NET / Defender platform updates flow with the OS | Intune → Devices → Windows → Update rings |
| **Windows feature updates** | Feature update policy pinned to the target version | Intune → Devices → Windows → Feature updates |
| **Drivers / firmware** | Driver update policy (auto-approve recommended drivers, deferral 0–30 days) ([docs](https://learn.microsoft.com/intune/device-updates/windows/configure-driver-update-policy)) | Intune → Devices → Windows → Driver updates |
| **Microsoft 365 Apps** | Update channel (Current / Monthly Enterprise / Semi-Annual) configured via ODT, Cloud Update, or Config Mgr ([docs](https://learn.microsoft.com/microsoft-365-apps/updates/configure-update-settings-microsoft-365-apps)) | Office Deployment Tool / M365 admin center / ConfigMgr |
| **Microsoft Edge** | Either leave Edge auto-update on (default) **or** turn on Autopatch Edge updates per Autopatch group ([docs](https://learn.microsoft.com/windows/deployment/windows-autopatch/manage/windows-autopatch-edge)) | Edge Update policies / Intune → Tenant Admin → Windows Autopatch |
| **Third-party apps (Intune)** | Devices Intune-MDM-enrolled + Intune Management Extension installed; vendor installers reachable from device | Intune → Devices |
| **Third-party apps (MECM)** | Standard ConfigMgr application + supersedence rules | Configuration Manager |

### Known gaps in this framework

| Gap | Impact | How to fix it |
|---|---|---|
| **Third-party path requires Intune MDM enrollment** | MECM-only or unmanaged devices fall back to email notification | Stand up co-management or move workloads to Intune. For pure MECM shops, build an Automatic Deployment Rule that subscribes to the email notifications and pushes the third-party patch via standard ConfigMgr application deployment. |
| **Third-party installer path is lab/POC only** (`Update-KEVRemediateThirdPartyPath.ps1` has hard-coded vendor URLs) | Built to demo the SOAR pattern in a test tenant. Pulling installers from the public internet on every device is not appropriate for prod, especially gov | **Don't use this path in gov.** Have the Logic App **notify** the Intune / MECM team instead, then push third-party patches via **Intune Win32 apps with supersedence** ([docs](https://learn.microsoft.com/intune/app-management/deployment/add-win32)) or **MECM application deployment**. Both handle versioning, retries, and rollback natively. |
| **Email sender uses `Mail.Send` application permission** | Tenant-wide impersonation if not scoped | **Required:** lock down with an [Exchange Application Access Policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access) targeting a mail-enabled security group that contains only the approved sender address. See the *Permissions* section below for the PowerShell snippet. |
| **No automatic rollback if a deployment breaks a device** | Bad KB or installer requires help desk to manually clean up | **Use a pilot ring** in Intune (small canary group) before broad deployment. Let the Logic App expedite to the pilot ring first; broad ring follows on its normal cadence. If the pilot fires alerts, pause the analytics rule before the broad ring picks it up. For driver-related issues, use Intune's **Pause** action on the driver update policy ([docs](https://learn.microsoft.com/intune/device-updates/windows/configure-driver-update-policy)). |
| **Office, Edge, drivers, and feature updates are not triggered by this framework** | Those CVEs stay open until their normal Intune policy runs | Configure the policies in the *Configuration required per update type* table above. Specifically: turn on `Allow Microsoft product updates` in update rings, configure M365 Apps update channel via ODT or Cloud Update, leave Edge auto-update on (or use Autopatch), and create a Windows driver update policy. |

### Microsoft Learn references

- [Deploy expedited quality updates via Graph](https://learn.microsoft.com/graph/windowsupdates-deploy-expedited-update)
- [Capabilities of Windows Autopatch (expedite supports quality only)](https://learn.microsoft.com/graph/windowsupdates-concept-overview#capabilities-of-windows-autopatch)
- [Windows update management overview (Intune)](https://learn.microsoft.com/intune/device-updates/windows/)
- [Manage Windows driver updates](https://learn.microsoft.com/intune/device-updates/windows/manage-driver-updates)
- [Configure update settings for Microsoft 365 Apps](https://learn.microsoft.com/microsoft-365-apps/updates/configure-update-settings-microsoft-365-apps)
- [Microsoft 365 Apps update channels](https://learn.microsoft.com/microsoft-365-apps/updates/overview-update-channels)
- [Microsoft Edge update policies](https://learn.microsoft.com/deployedge/microsoft-edge-update-policies)
- [Windows Autopatch — Microsoft Edge updates](https://learn.microsoft.com/windows/deployment/windows-autopatch/manage/windows-autopatch-edge)
- [Add a Win32 app to Intune (with supersedence)](https://learn.microsoft.com/intune/app-management/deployment/add-win32)

---

## Prerequisites

| Requirement | Component |
|---|---|
| Azure subscription (Commercial, GCC, or GCC High) | All |
| Sentinel workspace | tvm-data-ingest, sentinel-analytics, sentinel-workbooks, kev-remediation |
| Defender for Endpoint P2 with MDVM | All |
| Windows E3/E5 | kev-remediation (WUfB path) |
| Intune Plan 1 + Entra ID P1/P2 | kev-remediation (third-party path) |
| Az CLI | Deployment |

---

## Permissions

| Component | Identity | Permission | Scope |
|---|---|---|---|
| tvm-data-ingest | Logic App MI | `Vulnerability.Read.All` | WindowsDefenderATP |
| tvm-data-ingest | Logic App MI | `Monitoring Metrics Publisher` | DCR resource |
| sentinel-workbooks | User/group | `Microsoft Sentinel Reader` | Workspace RG |
| kev-remediation | Logic App MI | `Microsoft Sentinel Responder` | Workspace |
| kev-remediation | Logic App MI | `Log Analytics Reader` | Workspace |
| kev-remediation | Logic App MI | `WindowsUpdates.ReadWrite.All` | Graph API |
| kev-remediation | Logic App MI | `Device.Read.All` | Graph API |
| kev-remediation | Logic App MI | `DeviceManagementManagedDevices.Read.All` | Graph API |
| kev-remediation | Logic App MI | `DeviceManagementManagedDevices.PrivilegedOperations.All` | Graph API |
| kev-remediation | Logic App MI | `DeviceManagementScripts.ReadWrite.All` | Graph API |
| kev-remediation | Logic App MI | `Mail.Send` | Graph API ||

> **Security note on `Mail.Send`:** This application permission allows the managed identity to send email as **any user** in the tenant. Scope it down with an Exchange Application Access Policy:
> ```powershell
> New-ApplicationAccessPolicy -AppId <logic-app-mi-app-id> \
>   -PolicyScopeGroupId <mail-security-group> \
>   -AccessRight RestrictAccess \
>   -Description "Restrict KEV-Remediate to send from approved address only"
> ```
> Create a mail-enabled security group containing only the approved sender address.

| kev-remediation | Logic App MI | `Windows Update Deployment Administrator` | Entra role |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `RequestEntityTooLarge` in Logic App | Batch >1 MB | Lower `BatchSize` variable |
| `MDETVM_CL` empty after 204 | Schema lag | Wait 15-30 min; check DCR diagnostics |
| `403 Missing application roles` | MI token cache | Recycle MI identity, re-grant roles |
| Intune remediation stays `pending` | IME not installed | Assign IME bootstrap script to device group |
| `initiateOnDemandProactiveRemediation` 404 | Device not MDM-managed | Enroll device into Intune MDM |
| Detection finds no updates | Packages already current | Check registry versions on device |
| No `MdmUrl` after enrollment | User not in MDM scope | Add user to auto-enrollment group |
| WUfB expedited deployment no effect | Device not Entra joined | Device must be Entra joined or hybrid joined |

---

## Cloud Support

| Cloud | Graph API base | MDE API base | Notes |
|---|---|---|---|
| Commercial | `https://graph.microsoft.com` | `https://api.securitycenter.microsoft.com` | Default |
| GCC | `https://graph.microsoft.com` | `https://api-gcc.securitycenter.microsoft.us` | Same Graph base |
| GCC High | `https://graph.microsoft.us` | `https://api-gov.securitycenter.microsoft.us` | Different Graph base |

---

## Credits

- **[Cyberlorians](https://github.com/Cyberlorians)** — Original MDETVM Logic App and TVM-to-Sentinel ingestion concept
- **[Matt Zorich / kqlquery.com](https://kqlquery.com)** — CISA KEV correlation pattern using `externaldata()`
