# Sentinel KEV Remediation Framework

Modular solution for detecting and remediating [CISA Known Exploited Vulnerabilities (KEVs)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) using Microsoft Defender Vulnerability Management (MDVM), Microsoft Sentinel, and Intune/WUfB.

**Each component is independent.** Deploy only what you need:

| Component | What it does | Requires |
|---|---|---|
| **TVM Data Ingest** | Daily pipeline: MDE API → `MDETVM_CL` custom table in Sentinel | Sentinel, MDE P2 |
| **Sentinel Analytics** | KQL rule correlates `MDETVM_CL` against CISA KEV catalog → incidents | TVM Data Ingest |
| **Sentinel Workbooks** | Visual dashboards for KEV exposure and remediation tracking | TVM Data Ingest |
| **Defender Hunting** | Standalone Advanced Hunting queries for the Defender XDR portal | MDE P2 (no Sentinel needed) |
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

## Remediation Paths

| Path | Trigger | Action | Automation Level |
|---|---|---|---|
| **Windows KB** | CVE has a `recommendedSecurityUpdateId` | WUfB expedited deployment via Graph API | Fully automated |
| **Third-party (Intune)** | No KB, device is Intune MDM-managed | On-demand remediation: registry detection → download installer → silent install | Automated (device-gated) |
| **Third-party (MECM)** | No KB, device is MECM-managed | Notification with CVE + device list + required version | Manual deployment |

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
