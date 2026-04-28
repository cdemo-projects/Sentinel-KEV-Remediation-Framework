# Sentinel KEV Remediation Framework — Deployment Guide

## Big Picture

You're deploying two things:

1. **MDETVM Logic App** — A daily-scheduled Logic App that calls the MDE Defender API, handles API pagination, and writes all vulnerability-by-device records into the `MDETVM_CL` custom table in your Sentinel Log Analytics workspace.
2. **CISA KEV Analytics Rule** — A Sentinel scheduled analytics rule that joins `MDETVM_CL` against the live [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and creates a Sentinel incident whenever a device in your environment has a CVE recently added to the KEV catalog.

**Environment:** GCC  
**Source:** [Cyberlorians MDETVM Playbook](https://github.com/Cyberlorians/Articles/blob/main/TVMIngestion.md)

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Azure Subscription** | GCC subscription |
| **Sentinel Workspace** | Log Analytics workspace with Microsoft Sentinel enabled |
| **Permissions** | Owner on the resource group + Global Admin (or Application Admin) in Entra ID |
| **Defender for Endpoint** | MDE license with Threat & Vulnerability Management (TVM) active |

---

## Step 1: Deploy the Logic App

### Option A: Azure Portal (custom template)

1. Go to **Azure Portal** → search **"Deploy a custom template"**
2. Click **"Build your own template in the editor"**
3. Paste the full contents of [MDETVM-LogicApp.json](MDETVM-LogicApp.json) and click **Save**
4. Set:
   - **Subscription** → your GCC subscription
   - **Resource Group** → same RG as your Sentinel workspace (recommended)
   - **Playbook Name** → `MDETVM` (default)
5. Click **Review + Create** → **Create**

### Option B: Azure CLI

```powershell
az deployment group create `
  --name "mdetvm-logicapp-deploy" `
  --resource-group "<YOUR-RG>" `
  --template-file "MDETVM-LogicApp.json"
```

### What gets deployed

| Resource | Purpose |
|---|---|
| **Logic App** (`MDETVM`) | Daily scheduler — calls MDE API, handles pagination, sends data to Sentinel |
| **System Assigned Managed Identity** | Auth identity for the Defender API call (shares the Logic App name) |
| **API Connection** (`Azureloganalyticsdatacollector-MDETVM`) | Connection to the Log Analytics HTTP Data Collector endpoint |

---

## Step 2: Authorize the API Connection

The ARM template creates the Log Analytics API connection but it needs your workspace credentials before it will work.

1. Open the deployed **Logic App** in the Azure Portal
2. In the left blade, click **API connections**
3. Click **`Azureloganalyticsdatacollector-MDETVM`**
4. Click **Edit API connection**
5. Enter:
   - **Workspace ID** — found in Sentinel/Log Analytics → **Agents** blade
   - **Workspace Key** — the Primary Key from the same Agents blade
6. Click **Save** — the connection should show **Connected**

---

## Step 3: Assign Defender API Permissions

The Logic App needs `Vulnerability.Read.All` on `WindowsDefenderATP`. The ARM template enables the managed identity but can't grant API permissions automatically.

**Run the script:** [Assign-MDVMPermissions.ps1](Assign-MDVMPermissions.ps1)

```powershell
.\Assign-MDVMPermissions.ps1 `
  -TenantId "<YOUR-TENANT-ID>" `
  -ResourceGroupName "<YOUR-RG>" `
  -LogicAppName "MDETVM"
```

**Requires:** Global Admin or Application Administrator in Entra ID.

This script:
- Reads the Logic App resource to get its System Assigned Managed Identity principal ID
- Finds the `WindowsDefenderATP` service principal (AppId: `fc780465-2017-40d4-a0c5-307022471b92`)
- Assigns `Vulnerability.Read.All` via the Microsoft Graph API

---

## Step 4: Trigger the First Data Pull

The Logic App runs automatically at **02:00 UTC daily**. To pull data immediately:

1. **Portal** → Open the **MDETVM** Logic App
2. Click **Run Trigger** → **Recurrence**
3. Watch the run history — first run may take 5–20 minutes depending on environment size

Or via CLI:

```powershell
az logic workflow trigger run `
  --resource-group "<YOUR-RG>" `
  --name "MDETVM" `
  --trigger-name "Recurrence"
```

**Pagination note:** The Logic App uses an `Until` loop checking `@odata.nextLink` to pull all pages from the API. The original Cyberlorians playbook only pulls the first page — this version captures everything.

---

## Step 5: Verify Data in MDETVM_CL

Wait 10–15 minutes after the first run, then run this in **Sentinel → Logs**:

```kql
MDETVM_CL
| summarize
    TotalRecords = count(),
    Devices = dcount(deviceName_s),
    UniqueCVEs = dcount(cveId_s),
    MostRecent = max(TimeGenerated)
```

Expect `Devices > 0` and `UniqueCVEs > 0`. If the table doesn't exist, the Logic App hasn't run successfully — check the **Logic App run history** for errors (HTTP 403 = permissions issue from Step 3).

More verification queries: [Verify-MDVMTables.kql](Verify-MDVMTables.kql)

---

## Step 6: Deploy the CISA KEV Analytics Rule

### Option A: Import via Portal

1. **Sentinel** → **Analytics** → **Import** (top bar)
2. Select [CISA-KEV-MDVM-AnalyticsRule.json](CISA-KEV-MDVM-AnalyticsRule.json)
3. When prompted, enter your **workspace name**
4. Review and click **Create**

### Option B: Deploy via CLI

```powershell
az deployment group create `
  --name "cisa-kev-analytics-rule" `
  --resource-group "<YOUR-RG>" `
  --template-file "CISA-KEV-MDVM-AnalyticsRule.json" `
  --parameters workspace="<YOUR-WORKSPACE-NAME>"
```

### What the rule does

| Setting | Value |
|---|---|
| **Name** | CISA KEV Detected on Device — MDVM |
| **Severity** | High |
| **Frequency** | Runs every 1 hour |
| **Lookback** | 1 day of MDETVM_CL data |
| **Trigger** | CVEs added to the CISA KEV catalog in the last 24 hours that match a device in MDETVM_CL |
| **Dedup** | Checks `SecurityIncident` table to avoid re-firing on the same CVE+device |
| **Entity** | CVE ID mapped for SOAR/response actions |

**Test before enabling:** Run Query 5 in [Verify-MDVMTables.kql](Verify-MDVMTables.kql). If it returns rows, your analytics rule will generate incidents when enabled.

---

## Files in This Folder

| File | What It Does |
|---|---|
| [MDETVM-LogicApp.json](MDETVM-LogicApp.json) | ARM template for the Logic App (GCC, paginated) — **deploy this** |
| [Assign-MDVMPermissions.ps1](Assign-MDVMPermissions.ps1) | Grants the Logic App managed identity `Vulnerability.Read.All` |
| [CISA-KEV-MDVM-AnalyticsRule.json](CISA-KEV-MDVM-AnalyticsRule.json) | Sentinel analytics rule ARM template |
| [CISA-KEV-MDVM-Correlation.kql](CISA-KEV-MDVM-Correlation.kql) | KQL query options for CISA KEV correlation (testing + hunting) |
| [Verify-MDVMTables.kql](Verify-MDVMTables.kql) | Post-deployment verification queries |
| [DEPLOY-GUIDE.md](DEPLOY-GUIDE.md) | This guide |
| [azureDeploy-modified.json](azureDeploy-modified.json) | *(Alternative)* Full Function App connector — richer data (6 tables), more infra |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| **API connection shows "Unauthorized"** | Re-do Step 2. Workspace ID must be the GUID, not the workspace name |
| **Logic App runs but MDETVM_CL is empty** | Confirm `Vulnerability.Read.All` was assigned (Step 3). Check run history for HTTP 403 on the HTTP_Get_Page step |
| **Logic App stuck in Until loop** | Check that `api-gcc.securitycenter.microsoft.us` is reachable. Look at the Set_NextLink step — if it's always getting a nextLink, the API may be returning errors on later pages |
| **Analytics rule fires no alerts** | The `NewKEVs` filter only matches CVEs added to the catalog in the last 24 hours. Use Option B in `CISA-KEV-MDVM-Correlation.kql` to confirm the join works against the full catalog |
| **Duplicate incidents** | The rule includes a `SecurityIncident` dedup check. If still duplicating, increase the suppression window in the rule settings |
| **GCC API 404 errors** | Verify the HTTP action URI is exactly `https://api-gcc.securitycenter.microsoft.us/api/machines/SoftwareVulnerabilitiesByMachine` |

---

## Key Concepts

- **Data freshness:** The Logic App pulls a full snapshot daily. Use `| where TimeGenerated > ago(1d)` to get today's snapshot only — without that filter you'll see duplicate CVE+device rows across multiple days.
- **Field naming:** `MDETVM_CL` was created by the legacy HTTP Data Collector API. Fields use type suffixes: `_s` (string), `_d` (double/number), `_b` (boolean). Example: `cveId` → `cveId_s`, `cvssScore` → `cvssScore_d`.
- **GCC endpoints:** Commercial = `api.securitycenter.microsoft.com` | GCC = `api-gcc.securitycenter.microsoft.us` | GCCH = `api-gov.securitycenter.microsoft.us`
- **CISA KEV CSV columns:** `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`
