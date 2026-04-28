# 🔐 Tenant-Level Hardening

Most security hardening is now **baked into the base templates** in `kev-remediation/` and the analytics rules in `sentinel-analytics/`. Anyone who runs the standard Quick Start gets:

- Incident-source validation in the KEV-Remediate Logic App
- Two-snapshot logic in the AutoClose Logic App
- ReadOnly resource locks on both Logic Apps
- Diagnostic settings sending Logic App run history to Sentinel
- Four detection analytics rules (deploy disabled by default)

The two scripts in this folder cover **tenant-level controls** that ARM templates cannot apply automatically.

## What's In This Folder

| Script | Required? | What It Does |
|---|---|---|
| `Lock-MailSendScope.ps1` | **Required for prod** | Creates a dedicated shared mailbox + Exchange Application Access Policy that restricts the Logic App's `Mail.Send` permission to ONE mailbox instead of tenant-wide |
| `Move-TeamsWebhookToKeyVault.ps1` | Optional | Moves the Teams webhook URL from a Logic App SecureString parameter into Azure Key Vault. Only run if you use Teams notifications. |

## Why These Aren't Auto-Deployed

| Script | Why Manual |
|---|---|
| `Lock-MailSendScope.ps1` | Touches Exchange Online (different API/permission model than Azure ARM). Requires Exchange Administrator role. |
| `Move-TeamsWebhookToKeyVault.ps1` | Needs the actual webhook URL value (which doesn't exist at template-deploy time) AND requires RG Owner to grant the MI Key Vault RBAC. |

## Order of Operations

After running the base Quick Start (Options 1+2+3 from the root README):

```powershell
# 1. Required: lock down Mail.Send scope (Exchange Admin)
.\Lock-MailSendScope.ps1 -TenantDomain "<your-tenant-domain>"

# 2. Optional: move webhook to Key Vault (RG Owner, only if using Teams)
.\Move-TeamsWebhookToKeyVault.ps1 `
  -ResourceGroupName "<your-rg>" `
  -KeyVaultName "<unique-kv-name>"
```

That's it. Three commands total to deploy the framework end-to-end with full hardening:

1. Quick Start Options 1+2+3 (resources + analytics + remediation, all hardened by default)
2. `Lock-MailSendScope.ps1` (Exchange Admin, one-time)
3. `Move-TeamsWebhookToKeyVault.ps1` (RG Owner, optional)

## What Changed From the Earlier Pack

Earlier versions of this folder had 5 fix scripts + 4 detection rule files. They've been refactored:

| Item | Where It Lives Now |
|---|---|
| Resource locks + diagnostic settings | Built into the Logic App ARM templates in `kev-remediation/` |
| Incident source validation | Built into `KEV-Remediate-LogicApp.json` as `Validate_Incident_Source` action |
| Two-snapshot AutoClose logic | Built into `AutoClose-KEVIncidents-LogicApp.json` query |
| 4 detection analytics rules | Moved to `sentinel-analytics/Detect-*.json` |

This means **nothing manual is required for the resource-layer hardening** — it ships with every deployment now.
