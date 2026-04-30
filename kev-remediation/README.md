# `kev-remediation/`

Automation that consumes KEV-flagged CVEs from MDETVM_CL and pushes patches.

## Folder layout

```
shared/         Cloud-agnostic assets (Sentinel automation rule, Intune baseline,
                Win32 packaging guide + mapping table, remediation verifier)
commercial/    Azure Commercial deployable templates and permissions scripts
gov/           Azure US Government deployable templates and permissions scripts
```

## What's in each

### `shared/`
| File | Purpose |
|---|---|
| `Setup-IntuneBaseline.ps1` | Bootstrap Intune scaffolding (groups, rings, IME) |
| `Intune-KEV-Starter-Policy.md` | Reference policy values for Intune-only customers |
| `KEV-Remediate-AutomationRule.json` | Sentinel automation rule template (cloud-agnostic) |
| `Win32-App-Mapping.json` | CVE -> Intune app GUID lookup the Logic App reads at runtime |
| `Package-Win32App-Guide.md` | Admin runbook: package vendor MSI/EXE as `.intunewin` |
| `Verify-Remediation.ps1` | Post-deployment verifier (queries `MDETVM_CL` for CveRows == 0) |

### `commercial/`
| File | Purpose |
|---|---|
| `KEV-Remediate-LogicApp.json` | Main remediation Logic App (commercial endpoints) |
| `KEV-Remediate-Win32-Snippet.json` | Drop-in Path_B scope: assigns Win32 apps via Graph |
| `AutoClose-KEVIncidents-LogicApp.json` | Auto-closes Sentinel incidents once `CveRows == 0` |
| `Assign-KEVRemediatePermissions.ps1` | Grants the MI its Graph + workspace + Entra roles |

### `gov/`
| File | Purpose |
|---|---|
| `KEV-Remediate-LogicApp.gov.json` | Same as commercial, with GCC endpoints (`graph.microsoft.us`, `monitor.azure.us`) |
| `KEV-Remediate-Win32-Snippet.gov.json` | Drop-in Path_B scope for gov |
| `AutoClose-KEVIncidents-LogicApp.gov.json` | Gov variant of incident closer |
| `Assign-KEVRemediatePermissions.gov.ps1` | Gov perms script: `AzureUSGovernment` env, `graph.microsoft.us`, includes `DeviceManagementApps.ReadWrite.All` |

## Deployment order

1. `shared/Setup-IntuneBaseline.ps1` (one time, both clouds)
2. `<cloud>/KEV-Remediate-LogicApp.<gov.>json` -> deploy via portal or `az deployment group create`
3. `<cloud>/Assign-KEVRemediatePermissions[.gov].ps1`
4. Package apps per `shared/Package-Win32App-Guide.md` and add GUIDs to `shared/Win32-App-Mapping.json`
5. Patch the Logic App's Path_B scope with `<cloud>/KEV-Remediate-Win32-Snippet[.gov].json`
6. Deploy `<cloud>/AutoClose-KEVIncidents-LogicApp[.gov].json`
7. Deploy `shared/KEV-Remediate-AutomationRule.json` (binds the Sentinel rule to the Logic Apps)

Lab-only POC scripts (public-internet WinGet path) live under [../_archive-remediation-poc/](../_archive-remediation-poc/) for reference only.
