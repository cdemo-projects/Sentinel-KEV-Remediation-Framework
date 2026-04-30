# `tvm-data-ingest/`

Pulls MDE Vulnerability Management data into Sentinel as `MDETVM_CL`.

## Folder layout

```
shared/         Cloud-agnostic verifier + alerting templates
commercial/    Azure Commercial deployable templates
gov/           Azure US Government deployable templates
```

## What's in each

### `shared/`
| File | Purpose |
|---|---|
| `Verify-MDVMTables.kql` | Sanity check: row counts, distinct devices/CVEs, freshness |
| `Pipeline-Health-Alerts.json` | Sentinel alerts for stalled ingestion |

### `commercial/`
| File | Purpose |
|---|---|
| `MDETVM-LogicApp.json` | Logic App that pulls MDVM REST API and writes to DCR (commercial endpoints) |
| `Assign-MDVMPermissions.ps1` | Grants MI `Vulnerability.Read.All` on WindowsDefenderATP + `Monitoring Metrics Publisher` on the DCR |

### `gov/`
| File | Purpose |
|---|---|
| `MDETVM-LogicApp.gov.json` | Same as commercial, with GCC endpoints (`api-gov.securitycenter.microsoft.us`, `monitor.azure.us`) and cross-RG workspace support |
| `Assign-MDVMPermissions.gov.ps1` | Gov perms script: `AzureUSGovernment` env, `graph.microsoft.us` |

## Deployment order

1. Deploy `<cloud>/MDETVM-LogicApp[.gov].json` (creates Logic App, DCR, custom table)
2. Run `<cloud>/Assign-MDVMPermissions[.gov].ps1` to grant permissions
3. Manually trigger the Logic App once
4. Run `shared/Verify-MDVMTables.kql` in Sentinel Logs - expect rows within 10-15 min
