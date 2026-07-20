# `tvm-data-ingest/`

Pulls MDE Vulnerability Management data into Sentinel as `MDETVM_CL`.

## Folder layout

```
shared/        Cloud-agnostic verifier + alerting templates
commercial/    Azure Commercial deployable templates
gcc/           GCC (Moderate) deployable templates
gcc-high/      GCC High / DoD deployable templates
```

## Pick your cloud

GCC is a **hybrid**: it uses the commercial identity/Azure plane but the gov
Defender data plane. Choose the folder that matches your tenant:

| Tier | Identity / `Connect-AzAccount` | Graph | Defender API | DCR / Monitor audience |
|---|---|---|---|---|
| Commercial | `AzureCloud` | `graph.microsoft.com` | `api.securitycenter.microsoft.com` | `monitor.azure.com` |
| **GCC** | `AzureCloud` | `graph.microsoft.com` | **`api-gcc.securitycenter.microsoft.us`** | `monitor.azure.com` |
| GCC High / DoD | `AzureUSGovernment` | `graph.microsoft.us` | `api-gov.securitycenter.microsoft.us` | `monitor.azure.us` |

Source: [Defender for Endpoint for US Government customers](https://learn.microsoft.com/en-us/defender-endpoint/gov#api).

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

### `gcc/`
| File | Purpose |
|---|---|
| `MDETVM-LogicApp.gcc.json` | GCC (Moderate) Logic App. Defender API `api-gcc.securitycenter.microsoft.us`, DCR audience `monitor.azure.com`, cross-RG workspace support |
| `Assign-MDVMPermissions.gcc.ps1` | GCC perms script: connects to **Azure Commercial** (`AzureCloud`), `graph.microsoft.com` |

### `gcc-high/`
| File | Purpose |
|---|---|
| `MDETVM-LogicApp.gcc-high.json` | GCC High / DoD Logic App. Defender API `api-gov.securitycenter.microsoft.us`, DCR audience `monitor.azure.us`, cross-RG workspace support |
| `Assign-MDVMPermissions.gcc-high.ps1` | GCC High / DoD perms script: `AzureUSGovernment` env, `graph.microsoft.us` |

## Deployment order

1. Deploy `<cloud>/MDETVM-LogicApp.<cloud>.json` (creates Logic App, DCR, custom table)
2. Run `<cloud>/Assign-MDVMPermissions.<cloud>.ps1` to grant permissions
3. Manually trigger the Logic App once
4. Run `shared/Verify-MDVMTables.kql` in Sentinel Logs - expect rows within 10-15 min

> `<cloud>` is `commercial`, `gcc`, or `gcc-high`. The commercial files have no
> cloud suffix (`MDETVM-LogicApp.json` / `Assign-MDVMPermissions.ps1`).

> **Redeploying resets the managed identity.** The Logic App uses a system-assigned
> MI. Deleting/redeploying the app - or toggling its identity off/on - generates a
> **new** principal ID and orphans the role assignments. **Re-run the permissions
> script after any redeploy.**

## Permissions

**The MI needs** (granted by the script):

- `Vulnerability.Read.All` on WindowsDefenderATP - for the Defender pull (`Get_MDVM_Page`)
- `Monitoring Metrics Publisher` on the **DCR** - for the ingestion write (`Send_Batch_To_DCR`)

**Whoever runs the script needs:**

- To grant the DCR role: **Owner**, **User Access Administrator**, or **Role Based
  Access Control Administrator** on the DCR (or a parent scope). **Contributor cannot
  assign roles** - the grant silently fails.
- To grant the Defender app role: a directory role with app-role-assignment rights
  (**Privileged Role Administrator** or **Global Administrator**).

> Grant the DCR role at the **DCR scope** - it's the tightest scope that works.
> Subscription/RG scope also work by inheritance but aren't required.

## Troubleshooting

Open the failed run: **Logic App -> Run history -> expand `Page_Loop`**. The action
that fails and its error code tell you the layer.

| Symptom | Error | Cause | Fix |
|---|---|---|---|
| `Send_Batch_To_DCR` fails | **AADSTS500011** "resource principal not found" | `audience` is set to the DCR endpoint URL instead of the Monitor resource ID | Set `audience` to `monitor.azure.com` (commercial/GCC) or `monitor.azure.us` (GCC High). It is NOT the endpoint URL. |
| `Send_Batch_To_DCR` fails | **403** "token provided does not have access to ingest" | MI lacks **Monitoring Metrics Publisher** on the DCR | Assign the role (see Permissions); allow up to 30 min to propagate, then start a fresh run |
| `Get_MDVM_Page` fails | **403** / **AADSTS** | MI lacks **Vulnerability.Read.All** on WindowsDefenderATP | Re-run the permissions script (needs a directory admin) |
| Run hangs 30+ min | - | An HTTP action is retrying a failing auth call inside the `Until` loops | Cancel, fix the underlying auth/RBAC issue, start a fresh run |
| Run succeeds, no data | - | Ingestion latency, or transformation/schema mismatch | Wait 10-15 min; check `MDETVM_CL` and the DCR transform |

> **`uri` vs `audience` (managed identity HTTP calls)**
> - `uri` = where the request is sent (the DCR ingestion endpoint hostname)
> - `audience` = the resource the MI requests a token *for* (`monitor.azure.com` / `monitor.azure.us`)
>
> Never put the DCR endpoint URL in `audience` - it's not an app identity and causes AADSTS500011.

> **AADSTS500011 vs 403** are different layers:
> - **AADSTS500011** = token never issued (audience / resource-app problem) - *authentication*
> - **403** = token issued fine, but lacks permission - *authorization (RBAC)*

> Verify the **published** definition from CLI, not the portal editor (Standard Logic
> Apps have a draft/active split):
>
> ```
> az rest --method get \
>   --uri ".../workflows/<name>?api-version=2019-05-01" \
>   --query "properties.definition.actions.Page_Loop.actions.Send_Page_Batched.actions.Send_Batch_To_DCR.inputs.authentication.audience"
> ```
