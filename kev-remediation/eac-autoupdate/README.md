# EAC Auto-Update  ·  *API-direct (no Sentinel)*

**What it does:** Automatically remediates third-party KEVs by adding each exposed device to an Enterprise App Catalog **auto-update** app's `KEV-Remediate-<app>` group. IME then installs the latest catalog version from `*.manage.microsoft.com` (firewall-safe). Correlation runs in the Logic App against the live CISA KEV feed ∩ Defender MDVM — **no Sentinel dependency**.

| File | Role |
|---|---|
| `commercial/KEV-EAC-Remediate-LogicApp.json`, `gcc/…gcc.json` | Scheduled orchestrator: CISA∩MDVM → EAC group-add **or** ServiceNow+email fallback; score + CISA-deadline prioritization |
| `shared/eac-apps.json` | App registry + fallback policy |
| `shared/Onboard-EacAutoUpdateApp.ps1` | Pre-stage the auto-update app + group + Required assignment (admin) |
| `shared/Assign-KEVEacPermissions.ps1` | Runtime managed-identity least-priv grants |

**Depends on:** `../fallback-ticketing/` (ServiceNow ticket) for the fallback path. Does **not** require the TVM→Sentinel foundation.
