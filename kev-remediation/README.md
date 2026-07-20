# `kev-remediation/`

Automatically remediate CISA **Known Exploited Vulnerabilities (KEVs)** on affected devices. The project began as TVM→Sentinel ingest (see `../tvm-data-ingest/`, `../sentinel-analytics/`, `../sentinel-workbooks/`) and evolved into the remediation approaches below — each in its own labeled folder.

## Solutions (pick the approach that fits)

| Folder | Approach | Layer |
|---|---|---|
| [`incident-triggered/`](incident-triggered/) | Sentinel **playbook** — WUfB expedite (Path A) + Win32 (Path B), incident-driven | Sentinel-dependent |
| [`wufb-expedite/`](wufb-expedite/) | Expedite Windows **quality updates (KBs)** | *(label; logic in incident-triggered Path A)* |
| [`win32-static/`](win32-static/) | Assign a **version-pinned Win32** app to affected devices | either |
| [`eac-autoupdate/`](eac-autoupdate/) | **EAC auto-update** — add exposed device to an Enterprise App Catalog auto-update group; **API-direct (no Sentinel)** | API-direct |
| [`firstparty-ondevice-script/`](firstparty-ondevice-script/) | Intune Remediation **script** running native updaters (Defender/Office/Edge/Windows) — POC | API-direct |
| [`fallback-ticketing/`](fallback-ticketing/) | **ServiceNow ticket** + **Intune task** fallback when a KEV can't be auto-remediated | building block |
| [`_shared/`](_shared/) | Cross-cutting: ring groups, audit table, mapping host, Intune baseline, operator runbook | shared |

Each folder has its own `README.md`. Day-2 operations: [`_shared/OperatorRunbook.md`](_shared/OperatorRunbook.md).

## Pick your cloud

**GCC is a hybrid** — commercial identity / Graph / Azure plane, but the **gov Defender API**. That's why it's distinct from GCC High.

| Plane | Commercial | GCC (Moderate) | GCC High / DoD |
|---|---|---|---|
| `Connect-AzAccount` env | `AzureCloud` | `AzureCloud` | `AzureUSGovernment` |
| Microsoft Graph | `graph.microsoft.com` | `graph.microsoft.com` | `graph.microsoft.us` |
| Defender API | `api.securitycenter.microsoft.com` | `api-gcc.securitycenter.microsoft.us` | `api-gov.securitycenter.microsoft.us` |
| Log Analytics | `api.loganalytics.io` | `api.loganalytics.io` | `api.loganalytics.us` |
| Security portal | `security.microsoft.com` | `security.microsoft.com` | `security.microsoft.us` (DoD `security.apps.mil`) |

Per Microsoft Learn: [Defender for Endpoint for US Government — API](https://learn.microsoft.com/defender-endpoint/gov#api). Cloud is selected by file suffix (`none` / `.gcc` / `.gcc-high`) within each approach folder.

## ServiceNow scope boundary

- `fallback-ticketing/` ServiceNow/IntuneTask artifacts are for the **KEV exception path only** (ticket an admin when auto-remediation isn't possible). The `KEV-ServiceNow-Integration-Guide` lives here.
- **General** Sentinel/Defender ↔ ServiceNow synchronization is out of scope and stays under `../../servicenow-integrations/general-sentinel-defender-sync/`.

---

Lab-only POC scripts (public-internet WinGet path) live under [`../_archive-remediation-poc/`](../_archive-remediation-poc/) for reference only.
