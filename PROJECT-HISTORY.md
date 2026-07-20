# Project History & Context — Sentinel KEV Remediation Framework

> Read this first if you're picking up the project cold (human or AI). It captures what this is,
> how it evolved, the design decisions, the most recent changes, the current layout, and the gotchas.
> Last updated: 2026-06-26.

---

## 1. What this project is

Automation to detect and **automatically remediate CISA Known Exploited Vulnerabilities (KEVs)** across
a Microsoft-managed device fleet, using Microsoft Defender Vulnerability Management (MDVM), Microsoft
Sentinel, Microsoft Intune, and Windows Update for Business (WUfB). Lives in `mdvm-cisa-connector/`.

## 2. How it evolved (the layers, oldest → newest)

| Layer | Folder(s) | Summary |
|---|---|---|
| **Foundation — TVM into Sentinel** *(where it started)* | `tvm-data-ingest/` | Daily pipeline: MDE API → `MDETVM_CL` custom Sentinel table (via DCR / Logs Ingestion). |
| **KEV detection** | `sentinel-analytics/`, `sentinel-workbooks/` | KQL correlates `MDETVM_CL` against the CISA KEV catalog → incidents + dashboards. |
| **KEV auto-remediation** *(what it grew into)* | `kev-remediation/` | Multiple remediation approaches — each in its own labeled folder. |
| **Hardening** | `security/` | Mail.Send scoping, Key Vault, etc. |

The project **started** as "get TVM data into Sentinel" and **evolved** into "automatically remediate KEVs."
Keep the foundation (`tvm-data-ingest/`, `sentinel-analytics/`, `sentinel-workbooks/`) intact — it's load-bearing.

## 3. The remediation approaches (`kev-remediation/`)

Each approach is a labeled folder with its own `README.md`:

| Folder | Approach | Sentinel? |
|---|---|---|
| `incident-triggered/` | Original Sentinel **playbook** — WUfB expedite (Path A) + Win32 (Path B), incident-driven | Yes |
| `wufb-expedite/` | Expedite Windows **quality updates (KBs)** *(label; logic lives in incident-triggered Path A)* | Yes |
| `win32-static/` | Assign a **version-pinned Win32** app to affected devices (admin repackages per version) | either |
| `eac-autoupdate/` | **EAC auto-update** — add exposed device to an Enterprise App Catalog *auto-update* app's group; **API-direct, no Sentinel** | No |
| `firstparty-ondevice-script/` | Intune Remediation **script** running native updaters (Defender/Office/Edge/Windows) — POC | No |
| `fallback-ticketing/` | **ServiceNow ticket + Intune task** fallback when a KEV can't be auto-remediated | building block |
| `_shared/` | Cross-cutting plumbing: ring groups, audit table, mapping host, Intune baseline, operator runbook | shared |

## 4. Key design decisions & rationale

- **EAC auto-update is the headline remediation mechanism.** It adds an exposed device to a
  `windowsAutoUpdateCatalogApp` (Enterprise App Catalog *auto-update* app) group; IME installs the latest
  catalog version from `*.manage.microsoft.com`. **Firewall-safe** — no device→vendor-CDN egress (the
  reason the on-device-script and Edge-updater paths were dropped for locked-down/gov fleets).
- **Edge is NOT in the Enterprise App Catalog** — it's a Windows Autopatch workload. Don't try to remediate
  Edge via EAC; use Autopatch / Edge's own channels / Win32 MSI / Connected Cache.
- **API-direct correlation (no Sentinel) for the EAC path.** The CISA KEV catalog is a public JSON feed;
  correlation = exposed CVEs (from Defender `SoftwareVulnerabilityChangesByMachine`) ∩ KEV list. Done in the
  Logic App, so this path doesn't depend on the `MDETVM_CL`/Sentinel foundation. (The incident-triggered
  path *does* depend on Sentinel.)
- **Eager pre-staging, not lazy.** Catalog apps + `KEV-Remediate-<app>` groups + Required assignments are
  created **once** by `Onboard-EacAutoUpdateApp.ps1`; the runtime only manages **group membership**. This
  keeps the runtime managed identity at **least privilege** (no app/group create rights).
- **Device targeting translation.** MDVM identifies a device by its MDE machine id (no Entra id). Chain:
  MDE `DeviceId` → `GET /api/machines/{id}.aadDeviceId` → Graph `GET /devices?$filter=deviceId eq '{aad}'`
  → directory object id → `POST /groups/{id}/members/$ref`. Only Entra-joined devices have `aadDeviceId`;
  others fall to the ticket+email fallback.
- **Fallback = ServiceNow ticket + email** (not a Sentinel incident — the customer is moving away from
  Sentinel *alerts* for KEV). Fires when software has no EAC mapping, is excluded, isn't in the catalog,
  or the device isn't Entra-resolvable.
- **Prioritization (score + CISA deadline)** is computed per exposure (ransomware + exploitability + CVSS +
  CISA `dueDate`) and surfaced on the fallback tickets/emails (`[EXPEDITE]`). **Phasing/waves are built but
  paused** — every matched device is admitted immediately; true priority-sequencing of patching = phasing
  (waves across runs), which is the seam left for later. Within-run ordering wouldn't help because installs
  are async/IME-driven.
- **GCC is a hybrid.** Commercial identity / Graph / Azure plane, but the **gov Defender API**:
  - Commercial: Defender `api.securitycenter.microsoft.com`, Graph `graph.microsoft.com`
  - GCC: Defender `api-gcc.securitycenter.microsoft.us`, Graph `graph.microsoft.com`
  - GCC High/DoD: Defender `api-gov.securitycenter.microsoft.us`, Graph `graph.microsoft.us`
- **Versioning discipline:** never mutate a live deployed resource in place — deploy a versioned successor
  and keep the prior version until validated. Logic Apps here ship `state: Disabled`.

## 5. Change log — June 2026 (this body of work)

1. **Built the EAC auto-update solution** into `kev-remediation/eac-autoupdate/`:
   - `commercial/` + `gcc/` scheduled orchestrator Logic Apps (CISA∩MDVM → EAC group-add **or**
     ServiceNow+email fallback; score + CISA-deadline prioritization).
   - `shared/`: `eac-apps.json` (app registry + fallback policy), `Onboard-EacAutoUpdateApp.ps1`
     (pre-stage catalog app + group + assignment), `Assign-KEVEacPermissions.ps1` (runtime MI least-priv).
2. **Added the commercial ServiceNow ticket Logic App** (`KEV-ServiceNow-v1.json`) — gcc/gcc-high already existed.
3. **Consolidated a separate `kev-patch-automation/` prototype folder into the connector:** its 1st-party
   on-device script became `firstparty-ondevice-script/`; the EAC prototypes (which duplicated the connector
   work) were deleted; the empty folder was removed.
4. **Reorganized `kev-remediation/` by approach** (was per-cloud `commercial/gcc/gcc-high/shared`): now
   `incident-triggered/`, `wufb-expedite/`, `win32-static/`, `eac-autoupdate/`, `firstparty-ondevice-script/`,
   `fallback-ticketing/` (renamed from `notify/`), `_shared/` — each with a README label.
5. **Moved the KEV-ServiceNow integration guide** in from `servicenow-integrations/kev-ticketing-guides/`
   → `fallback-ticketing/`.
6. **Moved misplaced bidirectional-sync diagrams** (`runbook-assets/diagram-*` = forward/reverse/loopguard/
   roles/architecture/dayplan) **out** of `_shared/` → `servicenow-integrations/general-sentinel-defender-sync/`
   (they document the general Sentinel↔ServiceNow sync, not KEV).
7. **Cleaned 76 gitignored scratch/raw-export files** from the connector root (root now: `.gitignore`,
   `LICENSE`, `README.md`, `sentinel-kev-framework.html`, `PROJECT-HISTORY.md` + solution folders).

> The general **bidirectional Sentinel↔ServiceNow sync** solution lives separately under
> `../servicenow-integrations/general-sentinel-defender-sync/` — it is **not** part of this connector.

## 6. Outstanding / next steps & validation caveats

- **Live validation needs a properly licensed tenant** (not yet done): Enterprise App Management / Intune
  Suite (for `windowsAutoUpdateCatalogApp` create), MDVM, and a real ServiceNow instance + Key Vault secret.
- **`windowsAutoUpdateCatalogApp` create caveat:** `mobileAppCatalogPackageBranchId` is documented Read-Only
  yet appears in the create example — validate on first run; fall back to the `createCatalogApp` action or
  the Intune portal if rejected. Run `Onboard-EacAutoUpdateApp.ps1 -DumpCatalog` to align product names + branch ids.
- **Hand-authored Logic Apps** — open them once in the Designer to confirm they round-trip before relying on them.
- **Phasing/waves** are paused (admit-all). Un-pausing = score-sorted, batched-wave admission across runs
  (needs a pre-pass sort; Logic Apps can't sort inline).
- **Fallback granularity** is currently one ticket+email per (device × CVE); batching per CVE is a refinement.
- **EAC = third-party catalog apps only.** Map what your fleet actually runs; unmatched software → fallback.

## 7. Gotchas / conventions for the next AI or engineer

- **Verify every Microsoft claim on Microsoft Learn before stating it** (product behavior, endpoints, API
  shapes, permission names, GCC/GCC High parity). This is a hard project rule.
- **This workspace's terminal mangles multi-line pasted PowerShell** — write a script file and run it with
  `pwsh -NoProfile -File <script>` instead of pasting big blocks.
- **`mv` is a built-in PowerShell alias for `Move-Item`** — don't name a helper function `Mv` (the alias wins
  and silently calls Move-Item). Use a distinct name (e.g., `Relocate`).
- **Never commit secrets or tenant data.** `.gitignore` already excludes `_*` scratch, `KEV-Remediate-backup/
    planned-*.json` raw exports (they contain real tenant/subscription/group IDs), `.notes/`, `conversations/`.
- **Well-known public service-principal app IDs** used by the grant scripts: Microsoft Graph
  `00000003-0000-0000-c000-000000000000`, WindowsDefenderATP `fc780465-2017-40d4-a0c5-307022471b92`.
- **Runtime MI least-priv (EAC path):** `Vulnerability.Read.All`, `Machine.Read.All` (Defender);
  `Device.Read.All`, `GroupMember.ReadWrite.All`, `Mail.Send` (Graph). App/group **create** rights live only
  in the admin-run onboarding, never on the runtime identity.

---

*Drafting assistance: Claude Opus 4.8 (via GitHub Copilot), grounded in official Microsoft Learn documentation.*
