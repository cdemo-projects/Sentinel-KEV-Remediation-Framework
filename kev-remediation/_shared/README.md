# `_shared/` — cross-cutting assets

**Not a remediation approach.** Shared tooling, infrastructure, and docs used by **multiple** approaches in `kev-remediation/`. (The `_` prefix sorts it to the top and marks it as shared.)

| File | Purpose |
|---|---|
| `Setup-KEVRingGroups.ps1` | One-time: create the 3 universal ring groups (Pilot/Early/Broad) in Entra |
| `Setup-IntuneBaseline.ps1`, `Intune-KEV-Starter-Policy.md` | Bootstrap Intune scaffolding for tenants that don't have it yet |
| `mapping-host-storage.bicep`, `Deploy-MappingHost.ps1` | Azure Storage that hosts `Win32-App-Mapping.json`; grants the Logic App MI Storage Blob Data Reader |
| `audit-table.bicep`, `audit-table-customtable.bicep`, `Deploy-AuditTable.ps1` | Sentinel audit custom table (`KEVRemediation_CL`) + DCR/DCE |
| `Verify-Remediation.ps1` | Post-deployment verifier (queries `MDETVM_CL` for `CveRows == 0`) |
| `concurrent-lock-design.md` | Design: per-app lease to prevent concurrent-incident races |
| `OperatorRunbook.md` | End-to-end operator playbook (tenant setup, day-2 ops, failure scenarios) |

**Used by:** `incident-triggered/` and `win32-static/` (rings, mapping host, audit), and available to the other approaches.
