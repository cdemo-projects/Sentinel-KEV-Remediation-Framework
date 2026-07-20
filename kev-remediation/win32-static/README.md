# Win32 Static App Assignment

**What it does:** Remediates third-party KEVs by assigning a **pre-packaged, version-pinned** Intune Win32 app to affected devices. An admin repackages each new version (supersedence).

| File | Role |
|---|---|
| `commercial\|gcc\|gcc-high/KEV-Remediate-Win32-Snippet*.json` | Drop-in Logic App scope (assigns the app to affected devices) |
| `Win32-App-Mapping.json` | CVE → Intune app GUID lookup + ring strategy |
| `Onboard-AppToFramework.ps1` | Onboard a Win32 app + patch group to the framework |
| `Package-Win32App-Guide.md`, `Patch-KEVRemediate-Win32.ps1`, `win32-packaging/` | Packaging runbook + tooling |

**Contrast:** `../eac-autoupdate/` auto-tracks the latest catalog version (no manual repackaging); this path pins a specific version.
