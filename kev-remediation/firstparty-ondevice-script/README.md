# 1st-Party On-Device Script  ·  *POC / lab*

**What it does:** An Intune Remediation (deviceHealthScript) that runs **native updaters on the device** for Microsoft 1st-party apps (Defender / Office / Edge / Windows).

> ⚠️ **Caveat:** this approach depends on each device reaching vendor/update endpoints, so it's **blocked by egress firewalls** — which is exactly why the `../eac-autoupdate/` path (content delivered via `*.manage.microsoft.com`) was built. Kept here as POC/lab reference.

| File | Role |
|---|---|
| `scripts/Detect-FirstPartyUpdates.ps1`, `Remediate-FirstPartyUpdates.ps1` | Detect / update logic (toggle per component) |
| `scripts/New-Remediation.ps1`, `Invoke-Wiring.ps1`, `Grant-GraphPermissions.ps1` | Create + wire the Intune Remediation, grant MI |
| `infra/` | Consumption Logic App (on-demand proactive remediation) |
| `workflow/workflow.json` | The remediation workflow |
