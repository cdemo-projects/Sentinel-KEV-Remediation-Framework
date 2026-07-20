# Incident-Triggered Remediation  ·  *Sentinel*

**What it does:** The original Sentinel **playbook** — triggered by a CISA-KEV incident from `../../sentinel-analytics/` — that dispatches two remediation paths in one Logic App: **WUfB expedite** (Windows KBs, Path A) and **Win32** (third-party, Path B), plus incident auto-close.

| File | Role |
|---|---|
| `commercial\|gcc\|gcc-high/KEV-Remediate-LogicApp*.json` | The playbook (WUfB + Win32 paths combined) |
| `…/AutoClose-KEVIncidents-LogicApp*.json` | Auto-close resolved KEV incidents |
| `…/Assign-KEVRemediatePermissions*.ps1` | Managed-identity grants |
| `KEV-Remediate-AutomationRule.json` | Sentinel automation rule: incident → playbook |

**Builds on** the TVM→Sentinel foundation. The two approaches it runs are documented in `../wufb-expedite/` and `../win32-static/`.
