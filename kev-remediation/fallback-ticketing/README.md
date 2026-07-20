# Fallback Ticketing  ·  *building blocks*

**What it does:** HTTP-callable Logic Apps that raise a **ServiceNow ticket** or an **Intune security task** when a KEV **can't be auto-remediated** — the fallback for both `../eac-autoupdate/` and `../incident-triggered/`.

| File | Role |
|---|---|
| `commercial\|gcc\|gcc-high/KEV-ServiceNow-v1*.json` | ServiceNow ticket creator (Table API) |
| `gcc\|gcc-high/KEV-IntuneTask-v1*.json` | Intune security task creator |
| `…/Deploy-*`, `…/Test-*` | Deploy + test helpers |
| `KEV-ServiceNow-Integration-Guide.md/.docx` | Integration guide (moved in from `servicenow-integrations/`) |
