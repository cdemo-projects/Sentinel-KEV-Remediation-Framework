# 🔐 Security Hardening Pack

Production hardening for the Sentinel KEV Remediation Framework. Each fix here addresses a specific risk identified during security review.

## Risk → Fix Mapping

| Risk | Fix | File |
|---|---|---|
| Tenant-wide impersonation via `Mail.Send` | Exchange Application Access Policy scoped to one mailbox | [`Lock-MailSendScope.ps1`](Lock-MailSendScope.ps1) |
| Logic App definition tampering | Resource lock + diagnostic settings | [`Lock-KEVRemediateResources.ps1`](Lock-KEVRemediateResources.ps1) |
| Teams webhook URL exposure | Move webhook to Key Vault, reference from Logic App | [`Move-TeamsWebhookToKeyVault.ps1`](Move-TeamsWebhookToKeyVault.ps1) |
| Forged Sentinel incident → unauthorized expedite | Validate incident source rule ID inside Logic App | [`Patch-IncidentSourceValidation.ps1`](Patch-IncidentSourceValidation.ps1) |
| Auto-close on a single noisy snapshot | Require two consecutive clean snapshots | [`Patch-AutoCloseTwoSnapshots.ps1`](Patch-AutoCloseTwoSnapshots.ps1) |
| Logic App definition changes go unnoticed | Sentinel rule on `Microsoft.Logic/workflows/write` | [`Detect-LogicAppDefinitionChange.json`](Detect-LogicAppDefinitionChange.json) |
| Compromised MI silently closes incidents | Sentinel rule on incidents closed by the MI | [`Detect-MIClosedIncident.json`](Detect-MIClosedIncident.json) |
| Watchlist suppression abuse | Sentinel rule on watchlist row changes | [`Detect-WatchlistChange.json`](Detect-WatchlistChange.json) |
| KEV-Remediate failures unnoticed | Sentinel rule on Logic App run failures | [`Detect-KEVRemediateFailure.json`](Detect-KEVRemediateFailure.json) |

## Apply Order

1. Run `Lock-MailSendScope.ps1` (immediate, no dependencies)
2. Run `Lock-KEVRemediateResources.ps1` (resource lock + diagnostic settings → Sentinel)
3. Run `Move-TeamsWebhookToKeyVault.ps1` (optional but recommended)
4. Run `Patch-IncidentSourceValidation.ps1` against the live KEV-Remediate Logic App
5. Run `Patch-AutoCloseTwoSnapshots.ps1` against the live AutoClose Logic App
6. Deploy the four `Detect-*.json` analytics rules

## Why These and Not Others

The hardening pack focuses on **technical controls inside Azure**. It does NOT cover:

- **Tenant-wide RBAC review** (who can edit Sentinel incidents, who has Logic App Contributor) — handle in your IAM governance process
- **Mirroring CISA KEV catalog locally** — recommended for air-gapped scenarios; not implemented here because most environments accept the dependency on `cisa.gov`
- **Setup-IntuneBaseline.ps1 review** — the script uses interactive device-code auth and grants only baseline configurations; reviewed and clean
