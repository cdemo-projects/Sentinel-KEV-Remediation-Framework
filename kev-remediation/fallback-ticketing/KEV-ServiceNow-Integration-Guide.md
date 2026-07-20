# KEV → ServiceNow Ticketing Integration Guide

**Purpose:** Automatically create a ServiceNow ticket when a CISA Known Exploited Vulnerability (KEV) is detected on managed devices, so a SOC analyst or Intune administrator knows to patch the affected software.

**Drafting assistance:** Claude Opus 4.8 (via GitHub Copilot), grounded in official Microsoft Learn documentation
**Last updated:** 2026-06-12

---

## 1. What this integration does

This is a **notification workflow**, not an auto-remediation workflow. When the pipeline finds a KEV-listed CVE on a device, it creates a ServiceNow incident containing the CVE, affected application, device count, remediation guidance, and a link back to the Microsoft Defender portal. A human then performs the patching.

```
MDETVM Logic App        →  Pulls MDVM vulnerability data into MDETVM_CL (Log Analytics)
        │
Trigger logic           →  Detects KEV matches (scheduled query against MDETVM_CL)
        │
KEV-ServiceNow Logic App →  HTTP POST to ServiceNow Table API (Basic Auth)
        │
ServiceNow              →  Incident created and routed to the assignment group
```

### Important scope note: self-resolution

- **Microsoft Defender Vulnerability Management (MDVM)** is the source of truth for whether a vulnerability exists. A CVE clears from the Defender **Vulnerabilities / Weaknesses** page automatically once the device is patched and the sensor rescans. This self-resolution happens natively in Defender.
- The **ServiceNow ticket does NOT self-resolve.** Closing a ticket does not update Defender, and Defender clearing a CVE does not close the ticket. The ticket is a work-tracking artifact and is managed in ServiceNow.

---

## 2. Architecture: how ServiceNow is called

The Logic App talks to ServiceNow with a plain **HTTP POST to the ServiceNow REST Table API** — it does **not** depend on the managed ServiceNow connector. The key actions are:

1. **Trigger** — HTTP Request trigger, called with a JSON payload (`cveId`, `appName`, `appVersion`, `managedDeviceCount`, etc.)
2. **Compose ticket body** — builds the ServiceNow incident fields (short description, description, urgency/impact/priority, assignment group, custom `u_*` fields)
3. **Create ServiceNow ticket** — HTTP `POST` to `{instanceUrl}/api/now/table/{table}` using **Basic Auth** (service account username + password)
4. **Response** — returns the HTTP status and ServiceNow response (runs on both success and failure so errors surface)

### Is the managed ServiceNow connector available in GCC?

Yes. Per the [ServiceNow connector reference](https://learn.microsoft.com/connectors/service-now/), the Logic Apps ServiceNow connector is available in **all Logic Apps regions except US Department of Defense (DoD)** — so **GCC and GCC High are supported**.

**However**, Microsoft's own guidance notes that the connector supports only `service-now.com` instance URLs, and **for GCC instances on alternative domains, Basic Authentication is recommended** (Known Issues #3 on the connector page). This implementation uses **HTTP + Basic Auth**, which works in GCC, GCC High, and DoD regardless of the connector's region availability, and sidesteps the domain limitation entirely.

---

## 3. Azure Key Vault: protecting the ServiceNow password

The ServiceNow service-account password must be stored in **Azure Key Vault**, not hardcoded in the Logic App. Key Vault is a secure secret store; the Logic App reads the password at runtime through its managed identity.

### How Key Vault protects the credential (verified, Microsoft Learn)

| Layer | Protection | Source |
|---|---|---|
| Encryption at rest | Secrets encrypted by a key hierarchy protected by FIPS-validated modules (Standard = FIPS 140-2 Level 1; Premium = FIPS 140-3 Level 3 HSM) | [About Key Vault secrets](https://learn.microsoft.com/azure/key-vault/secrets/about-secrets), [About Key Vault](https://learn.microsoft.com/azure/key-vault/general/overview) |
| Encryption in transit | All access over HTTPS/TLS | [Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide) |
| Identity + authorization | Microsoft Entra authentication + RBAC (least privilege) | [Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide) |
| No plaintext in the app | Workflow holds only a reference; the secret is never in the definition or config | — |
| Soft delete + purge protection | Deleted secrets recoverable 7-90 days; purge protection cannot be overridden, even by Microsoft | [Soft-delete overview](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview) |
| Audit logging | Every secret access is logged | — |

> **Production requirement:** the password parameter must hold a true **Key Vault reference**, not a plaintext value. If deployed with a plaintext password (demo mode), none of the protections above apply.

---

## 4. Roles required

### Azure side (verified against Microsoft Learn)

| Who / what | Role | Scope | Purpose | Source |
|---|---|---|---|---|
| Deployer | **Logic Apps Standard Contributor** (or **Logic App Contributor** for Consumption) | Resource group | Create / edit the playbook | [Automate threat response with playbooks](https://learn.microsoft.com/azure/sentinel/automation/automate-responses-with-playbooks#prerequisites) |
| Deployer | **Contributor** | Resource group | Deploy the Logic App + Key Vault | [Steps to assign an Azure role](https://learn.microsoft.com/azure/role-based-access-control/role-assignments-steps#step-2-select-the-appropriate-role) |
| Logic App managed identity | **Key Vault Secrets User** | The Key Vault (or RG) | Read the ServiceNow password at runtime (RBAC permission model) | [Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide) |
| Deployer (to grant the role above) | **Owner** or **User Access Administrator** | Key Vault / RG | Create the role assignment | [Steps to assign an Azure role](https://learn.microsoft.com/azure/role-based-access-control/role-assignments-steps#step-4-check-your-prerequisites) |

> If the trigger is a **Sentinel automation rule** instead of a scheduled query, also assign **Microsoft Sentinel Contributor** (to attach the playbook) and grant the Sentinel service account **Microsoft Sentinel Automation Contributor** on the playbook's resource group ([source](https://learn.microsoft.com/azure/sentinel/automation/run-playbooks#prerequisites)). The scheduled-query approach used here does not require these.

### ServiceNow side (confirm with your ServiceNow administrator)

| Item | Requirement |
|---|---|
| Service account | Dedicated, active, non-MFA (Basic Auth requires username/password) |
| Role | Create access on the target table. For the standard `incident` table, the **`itil`** role is the common grant. SecOps (`sn_si_incident`) or Vulnerability Response (`sn_vul_vulnerable_item`) require the corresponding module role. *(ServiceNow is not a Microsoft product — the exact minimum role is governed by your instance's ACL model and must be confirmed by your ServiceNow admin.)* |
| API access | Permission to call the REST [Table API](https://learn.microsoft.com/connectors/service-now/) (`/api/now/table/{table}`) |
| Schema | Custom fields (`u_cve_id`, `u_app_name`, `u_app_version`, `u_affected_count`, `u_source`, `u_kev_listed`) must exist on the target table |
| Assignment group | The group the tickets route to (e.g., "Endpoint Engineering") must exist |

### Network

- Outbound **HTTPS (443)** from the Logic App to the ServiceNow instance must be permitted.

---

## 5. Implementation steps

1. **Provision Key Vault** and store the ServiceNow service-account password as a secret.
2. **Deploy the Logic App** (`Deploy-KEVServiceNow.<cloud>.ps1`) with the ServiceNow instance URL, table, service-account username, and a **Key Vault reference** for the password.
3. **Grant the Logic App managed identity** the **Key Vault Secrets User** role on the vault.
4. **Configure the trigger** — a scheduled Logic App that queries `MDETVM_CL` for KEV matches and calls the ServiceNow playbook. (Include de-duplication so the same CVE/device does not generate repeated tickets.)
5. **Test safely** — point the instance URL at a `webhook.site` collector first to inspect the payload without touching production ServiceNow, then switch to the real instance.

---

## 6. Protective measures built in

| Pitfall | Protection |
|---|---|
| Ticket flood from every vulnerability | KEV-only scoping (only CISA KEV-listed CVEs trigger) |
| Duplicate tickets for the same CVE/device | De-duplication logic (90-day lookback) — must be carried into the trigger if using a scheduled query |
| Tickets for accepted-risk items | Exception watchlist filtering |
| Plaintext credentials | Key Vault reference for the password |
| Over-privileged identity | Dedicated ServiceNow service account; least-privilege Azure roles |
| Silent failures | Response action runs on both success and failure, returning the HTTP status |
| Risky testing against production | `webhook.site` demo mode |

---

## 7. Sources

All Microsoft claims in this guide were verified against Microsoft Learn:

- [Automate threat response with playbooks in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/automation/automate-responses-with-playbooks#prerequisites)
- [Automate and run Microsoft Sentinel playbooks](https://learn.microsoft.com/azure/sentinel/automation/run-playbooks#prerequisites)
- [Roles and permissions in the Microsoft Sentinel platform](https://learn.microsoft.com/azure/sentinel/roles#built-in-azure-roles-for-microsoft-sentinel)
- [Steps to assign an Azure role](https://learn.microsoft.com/azure/role-based-access-control/role-assignments-steps)
- [Provide access to Key Vault with Azure RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [About Azure Key Vault secrets](https://learn.microsoft.com/azure/key-vault/secrets/about-secrets)
- [About Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/overview)
- [Azure Key Vault soft-delete overview](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)
- [ServiceNow connector reference (availability + Basic Auth guidance for GCC)](https://learn.microsoft.com/connectors/service-now/)
- [Microsoft Defender Vulnerability Management — Vulnerabilities / Weaknesses](https://learn.microsoft.com/defender-vulnerability-management/tvm-weaknesses)

> The ServiceNow `itil` role is a ServiceNow product role, not a Microsoft role, and is therefore not citable from Microsoft Learn. Confirm the minimum required role with your ServiceNow administrator against your instance's ACL configuration.
