# Concurrent-incident locking pattern (Phase 6 design)

## Problem

Two Sentinel incidents fire within seconds of each other for the **same Intune app** (e.g., two different KEV CVEs for 7-Zip). Two Logic App runs start in parallel. Both try to:

1. Add overlapping device sets to `AAD-KEV-AppPatch-7Zip` (idempotent, harmless)
2. Wait 24 hr
3. Poll install state (returns same data, harmless)
4. **Cleanup: remove devices from group when CveRows == 0** &mdash; here's where it breaks

Run A might delete a device that Run B still needs in the group because Run B's CVE hasn't cleared yet. Race condition.

## Solution: per-app lease in Azure Storage Tables

Cheap, gov-supported, no extra infrastructure beyond the Storage account already provisioned for the mapping JSON.

### Storage table schema

```
Table: KEVAppLeases
PartitionKey: appKey               (e.g., "7zip")
RowKey:       "active"             (one active lease per app)
Properties:
  HolderRunId:   <Logic App run ID>
  AcquiredAt:    <UTC timestamp>
  ExpiresAt:     <UTC timestamp, AcquiredAt + max ring delay + buffer>
  CveIds:        <comma-separated list of CVEs included in this lease>
  Etag:          <auto-managed by Storage for optimistic concurrency>
```

### Acquire-lease logic (start of Logic App run)

```
GET KEVAppLeases/<appKey>/active
IF row exists AND ExpiresAt > now:
    APPEND new CveId to CveIds list
    PATCH the row (with If-Match etag)
    Continue as a "joined" run -- skip the cleanup at end
ELSE:
    INSERT or REPLACE the row with HolderRunId = my-run-id
    Continue as the "lead" run -- responsible for cleanup
```

### Release-lease logic (end of Logic App run, after CveRows == 0)

```
GET KEVAppLeases/<appKey>/active
IF HolderRunId == my-run-id:
    Cleanup: remove devices from group, DELETE the lease row
ELSE:
    My run was a joiner; do not cleanup. Lead run will handle it.
```

### Why Storage tables (not Cosmos, not Service Bus, not blob lease)

| Option | Verdict |
|---|---|
| **Storage tables** | Cheap (~$0.01/mo at this volume), simple, Etag-based optimistic concurrency, gov-supported. **Pick this.** |
| Blob lease | Works but blob leases auto-renew which complicates "joined run" logic |
| Cosmos | Overkill, expensive |
| Service Bus session | Wrong tool; we want state, not messaging |

## What still goes wrong (acceptable)

- **Joined run still adds devices to the group.** Idempotent, fine.
- **Joined run still polls install state.** Wasted Graph calls, fine.
- **Joined run still posts audit rows.** That's actually what we want &mdash; both CVEs need their own audit trail.
- **Lease expires while a slow run is still in progress.** Set ExpiresAt = AcquiredAt + (defaultPilotToEarlyHours + defaultEarlyToBroadHours + 24h buffer). Logic App refreshes the lease at each wave checkpoint.

## Implementation when we get to it

1. Add Storage table provisioning to `mapping-host-storage.bicep`
2. Add Storage Table Data Contributor RBAC for the Logic App MI
3. Add lease acquire/refresh/release Scope blocks at start and end of Path_B_Win32_App_Assignment
4. Estimated build: **half a day** including testing

## Why we're deferring this

For initial customer pilot at one site with KEV-velocity SLAs of hours-to-days, the race condition is theoretical. The cleanup logic in v2 of the snippet doesn't even exist yet (cleanup is a planned wave-4 action). When we add cleanup, we add the lease at the same time. Two birds, one PR.
