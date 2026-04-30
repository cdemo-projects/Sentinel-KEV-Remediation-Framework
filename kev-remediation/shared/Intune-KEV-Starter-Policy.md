# Intune Tenant Bootstrap Baseline For KEV Remediation

Use this baseline when the tenant does not yet have the Intune foundation needed for Windows patching and remediation. This policy set is separate from the KEV remediation package. It creates the tenant scaffolding that lets Windows devices enroll into Intune, receive update rings, install the Intune Management Extension, and later run KEV remediation packages on demand.

Start with the pilot scope below, prove one Windows device works end to end, then expand into production rings.

## Prerequisites

| Requirement | Starter expectation |
| --- | --- |
| Licensing | Microsoft Intune Plan 1 for managed users/devices |
| Entra licensing | Microsoft Entra ID P1 or P2 for automatic MDM enrollment |
| Admin role | Global Administrator for automatic enrollment setup, then Intune Administrator for Intune policy work |
| Device OS | Windows Pro, Enterprise, Education, or supported IoT Enterprise |
| Network | Device can reach Intune service endpoints, Windows Update endpoints, and Windows Push Notification Service |
| Device state | Microsoft Entra joined, hybrid joined, or Entra registered and eligible for MDM enrollment |

## Groups

Create security groups in Microsoft Entra ID. Keep user groups and device groups separate.

| Group | Type | Purpose |
| --- | --- | --- |
| `Intune-Enrollment-Pilot-Users` | Assigned user group | Users allowed to enroll devices during pilot |
| `Intune-Windows-Pilot-Devices` | Assigned device group | First managed Windows devices, including `cdemo` after enrollment |
| `Intune-Windows-Broad-Devices` | Assigned or dynamic device group | Next rollout ring after pilot succeeds |
| `Intune-Windows-Update-Exclusions` | Assigned device group | Devices temporarily excluded from rings or policy tests |

Do not assign production policies to `All devices` until the pilot device is Intune-managed, syncing, and receiving the update ring.

## Policy 1: Windows Automatic MDM Enrollment

Portal path: **Intune admin center > Devices > Device onboarding > Enrollment > Windows > Automatic Enrollment**

| Setting | Pilot value |
| --- | --- |
| MDM user scope | `Some` |
| Selected groups | `Intune-Enrollment-Pilot-Users` |
| MDM terms of use URL | Default value |
| MDM discovery URL | Default value |
| MDM compliance URL | Default value |
| Disable MDM enrollment when adding work or school account | `Off` |
| WIP user scope | `None` |

This is the setting that makes Windows populate `MdmUrl` after enrollment. If the enrolling user is outside this scope, the device can be Entra-connected or MDE-visible but still not Intune MDM-managed.

## Policy 2: Windows Enrollment Restriction

Portal path: **Intune admin center > Devices > Device onboarding > Enrollment > Device platform restriction**

Create a higher-priority pilot restriction assigned to `Intune-Enrollment-Pilot-Users`.

| Setting | Pilot value |
| --- | --- |
| Name | `Windows Enrollment - KEV Pilot` |
| Priority | Higher than default |
| Platform | Windows allowed |
| Minimum OS version | Leave blank for first proof, or set tenant standard |
| Maximum OS version | Blank |
| Personally owned Windows devices | Allow for pilot only |
| Assignment | `Intune-Enrollment-Pilot-Users` |

For production, tighten this. Prefer Autopilot, corporate identifiers, Device Enrollment Manager, GPO enrollment, or co-management for corporate ownership control.

## Policy 3: Windows Update Ring - Pilot

Portal path: **Intune admin center > Devices > By platform > Windows > Manage updates > Windows updates > Update rings > Create profile**

Assign this ring to `Intune-Windows-Pilot-Devices`.

| Setting | Pilot value |
| --- | --- |
| Name | `Windows Update Ring - Pilot` |
| Microsoft product updates | Allow |
| Windows drivers | Block for first proof |
| Quality update deferral period | `0` days |
| Feature update deferral period | `30` days |
| Upgrade Windows 10 devices to latest Windows 11 release | No |
| Feature update uninstall period | `10` days |
| Automatic update behavior | Auto install at maintenance time |
| Active hours start | `08:00` |
| Active hours end | `17:00` |
| Option to pause Windows updates | Disable |
| Option to check for Windows updates | Enable |
| Change notification update level | Use default Windows Update notifications |
| Use deadline settings | Allow |
| Deadline for quality updates | `2` days |
| Deadline for feature updates | `7` days |
| Grace period | `1` day |
| Auto reboot before deadline | Yes |

This ring gives you a real Intune Windows Update for Business baseline without unexpectedly upgrading the lab VM to a new Windows release.

## Policy 4: Windows Update Ring - Broad

Create this after the pilot ring works. Assign to `Intune-Windows-Broad-Devices` and exclude `Intune-Windows-Update-Exclusions`.

| Setting | Broad value |
| --- | --- |
| Name | `Windows Update Ring - Broad` |
| Microsoft product updates | Allow |
| Windows drivers | Block, or manage through a separate driver update policy |
| Quality update deferral period | `3` days |
| Feature update deferral period | `30` days |
| Upgrade Windows 10 devices to latest Windows 11 release | No unless intentionally migrating |
| Automatic update behavior | Auto install at maintenance time |
| Active hours start | `08:00` |
| Active hours end | `17:00` |
| Option to pause Windows updates | Disable |
| Option to check for Windows updates | Enable |
| Use deadline settings | Allow |
| Deadline for quality updates | `5` days |
| Deadline for feature updates | `14` days |
| Grace period | `2` days |
| Auto reboot before deadline | Yes |

Do not assign both Pilot and Broad rings to the same device. Use one active ring per device population.

## Policy 5: Pilot Compliance Policy

Portal path: **Intune admin center > Devices > Compliance policies > Create policy > Windows 10 and later**

Assign to `Intune-Windows-Pilot-Devices`.

| Setting | Pilot value |
| --- | --- |
| Name | `Windows Compliance - Pilot` |
| Require active Microsoft Defender Antivirus | Require |
| Require real-time protection | Require |
| Require firewall | Require |
| Minimum OS version | Leave unset for first proof, then set tenant standard |
| Mark device noncompliant | After 1 day |

Avoid BitLocker, TPM, and Secure Boot requirements until the lab VM is enrolled and stable. Add those controls later if they match the device class.

## Policy 6: Intune Management Extension Bootstrap

The KEV package is not the bootstrap. Create a separate low-risk PowerShell script assignment so Intune installs the Intune Management Extension before you test on-demand remediation.

Portal path: **Intune admin center > Devices > Scripts and remediations > Platform scripts > Add > Windows 10 and later**

| Setting | Pilot value |
| --- | --- |
| Name | `IME Bootstrap - Windows Pilot` |
| Script content | `Write-Output "IME bootstrap complete"` |
| Run this script using logged-on credentials | No |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | Yes |
| Assignment | `Intune-Windows-Pilot-Devices` |

After this runs, the device should have the `IntuneManagementExtension` service. Then the KEV remediation package can be created and invoked separately.

## Setup Order

1. Confirm Intune licensing and admin roles.
2. Create the four security groups.
3. Configure Windows automatic MDM enrollment for `Intune-Enrollment-Pilot-Users`.
4. Create the Windows enrollment restriction for pilot users.
5. Create `Windows Update Ring - Pilot`.
6. Create `Windows Compliance - Pilot`.
7. Enroll `cdemo` using Settings > Accounts > Access work or school > Enroll only in device management.
8. Add the enrolled `cdemo` device object to `Intune-Windows-Pilot-Devices`.
9. Assign the IME bootstrap script and sync the device.
10. Confirm update ring and IME status before testing KEV remediation.

## Verification On `cdemo`

Run on the VM after enrollment:

```powershell
dsregcmd /status | Select-String "AzureAdJoined|WorkplaceJoined|AzureAdPrt|IsUserAzureAD|MdmUrl|MdmTouUrl|MdmComplianceUrl"
```

Expected MDM proof:

```text
MdmUrl : https://enrollment.manage.microsoft.com/...
```

Confirm Intune Management Extension:

```powershell
Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue
```

Confirm Windows Update policy landed:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -ErrorAction SilentlyContinue
```

Useful sync command:

```powershell
Start-Process "ms-settings:workplace"
```

Then select the connected work or school account and click **Info > Sync** if the Info button is available.

## If Enrollment Still Does Not Work

Pull the local enrollment errors:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 25 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message |
  Format-List
```

Most likely causes:

| Symptom | Likely cause |
| --- | --- |
| No `MdmUrl` | User not in MDM user scope, unlicensed user, or enrollment restriction blocked Windows |
| Device shows `Managed by: MDE` only | Device is MDE-discovered, not Intune MDM-managed |
| No `IntuneManagementExtension` service | No script, Win32 app, or remediation assignment has installed IME yet |
| Update ring not applying | Device not in the assigned device group, sync not complete, or conflicting update policies |

## When This Baseline Is Ready For KEV Automation

The tenant baseline is ready when the test device has all of these:

| Check | Required result |
| --- | --- |
| `dsregcmd /status` | `MdmUrl` is populated |
| Intune portal | Device is managed by Intune or co-managed, not MDE-only |
| Update ring report | Pilot ring assigned and succeeded or pending check-in |
| Local service | `IntuneManagementExtension` exists and is running |
| Device sync | Recent Intune check-in time |
| IME bootstrap | Platform script run state shows `success` |

Only after that should the KEV remediation package be tested.

## Lessons Learned

These findings came from the commercial tenant proof on `cdemo`:

| Finding | Detail |
| --- | --- |
| IME requires an assignment | IME only installs when a Win32 app, PowerShell script, or Remediation is assigned. The IME bootstrap script handles this. |
| On-demand remediation requires IME | `initiateOnDemandProactiveRemediation` fails silently if IME is not installed. Always verify IME first. |
| Remediation package must be assigned | Even if on-demand submission returns HTTP 204, Intune shows "Not deployed" unless the package is assigned to a group. |
| `runRemediationScript` flag | The Graph beta `assign` action may save `runRemediationScript=false` even when `true` is sent. Use the **Run remediation** device action from the Intune portal as a workaround. |
| Duplicate groups | Running baseline scripts multiple times can create duplicate groups with the same display name. Check for duplicates before creating. |
| Detection exit code matters | Detection exit `0` = no issue found, remediation skipped. Exit `1` = issue found, remediation runs. If the mapped packages are already current, detection exits `0` and nothing happens. |
| Token errors in IME log | `LogonUser failed with error code : 1008` and AAD token errors in the IME log are noisy but not blocking. IME continues and executes scripts after these errors. |

## Microsoft References

- Windows automatic MDM enrollment: https://learn.microsoft.com/en-us/intune/device-enrollment/windows/enable-automatic-mdm
- Intune group requirements: https://learn.microsoft.com/en-us/intune/fundamentals/tenant-administration/add-groups
- Windows update rings: https://learn.microsoft.com/en-us/intune/device-updates/windows/manage-update-rings
- Update ring settings reference: https://learn.microsoft.com/en-us/intune/device-updates/windows/ref-update-ring-settings
- Intune enrollment restrictions: https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions
- Intune Remediations prerequisites and on-demand runs: https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations