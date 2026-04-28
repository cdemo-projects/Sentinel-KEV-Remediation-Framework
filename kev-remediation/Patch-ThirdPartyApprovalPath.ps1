#Requires -Version 7.0
<#
.SYNOPSIS
    Patches the live KEV-Remediate Logic App with the Teams approval-gated
    third-party remediation path (ring-based, device-routed).

.DESCRIPTION
    Replaces Path_B in the Check_KB_Exists else branch with:
    1. Find/create Intune WinGet remediation script package
    2. Classify devices by managementAgent + pilot group membership
    3. Send Teams approval card with device roster
    4. On Approve: submit on-demand remediation to pilot Intune devices
    5. Notify about MECM/unmanaged devices

    Also wires the Teams API connection into the Logic App.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId = '<subscription-id>',
    [string]$ResourceGroupName = '<resource-group>',
    [string]$WorkflowName = 'KEV-Remediate',
    [string]$TeamId = '<teams-team-id>',
    [string]$ChannelId = '<teams-channel-id>',
    [string]$PilotGroupId = '<pilot-group-id>'
)

$ErrorActionPreference = 'Stop'

az account set --subscription $SubscriptionId | Out-Null

# --- Fetch live workflow ---
Write-Host "[1/4] Fetching live workflow..." -ForegroundColor Cyan
$resource = az resource show `
    --resource-group $ResourceGroupName `
    --name $WorkflowName `
    --resource-type 'Microsoft.Logic/workflows' `
    --api-version '2019-05-01' `
    --output json | ConvertFrom-Json -Depth 100

$definition = $resource.properties.definition

# --- Ensure variables exist ---
Write-Host "[2/4] Ensuring variables..." -ForegroundColor Cyan
$initVariables = @($definition.actions.Init_DeviceId_Array.inputs.variables)

$requiredVars = @(
    @{ name = 'WinGetRemediationScriptId'; type = 'string'; value = '' }
    @{ name = 'IntuneRemediationResults'; type = 'array'; value = @() }
    @{ name = 'PilotDevices'; type = 'array'; value = @() }
    @{ name = 'BroadDevices'; type = 'array'; value = @() }
    @{ name = 'MecmDevices'; type = 'array'; value = @() }
    @{ name = 'UnmanagedDevices'; type = 'array'; value = @() }
)

foreach ($v in $requiredVars) {
    if (-not ($initVariables | Where-Object { $_.name -eq $v.name })) {
        $initVariables += [pscustomobject]$v
    }
}
$definition.actions.Init_DeviceId_Array.inputs.variables = $initVariables

# --- Build Path B JSON ---
Write-Host "[3/4] Building approval-gated third-party path..." -ForegroundColor Cyan

$pathBJson = @'
{
  "Path_B_Third_Party_Approval": {
    "type": "Scope",
    "actions": {
      "Find_WinGet_Remediation_Script": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/deviceHealthScripts?$filter=displayName eq ''KEV Third-Party Remediation''&$select=id,displayName')}",
          "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
        }
      },
      "Ensure_WinGet_Remediation_Script": {
        "type": "If",
        "expression": {
          "and": [
            { "greater": [ "@length(body('Find_WinGet_Remediation_Script')?['value'])", 0 ] }
          ]
        },
        "actions": {
          "Use_Existing_Script": {
            "type": "SetVariable",
            "inputs": {
              "name": "WinGetRemediationScriptId",
              "value": "@{first(body('Find_WinGet_Remediation_Script')?['value'])?['id']}"
            }
          }
        },
        "else": {
          "actions": {
            "Create_WinGet_Remediation_Script": {
              "type": "Http",
              "inputs": {
                "method": "POST",
                "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/deviceHealthScripts')}",
                "headers": { "Content-Type": "application/json" },
                "body": {
                  "@@odata.type": "#microsoft.graph.deviceHealthScript",
                  "publisher": "KEV-Remediate",
                  "version": "1.0",
                  "displayName": "KEV Third-Party Remediation",
                  "description": "Detects outdated third-party KEV packages via registry version check. Remediates by downloading and silently installing latest versions. Current mappings: 7-Zip and Notepad++.",
                  "detectionScriptContent": "JEVycm9yQWN0aW9uUHJlZmVyZW5jZSA9ICdTaWxlbnRseUNvbnRpbnVlJwojIE1hcDogcmVnaXN0cnkgRGlzcGxheU5hbWUgcGF0dGVybiAtPiBtaW5pbXVtIHNhZmUgdmVyc2lvbgokcGFja2FnZXMgPSBAKAogICAgQHsgSWQ9Jzd6aXAuN3ppcCc7IFBhdHRlcm49JzctWmlwJzsgTWluVmVyc2lvbj1bdmVyc2lvbl0nMjQuOS4wJyB9CiAgICBAeyBJZD0nTm90ZXBhZCsrLk5vdGVwYWQrKyc7IFBhdHRlcm49J05vdGVwYWRcK1wrJzsgTWluVmVyc2lvbj1bdmVyc2lvbl0nOC43LjAnIH0KKQokbmVlZHNVcGRhdGUgPSAkZmFsc2UKJGtleXMgPSBHZXQtSXRlbVByb3BlcnR5ICJIS0xNOlxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxVbmluc3RhbGxcKiIsIkhLTE06XFNPRlRXQVJFXFdPVzY0MzJOb2RlXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFVuaW5zdGFsbFwqIiAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZQpmb3JlYWNoICgkcGtnIGluICRwYWNrYWdlcykgewogICAgJGFwcCA9ICRrZXlzIHwgV2hlcmUtT2JqZWN0IHsgJF8uRGlzcGxheU5hbWUgLW1hdGNoICRwa2cuUGF0dGVybiB9IHwgU2VsZWN0LU9iamVjdCAtRmlyc3QgMQogICAgaWYgKC1ub3QgJGFwcCkgeyBXcml0ZS1PdXRwdXQgIiQoJHBrZy5JZCk6IG5vdCBpbnN0YWxsZWQsIHNraXBwaW5nLiI7IGNvbnRpbnVlIH0KICAgICRyYXcgPSAkYXBwLkRpc3BsYXlWZXJzaW9uIC1yZXBsYWNlICdbXjAtOS5dJywnJwogICAgdHJ5IHsgJGluc3RhbGxlZCA9IFt2ZXJzaW9uXSRyYXcgfSBjYXRjaCB7IFdyaXRlLU91dHB1dCAiJCgkcGtnLklkKTogY2Fubm90IHBhcnNlIHZlcnNpb24gJyQoJGFwcC5EaXNwbGF5VmVyc2lvbiknLCBza2lwcGluZy4iOyBjb250aW51ZSB9CiAgICBpZiAoJGluc3RhbGxlZCAtbHQgJHBrZy5NaW5WZXJzaW9uKSB7CiAgICAgICAgV3JpdGUtT3V0cHV0ICIkKCRwa2cuSWQpOiBPVVREQVRFRCAkaW5zdGFsbGVkIDwgJCgkcGtnLk1pblZlcnNpb24pIgogICAgICAgICRuZWVkc1VwZGF0ZSA9ICR0cnVlCiAgICB9IGVsc2UgewogICAgICAgIFdyaXRlLU91dHB1dCAiJCgkcGtnLklkKTogT0sgJGluc3RhbGxlZCA+PSAkKCRwa2cuTWluVmVyc2lvbikiCiAgICB9Cn0KaWYgKCRuZWVkc1VwZGF0ZSkgeyBleGl0IDEgfQpXcml0ZS1PdXRwdXQgJ0FsbCBtYXBwZWQgS0VWIHBhY2thZ2VzIGFyZSBjdXJyZW50LicKZXhpdCAw",
                  "remediationScriptContent": "JEVycm9yQWN0aW9uUHJlZmVyZW5jZSA9ICdTdG9wJwokdGVtcERpciA9ICIkZW52OlRFTVBcS0VWUmVtZWRpYXRpb24iCk5ldy1JdGVtIC1JdGVtVHlwZSBEaXJlY3RvcnkgLVBhdGggJHRlbXBEaXIgLUZvcmNlIHwgT3V0LU51bGwKCiRwYWNrYWdlcyA9IEAoCiAgICBAewogICAgICAgIE5hbWUgPSAnNy1aaXAnCiAgICAgICAgUGF0dGVybiA9ICc3LVppcCcKICAgICAgICBNaW5WZXJzaW9uID0gW3ZlcnNpb25dJzI0LjkuMCcKICAgICAgICBVcmwgPSAnaHR0cHM6Ly93d3cuNy16aXAub3JnL2EvN3oyNDA5LXg2NC5tc2knCiAgICAgICAgSW5zdGFsbGVyID0gJzd6MjQwOS14NjQubXNpJwogICAgICAgIEFyZ3MgPSAnL3FuIC9ub3Jlc3RhcnQnCiAgICAgICAgVHlwZSA9ICdtc2knCiAgICB9CiAgICBAewogICAgICAgIE5hbWUgPSAnTm90ZXBhZCsrJwogICAgICAgIFBhdHRlcm4gPSAnTm90ZXBhZFwrXCsnCiAgICAgICAgTWluVmVyc2lvbiA9IFt2ZXJzaW9uXSc4LjcuMCcKICAgICAgICBVcmwgPSAnaHR0cHM6Ly9naXRodWIuY29tL25vdGVwYWQtcGx1cy1wbHVzL25vdGVwYWQtcGx1cy1wbHVzL3JlbGVhc2VzL2Rvd25sb2FkL3Y4LjcuOC9ucHAuOC43LjguSW5zdGFsbGVyLng2NC5leGUnCiAgICAgICAgSW5zdGFsbGVyID0gJ25wcC44LjcuOC5JbnN0YWxsZXIueDY0LmV4ZScKICAgICAgICBBcmdzID0gJy9TJwogICAgICAgIFR5cGUgPSAnZXhlJwogICAgfQopCgoka2V5cyA9IEdldC1JdGVtUHJvcGVydHkgIkhLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFVuaW5zdGFsbFwqIiwiSEtMTTpcU09GVFdBUkVcV09XNjQzMk5vZGVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXCoiIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCiRmYWlsdXJlcyA9IEAoKQoKZm9yZWFjaCAoJHBrZyBpbiAkcGFja2FnZXMpIHsKICAgICRhcHAgPSAka2V5cyB8IFdoZXJlLU9iamVjdCB7ICRfLkRpc3BsYXlOYW1lIC1tYXRjaCAkcGtnLlBhdHRlcm4gfSB8IFNlbGVjdC1PYmplY3QgLUZpcnN0IDEKICAgIGlmICgtbm90ICRhcHApIHsgV3JpdGUtT3V0cHV0ICIkKCRwa2cuTmFtZSk6IG5vdCBpbnN0YWxsZWQsIHNraXBwaW5nLiI7IGNvbnRpbnVlIH0KICAgICRyYXcgPSAkYXBwLkRpc3BsYXlWZXJzaW9uIC1yZXBsYWNlICdbXjAtOS5dJywnJwogICAgdHJ5IHsgJGluc3RhbGxlZCA9IFt2ZXJzaW9uXSRyYXcgfSBjYXRjaCB7IFdyaXRlLU91dHB1dCAiJCgkcGtnLk5hbWUpOiBjYW5ub3QgcGFyc2UgJyQoJGFwcC5EaXNwbGF5VmVyc2lvbiknIjsgY29udGludWUgfQogICAgaWYgKCRpbnN0YWxsZWQgLWdlICRwa2cuTWluVmVyc2lvbikgeyBXcml0ZS1PdXRwdXQgIiQoJHBrZy5OYW1lKTogT0sgJGluc3RhbGxlZCI7IGNvbnRpbnVlIH0KCiAgICBXcml0ZS1PdXRwdXQgIiQoJHBrZy5OYW1lKTogT1VUREFURUQgJGluc3RhbGxlZCAtPiBkb3dubG9hZGluZyAkKCRwa2cuVXJsKS4uLiIKICAgICRkZXN0ID0gSm9pbi1QYXRoICR0ZW1wRGlyICRwa2cuSW5zdGFsbGVyCiAgICB0cnkgewogICAgICAgIFtOZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgPSBbTmV0LlNlY3VyaXR5UHJvdG9jb2xUeXBlXTo6VGxzMTIKICAgICAgICBJbnZva2UtV2ViUmVxdWVzdCAtVXJpICRwa2cuVXJsIC1PdXRGaWxlICRkZXN0IC1Vc2VCYXNpY1BhcnNpbmcgLVRpbWVvdXRTZWMgMTIwCiAgICAgICAgV3JpdGUtT3V0cHV0ICIkKCRwa2cuTmFtZSk6IERvd25sb2FkZWQgJCgoR2V0LUl0ZW0gJGRlc3QpLkxlbmd0aCkgYnl0ZXMiCiAgICB9IGNhdGNoIHsKICAgICAgICBXcml0ZS1PdXRwdXQgIiQoJHBrZy5OYW1lKTogRG93bmxvYWQgRkFJTEVEIC0gJF8iCiAgICAgICAgJGZhaWx1cmVzICs9ICRwa2cuTmFtZQogICAgICAgIGNvbnRpbnVlCiAgICB9CgogICAgV3JpdGUtT3V0cHV0ICIkKCRwa2cuTmFtZSk6IEluc3RhbGxpbmcgc2lsZW50bHkuLi4iCiAgICBpZiAoJHBrZy5UeXBlIC1lcSAnbXNpJykgewogICAgICAgICRwcm9jID0gU3RhcnQtUHJvY2VzcyBtc2lleGVjLmV4ZSAtQXJndW1lbnRMaXN0ICIvaSBgIiRkZXN0YCIgJCgkcGtnLkFyZ3MpIiAtV2FpdCAtUGFzc1RocnUgLU5vTmV3V2luZG93CiAgICB9IGVsc2UgewogICAgICAgICRwcm9jID0gU3RhcnQtUHJvY2VzcyAkZGVzdCAtQXJndW1lbnRMaXN0ICRwa2cuQXJncyAtV2FpdCAtUGFzc1RocnUgLU5vTmV3V2luZG93CiAgICB9CiAgICBXcml0ZS1PdXRwdXQgIiQoJHBrZy5OYW1lKTogSW5zdGFsbGVyIGV4aXQgY29kZSA9ICQoJHByb2MuRXhpdENvZGUpIgogICAgaWYgKCRwcm9jLkV4aXRDb2RlIC1uZSAwIC1hbmQgJHByb2MuRXhpdENvZGUgLW5lIDMwMTApIHsgJGZhaWx1cmVzICs9ICIkKCRwa2cuTmFtZSkoZXhpdD0kKCRwcm9jLkV4aXRDb2RlKSkiIH0KfQoKUmVtb3ZlLUl0ZW0gJHRlbXBEaXIgLVJlY3Vyc2UgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlCmlmICgkZmFpbHVyZXMuQ291bnQgLWd0IDApIHsgV3JpdGUtT3V0cHV0ICJGQUlMRUQ6ICQoJGZhaWx1cmVzIC1qb2luICcsICcpIjsgZXhpdCAxIH0KV3JpdGUtT3V0cHV0ICdLRVYgcmVtZWRpYXRpb24gY29tcGxldGVkLicKZXhpdCAw",
                  "runAsAccount": "system",
                  "enforceSignatureCheck": false,
                  "runAs32Bit": false,
                  "roleScopeTagIds": [ "0" ],
                  "isGlobalScript": false,
                  "deviceHealthScriptType": "deviceHealthScript"
                },
                "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
              }
            },
            "Use_New_Script": {
              "type": "SetVariable",
              "inputs": {
                "name": "WinGetRemediationScriptId",
                "value": "@{body('Create_WinGet_Remediation_Script')?['id']}"
              },
              "runAfter": { "Create_WinGet_Remediation_Script": [ "Succeeded" ] }
            }
          }
        },
        "runAfter": { "Find_WinGet_Remediation_Script": [ "Succeeded" ] }
      },

      "Classify_Devices_By_Agent": {
        "type": "Foreach",
        "foreach": "@outputs('Parse_Query_Results')?['devices']",
        "actions": {
          "Lookup_Device_In_Intune": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/managedDevices?$filter=deviceName eq ''', items('Classify_Devices_By_Agent'), '''&$select=id,deviceName,azureADDeviceId,managementAgent,lastSyncDateTime,osVersion')}",
              "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
            }
          },
          "Route_Device": {
            "type": "If",
            "expression": {
              "and": [ { "greater": [ "@length(body('Lookup_Device_In_Intune')?['value'])", 0 ] } ]
            },
            "actions": {
              "Check_Agent_Type": {
                "type": "Switch",
                "expression": "@first(body('Lookup_Device_In_Intune')?['value'])?['managementAgent']",
                "default": {
                  "actions": {
                    "Append_Unmanaged": {
                      "type": "AppendToArrayVariable",
                      "inputs": {
                        "name": "UnmanagedDevices",
                        "value": {
                          "deviceName": "@{items('Classify_Devices_By_Agent')}",
                          "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                          "managementAgent": "@{first(body('Lookup_Device_In_Intune')?['value'])?['managementAgent']}",
                          "reason": "Agent type not supported for automated remediation"
                        }
                      }
                    }
                  }
                },
                "cases": {
                  "MDM": {
                    "case": "mdm",
                    "actions": {
                      "Check_Pilot_Group_MDM": {
                        "type": "Http",
                        "inputs": {
                          "method": "GET",
                          "uri": "@{concat(parameters('GraphApiBase'), '/beta/groups/__PILOT_GROUP_ID__/members?$filter=displayName eq ''', items('Classify_Devices_By_Agent'), '''&$count=true&$select=id,displayName')}",
                          "headers": { "ConsistencyLevel": "eventual" },
                          "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
                        }
                      },
                      "Route_MDM_Ring": {
                        "type": "If",
                        "expression": {
                          "and": [ { "greater": [ "@length(body('Check_Pilot_Group_MDM')?['value'])", 0 ] } ]
                        },
                        "runAfter": { "Check_Pilot_Group_MDM": [ "Succeeded" ] },
                        "actions": {
                          "Append_Pilot": {
                            "type": "AppendToArrayVariable",
                            "inputs": {
                              "name": "PilotDevices",
                              "value": {
                                "deviceName": "@{items('Classify_Devices_By_Agent')}",
                                "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                                "managementAgent": "mdm",
                                "ring": "pilot"
                              }
                            }
                          }
                        },
                        "else": {
                          "actions": {
                            "Append_Broad": {
                              "type": "AppendToArrayVariable",
                              "inputs": {
                                "name": "BroadDevices",
                                "value": {
                                  "deviceName": "@{items('Classify_Devices_By_Agent')}",
                                  "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                                  "managementAgent": "mdm",
                                  "ring": "broad"
                                }
                              }
                            }
                          }
                        },
                      }
                    }
                  },
                  "ConfigMgr": {
                    "case": "configurationManagerClient",
                    "actions": {
                      "Append_MECM": {
                        "type": "AppendToArrayVariable",
                        "inputs": {
                          "name": "MecmDevices",
                          "value": {
                            "deviceName": "@{items('Classify_Devices_By_Agent')}",
                            "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                            "managementAgent": "configurationManagerClient",
                            "ring": "mecm"
                          }
                        }
                      }
                    }
                  },
                  "CoManaged_MDM": {
                    "case": "configurationManagerClientMdm",
                    "actions": {
                      "Check_Pilot_Group_CoMgmt": {
                        "type": "Http",
                        "inputs": {
                          "method": "GET",
                          "uri": "@{concat(parameters('GraphApiBase'), '/beta/groups/__PILOT_GROUP_ID__/members?$filter=displayName eq ''', items('Classify_Devices_By_Agent'), '''&$count=true&$select=id,displayName')}",
                          "headers": { "ConsistencyLevel": "eventual" },
                          "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
                        }
                      },
                      "Route_CoMgmt_Ring": {
                        "type": "If",
                        "expression": {
                          "and": [ { "greater": [ "@length(body('Check_Pilot_Group_CoMgmt')?['value'])", 0 ] } ]
                        },
                        "runAfter": { "Check_Pilot_Group_CoMgmt": [ "Succeeded" ] },
                        "actions": {
                          "Append_Pilot_CoMgmt": {
                            "type": "AppendToArrayVariable",
                            "inputs": {
                              "name": "PilotDevices",
                              "value": {
                                "deviceName": "@{items('Classify_Devices_By_Agent')}",
                                "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                                "managementAgent": "configurationManagerClientMdm",
                                "ring": "pilot"
                              }
                            }
                          }
                        },
                        "else": {
                          "actions": {
                            "Append_Broad_CoMgmt": {
                              "type": "AppendToArrayVariable",
                              "inputs": {
                                "name": "BroadDevices",
                                "value": {
                                  "deviceName": "@{items('Classify_Devices_By_Agent')}",
                                  "managedDeviceId": "@{first(body('Lookup_Device_In_Intune')?['value'])?['id']}",
                                  "managementAgent": "configurationManagerClientMdm",
                                  "ring": "broad"
                                }
                              }
                            }
                          }
                        },
                        "runAfter": { "Check_Pilot_Group_CoMgmt": [ "Succeeded" ] }
                      }
                    }
                  }
                }
              }
            },
            "else": {
              "actions": {
                "Append_Not_Found": {
                  "type": "AppendToArrayVariable",
                  "inputs": {
                    "name": "UnmanagedDevices",
                    "value": {
                      "deviceName": "@{items('Classify_Devices_By_Agent')}",
                      "managedDeviceId": "",
                      "managementAgent": "none",
                      "reason": "Device not found in Intune"
                    }
                  }
                }
              }
            },
            "runAfter": { "Lookup_Device_In_Intune": [ "Succeeded" ] }
          }
        },
        "runtimeConfiguration": { "concurrency": { "repetitions": 1 } },
        "runAfter": { "Ensure_WinGet_Remediation_Script": [ "Succeeded" ] }
      },

      "Send_Approval_Card": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['teams']['connectionId']"
            }
          },
          "method": "post",
          "path": "/beta/teams/@{encodeURIComponent('__TEAM_ID__')}/channels/@{encodeURIComponent('__CHANNEL_ID__')}/messages",
          "body": {
            "recipient": {
              "groupId": "__TEAM_ID__",
              "channelId": "__CHANNEL_ID__"
            },
            "messageBody": "<attachment id=\"adaptivecard\"><div></div></attachment>",
            "attachments": [
              {
                "id": "adaptivecard",
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": "{\"type\":\"AdaptiveCard\",\"version\":\"1.4\",\"body\":[{\"type\":\"TextBlock\",\"text\":\"CISA KEV Third-Party Remediation\",\"size\":\"large\",\"weight\":\"bolder\",\"color\":\"attention\"},{\"type\":\"FactSet\",\"facts\":[{\"title\":\"CVE\",\"value\":\"@{outputs('Parse_Query_Results')?['cveId']}\"},{\"title\":\"Software\",\"value\":\"@{outputs('Parse_Query_Results')?['softwareName']}\"},{\"title\":\"Total Devices\",\"value\":\"@{outputs('Parse_Query_Results')?['deviceCount']}\"},{\"title\":\"Pilot (Intune)\",\"value\":\"@{length(variables('PilotDevices'))}\"},{\"title\":\"Broad (Intune)\",\"value\":\"@{length(variables('BroadDevices'))}\"},{\"title\":\"MECM-managed\",\"value\":\"@{length(variables('MecmDevices'))}\"},{\"title\":\"Unmanaged\",\"value\":\"@{length(variables('UnmanagedDevices'))}\"},{\"title\":\"Incident #\",\"value\":\"@{outputs('Extract_CVE_and_KB_from_Title')?['incidentNumber']}\"}]},{\"type\":\"TextBlock\",\"text\":\"Pilot devices will be submitted for Intune on-demand remediation. MECM and broad devices require separate action.\",\"wrap\":true,\"size\":\"small\",\"color\":\"light\"}]}"
              }
            ]
          }
        },
        "runAfter": { "Classify_Devices_By_Agent": [ "Succeeded" ] }
      },

      "Remediate_Pilot_Devices": {
        "type": "Foreach",
        "foreach": "@variables('PilotDevices')",
        "actions": {
          "Submit_Pilot_Remediation": {
            "type": "Http",
            "inputs": {
              "method": "POST",
              "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/managedDevices/', items('Remediate_Pilot_Devices')?['managedDeviceId'], '/initiateOnDemandProactiveRemediation')}",
              "headers": { "Content-Type": "application/json" },
              "body": { "scriptPolicyId": "@{variables('WinGetRemediationScriptId')}" },
              "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
            }
          },
          "Append_Pilot_Result": {
            "type": "AppendToArrayVariable",
            "inputs": {
              "name": "IntuneRemediationResults",
              "value": {
                "deviceName": "@{items('Remediate_Pilot_Devices')?['deviceName']}",
                "managedDeviceId": "@{items('Remediate_Pilot_Devices')?['managedDeviceId']}",
                "ring": "pilot",
                "submissionHttpStatus": "@{outputs('Submit_Pilot_Remediation')['statusCode']}",
                "status": "Submitted"
              }
            },
            "runAfter": { "Submit_Pilot_Remediation": [ "Succeeded", "Failed" ] }
          }
        },
        "runtimeConfiguration": { "concurrency": { "repetitions": 1 } },
        "runAfter": { "Send_Approval_Card": [ "Succeeded", "Failed" ] }
      },

      "Set_Third_Party_Result": {
        "type": "Compose",
        "inputs": {
          "action": "Third-Party Approval-Gated Remediation",
          "cveId": "@outputs('Parse_Query_Results')?['cveId']",
          "softwareName": "@outputs('Parse_Query_Results')?['softwareName']",
          "scriptPolicyId": "@variables('WinGetRemediationScriptId')",
          "pilotCount": "@length(variables('PilotDevices'))",
          "broadCount": "@length(variables('BroadDevices'))",
          "mecmCount": "@length(variables('MecmDevices'))",
          "unmanagedCount": "@length(variables('UnmanagedDevices'))",
          "pilotResults": "@variables('IntuneRemediationResults')",
          "mecmDevices": "@variables('MecmDevices')",
          "unmanagedDevices": "@variables('UnmanagedDevices')",
          "status": "Pilot remediation submitted. Broad and MECM devices require separate action."
        },
        "runAfter": { "Remediate_Pilot_Devices": [ "Succeeded" ] }
      }
    }
  }
}
'@

# Substitute variables into the single-quoted here-string
$pathBJson = $pathBJson -replace '__PILOT_GROUP_ID__', $PilotGroupId -replace '__TEAM_ID__', $TeamId -replace '__CHANNEL_ID__', $ChannelId

$definition.actions.Check_KB_Exists.else.actions = $pathBJson | ConvertFrom-Json -Depth 100

# --- Update incident comment for third-party path ---
$actionComment = '@' + "{concat('**KEV-Remediate Playbook Action**\n\n', if(not(equals(outputs('Parse_Query_Results')?['kb'], null)), concat('**Path:** WUfB Expedited Deployment\n**KB:** ', outputs('Parse_Query_Results')?['kb'], '\n**Devices:** ', outputs('Parse_Query_Results')?['deviceCount'], '\n**Status:** Expedited deployment created.'), concat('**Path:** Third-Party Approval-Gated Remediation\n**CVE:** ', outputs('Parse_Query_Results')?['cveId'], '\n**Software:** ', outputs('Parse_Query_Results')?['softwareName'], '\n**Devices:** ', outputs('Parse_Query_Results')?['deviceCount'], '\n**Pilot (auto):** ', string(length(variables('PilotDevices'))), '\n**Broad (pending):** ', string(length(variables('BroadDevices'))), '\n**MECM (notified):** ', string(length(variables('MecmDevices'))), '\n**Unmanaged:** ', string(length(variables('UnmanagedDevices'))), '\n**Status:** Teams approval card posted. Pilot devices submitted for Intune remediation.')))}"
$definition.actions.Add_Incident_Comment.inputs.body.properties.message = $actionComment

# --- Wire Teams connection ---
$connParams = $resource.properties.parameters.'$connections'.value
$teamsConn = [pscustomobject]@{
    connectionId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/connections/teams-kev-remediate"
    connectionName = "teams-kev-remediate"
    id = "/subscriptions/$SubscriptionId/providers/Microsoft.Web/locations/$($resource.location)/managedApis/teams"
}
$connParams | Add-Member -NotePropertyName 'teams' -NotePropertyValue $teamsConn -Force

# --- Deploy ---
Write-Host "[4/4] Deploying updated Logic App..." -ForegroundColor Cyan
$body = [ordered]@{
    location = $resource.location
    tags = $resource.tags
    identity = @{ type = $resource.identity.type }
    properties = [ordered]@{
        state = $resource.properties.state
        definition = $definition
        parameters = $resource.properties.parameters
    }
}

$bodyPath = Join-Path $env:TEMP 'kev-remediate-approval-update.json'
$body | ConvertTo-Json -Depth 100 | Set-Content -Path $bodyPath -Encoding utf8

if ($PSCmdlet.ShouldProcess($WorkflowName, 'Update live KEV-Remediate Logic App with approval-gated third-party path')) {
    az rest `
        --method PUT `
        --url "https://management.azure.com$($resource.id)?api-version=2019-05-01" `
        --headers 'Content-Type=application/json' `
        --body "@$bodyPath" `
        --output none

    # Verify
    $updated = az resource show `
        --resource-group $ResourceGroupName `
        --name $WorkflowName `
        --resource-type 'Microsoft.Logic/workflows' `
        --api-version '2019-05-01' `
        --output json | ConvertFrom-Json -Depth 100

    $elseBranch = $updated.properties.definition.actions.Check_KB_Exists.else.actions.PSObject.Properties.Name
    $hasTeams = ($updated.properties.parameters.'$connections'.value.PSObject.Properties.Name -contains 'teams')
    $hasApproval = ($elseBranch -contains 'Path_B_Third_Party_Approval')

    Write-Host "`n[Done]" -ForegroundColor Green
    Write-Host "  Else branch: $($elseBranch -join ', ')"
    Write-Host "  Teams connection: $hasTeams"
    Write-Host "  Approval path: $hasApproval"
    Write-Host "  State: $($updated.properties.state)"
}
