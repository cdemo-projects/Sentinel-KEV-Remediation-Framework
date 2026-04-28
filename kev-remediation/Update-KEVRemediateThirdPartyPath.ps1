#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId = '<subscription-id>',
    [string]$ResourceGroupName = '<resource-group>',
    [string]$WorkflowName = 'KEV-Remediate'
)

$ErrorActionPreference = 'Stop'

az account set --subscription $SubscriptionId | Out-Null

$resource = az resource show `
    --resource-group $ResourceGroupName `
    --name $WorkflowName `
    --resource-type 'Microsoft.Logic/workflows' `
    --api-version '2019-05-01' `
    --output json | ConvertFrom-Json -Depth 100

$definition = $resource.properties.definition
$initVariables = @($definition.actions.Init_DeviceId_Array.inputs.variables)

if (-not ($initVariables | Where-Object { $_.name -eq 'WinGetRemediationScriptId' })) {
    $initVariables += [pscustomobject]@{ name = 'WinGetRemediationScriptId'; type = 'string'; value = '' }
}

if (-not ($initVariables | Where-Object { $_.name -eq 'IntuneRemediationResults' })) {
    $initVariables += [pscustomobject]@{ name = 'IntuneRemediationResults'; type = 'array'; value = @() }
}

$definition.actions.Init_DeviceId_Array.inputs.variables = $initVariables

$pathBJson = @'
{
  "Path_B_MDE_Remediation_Task": {
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
          "Use_Existing_WinGet_Remediation_Script": {
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
            "Use_New_WinGet_Remediation_Script": {
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
      "Run_WinGet_Remediation_On_Devices": {
        "type": "Foreach",
        "foreach": "@outputs('Parse_Query_Results')?['devices']",
        "actions": {
          "Get_Intune_Managed_Device": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/managedDevices?$filter=deviceName eq ''', items('Run_WinGet_Remediation_On_Devices'), '''&$select=id,deviceName,azureADDeviceId,operatingSystem,osVersion,managementAgent,complianceState,lastSyncDateTime')}",
              "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
            }
          },
          "If_Intune_Device_Found": {
            "type": "If",
            "expression": {
              "and": [
                { "greater": [ "@length(body('Get_Intune_Managed_Device')?['value'])", 0 ] }
              ]
            },
            "actions": {
              "If_Intune_Remediation_Capable": {
                "type": "If",
                "expression": {
                  "or": [
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "mdm" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "easMdm" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "intuneClient" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "easIntuneClient" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "configurationManagerClientMdm" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "configurationManagerClientMdmEas" ] },
                    { "equals": [ "@first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']", "microsoft365ManagedMdm" ] }
                  ]
                },
                "actions": {
                  "Invoke_OnDemand_WinGet_Remediation": {
                    "type": "Http",
                    "inputs": {
                      "method": "POST",
                      "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/managedDevices/', first(body('Get_Intune_Managed_Device')?['value'])?['id'], '/initiateOnDemandProactiveRemediation')}",
                      "headers": { "Content-Type": "application/json" },
                      "body": { "scriptPolicyId": "@{variables('WinGetRemediationScriptId')}" },
                      "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
                    }
                  },
                  "Get_WinGet_Remediation_Device_Run_State": {
                    "type": "Http",
                    "inputs": {
                      "method": "GET",
                      "uri": "@{concat(parameters('GraphApiBase'), '/beta/deviceManagement/deviceHealthScripts/', variables('WinGetRemediationScriptId'), '/deviceRunStates')}",
                      "authentication": { "type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com" }
                    },
                    "runAfter": { "Invoke_OnDemand_WinGet_Remediation": [ "Succeeded" ] }
                  },
                  "Append_OnDemand_Remediation_Result": {
                    "type": "AppendToArrayVariable",
                    "inputs": {
                      "name": "IntuneRemediationResults",
                      "value": {
                        "deviceName": "@{items('Run_WinGet_Remediation_On_Devices')}",
                        "managedDeviceId": "@{first(body('Get_Intune_Managed_Device')?['value'])?['id']}",
                        "intuneLastSyncDateTime": "@{first(body('Get_Intune_Managed_Device')?['value'])?['lastSyncDateTime']}",
                        "managementAgent": "@{first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']}",
                        "osVersion": "@{first(body('Get_Intune_Managed_Device')?['value'])?['osVersion']}",
                        "submissionHttpStatus": "@outputs('Invoke_OnDemand_WinGet_Remediation')?['statusCode']",
                        "runStateQueryHttpStatus": "@outputs('Get_WinGet_Remediation_Device_Run_State')?['statusCode']",
                        "deviceHealthScriptStates": "@body('Get_WinGet_Remediation_Device_Run_State')?['value']",
                        "status": "Submitted"
                      }
                    },
                    "runAfter": { "Get_WinGet_Remediation_Device_Run_State": [ "Succeeded", "Failed" ] }
                  }
                },
                "else": {
                  "actions": {
                    "Append_OnDemand_Remediation_Unsupported_Agent": {
                      "type": "AppendToArrayVariable",
                      "inputs": {
                        "name": "IntuneRemediationResults",
                        "value": {
                          "deviceName": "@{items('Run_WinGet_Remediation_On_Devices')}",
                          "managedDeviceId": "@{first(body('Get_Intune_Managed_Device')?['value'])?['id']}",
                          "intuneLastSyncDateTime": "@{first(body('Get_Intune_Managed_Device')?['value'])?['lastSyncDateTime']}",
                          "managementAgent": "@{first(body('Get_Intune_Managed_Device')?['value'])?['managementAgent']}",
                          "osVersion": "@{first(body('Get_Intune_Managed_Device')?['value'])?['osVersion']}",
                          "status": "Unsupported managementAgent for Intune Remediations; device must be Intune MDM-enrolled or co-managed with Intune Management Extension installed"
                        }
                      }
                    }
                  }
                }
              }
            },
            "else": {
              "actions": {
                "Append_OnDemand_Remediation_Device_Not_Found": {
                  "type": "AppendToArrayVariable",
                  "inputs": {
                    "name": "IntuneRemediationResults",
                    "value": {
                      "deviceName": "@{items('Run_WinGet_Remediation_On_Devices')}",
                      "managedDeviceId": "",
                      "status": "Intune managed device not found"
                    }
                  }
                }
              }
            },
            "runAfter": { "Get_Intune_Managed_Device": [ "Succeeded" ] }
          }
        },
        "runtimeConfiguration": { "concurrency": { "repetitions": 1 } },
        "runAfter": { "Ensure_WinGet_Remediation_Script": [ "Succeeded" ] }
      },
      "Set_Result_Remediation_Task": {
        "type": "Compose",
        "inputs": {
          "action": "Intune On-Demand Proactive Remediation",
          "scriptPolicyId": "@variables('WinGetRemediationScriptId')",
          "deviceCount": "@outputs('Parse_Query_Results')?['deviceCount']",
          "cveId": "@outputs('Parse_Query_Results')?['cveId']",
          "results": "@variables('IntuneRemediationResults')",
          "status": "Third-party WinGet remediation evaluated; submitted only for Intune remediation-capable devices"
        },
        "runAfter": { "Run_WinGet_Remediation_On_Devices": [ "Succeeded" ] }
      }
    }
  }
}
'@

$definition.actions.Check_KB_Exists.else.actions = $pathBJson | ConvertFrom-Json -Depth 100

$actionComment = "@{concat('**KEV-Remediate Playbook Action**\n\n', if(not(equals(outputs('Parse_Query_Results')?['kb'], null)), concat('**Path:** WUfB Expedited Deployment\n**KB:** ', outputs('Parse_Query_Results')?['kb'], '\n**Devices:** ', outputs('Parse_Query_Results')?['deviceCount'], '\n**Status:** Expedited deployment created. Devices will receive update on next Windows Update scan.'), concat('**Path:** Intune On-Demand Proactive Remediation\n**CVE:** ', outputs('Parse_Query_Results')?['cveId'], '\n**Devices:** ', outputs('Parse_Query_Results')?['deviceCount'], '\n**Status:** No Windows KB available. WinGet remediation is submitted only for Intune remediation-capable devices; unsupported agents are recorded in the playbook result.')))}"
$definition.actions.Add_Incident_Comment.inputs.body.properties.message = $actionComment

$teamsFact = $definition.actions.Notify_Teams.actions.Send_Teams_Card.inputs.body.sections[0].facts | Where-Object { $_.name -eq 'Action Taken' }
if ($teamsFact) {
    $teamsFact.value = "@{if(not(equals(outputs('Parse_Query_Results')?['kb'], null)), 'WUfB Expedited Deployment', 'Intune On-Demand Proactive Remediation (capability-gated)')}"
}

$emailContent = '@{concat(''<h2>CISA KEV Remediation Action Taken</h2><table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;font-family:Segoe UI,sans-serif"><tr><td><b>CVE</b></td><td>'', outputs(''Parse_Query_Results'')?[''cveId''], ''</td></tr><tr><td><b>KB</b></td><td>'', coalesce(outputs(''Parse_Query_Results'')?[''kb''], ''None (third-party)''), ''</td></tr><tr><td><b>Affected Devices</b></td><td>'', outputs(''Parse_Query_Results'')?[''deviceCount''], ''</td></tr><tr><td><b>Action</b></td><td>'', if(not(equals(outputs(''Parse_Query_Results'')?[''kb''], null)), ''WUfB Expedited Deployment (automated)'', ''Intune On-Demand Proactive Remediation (capability-gated)''), ''</td></tr><tr><td><b>Incident #</b></td><td>'', outputs(''Extract_CVE_and_KB_from_Title'')?[''incidentNumber''], ''</td></tr></table><br><p style="color:#666">Sent by KEV-Remediate playbook</p>'')}'
$definition.actions.Send_Email_Notification.inputs.body.message.body.content = $emailContent

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

$bodyPath = Join-Path $env:TEMP 'kev-remediate-updated.json'
$body | ConvertTo-Json -Depth 100 | Set-Content -Path $bodyPath -Encoding utf8

if ($PSCmdlet.ShouldProcess($WorkflowName, 'Update live KEV-Remediate Logic App third-party remediation path')) {
    az rest `
        --method PUT `
        --url "https://management.azure.com$($resource.id)?api-version=2019-05-01" `
        --headers 'Content-Type=application/json' `
        --body "@$bodyPath" `
        --output none
}

$updated = az resource show `
    --resource-group $ResourceGroupName `
    --name $WorkflowName `
    --resource-type 'Microsoft.Logic/workflows' `
    --api-version '2019-05-01' `
    --output json | ConvertFrom-Json -Depth 100

$updatedDefinitionJson = $updated.properties.definition | ConvertTo-Json -Depth 100
$updatedElseActions = $updated.properties.definition.actions.Check_KB_Exists.else.actions.Path_B_MDE_Remediation_Task.actions.PSObject.Properties.Name

[pscustomobject]@{
    Workflow = $WorkflowName
    State = $updated.properties.state
    ElseBranchActions = ($updatedElseActions -join ', ')
    ContainsUnsupportedRemediationTaskPost = ($updatedDefinitionJson -match '/api/remediationTasks')
    HasIntuneOnDemandAction = ($updatedDefinitionJson -match 'initiateOnDemandProactiveRemediation')
}