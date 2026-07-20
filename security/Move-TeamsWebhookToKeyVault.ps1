<#
.SYNOPSIS
    Moves the Teams webhook URL from a Logic App SecureString parameter into
    Azure Key Vault, then rewires the Logic App to pull from Key Vault at runtime.

.DESCRIPTION
    By default, the KEV-Remediate Logic App stores the Teams Incoming Webhook URL
    as a SecureString parameter. This is encrypted at rest, BUT anyone with Read
    on the Logic App resource can retrieve it via the management API.

    A leaked webhook URL lets an attacker post fake messages into your security
    Teams channel - good for social engineering or covering tracks during an
    intrusion.

    This script:
      1. Creates (or reuses) a Key Vault
      2. Stores the webhook URL as a secret
      3. Grants the Logic App's MI 'Key Vault Secrets User' on the vault
      4. Updates the Logic App's TeamsWebhookUrl parameter to a Key Vault reference

    After running, the secret is only retrievable by:
      - The Logic App's MI (at runtime)
      - Identities with explicit Key Vault Secrets Officer/User RBAC
    Logic App readers no longer see the webhook value.

.PARAMETER ResourceGroupName
    Resource group for the Key Vault and Logic App.

.PARAMETER LogicAppName
    Name of the KEV-Remediate Logic App. Default: KEV-Remediate

.PARAMETER KeyVaultName
    Name of an existing Key Vault, or a new one to create.
    Must be globally unique if creating new.

.PARAMETER WebhookUrl
    The Teams Incoming Webhook URL. If omitted, the script reads the current
    value from the Logic App parameter.

.PARAMETER SecretName
    Name of the secret in Key Vault. Default: TeamsWebhookUrl

.EXAMPLE
    .\Move-TeamsWebhookToKeyVault.ps1 `
        -ResourceGroupName rg-sentinel `
        -KeyVaultName kv-kev-remediate

.NOTES
    Requires:
      - Az.KeyVault, Az.Resources, Az.LogicApp modules
      - Owner or User Access Administrator on the resource group (to grant RBAC)
      - Key Vault must use RBAC permission model (not access policies)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [string]$LogicAppName = 'KEV-Remediate',

    [string]$SecretName = 'TeamsWebhookUrl',

    [string]$WebhookUrl
)

$ErrorActionPreference = 'Stop'

# ── Get the Logic App + MI ──
Write-Host '[1/5] Resolving Logic App + managed identity...' -ForegroundColor Cyan
$logicApp = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Logic/workflows -Name $LogicAppName
if (-not $logicApp) { throw "Logic App '$LogicAppName' not found." }
$miPrincipalId = $logicApp.Identity.PrincipalId
if (-not $miPrincipalId) { throw "Logic App '$LogicAppName' has no system-assigned managed identity." }

# ── Get the current webhook value if not provided ──
if (-not $WebhookUrl) {
    Write-Host '[2/5] Reading current TeamsWebhookUrl from Logic App...' -ForegroundColor Cyan
    $current = Get-AzLogicApp -ResourceGroupName $ResourceGroupName -Name $LogicAppName
    $WebhookUrl = $current.Parameters.TeamsWebhookUrl.Value
    if (-not $WebhookUrl) {
        throw 'TeamsWebhookUrl parameter is empty. Pass -WebhookUrl explicitly.'
    }
} else {
    Write-Host '[2/5] Using webhook URL provided as parameter.' -ForegroundColor Cyan
}

# ── Ensure Key Vault exists ──
Write-Host '[3/5] Ensuring Key Vault exists...' -ForegroundColor Cyan
$kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-not $kv) {
    if ($PSCmdlet.ShouldProcess($KeyVaultName, 'Create Key Vault (RBAC mode)')) {
        $kv = New-AzKeyVault `
            -Name $KeyVaultName `
            -ResourceGroupName $ResourceGroupName `
            -Location $logicApp.Location `
            -EnableRbacAuthorization `
            -EnabledForTemplateDeployment
        Write-Host "  Created $KeyVaultName" -ForegroundColor Green
    }
} else {
    Write-Host "  Reusing existing Key Vault $KeyVaultName" -ForegroundColor Yellow
    if (-not $kv.EnableRbacAuthorization) {
        Write-Warning "Key Vault $KeyVaultName uses access policies, not RBAC. This script assumes RBAC. Convert it via 'Update-AzKeyVault -EnableRbacAuthorization' before re-running."
    }
}

# ── Store the secret ──
Write-Host '[4/5] Writing secret + granting MI access...' -ForegroundColor Cyan

# Caller needs Secrets Officer on the vault to write
$vaultId = $kv.ResourceId
$callerObjectId = (Get-AzADUser -SignedIn).Id
$officerRoleAssigned = Get-AzRoleAssignment -ObjectId $callerObjectId -Scope $vaultId -RoleDefinitionName 'Key Vault Secrets Officer' -ErrorAction SilentlyContinue
if (-not $officerRoleAssigned) {
    if ($PSCmdlet.ShouldProcess($vaultId, "Grant Secrets Officer to caller for setup")) {
        New-AzRoleAssignment -ObjectId $callerObjectId -Scope $vaultId -RoleDefinitionName 'Key Vault Secrets Officer' | Out-Null
        Write-Host '  Granted caller temporary Secrets Officer.' -ForegroundColor Yellow
        Start-Sleep -Seconds 30
    }
}

$secretValue = ConvertTo-SecureString $WebhookUrl -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -SecretValue $secretValue | Out-Null
$secretUri = "https://$KeyVaultName.vault.azure.net/secrets/$SecretName"
Write-Host "  Secret stored at $secretUri" -ForegroundColor Green

# Grant the Logic App MI access
$miUserAssigned = Get-AzRoleAssignment -ObjectId $miPrincipalId -Scope $vaultId -RoleDefinitionName 'Key Vault Secrets User' -ErrorAction SilentlyContinue
if (-not $miUserAssigned) {
    if ($PSCmdlet.ShouldProcess($miPrincipalId, "Grant Logic App MI 'Key Vault Secrets User'")) {
        New-AzRoleAssignment -ObjectId $miPrincipalId -Scope $vaultId -RoleDefinitionName 'Key Vault Secrets User' -ObjectType ServicePrincipal | Out-Null
        Write-Host '  Granted Logic App MI Secrets User.' -ForegroundColor Green
    }
} else {
    Write-Host '  MI already has Secrets User on the vault.' -ForegroundColor Yellow
}

# ── Update the Logic App parameter to the Key Vault URI ──
Write-Host '[5/5] Updating Logic App parameter...' -ForegroundColor Cyan
Write-Host "  Set the Logic App's TeamsWebhookUrl parameter manually OR re-deploy the ARM template with:" -ForegroundColor Yellow
Write-Host "    TeamsWebhookUrl = $secretUri" -ForegroundColor Gray
Write-Host '' -ForegroundColor Yellow
Write-Host '  Then update the HTTP_Notify_Teams action to fetch the secret at runtime:' -ForegroundColor Yellow
Write-Host '    "uri": "@{body(''Get_Teams_Webhook_Secret'')?[''value'']}"' -ForegroundColor Gray
Write-Host '  And add a preceding HTTP action that calls:' -ForegroundColor Yellow
Write-Host "    GET $secretUri/?api-version=7.4" -ForegroundColor Gray
Write-Host "    authentication: ManagedServiceIdentity, audience: https://vault.azure.net" -ForegroundColor Gray

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host "Webhook secret stored in Key Vault. Update the Logic App's HTTP action to fetch it at runtime, then clear the SecureString parameter from the deployed Logic App." -ForegroundColor White
