<#
.SYNOPSIS
  Delete every lab resource: remove role assignments first, then the resource group.

  [AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending
  Order matters: deleting an identity before its role assignments leaves orphaned
  assignments that show up as "Unknown" principals.
#>
param([string]$ResourceGroup = "rg-cspm-lab")
$ErrorActionPreference = "Stop"
function Assert-Ok([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit code $LASTEXITCODE)" }
}

Write-Host "Resources that will be deleted:"
az resource list --resource-group $ResourceGroup --query "[].{name:name, type:type}" -o table
Assert-Ok "Listing resources"

$confirm = Read-Host "Type the resource group name ($ResourceGroup) to delete everything"
if ($confirm -ne $ResourceGroup) { Write-Host "Cancelled."; return }

# 1. Remove any role assignments held by managed identities in this group.
$principalIds = az identity list --resource-group $ResourceGroup --query "[].principalId" -o tsv
Assert-Ok "Listing identities"
foreach ($principalId in $principalIds) {
    $ids = az role assignment list --all --fill-principal-name false --query "[?principalId=='$principalId'].id" -o tsv
    Assert-Ok "Listing role assignments"
    foreach ($id in $ids) {
        az role assignment delete --ids $id
        Assert-Ok "Deleting role assignment"
        Write-Host "Removed role assignment held by identity $principalId"
    }
}

# 2. Delete the resource group (storage, NSG, identity, alerts, action group).
az group delete --name $ResourceGroup --yes
Assert-Ok "Deleting resource group"

# 3. Verify.
$exists = az group exists --name $ResourceGroup
Write-Host "Resource group still exists: $exists (expected: false)"
Write-Host "Remaining resource groups in the subscription:"
az group list --query "[].name" -o tsv
