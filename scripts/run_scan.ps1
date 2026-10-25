<#
.SYNOPSIS
  One full pipeline run: Prowler scan -> load -> custom NSG check -> score -> diff -> report.

.EXAMPLE
  .\scripts\run_scan.ps1 -Label after-teardown -Before after-alerts

  [AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending
  Native commands (az, prowler, python) don't stop PowerShell on failure, so every step checks
  its exit code explicitly. A failed step stops the run instead of feeding bad data forward.
#>
param(
    [Parameter(Mandatory)][string]$Label,
    [string]$Before,
    [string]$ResourceGroup = "rg-cspm-lab"
)
$ErrorActionPreference = "Stop"

function Assert-Ok([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit code $LASTEXITCODE)" }
}

$out = "scans\$Label"
if (Test-Path $out) { throw "$out already exists; pick a new label" }

$subscription = az account show --query id -o tsv
Assert-Ok "az account show (run 'az login' first)"

# Prowler exits 3 when any check fails, which is normal here; anything else is an error.
prowler azure --az-cli-auth --subscription-ids $subscription --excluded-services entra --output-directory $out
if ($LASTEXITCODE -notin 0, 3) { throw "Prowler failed (exit code $LASTEXITCODE)" }

$ocsf = Get-ChildItem "$out\*.ocsf.json" | Select-Object -First 1
if (-not $ocsf) { throw "No OCSF output found in $out" }

$env:PYTHONPATH = "src"
python -m cspm.db load $ocsf.FullName --label $Label
Assert-Ok "Loading scan"

# After teardown the resource group is gone; record "no NSGs" instead of failing.
$exists = az group exists --name $ResourceGroup
Assert-Ok "az group exists"
$nsgFile = "$out\nsg_rules.json"
if ($exists -eq "true") {
    az network nsg list --resource-group $ResourceGroup -o json | Out-File -Encoding utf8 $nsgFile
    Assert-Ok "Exporting NSG rules"
} else {
    "[]" | Out-File -Encoding utf8 $nsgFile
}
python -m cspm.nsg_check --label $Label --input $nsgFile
Assert-Ok "Custom NSG check"

python -m cspm.scoring --label $Label
Assert-Ok "Scoring"

if ($Before) {
    python -m cspm.diff --before $Before --after $Label
    Assert-Ok "Diff"
}

python -m cspm.report --label $Label
Assert-Ok "Report"
Write-Host "`nDone: scans\$Label loaded; report in reports\report.html"
