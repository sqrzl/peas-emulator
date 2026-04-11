$ErrorActionPreference = "Stop"

$matrixPath = Join-Path $PSScriptRoot "..\compatibility-matrix.json"
$matrix = Get-Content $matrixPath -Raw | ConvertFrom-Json

$allowed = @("pass", "partial", "missing", "deferred")
$providers = $matrix.providers.PSObject.Properties

foreach ($provider in $providers) {
    foreach ($operation in $provider.Value.PSObject.Properties) {
        if (-not $operation.Value.PSObject.Properties["status"]) {
            throw "Missing status for provider '$($provider.Name)' operation '$($operation.Name)'"
        }
        if (-not $operation.Value.PSObject.Properties["verified_by"]) {
            throw "Missing verified_by for provider '$($provider.Name)' operation '$($operation.Name)'"
        }

        $status = [string]$operation.Value.status
        if ($allowed -notcontains $status) {
            throw "Invalid compatibility status '$status' for provider '$($provider.Name)' operation '$($operation.Name)'"
        }

        $verifiedBy = @($operation.Value.verified_by)
        if ($status -eq "pass" -and $verifiedBy.Count -eq 0) {
            throw "Pass status requires at least one verifier for provider '$($provider.Name)' operation '$($operation.Name)'"
        }
    }
}

Write-Host "Compatibility matrix is valid."
