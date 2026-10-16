function Invoke-VerifiedNetworkReset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Services,
        [Parameter(Mandatory)][string]$Output,
        [Parameter(Mandatory)][scriptblock]$ResetService
    )

    $absolute = [IO.Path]::GetFullPath($Output)
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($absolute))
    # Reserve the evidence path before any reset mutation and hold it exclusively
    # so concurrent runs cannot replace evidence created by another run.
    $stream = [IO.File]::Open($absolute, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $after = [ordered]@{}
        $errors = [ordered]@{}
        $targets = [ordered]@{}
        foreach ($service in @($Services | Select-Object -Unique)) {
            try {
                $result = & $ResetService $service
                if (-not $result -or -not $result.success -or -not $result.after) {
                    $reason = if ($result -and $result.error) { [string]$result.error } else { 'Reset command did not verify the LAN qdisc.' }
                    throw $reason
                }
                $qdisc = [string]$result.after
                if ($qdisc -notmatch '(?m)^qdisc noqueue\s+[^\r\n]*\broot\b') {
                    throw 'Reset command returned without a verified root noqueue qdisc.'
                }
                $after[$service] = $qdisc
                $targets[$service] = [ordered]@{success=$true;after=$qdisc;error=$null}
            }
            catch {
                $message = $_.Exception.Message
                $errors[$service] = $message
                $targets[$service] = [ordered]@{success=$false;after=$null;error=$message}
            }
        }

        $evidence = [ordered]@{
            schema_version=1; created_utc=[DateTime]::UtcNow.ToString('o'); profile='lan'
            services=@($Services | Select-Object -Unique); after=$after; targets=$targets
            errors=$errors; success=($errors.Count -eq 0)
        }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($evidence | ConvertTo-Json -Depth 12))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        return [pscustomobject]$evidence
    }
    finally { $stream.Dispose() }
}

function Invoke-ComposeNetworkReset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Services,
        [Parameter(Mandatory)][string]$Output,
        [Parameter(Mandatory)][string]$ShaperPath,
        [Parameter(Mandatory)][string]$ComposeFile,
        [Parameter(Mandatory)][string]$ProjectName
    )

    # Keep every dependency as a function-local value captured by the callback.
    # The experiment runner's script scope is not the callback's scope once this
    # function is invoked through Invoke-VerifiedNetworkReset.
    $resetInvoker = {
        param($service)
        $targetEvidence = [IO.Path]::ChangeExtension($Output, ".reset-$service.json")
        & $ShaperPath -ComposeFile $ComposeFile -ProjectName $ProjectName `
            -Services @($service) -Profile lan -Output $targetEvidence | Out-Host
        $individual = Get-Content -LiteralPath $targetEvidence -Raw | ConvertFrom-Json
        $qdiscProperty = $individual.after.PSObject.Properties[$service]
        $verifiedQdisc = if ($qdiscProperty) { [string]$qdiscProperty.Value } else { $null }
        $successProperty = $individual.PSObject.Properties['success']
        $isSuccessful = $successProperty -and [bool]$successProperty.Value
        $errorProperty = $individual.PSObject.Properties['error']
        $serviceError = if ($errorProperty) { $errorProperty.Value } else { $null }
        return [pscustomobject]@{success=[bool]$isSuccessful;after=$verifiedQdisc;error=$serviceError}
    }.GetNewClosure()

    return Invoke-VerifiedNetworkReset -Services $Services -Output $Output -ResetService $resetInvoker
}
