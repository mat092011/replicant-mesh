$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/NetworkReset.ps1')

$temp = Join-Path ([IO.Path]::GetTempPath()) ('steamboat-reset-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    $calls = New-Object 'System.Collections.Generic.List[string]'
    $mock = {
        param($service)
        $calls.Add($service)
        if ($service -eq 'worker-2') { throw 'container is stopped' }
        return [pscustomobject]@{success=$true;after="qdisc noqueue 0: root refcnt 2";error=$null}
    }.GetNewClosure()
    $evidencePath = Join-Path $temp 'reset.json'
    $result = Invoke-VerifiedNetworkReset -Services @('worker-1','worker-2','worker-3','coordinator') `
        -Output $evidencePath -ResetService $mock
    if ($result.success) { throw 'Expected aggregate reset failure for stopped worker.' }
    if (($calls -join ',') -ne 'worker-1,worker-2,worker-3,coordinator') {
        throw "Reset did not attempt every target: $($calls -join ',')"
    }
    if ($result.after.Count -ne 3 -or -not $result.after.Contains('worker-3') -or -not $result.after.Contains('coordinator')) {
        throw 'Successful survivor qdiscs were not retained in the aggregate after map.'
    }
    if ($result.errors['worker-2'] -ne 'container is stopped') { throw 'Stopped target error was not retained.' }
    $saved = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    if ($saved.success -or $saved.after.'worker-3' -notmatch 'noqueue' -or $saved.errors.'worker-2' -ne 'container is stopped') {
        throw 'Aggregate reset JSON did not preserve verified survivors and per-target errors.'
    }

    # An empty/non-verifying response must count as failure too, even when no command throws.
    $unverified = { param($service) [pscustomobject]@{success=$true;after='';error=$null} }
    $second = Invoke-VerifiedNetworkReset -Services @('worker-1') -Output (Join-Path $temp 'unverified.json') -ResetService $unverified
    if ($second.success -or -not $second.errors.Contains('worker-1')) { throw 'Unverified reset was incorrectly accepted.' }

    $existingPath = Join-Path $temp 'existing.json'
    [IO.File]::WriteAllText($existingPath, 'preserve this evidence')
    $neverCall = { param($service) throw 'Reset callback must not run when evidence exists.' }
    $refused = $false
    try { $null = Invoke-VerifiedNetworkReset -Services @('worker-1') -Output $existingPath -ResetService $neverCall }
    catch { $refused = $true }
    if (-not $refused) { throw 'Existing evidence output path was overwritten or accepted.' }
    if ((Get-Content -LiteralPath $existingPath -Raw) -ne 'preserve this evidence') { throw 'Existing evidence was modified.' }

    # Exercise the same shaper callback wrapper used by Invoke-PytorchExperiment,
    # with external paths passed explicitly instead of relying on script scope.
    $mockShaperPath = Join-Path $temp 'mock-shaper.ps1'
    $mockShaper = @'
param([string]$ComposeFile,[string]$ProjectName,[string[]]$Services,[string]$Profile,[string]$Output)
if ($Services.Count -ne 1) { throw 'Expected exactly one target per shaper call.' }
if ($Services[0] -eq 'worker-2') { throw 'mock stopped worker-2' }
$evidence = [ordered]@{success=$true;error=$null;after=@{$Services[0]='qdisc noqueue 0: root refcnt 2'}}
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($evidence | ConvertTo-Json -Depth 8))
$file = [IO.File]::Open($Output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $file.Write($bytes,0,$bytes.Length) } finally { $file.Dispose() }
'@
    [IO.File]::WriteAllText($mockShaperPath, $mockShaper, (New-Object Text.UTF8Encoding($false)))
    $composeReset = Invoke-ComposeNetworkReset -Services @('worker-1','worker-2','worker-3','coordinator') `
        -Output (Join-Path $temp 'compose-reset.json') -ShaperPath $mockShaperPath `
        -ComposeFile (Join-Path $temp 'compose.mock.yaml') -ProjectName 'mock-reset-test'
    if ($composeReset.success -or $composeReset.errors['worker-2'] -ne 'mock stopped worker-2') {
        throw 'Compose reset wrapper did not preserve the expected per-target failure.'
    }
    foreach ($service in @('worker-1','worker-3','coordinator')) {
        if (-not $composeReset.after.Contains($service)) { throw "Compose reset wrapper failed to verify $service." }
    }
    Write-Output 'Network reset mocked tests passed.'
}
finally {
    $resolvedTempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $resolvedDeleteTarget = [IO.Path]::GetFullPath($temp)
    $tempPrefix = $resolvedTempParent + [IO.Path]::DirectorySeparatorChar
    if ($resolvedDeleteTarget -eq $resolvedTempParent -or -not $resolvedDeleteTarget.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing recursive cleanup outside the intended temporary directory: $resolvedDeleteTarget"
    }
    Remove-Item -LiteralPath $resolvedDeleteTarget -Recurse -Force
}
