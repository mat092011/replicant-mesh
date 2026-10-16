<#
.SYNOPSIS
Run three frozen LAN complete-model control repetitions, retaining every attempt.
.DESCRIPTION
Requires four healthy replicas and the thin pipeline-benchmark driver. Stop the
pipeline inference services first to avoid their background health-check load.
Each replica has two CPU quota units and 3 GiB; all four are warmed before timing.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExpectedImage, [switch]$PlanOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $repo 'compose.pytorch.yaml'
$project = 'steamboat-pytorch-m1'
$docker = (Get-Command docker -CommandType Application | Select-Object -First 1).Source
$composeArgs = @('compose','-f',$compose,'-p',$project)
$services = @('replica-1','replica-2','replica-3','replica-4')
$shaper = Join-Path $PSScriptRoot 'Set-NetworkProfile.ps1'
. (Join-Path $PSScriptRoot 'NetworkReset.ps1')
$runId = 'matched-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$directory = Join-Path $repo ".lab/pytorch-results/$runId"
$null = New-Item -ItemType Directory -Path $directory
function Save($name,$value) {
    $path = Join-Path $directory $name
    $stream = [IO.File]::Open($path,[IO.FileMode]::CreateNew)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 40)); $stream.Write($bytes,0,$bytes.Length) }
    finally { $stream.Dispose() }
}
function Docker([string[]]$Arguments,[string]$Log) {
    $lines = & $docker @Arguments 2>&1
    $code = $LASTEXITCODE
    $value = ($lines | ForEach-Object { $_.ToString() }) -join "`n"
    if ($Log) { Save $Log @{exit_code=$code;output=$value} }
    if ($code -ne 0) { throw "Docker exit ${code}: $value" }
    return $value
}
function Snapshot {
    $records = @()
    foreach ($service in @($services + 'pipeline-benchmark')) {
        $id = Docker ($composeArgs + @('ps','-q',$service))
        $item = @((Docker @('inspect',$id)) | ConvertFrom-Json)[0]
        if (-not $item.State.Running -or $item.Image -ne $ExpectedImage) { throw "Unexpected runtime for $service" }
        $expectedCpu = if ($service -eq 'pipeline-benchmark') { 1000000000 } else { 2000000000 }
        $expectedMemory = if ($service -eq 'pipeline-benchmark') { 1073741824 } else { 3221225472 }
        if ($item.HostConfig.NanoCpus -ne $expectedCpu -or $item.HostConfig.Memory -ne $expectedMemory) { throw "Resource budget mismatch: $service" }
        $records += [ordered]@{service=$service;image=$item.Image;container_id=$id;
            nano_cpus=$item.HostConfig.NanoCpus;memory_limit_bytes=$item.HostConfig.Memory;
            memory_current_bytes=[long](Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.current')));
            memory_peak_bytes=[long](Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.peak')));
            cpu_stat=(Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/cpu.stat')));
            memory_events=(Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.events')))}
    }
    return $records
}
function Reset($name) {
    $result = Invoke-ComposeNetworkReset -Services $services -Output (Join-Path $directory $name) `
        -ShaperPath $shaper -ComposeFile $compose -ProjectName $project
    if (-not $result.success) { throw 'Replica network reset failed; inspect retained per-target evidence.' }
}
if ($ExpectedImage -notmatch '^sha256:[0-9a-f]{64}$') { throw 'ExpectedImage must be an immutable Docker image digest.' }
$sourceHashes = [ordered]@{}
foreach ($file in @('lab/matched_control.py','lab/benchmark.py','lab/pipeline_benchmark.py','scripts/Invoke-MatchedControl.ps1','scripts/Set-NetworkProfile.ps1','scripts/NetworkReset.ps1')) {
    $sourceHashes[$file] = (Get-FileHash (Join-Path $repo $file) -Algorithm SHA256).Hash.ToLower()
}
$plan = [ordered]@{schema_version=1;run_id=$runId;kind='matched LAN control';
    source_commit=(git -C $repo rev-parse HEAD);compose_sha256=(Get-FileHash $compose -Algorithm SHA256).Hash.ToLower();
    runtime_image=$ExpectedImage;source_sha256=$sourceHashes;created_utc=[DateTime]::UtcNow.ToString('o');
    cases=@(1..3 | ForEach-Object { @{repetition=$_;profile='lan';prompt_tokens=128;new_tokens=64;concurrency=3;completion_target=100;maximum_attempts=200} });
    inference_cpu_quota=8;inference_memory_limit_bytes=12884901888;client_cpu_quota=1;client_memory_limit_bytes=1073741824;
    topology='four complete-model copies with replica-local KV caches; thin client dispatch; pipeline coordinator budget included in matching';
    estimate=@{basis='unmeasured replica control; no reliable duration estimate';seconds=$null;timeout_attempt_ceiling_seconds=60000};
    limitations=@('same-host CPU quotas are ceilings','memory peaks are container lifetime','energy and thermals unmeasured')}
Save 'plan.json' $plan
Write-Output "Frozen control plan: $directory"
if ($PlanOnly) { return }
try { $experimentLock = [IO.File]::Open((Join-Path $repo '.lab/pytorch-experiment.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
catch { throw 'Another lab experiment owns the network/resource lock.' }
$summary = [ordered]@{success=$false;cases=@();error=$null;final_reset_verified=$false}
try {
    $tagImage = (Docker @('image','inspect','steamboat-pytorch:cpu','--format','{{.Id}}')).Trim()
    if ($tagImage -ne $ExpectedImage) { throw 'Validation image tag differs from frozen runtime image.' }
    foreach ($service in @('coordinator','worker-1','worker-2','worker-3')) {
        $id = Docker ($composeArgs + @('ps','--status','running','-q',$service))
        if ($id) { throw "Stop pipeline inference service before control measurements: $service" }
    }
    Save 'resources-before.json' (Snapshot)
    Reset 'preflight-reset.json'
    $null = Docker ($composeArgs + @('run','--rm','--no-deps','service-check','python','-m','lab.matched_control','check','--output',"/results/$runId/gate.json")) 'gate-log.json'
    foreach ($case in $plan.cases) {
        $rep = $case.repetition
        $record = [ordered]@{repetition=$rep;success=$false;error=$null;reset_verified=$false}
        $probeToken = [Guid]::NewGuid().ToString('N')
        $startedProbes = @()
        try {
            foreach ($service in $services) {
                $null = Docker ($composeArgs + @('exec','-d',$service,'python','-m','lab.network_probe','serve','--host','0.0.0.0','--port','50054','--private-network','--token',$probeToken))
                $startedProbes += $service
            }
            foreach ($service in $services) {
                $probe = Docker ($composeArgs + @('exec','-T','pipeline-benchmark','python','-m','lab.network_probe','measure','--host',$service,'--port','50054','--token',$probeToken))
                Save "r$rep-$service-probe.json" ($probe | ConvertFrom-Json)
            }
            foreach ($service in $startedProbes) {
                $null = Docker ($composeArgs + @('exec','-T',$service,'python','-m','lab.network_probe','stop','--port','50054','--token',$probeToken))
            }
            $startedProbes = @()
            Save "r$rep-resources-before.json" (Snapshot)
            $null = Docker ($composeArgs + @('exec','-T','pipeline-benchmark','python','-m','lab.benchmark','bench','--backend','matched',
                '--prompt-tokens','128','--new-tokens','64','--concurrency','3','--requests','100','--completion-target','100','--max-attempts','200',
                '--repetition',"$rep",'--run-order-index',"$($rep-1)",'--label',"$runId-r$rep",'--output',"/results/$runId/r$rep-benchmark.json")) "r$rep-log.json"
            $record.success=$true
        } catch { $record.error=$_.Exception.Message }
        finally {
            foreach ($service in $startedProbes) {
                try { $null = Docker ($composeArgs + @('exec','-T',$service,'python','-m','lab.network_probe','stop','--port','50054','--token',$probeToken)) }
                catch { $record.error="$($record.error); probe cleanup: $($_.Exception.Message)"; $record.success=$false }
            }
            try { Reset "r$rep-reset.json"; $record.reset_verified=$true }
            catch { $record.error = "$($record.error); $($_.Exception.Message)"; $record.success=$false }
            Save "r$rep-resources-after.json" (Snapshot)
            Save "r$rep-outcome.json" $record
            $summary.cases += $record
        }
        if (-not $record.reset_verified) { throw 'Stopping after unverified reset.' }
    }
    $summary.success = @($summary.cases | Where-Object { -not $_.success }).Count -eq 0
} catch { $summary.error=$_.Exception.Message }
finally {
    try { Reset 'final-reset.json'; $summary.final_reset_verified=$true }
    catch { $summary.error="$($summary.error); $($_.Exception.Message)"; $summary.success=$false }
    try { Save 'summary.json' $summary }
    finally { $experimentLock.Dispose() }
}
Write-Output "Control experiment: $directory"
if (-not $summary.success) { throw 'Control contains failures; preserved evidence requires review.' }
