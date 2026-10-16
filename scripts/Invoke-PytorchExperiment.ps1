<#
.SYNOPSIS
Run a frozen M5 smoke or performance matrix and verify network reset in finally.
.DESCRIPTION
Requires healthy workers, coordinator and pipeline-benchmark from compose.pytorch.yaml.
Smoke uses six small cases. Full selects the declared matrix, three repetitions,
100 completed requests and a 200-attempt ceiling. Optional Full filters select a
smaller declared subset; remaining combinations are explicitly uncollected.
All results, failures, TCP probes, resource observations and qdiscs are retained.
.EXAMPLE
.\scripts\Invoke-PytorchExperiment.ps1 -Mode Smoke
.EXAMPLE
.\scripts\Invoke-PytorchExperiment.ps1 -Mode Full -Profiles lan -PromptTokens 128 -Concurrencies 3
.EXAMPLE
.\scripts\Invoke-PytorchExperiment.ps1 -Mode Full -PlanOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('Smoke','Full')][string]$Mode = 'Smoke',
    [ValidateSet('lan','delay10','delay25','delay50','rate20','rate100','rate1000','wan25-100')]
    [string[]]$Profiles,
    [ValidateSet(128,1024)][int[]]$PromptTokens = @(128,1024),
    [ValidateSet(1,3,8)][int[]]$Concurrencies = @(1,3,8),
    [switch]$PlanOnly,
    [string]$FrozenPlanPath,
    [string]$ExpectedImage
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $repo 'compose.pytorch.yaml'
$project = 'steamboat-pytorch-m1'
$docker = (Get-Command docker -CommandType Application | Select-Object -First 1).Source
$composeArgs = @('compose','-f',$compose,'-p',$project)
$shaper = Join-Path $PSScriptRoot 'Set-NetworkProfile.ps1'
. (Join-Path $PSScriptRoot 'NetworkReset.ps1')
$targets = @('worker-1','worker-2','worker-3','coordinator')
$workers = @('worker-1','worker-2','worker-3')
$runId = 'm5-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$directory = Join-Path $repo ".lab/pytorch-results/$runId"
$null = New-Item -ItemType Directory -Path $directory
$utf8 = New-Object Text.UTF8Encoding($false)
function Save-Json($Path,$Value) {
    if (Test-Path -LiteralPath $Path) { throw "Refusing to replace evidence: $Path" }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30), $utf8)
}
function Get-EvidenceFingerprint([string]$Path) {
    $rootPath = [IO.Path]::GetFullPath($Path)
    $buffer = [IO.MemoryStream]::new()
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $rootPath -File -Recurse | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($rootPath.Length).TrimStart('\','/').Replace('\','/')
            $nameBytes = [Text.Encoding]::UTF8.GetBytes($relative)
            $buffer.Write($nameBytes,0,$nameBytes.Length); $buffer.WriteByte(0)
            $fileHash = [Convert]::FromHexString((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)
            $buffer.Write($fileHash,0,$fileHash.Length); $buffer.WriteByte(10)
        }
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($buffer.ToArray())).ToLowerInvariant()
    } finally { $buffer.Dispose() }
}
function Invoke-Docker([string[]]$Arguments,[string]$Log) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $lines = & $docker @Arguments 2>&1; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $saved }
    $result = ($lines | ForEach-Object { $_.ToString() }) -join "`n"
    if ($Log) { [IO.File]::WriteAllText($Log,$result,$utf8) }
    if ($code -ne 0) { throw "Docker exit ${code}: $($Arguments -join ' ')`n$result" }
    return $result
}
function Set-Profile([string]$Name,[string]$Evidence,[double]$Delay=0,[double]$Rate=0) {
    $parameters = @{ComposeFile=$compose; ProjectName=$project; Services=$targets; Output=$Evidence}
    if ($Name -eq 'lan') { & $shaper @parameters -Profile lan | Out-Host }
    else { & $shaper @parameters -Profile custom -DelayMs $Delay -RateMbit $Rate | Out-Host }
}
function Reset-Lan([string]$Evidence) {
    return Invoke-ComposeNetworkReset -Services $targets -Output $Evidence -ShaperPath $shaper `
        -ComposeFile $compose -ProjectName $project
}
function Resources([string]$Label) {
    $records = @()
    foreach ($service in @($targets + 'pipeline-benchmark')) {
        $id = Invoke-Docker ($composeArgs + @('ps','-q',$service))
        $item = @( (Invoke-Docker @('inspect',$id)) | ConvertFrom-Json )[0]
        $peak = Invoke-Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.peak'))
        $events = Invoke-Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.events'))
        $null = Invoke-Docker ($composeArgs + @('logs','--no-color','--tail','100',$service)) (Join-Path $directory "$Label-$service.log")
        $configuration = [ordered]@{command=@($item.Config.Cmd);environment=@($item.Config.Env | Sort-Object);
            mounts=@($item.Mounts | ForEach-Object { [ordered]@{source=$_.Source;destination=$_.Destination;rw=$_.RW} } | Sort-Object destination)}
        $configurationText = $configuration | ConvertTo-Json -Depth 10 -Compress
        $configurationHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($configurationText))).ToLowerInvariant()
        $records += [ordered]@{service=$service; image=$item.Image; image_reference=$item.Config.Image; running=$item.State.Running;
            config_fingerprint=$configurationHash;
            oom_killed=$item.State.OOMKilled; memory_limit_bytes=$item.HostConfig.Memory;
            nano_cpus=$item.HostConfig.NanoCpus; port_bindings=$item.HostConfig.PortBindings;
            cap_add=$item.HostConfig.CapAdd; memory_peak_bytes=[long]$peak; memory_events=$events;
            memory_peak_scope='container lifetime; not reset per case'; ready_log="$Label-$service.log"}
    }
    return $records
}
function CgroupUsage([string]$Label) {
    $snapshot = [ordered]@{label=$Label;captured_utc=[DateTime]::UtcNow.ToString('o');services=@()}
    foreach ($service in @($targets + 'pipeline-benchmark')) {
        $cpuText = Invoke-Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/cpu.stat')) $null
        $memory = Invoke-Docker ($composeArgs + @('exec','-T',$service,'cat','/sys/fs/cgroup/memory.current')) $null
        $cpu = [ordered]@{}
        foreach ($line in ($cpuText -split '\r?\n')) {
            if ($line -match '^([a-zA-Z0-9_]+)\s+(\d+)$') { $cpu[$Matches[1]]=[long]$Matches[2] }
        }
        $snapshot.services += [ordered]@{service=$service;cpu_stat=$cpu;memory_current_bytes=[long]$memory}
    }
    return $snapshot
}
$settings = @(
    @{name='lan';delay=0;rate=0}, @{name='delay10';delay=10;rate=0},
    @{name='delay25';delay=25;rate=0}, @{name='delay50';delay=50;rate=0},
    @{name='rate20';delay=0;rate=20}, @{name='rate100';delay=0;rate=100},
    @{name='rate1000';delay=0;rate=1000}, @{name='wan25-100';delay=25;rate=100})
$cases = @()
if ($Mode -eq 'Smoke') {
    if ($Profiles -or $PSBoundParameters.ContainsKey('PromptTokens') -or $PSBoundParameters.ContainsKey('Concurrencies')) {
        throw 'Filters apply only to Full; the six Smoke cases are fixed.'
    }
    foreach ($spec in @(@('lan',128,8,1,3),@('lan',128,8,3,6),@('lan',1024,64,8,8),
                        @('delay10',128,8,3,6),@('rate20',128,8,3,6),@('wan25-100',128,8,3,6))) {
        $setting = @($settings | Where-Object name -eq $spec[0])[0]
        $cases += [ordered]@{profile=$spec[0];delay_ms=$setting.delay;rate_mbit=$setting.rate;
            prompt_tokens=$spec[1];new_tokens=$spec[2];concurrency=$spec[3];requests=$spec[4];
            repetition=1;completion_target=$null;maximum_attempts=$spec[4]}
    }
} else {
    $selected = @($settings | Where-Object { -not $Profiles -or $Profiles -contains $_.name })
    $base = @()
    foreach ($setting in $selected) { foreach ($prompt in @($PromptTokens | Select-Object -Unique)) { foreach ($concurrency in @($Concurrencies | Select-Object -Unique)) {
        $base += [ordered]@{profile=$setting.name;delay_ms=$setting.delay;rate_mbit=$setting.rate;
            prompt_tokens=$prompt;new_tokens=64;concurrency=$concurrency;requests=100;
            completion_target=100;maximum_attempts=200}
    } } }
    # Construct three permutations whose position sums are identical for odd N,
    # or differ by exactly one for even N. Every configuration therefore has the
    # same mean position (within one third of a slot) across the three repetitions.
    $orders = @(@(0..($base.Count-1)), (New-Object 'int[]' $base.Count), (New-Object 'int[]' $base.Count))
    $shift = [int][Math]::Floor($base.Count / 2)
    for ($index=0; $index -lt $base.Count; $index++) {
        $secondPosition = ($index + $shift) % $base.Count
        $sum = [int][Math]::Floor(3 * ($base.Count - 1) / 2)
        if ($base.Count % 2 -eq 0 -and $index -lt $shift) { $sum++ }
        $thirdPosition = $sum - $index - $secondPosition
        $orders[1][$secondPosition] = $index
        $orders[2][$thirdPosition] = $index
    }
    for ($rep=1; $rep -le 3; $rep++) {
        foreach ($index in $orders[$rep-1]) {
            $case = [ordered]@{}
            foreach ($key in $base[$index].Keys) { $case[$key]=$base[$index][$key] }
            $case.repetition=$rep
            $cases += $case
        }
    }
}
$sourceCommit = (& git -C $repo rev-parse HEAD).Trim()
$composeHash = (Get-FileHash -LiteralPath $compose -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceRoots = @('src','lab','scripts','configs','docker') | ForEach-Object { Join-Path $repo $_ }
$sourceFiles = @($sourceRoots | ForEach-Object { Get-ChildItem -LiteralPath $_ -File -Recurse -ErrorAction SilentlyContinue } |
    Where-Object { $_.Extension -notin @('.pyc','.pyo') -and $_.FullName -notmatch '[\\/](?:__pycache__|node_modules|\.venv|\.git)[\\/]' } |
    Sort-Object { $_.FullName.Substring($repo.Length) })
$sourceManifest = ($sourceFiles | ForEach-Object {
    $_.FullName.Substring($repo.Length).Replace('\','/') + ':' +
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}) -join "`n"
$sourceFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($sourceManifest))).ToLowerInvariant()
$imageReference = 'steamboat-pytorch:cpu'
if (-not $ExpectedImage) {
    $ExpectedImage = (& $docker image inspect $imageReference --format '{{.Id}}' 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $ExpectedImage) {
        throw 'Plan creation needs a locally resolved runtime image; supply -ExpectedImage sha256:… when Docker image inspection is unavailable.'
    }
}
if ($ExpectedImage -notmatch '^sha256:[0-9a-f]{64}$') { throw '-ExpectedImage must be a resolved sha256 image ID.' }
$plan = [ordered]@{schema_version=1; created_utc=[DateTime]::UtcNow.ToString('o');mode=$Mode;
    run_id=$runId;source_commit=$sourceCommit;source_fingerprint=$sourceFingerprint;compose=$compose;compose_sha256=$composeHash;project=$project;
    runtime_image=$ExpectedImage;runtime_image_reference=$imageReference;
    cases=$cases;order_policy='three deterministic permutations with position sums equal (odd configuration count) or differing by one (even count)';
    completion_policy='keep every failed attempt; Full stops at >=100 completions or 200 attempts';
    limitations=@('same-host CPU lab','quotas are not dedicated cores','smoke is not performance evidence',
        'cgroup CPU counters are cumulative; memory.current is an instantaneous container snapshot and includes unrelated activity in that container',
        'unselected performance combinations remain uncollected','thermal state is not measured')}
if ($FrozenPlanPath) {
    $frozenPath = (Resolve-Path -LiteralPath $FrozenPlanPath).Path
    $frozen = Get-Content -LiteralPath $frozenPath -Raw | ConvertFrom-Json -AsHashtable
    if (-not $frozen.continuation -or -not $frozen.continuation.parent_plan_sha256) {
        throw 'Frozen plans must be continuation plans with explicit parent evidence references.'
    }
    if ($frozen.source_commit -ne $sourceCommit -or $frozen.source_fingerprint -ne $sourceFingerprint) { throw 'Frozen plan source identity does not match this checkout.' }
    if ($frozen.compose_sha256 -ne $composeHash) { throw 'Frozen plan compose configuration hash does not match.' }
    if ($frozen.runtime_image -ne $ExpectedImage) { throw 'Frozen plan runtime image digest differs from the expected image.' }
    if ($frozen.mode -ne $Mode) { throw 'Frozen plan mode differs from -Mode.' }
    if (@($frozen.cases).Count -eq 0 -or @($frozen.continuation.unfinished_case_indices).Count -ne @($frozen.cases).Count) {
        throw 'Frozen continuation has an empty or inconsistent case list.'
    }
    $parentDirectory = [string]$frozen.continuation.parent_directory
    $parentPlanPath = Join-Path $parentDirectory 'plan.json'
    if (-not (Test-Path -LiteralPath $parentPlanPath)) { throw 'Frozen continuation parent plan is missing.' }
    $actualParentPlanHash = (Get-FileHash -LiteralPath $parentPlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualParentPlanHash -ne $frozen.continuation.parent_plan_sha256) { throw 'Frozen continuation parent plan hash changed.' }
    if ((Get-EvidenceFingerprint $parentDirectory) -ne $frozen.continuation.parent_evidence_sha256) {
        throw 'Frozen continuation parent evidence changed after plan creation.'
    }
    $parentPlan = Get-Content -LiteralPath $parentPlanPath -Raw | ConvertFrom-Json -AsHashtable
    if (@($frozen.continuation.unfinished_case_indices | Select-Object -Unique).Count -ne $frozen.cases.Count) {
        throw 'Frozen continuation repeats a parent case index.'
    }
    for ($caseIndex=0; $caseIndex -lt $frozen.cases.Count; $caseIndex++) {
        $parentIndex = [int]$frozen.continuation.unfinished_case_indices[$caseIndex]
        if ($parentIndex -lt 0 -or $parentIndex -ge $parentPlan.cases.Count) { throw 'Frozen continuation references an invalid parent case.' }
        $frozenCase = ConvertTo-Json -InputObject $frozen.cases[$caseIndex] -Depth 20 -Compress
        $parentCase = ConvertTo-Json -InputObject $parentPlan.cases[$parentIndex] -Depth 20 -Compress
        if ($frozenCase -ne $parentCase) { throw 'Frozen continuation cases differ from the referenced parent plan.' }
        $spec = $frozen.cases[$caseIndex]
        $setting = @($settings | Where-Object name -eq $spec.profile)
        if ($setting.Count -ne 1 -or $spec.delay_ms -ne $setting[0].delay -or $spec.rate_mbit -ne $setting[0].rate -or
            $spec.prompt_tokens -notin @(128,1024) -or $spec.concurrency -notin @(1,3,8)) { throw 'Invalid frozen workload/network configuration.' }
        if ($Mode -eq 'Full' -and ($spec.new_tokens -ne 64 -or $spec.requests -ne 100 -or $spec.completion_target -ne 100 -or
            $spec.maximum_attempts -ne 200 -or $spec.repetition -notin @(1,2,3))) { throw 'Invalid frozen Full completion policy.' }
    }
    if ($Profiles -or $PSBoundParameters.ContainsKey('PromptTokens') -or $PSBoundParameters.ContainsKey('Concurrencies')) {
        throw 'Frozen plans own their complete case list; filters cannot be combined with -FrozenPlanPath.'
    }
    $frozenHash = (Get-FileHash -LiteralPath $frozenPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $plan = $frozen
    $plan.run_id = $runId
    $plan.execution_of_frozen_plan = [ordered]@{path=$frozenPath;sha256=$frozenHash}
    $cases = @($plan.cases)
}
Save-Json (Join-Path $directory 'plan.json') $plan
Write-Output "Frozen plan: $directory"
if ($PlanOnly) { return }
$lockPath = Join-Path $repo '.lab/pytorch-experiment.lock'
try { $experimentLock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
catch { throw 'Another lab experiment owns the network/resource lock. Wait for it to finish before continuing.' }
$summary = [ordered]@{run_id=$runId;success=$false;cases=@();final_reset_verified=$false;error=$null}
try {
    # No mutation until every target's status and tools have been checked.
    if ($plan.Contains('continuation') -and (Get-EvidenceFingerprint $plan.continuation.parent_directory) -ne $plan.continuation.parent_evidence_sha256) {
        throw 'Parent evidence changed before the experiment lock was acquired.'
    }
    & $shaper -ComposeFile $compose -ProjectName $project -Services $targets -StatusOnly -Output (Join-Path $directory 'preflight-qdiscs.json') | Out-Host
    Save-Json (Join-Path $directory 'resources-before.json') (Resources 'resources-before')
    if ($plan.Contains('continuation') -and $plan.continuation.parent_runtime_image) {
        $images = @(Get-Content -LiteralPath (Join-Path $directory 'resources-before.json') -Raw | ConvertFrom-Json |
            ForEach-Object { $_.image } | Sort-Object -Unique)
        if ($images.Count -ne 1 -or $images[0] -ne $plan.continuation.parent_runtime_image) {
            throw 'Runtime image identity differs from the frozen parent run.'
        }
    }
    $actualImages = @(Get-Content -LiteralPath (Join-Path $directory 'resources-before.json') -Raw | ConvertFrom-Json |
        Select-Object -ExpandProperty image -Unique)
    if ($actualImages.Count -ne 1 -or $actualImages[0] -ne $plan.runtime_image) {
        throw 'Resolved runtime image digest differs from frozen plan.'
    }
    $resourceRows = @(Get-Content -LiteralPath (Join-Path $directory 'resources-before.json') -Raw | ConvertFrom-Json)
    foreach ($resource in $resourceRows) {
        $expectedCpu = if ($resource.service -eq 'pipeline-benchmark') { 1000000000L } else { 2000000000L }
        $expectedMemory = if ($resource.service -eq 'pipeline-benchmark') { 1073741824L } else { 3221225472L }
        $limitsMatch = $resource.running -and [long]$resource.nano_cpus -eq $expectedCpu -and [long]$resource.memory_limit_bytes -eq $expectedMemory -and $resource.image_reference -eq $plan.runtime_image_reference
        if (-not $limitsMatch) {
            throw "Frozen runtime limits mismatch for service $($resource.service)."
        }
    }
    if ($plan.Contains('continuation') -and (Test-Path -LiteralPath (Join-Path $plan.continuation.parent_directory 'resources-before.json'))) {
        $parentResources = Get-Content -LiteralPath (Join-Path $plan.continuation.parent_directory 'resources-before.json') -Raw | ConvertFrom-Json
        $currentByService = @{}; foreach ($resource in $resourceRows) { $currentByService[$resource.service]=$resource }
        foreach ($previous in $parentResources) {
            $current = $currentByService[$previous.service]
            $sameConfiguration = $current -and $current.image -eq $previous.image -and $current.image_reference -eq $previous.image_reference -and $current.config_fingerprint -eq $previous.config_fingerprint -and [long]$current.nano_cpus -eq [long]$previous.nano_cpus -and [long]$current.memory_limit_bytes -eq [long]$previous.memory_limit_bytes -and ($current.cap_add | ConvertTo-Json -Compress) -eq ($previous.cap_add | ConvertTo-Json -Compress)
            if (-not $sameConfiguration) {
                throw "Runtime configuration differs from frozen parent service $($previous.service)."
            }
        }
    }
    $null = Invoke-Docker ($composeArgs + @('exec','-T','coordinator','tc','-V')) (Join-Path $directory 'tc-version.txt')
    $tagImage = (& $docker image inspect $imageReference --format '{{.Id}}' 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or $tagImage -ne $plan.runtime_image) {
        throw 'Configured runtime tag no longer resolves to the frozen image digest.'
    }
    # Re-establish numerical/lifecycle correctness for this exact running service
    # before collecting any benchmark or installing a shaped network profile.
    $null = Invoke-Docker ($composeArgs + @('run','--rm','--no-deps','service-check',
        'python','-m','steamboat_runtime.service_check','--coordinator','coordinator:50052',
        '--output',"/results/$runId")) (Join-Path $directory 'correctness-gate.log')
    for ($index=0; $index -lt $cases.Count; $index++) {
        $case = $cases[$index]
        $prefix = '{0:d3}-{1}-p{2}-c{3}-r{4}' -f $index,$case.profile,$case.prompt_tokens,$case.concurrency,$case.repetition
        $record = [ordered]@{index=$index;config=$case;success=$false;reset_verified=$false;error=$null;reset_error=$null;probe_stop_errors=@()}
        $token = [Guid]::NewGuid().ToString('N')
        $startedProbes = @()
        try {
            Set-Profile $case.profile (Join-Path $directory "$prefix-applied.json") $case.delay_ms $case.rate_mbit
            foreach ($worker in $workers) {
                # Starting an already-bound probe exits unsuccessfully; the
                # ownership token check prevents using/stopping another run's probe.
                $null = Invoke-Docker ($composeArgs + @('exec','-d',$worker,'python','-m','lab.network_probe','serve','--host','0.0.0.0','--private-network','--token',$token))
                $startedProbes += $worker
            }
            foreach ($worker in $workers) {
                $probe = Invoke-Docker ($composeArgs + @('exec','-T','coordinator','python','-m','lab.network_probe','measure','--host',$worker,'--token',$token))
                Save-Json (Join-Path $directory "$prefix-$worker-probe.json") ($probe | ConvertFrom-Json)
            }
            foreach ($worker in $startedProbes) {
                $null = Invoke-Docker ($composeArgs + @('exec','-T',$worker,'python','-m','lab.network_probe','stop','--token',$token))
            }
            $startedProbes=@()
            $args = @('exec','-T','pipeline-benchmark','python','-m','lab.benchmark','bench','--backend','pipeline',
                '--coordinator','coordinator:50052','--prompt-tokens',"$($case.prompt_tokens)",'--new-tokens',"$($case.new_tokens)",
                '--concurrency',"$($case.concurrency)",'--requests',"$($case.requests)",'--label',"$runId-$prefix",
                '--repetition',"$($case.repetition)",'--run-order-index',"$index",'--output',"/results/$runId/$prefix-benchmark.json")
            if ($Mode -eq 'Full') { $args += @('--completion-target','100','--max-attempts','200') }
            try {
                $usageBefore = CgroupUsage "$prefix-before"
                Save-Json (Join-Path $directory "$prefix-usage-before.json") $usageBefore
            } catch { $record.usage_before_error=$_.Exception.Message; Write-Warning $record.usage_before_error }
            $null = Invoke-Docker ($composeArgs + $args) (Join-Path $directory "$prefix-benchmark.log")
            $record.success=$true
        } catch { $record.error=$_.Exception.Message; Write-Warning $record.error }
        finally {
            try {
                $usageAfter = CgroupUsage "$prefix-after"
                Save-Json (Join-Path $directory "$prefix-usage-after.json") $usageAfter
            } catch { $record.usage_after_error=$_.Exception.Message; Write-Warning $record.usage_after_error }
            foreach ($worker in $startedProbes) {
                try { $null=Invoke-Docker ($composeArgs + @('exec','-T',$worker,'python','-m','lab.network_probe','stop','--token',$token)) }
                catch { $record.probe_stop_errors += $_.Exception.Message }
            }
            try {
                $reset = Reset-Lan (Join-Path $directory "$prefix-reset.json")
                $record.reset_verified=[bool]$reset.success
                if (-not $reset.success) { $record.reset_error=($reset.errors | ConvertTo-Json -Compress) }
            } catch { $record.reset_error=$_.Exception.Message }
            if (-not $record.reset_verified) { $record.success=$false }
            $summary.cases += $record
            Save-Json (Join-Path $directory "$prefix-outcome.json") $record
        }
        if (-not $record.reset_verified) { throw 'Stopping matrix because reset could not be verified.' }
    }
    Save-Json (Join-Path $directory 'resources-after.json') (Resources 'resources-after')
    $summary.success = @($summary.cases | Where-Object { -not $_.success }).Count -eq 0
} catch { $summary.error=$_.Exception.Message }
finally {
    try {
        $finalReset = Reset-Lan (Join-Path $directory 'final-reset.json')
        $summary.final_reset_verified=[bool]$finalReset.success
        if (-not $finalReset.success) {
            $finalError = "Final reset errors: $($finalReset.errors | ConvertTo-Json -Compress)"
            $summary.error = if ($summary.error) { "$($summary.error); $finalError" } else { $finalError }
            $summary.success=$false
        }
    }
    catch {
        $summary.error = if ($summary.error) { "$($summary.error); final reset failed: $($_.Exception.Message)" } else { "Final reset failed: $($_.Exception.Message)" }
        $summary.success=$false
    }
    try { Save-Json (Join-Path $directory 'summary.json') $summary }
    finally { $experimentLock.Dispose() }
}
Write-Output "Experiment: $directory"
if (-not $summary.success) { throw 'Experiment contains failures; inspect retained summary and run records.' }
