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
    [switch]$PlanOnly
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
        $records += [ordered]@{service=$service; image=$item.Image; running=$item.State.Running;
            oom_killed=$item.State.OOMKilled; memory_limit_bytes=$item.HostConfig.Memory;
            nano_cpus=$item.HostConfig.NanoCpus; port_bindings=$item.HostConfig.PortBindings;
            cap_add=$item.HostConfig.CapAdd; memory_peak_bytes=[long]$peak; memory_events=$events;
            memory_peak_scope='container lifetime; not reset per case'; ready_log="$Label-$service.log"}
    }
    return $records
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
$plan = [ordered]@{schema_version=1; created_utc=[DateTime]::UtcNow.ToString('o');mode=$Mode;
    run_id=$runId;source_commit=(git -C $repo rev-parse HEAD);compose=$compose;project=$project;
    cases=$cases;order_policy='three deterministic permutations with position sums equal (odd configuration count) or differing by one (even count)';
    completion_policy='keep every failed attempt; Full stops at >=100 completions or 200 attempts';
    limitations=@('same-host CPU lab','quotas are not dedicated cores','smoke is not performance evidence',
        'unselected performance combinations remain uncollected','thermal state is not measured')}
Save-Json (Join-Path $directory 'plan.json') $plan
Write-Output "Frozen plan: $directory"
if ($PlanOnly) { return }
$summary = [ordered]@{run_id=$runId;success=$false;cases=@();final_reset_verified=$false;error=$null}
try {
    # No mutation until every target's status and tools have been checked.
    & $shaper -ComposeFile $compose -ProjectName $project -Services $targets -StatusOnly -Output (Join-Path $directory 'preflight-qdiscs.json') | Out-Host
    Save-Json (Join-Path $directory 'resources-before.json') (Resources 'resources-before')
    $null = Invoke-Docker ($composeArgs + @('exec','-T','coordinator','tc','-V')) (Join-Path $directory 'tc-version.txt')
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
            $null = Invoke-Docker ($composeArgs + $args) (Join-Path $directory "$prefix-benchmark.log")
            $record.success=$true
        } catch { $record.error=$_.Exception.Message; Write-Warning $record.error }
        finally {
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
    Save-Json (Join-Path $directory 'summary.json') $summary
}
Write-Output "Experiment: $directory"
if (-not $summary.success) { throw 'Experiment contains failures; inspect retained summary and run records.' }
