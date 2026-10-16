<#
.SYNOPSIS
Set or inspect packet shaping inside the Steamboat container lab.
.DESCRIPTION
Only changes the eth0 egress queue in the selected Compose containers. LAN removes
this script's root netem queue. WAN adds 25 ms per direction and a 100 Mbit/s cap.
Shaping both peers adds approximately 50 ms to their round-trip latency. Custom
values apply to each selected sender, not to the laptop's network interface.
Settings last until reset or container recreation. This operation is not atomic:
if a service fails, the script reports which services were already changed.
The owned netem handle is 1a50:. Other root queues are never replaced or deleted.
.PARAMETER Profile
lan, wan, or custom. Defaults to lan (remove an existing root netem queue).
.PARAMETER DelayMs
Custom added one-way delay, in milliseconds. Default 0.
.PARAMETER JitterMs
Custom delay variation, in milliseconds; cannot exceed DelayMs. Default 0.
.PARAMETER LossPercent
Custom independent packet loss percentage, from 0 through 100. Default 0.
.PARAMETER RateMbit
Custom egress bandwidth cap, in Mbit/s. Zero means no configured cap. Default 0.
.PARAMETER Services
Selected worker-1, worker-2, worker-3, client or coordinator services.
Defaults to the three workers and the selected lab's relay.
.PARAMETER ComposeFile
Explicit Compose configuration. Defaults to the historical Petals lab.
.PARAMETER ProjectName
Explicit Compose project. Required with a custom ComposeFile.
.PARAMETER Output
Optional new JSON evidence file containing before/after qdiscs and errors.
.PARAMETER StatusOnly
Show current qdiscs without changing anything.
.EXAMPLE
.\scripts\Set-NetworkProfile.ps1 -Profile wan
.EXAMPLE
.\scripts\Set-NetworkProfile.ps1 -Profile custom -DelayMs 50 -JitterMs 5 -LossPercent 0.1 -RateMbit 20 -Services worker-2
.EXAMPLE
.\scripts\Set-NetworkProfile.ps1 -StatusOnly
.EXAMPLE
.\scripts\Set-NetworkProfile.ps1 -Profile lan
#>
[CmdletBinding(DefaultParameterSetName = 'Profile')]
param (
    [Parameter(ParameterSetName = 'Profile')]
    [ValidateSet('lan', 'wan', 'custom')]
    [string]$Profile = 'lan',

    [Parameter(ParameterSetName = 'Profile')]
    [ValidateRange(0.0, 60000.0)]
    [double]$DelayMs = 0,

    [Parameter(ParameterSetName = 'Profile')]
    [ValidateRange(0.0, 60000.0)]
    [double]$JitterMs = 0,

    [Parameter(ParameterSetName = 'Profile')]
    [ValidateRange(0.0, 100.0)]
    [double]$LossPercent = 0,

    [Parameter(ParameterSetName = 'Profile')]
    [ValidateRange(0.0, 100000.0)]
    [double]$RateMbit = 0,

    [ValidateCount(1, 4)]
    [ValidateSet('worker-1', 'worker-2', 'worker-3', 'client', 'coordinator')]
    [string[]]$Services,

    [string]$ComposeFile,

    [ValidatePattern('^[a-z0-9][a-z0-9_-]{0,62}$')]
    [string]$ProjectName = 'steamboat-net-lab',

    [string]$Output,

    [Parameter(Mandatory = $true, ParameterSetName = 'Status')]
    [switch]$StatusOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $StatusOnly) {
    foreach ($parameterName in @('DelayMs', 'JitterMs', 'LossPercent', 'RateMbit')) {
        if ($Profile -ne 'custom' -and $PSBoundParameters.ContainsKey($parameterName)) {
            throw "-$parameterName requires -Profile custom; preset settings cannot be overridden."
        }
        if ([double]::IsNaN((Get-Variable -Name $parameterName -ValueOnly))) {
            throw "-$parameterName must be a finite number."
        }
    }
    if ($JitterMs -gt $DelayMs) {
        throw '-JitterMs cannot exceed -DelayMs.'
    }
    if ($Profile -eq 'wan') {
        $DelayMs = 25
        $RateMbit = 100
    }
}

if ($ComposeFile -and -not $PSBoundParameters.ContainsKey('ProjectName')) {
    throw 'An explicit -ComposeFile requires -ProjectName to avoid targeting another lab.'
}
if (-not $ComposeFile) { $ComposeFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'compose.yaml' }
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Compose configuration is missing: $composeFile"
}
# Resolve the executable rather than a potentially unrelated shell alias/function.
$dockerCommand = Get-Command docker -CommandType Application -ErrorAction Stop | Select-Object -First 1
$ComposeFile = (Resolve-Path -LiteralPath $ComposeFile).Path
$composeArgs = @('compose', '-f', $ComposeFile, '-p', $ProjectName)
if ($Output -and (Test-Path -LiteralPath $Output)) { throw "Evidence file already exists: $Output" }

function Invoke-LabDocker {
    param([string[]]$DockerArguments)

    # Windows PowerShell turns native stderr into ErrorRecords. Collect it and
    # test the actual exit code so both Windows PowerShell and pwsh behave alike.
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $commandOutput = & $dockerCommand.Source @DockerArguments 2>&1
        $commandExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorPreference
    }
    $outputText = ($commandOutput | ForEach-Object { $_.ToString() }) -join "`n"
    if ($commandExitCode -ne 0) {
        throw "Docker command failed (exit $commandExitCode): docker $($DockerArguments -join ' ')`n$outputText"
    }
    return $outputText.Trim()
}

function Get-LabQdisc {
    param([string]$Service)
    return Invoke-LabDocker -DockerArguments ($composeArgs + @('exec', '-T', $Service, 'tc', 'qdisc', 'show', 'dev', 'eth0'))
}

function Format-TcNumber {
    param([double]$Number)
    # Decimal commas from e.g. German Windows locale are not valid tc arguments.
    return $Number.ToString('0.########', [Globalization.CultureInfo]::InvariantCulture)
}

$configuration = (Invoke-LabDocker -DockerArguments ($composeArgs + @('config', '--format', 'json'))) | ConvertFrom-Json
$available = @($configuration.services.PSObject.Properties.Name)
if (-not $Services) {
    $relay = if ($available -contains 'coordinator') { 'coordinator' } else { 'client' }
    $Services = @('worker-1', 'worker-2', 'worker-3', $relay)
}
$selectedServices = @($Services | Select-Object -Unique)
$targetEvidence = @{}
foreach ($service in $selectedServices) {
    if ($available -notcontains $service) { throw "Unknown Compose service: $service" }
    $containerId = Invoke-LabDocker -DockerArguments ($composeArgs + @('ps', '-q', $service))
    if ($containerId -notmatch '^[a-f0-9]{12,64}$') { throw "Expected one running container for $service" }
    $inspection = @( (Invoke-LabDocker -DockerArguments @('inspect', $containerId)) | ConvertFrom-Json )[0]
    if (-not $inspection.State.Running) { throw "Service is stopped: $service" }
    if ($inspection.HostConfig.NetworkMode -in @('host', 'none') -or
        $inspection.HostConfig.NetworkMode -like 'container:*') {
        throw "Service must use its own private Docker network namespace: $service"
    }
    if ($inspection.Config.Labels.'com.docker.compose.project' -ne $ProjectName -or
        $inspection.Config.Labels.'com.docker.compose.service' -ne $service) {
        throw "Container does not belong to the selected Compose project/service: $service"
    }
    if ($inspection.HostConfig.PortBindings -and
        @($inspection.HostConfig.PortBindings.PSObject.Properties | Where-Object { $_.Value }).Count) {
        throw "Published ports are not permitted for a shaping target: $service"
    }
    $networkNames = @($inspection.NetworkSettings.Networks.PSObject.Properties.Name)
    if (-not $networkNames.Count) { throw "Service has no private Docker network: $service" }
    foreach ($networkName in $networkNames) {
        $network = @((Invoke-LabDocker -DockerArguments @('network', 'inspect', $networkName)) | ConvertFrom-Json)[0]
        if (-not $network.Internal) { throw "Service $service is attached to a non-internal network: $networkName" }
    }
    $capabilities = @($inspection.HostConfig.CapAdd | ForEach-Object { $_ -replace '^CAP_', '' })
    if (-not $StatusOnly -and $capabilities -notcontains 'NET_ADMIN') {
        throw "Service lacks NET_ADMIN: $service"
    }
    $targetEvidence[$service] = @{container_id=$containerId; internal_networks=$networkNames;
        cap_add=@($inspection.HostConfig.CapAdd); network_mode=$inspection.HostConfig.NetworkMode}
}
$evidence = [ordered]@{created_utc=[DateTime]::UtcNow.ToString('o'); compose=$ComposeFile;
    project=$ProjectName; services=$selectedServices; profile=$Profile;
    delay_ms=$DelayMs; jitter_ms=$JitterMs; loss_percent=$LossPercent; rate_mbit=$RateMbit;
    status_only=[bool]$StatusOnly; owned_netem_handle='1a50:'; targets=$targetEvidence;
    before=@{}; after=@{}; changed=@(); success=$false; error=$null}
function Save-Evidence {
    if ($Output) {
        $absolute = [IO.Path]::GetFullPath($Output)
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($absolute))
        $stream = [IO.File]::Open($absolute, [IO.FileMode]::CreateNew)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes(($evidence | ConvertTo-Json -Depth 12))
            $stream.Write($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
    }
}

# Preflight every selected service before the first change. A stopped container
# or missing tc therefore cannot leave a partially applied profile at this point.
$currentQdiscs = @{}
foreach ($service in $selectedServices) {
    $currentQdiscs[$service] = Get-LabQdisc -Service $service
    if ($currentQdiscs[$service] -notmatch '(?m)^qdisc noqueue\s+[^\r\n]*\broot\b' -and
        $currentQdiscs[$service] -notmatch '(?m)^qdisc netem 1a50:\s+[^\r\n]*\broot\b') {
        throw "${service}: refusing to replace an unrelated root qdisc; expected noqueue or owned netem 1a50:."
    }
}
$evidence.before = $currentQdiscs
if ($StatusOnly) {
    foreach ($service in $selectedServices) {
        Write-Output ("{0}:`n{1}" -f $service, $currentQdiscs[$service])
    }
    $evidence.after = $currentQdiscs
    $evidence.success = $true
    Save-Evidence
    return
}

$netemArgs = @('qdisc', 'replace', 'dev', 'eth0', 'root', 'handle', '1a50:', 'netem')
if ($DelayMs -gt 0) {
    $netemArgs += @('delay', "$(Format-TcNumber $DelayMs)ms")
    if ($JitterMs -gt 0) { $netemArgs += "$(Format-TcNumber $JitterMs)ms" }
}
if ($LossPercent -gt 0) { $netemArgs += @('loss', "$(Format-TcNumber $LossPercent)%") }
if ($RateMbit -gt 0) { $netemArgs += @('rate', "$(Format-TcNumber $RateMbit)mbit") }

$changedServices = New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($service in $selectedServices) {
        $currentQdisc = Get-LabQdisc -Service $service
        if ($currentQdisc -ne $currentQdiscs[$service]) {
            throw "${service}: root qdisc changed after preflight; refusing to overwrite concurrent changes."
        }
        if ($Profile -eq 'lan') {
            # Do not suppress deletion failures, or remove an unrelated root qdisc.
            if ($currentQdisc -match '(?m)^qdisc netem 1a50:\s+[^\r\n]*\broot\b') {
                $null = Invoke-LabDocker -DockerArguments ($composeArgs + @('exec', '-T', $service, 'tc', 'qdisc', 'del', 'dev', 'eth0', 'root', 'handle', '1a50:'))
                $changedServices.Add($service)
            }
            elseif ($currentQdiscs[$service] -notmatch '(?m)^qdisc noqueue\s+[^\r\n]*\broot\b') {
                throw "${service}: no root netem queue found, but the root queue is not the expected noqueue. Inspect it before assuming LAN conditions."
            }
        }
        else {
            $null = Invoke-LabDocker -DockerArguments ($composeArgs + @('exec', '-T', $service, 'tc') + $netemArgs)
            $changedServices.Add($service)
        }
        $resultQdisc = Get-LabQdisc -Service $service
        $evidence.after[$service] = $resultQdisc
        $expected = if ($Profile -eq 'lan') { 'noqueue' } else { 'netem 1a50:' }
        if ($resultQdisc -notmatch "(?m)^qdisc $expected\s+[^\r\n]*\broot\b") {
            throw "${service}: qdisc verification failed."
        }
        Write-Output ("{0} ({1}):`n{2}" -f $service, $Profile, $resultQdisc)
    }
    $evidence.success = $true
}
catch {
    $evidence.error = $_.Exception.Message
    $changedSummary = if ($changedServices.Count) { $changedServices -join ', ' } else { '(none)' }
    Write-Warning "Profile application stopped. Services changed before this failure: $changedSummary. Inspect with -StatusOnly; restore with -Profile lan. No rollback was attempted."
    throw
}
finally {
    $evidence.changed = @($changedServices.ToArray())
    Save-Evidence
}
