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
One or more of worker-1, worker-2, worker-3, client. Defaults to all four.
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
    [ValidateSet('worker-1', 'worker-2', 'worker-3', 'client')]
    [string[]]$Services = @('worker-1', 'worker-2', 'worker-3', 'client'),

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

$composeFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'compose.yaml'
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Compose configuration is missing: $composeFile"
}
# Resolve the executable rather than a potentially unrelated shell alias/function.
$dockerCommand = Get-Command docker -CommandType Application -ErrorAction Stop | Select-Object -First 1
$composeArgs = @('compose', '-f', $composeFile, '-p', 'steamboat-net-lab')
$selectedServices = @($Services | Select-Object -Unique)

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

# Preflight every selected service before the first change. A stopped container
# or missing tc therefore cannot leave a partially applied profile at this point.
$currentQdiscs = @{}
foreach ($service in $selectedServices) {
    $currentQdiscs[$service] = Get-LabQdisc -Service $service
}
if ($StatusOnly) {
    foreach ($service in $selectedServices) {
        Write-Output ("{0}:`n{1}" -f $service, $currentQdiscs[$service])
    }
    return
}

$netemArgs = @('qdisc', 'replace', 'dev', 'eth0', 'root', 'netem')
if ($DelayMs -gt 0) {
    $netemArgs += @('delay', "$(Format-TcNumber $DelayMs)ms")
    if ($JitterMs -gt 0) { $netemArgs += "$(Format-TcNumber $JitterMs)ms" }
}
if ($LossPercent -gt 0) { $netemArgs += @('loss', "$(Format-TcNumber $LossPercent)%") }
if ($RateMbit -gt 0) { $netemArgs += @('rate', "$(Format-TcNumber $RateMbit)mbit") }

$changedServices = New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($service in $selectedServices) {
        if ($Profile -eq 'lan') {
            # Do not suppress deletion failures, or remove an unrelated root qdisc.
            if ($currentQdiscs[$service] -match '(?m)^qdisc netem\s+[^\r\n]*\broot\b') {
                $null = Invoke-LabDocker -DockerArguments ($composeArgs + @('exec', '-T', $service, 'tc', 'qdisc', 'del', 'dev', 'eth0', 'root'))
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
        Write-Output ("{0} ({1}):`n{2}" -f $service, $Profile, $resultQdisc)
    }
}
catch {
    $changedSummary = if ($changedServices.Count) { $changedServices -join ', ' } else { '(none)' }
    Write-Warning "Profile application stopped. Services changed before this failure: $changedSummary. Inspect with -StatusOnly; restore with -Profile lan. No rollback was attempted."
    throw
}
