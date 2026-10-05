<#
.SYNOPSIS
Runs snare's hardware truth tests (the ignored hw_* tests) on this Windows machine and writes a
report of what passed, failed and was skipped, with each skip's reason.

.DESCRIPTION
Nothing on the machine is changed unless -Mutate is given. With -Mutate the adapter tests write
one advanced property and restart the adapter (the original value is written back and the adapter
restarted again), and the npcap test sends a few broadcast frames (EtherType 0x88B5) on the
adapter. Run from an elevated PowerShell for the tests that need administrator rights; the others
run either way.

-Reflector instead serves as the peer for another machine's hw_* tests: it echoes UDP datagrams
on port 47000 (SNARE_HW_REFLECT_PORT) until idle for 600 s (SNARE_HW_REFLECT_SECS).

.EXAMPLE
scripts\test-hardware.ps1 -Adapter "Ethernet 2" -Npcap
.EXAMPLE
scripts\test-hardware.ps1 -Adapter "Ethernet 2" -Mutate -Report C:\temp\hw.txt
.EXAMPLE
scripts\test-hardware.ps1 -Reflector
#>
param(
    [string]$Adapter,
    [string]$Peer,
    [switch]$Mutate,
    [switch]$Npcap,
    [string]$Report,
    [switch]$Reflector
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($Reflector) {
    $env:SNARE_HW_REFLECT = '1'
    Write-Host "reflector: echoing UDP on port $(if ($env:SNARE_HW_REFLECT_PORT) { $env:SNARE_HW_REFLECT_PORT } else { 47000 })"
    cargo test -p snare --test hw_peer_reflector -- --include-ignored hw_peer_reflector --nocapture
    exit $LASTEXITCODE
}

if (-not $Report) { $Report = Join-Path $root 'target\hardware-report.txt' }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Report) | Out-Null

if ($Adapter) { $env:SNARE_HW_WIN_ADAPTER = $Adapter }
if ($Peer) { $env:SNARE_HW_PEER = $Peer }
$env:SNARE_HW_MUTATE = if ($Mutate) { '1' } else { '0' }
$npcapDll = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'
if ($Npcap -or (Test-Path $npcapDll)) { $env:SNARE_HW_NPCAP = '1'; $Npcap = $true }

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$shown = if ($env:SNARE_HW_WIN_ADAPTER) { $env:SNARE_HW_WIN_ADAPTER } else {
    (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -First 1).Name
}

Write-Host "snare hardware tests on $env:COMPUTERNAME ($([Environment]::OSVersion.VersionString))"
Write-Host "  adapter:  $(if ($shown) { $shown } else { '(none found)' })$(if (-not $env:SNARE_HW_WIN_ADAPTER) { ' (auto)' })"
Write-Host "  peer:     $(if ($env:SNARE_HW_PEER) { $env:SNARE_HW_PEER } else { '(none)' })"
Write-Host "  npcap:    $Npcap"
Write-Host "  elevated: $elevated"
if ($Mutate) {
    Write-Host "  WILL CHANGE: $shown's *InterruptModeration (or *FlowControl) and restart it, then restore it;"
    Write-Host "               send broadcast frames (EtherType 0x88B5) on it when npcap is present."
} else {
    Write-Host "  read-only: no adapter setting is changed and no frame is sent (pass -Mutate to allow)"
}

$skips = Join-Path ([IO.Path]::GetTempPath()) "snare-hw-skips-$PID.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $skips
$env:SNARE_HW_REPORT = $skips

$cargoArgs = @('test', '-p', 'snare', '--test', 'hw_*')
if ($Npcap) { $cargoArgs += @('--features', 'hw-npcap') }
$cargoArgs += @('--', '--include-ignored', 'hw_', '--test-threads=1')
Write-Host "cargo $($cargoArgs -join ' ')"
$ErrorActionPreference = 'Continue'
& cargo @cargoArgs 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -Variable lines
$status = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

$results = [ordered]@{}
foreach ($line in $lines) {
    if ($line -match '^test (\S+) \.\.\. (ok|FAILED|ignored)') { $results[$Matches[1]] = $Matches[2] }
}
$skipped = @{}
$notes = @()
if (Test-Path $skips) {
    foreach ($line in Get-Content $skips) {
        $parts = $line -split "`t", 3
        if ($parts.Count -lt 3) { continue }
        if ($parts[0] -eq 'SKIP') { $skipped[$parts[1]] = $parts[2] }
        elseif ($parts[0] -eq 'NOTE') { $notes += "$($parts[1]): $($parts[2])" }
    }
}

$passed = @(); $failed = @(); $skippedList = @()
foreach ($name in $results.Keys) {
    $r = $results[$name]
    if ($r -eq 'FAILED') { $failed += $name }
    elseif ($skipped.ContainsKey($name)) { $skippedList += "$name -- $($skipped[$name])" }
    elseif ($r -eq 'ok') { $passed += $name }
}

$text = @()
$text += "snare hardware report, $(Get-Date -Format s), $env:COMPUTERNAME"
$text += "adapter=$shown peer=$env:SNARE_HW_PEER npcap=$Npcap elevated=$elevated mutate=$Mutate"
$text += ''
$text += "PASSED ($($passed.Count))"; $text += $passed | ForEach-Object { "  $_" }
$text += "FAILED ($($failed.Count))"; $text += $failed | ForEach-Object { "  $_" }
$text += "SKIPPED ($($skippedList.Count))"; $text += $skippedList | ForEach-Object { "  $_" }
$text += "NOTES ($($notes.Count))"; $text += $notes | ForEach-Object { "  $_" }
if ($failed.Count -gt 0) {
    $text += ''
    $text += 'FAILURE OUTPUT'
    $text += $lines | Where-Object { $_ -match 'panicked at|assertion|left:|right:|---- ' }
}
$text | Set-Content -Encoding utf8 $Report
Remove-Item -Force -ErrorAction SilentlyContinue $skips
$text | Select-Object -First (6 + $passed.Count + $failed.Count + $skippedList.Count + $notes.Count + 4) | Write-Host
Write-Host "report: $Report"

if ($failed.Count -gt 0 -or $status -ne 0) { exit 1 }
exit 0
