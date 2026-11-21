#Requires -Version 5.1
<#
.SYNOPSIS
  Stop the target app's processes, selected by full image path under -Root, then stopped by
  PID. Dry run by default; -Confirm actually stops them. Reports survivors.

.DESCRIPTION
  Use it when a step needs the app closed (a P2 toggle test, a json-set or ini-set action with
  onlyWhenNotRunning) and the app keeps itself alive in the background.

  Selection is by image path only (QueryFullProcessImageNameW, plus the 8.3 form of each root),
  never by process name, so a same-named process elsewhere is never touched. Before each stop
  the PID's image path and start time are read again, so a reused PID is skipped.

  Order: processes whose parent is not itself selected go first (the browser or main process),
  then the rest, so helpers are not relaunched by a parent that is still alive.

  Processes that host a Windows service are listed but skipped unless -IncludeServices is
  given; the service control manager may restart them through its recovery actions.

  Side effect to expect: a force-stopped Chromium or Electron app may offer to restore pages on
  its next start. Record it, do not treat it as damage.

  Exit code: 0 when nothing is left (or dry run), 2 when processes under the root survive.

.PARAMETER Root
  One or more install directories (required).

.PARAMETER Confirm
  Actually stop the processes. Without it the script only prints what it would do.

.PARAMETER WhatIf
  Explicit dry run (the default). Cannot be combined with -Confirm.

.PARAMETER WaitSeconds
  How long to wait for processes to exit after stopping. Default 10.

.PARAMETER IncludeServices
  Also stop processes that host a service.

.PARAMETER Json
  Print the result as JSON instead of text.

.EXAMPLE
  .\stop_app.ps1 -Root "$env:LOCALAPPDATA\ExampleApp"            # dry run
  .\stop_app.ps1 -Root "$env:LOCALAPPDATA\ExampleApp" -Confirm   # stop
#>
param(
    [Parameter(Mandatory = $true)][string[]]$Root,
    [switch]$Confirm,
    [switch]$WhatIf,
    [int]$WaitSeconds = 10,
    [switch]$IncludeServices,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
if ($Confirm -and $WhatIf) { throw 'Pass either -Confirm or -WhatIf, not both.' }
$DryRun = -not $Confirm

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class AdStop {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, uint f, StringBuilder s, ref uint n);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static string ImagePath(uint pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);   // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) return null;
        try { var sb = new StringBuilder(1024); uint n = 1024; return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString() : null; }
        finally { CloseHandle(h); }
    }
}
'@

$prefixes = New-Object System.Collections.Generic.List[string]
foreach ($r in $Root) {
    try { $n = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($r.Trim('"'))).TrimEnd('\') } catch { Write-Warning "bad root: $r"; continue }
    if ($n -match '^[A-Za-z]:$' -or $n.ToLowerInvariant() -in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, $env:USERPROFILE).ForEach({ "$_".TrimEnd('\').ToLowerInvariant() })) {
        throw "Refusing a shared folder as root: $n"
    }
    $prefixes.Add($n.ToLowerInvariant())
    if (Test-Path -LiteralPath $n -PathType Container) {
        try { $sp = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($n).ShortPath.TrimEnd('\').ToLowerInvariant(); if (-not $prefixes.Contains($sp)) { $prefixes.Add($sp) } } catch { }
    }
}
if (-not $prefixes.Count) { throw 'No usable -Root.' }
function Test-UnderRoot([string]$path) {
    if (-not $path) { return $false }
    $l = $path.ToLowerInvariant()
    foreach ($p in $prefixes) { if ($l.StartsWith($p + '\')) { return $true } }
    $false
}
function Get-Selected {
    $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate)
    $res = @{}
    foreach ($p in $all) {
        $id = [int]$p.ProcessId; if ($id -le 4 -or $id -eq $PID) { continue }
        $img = $p.ExecutablePath; if (-not $img) { $img = [AdStop]::ImagePath([uint32]$id) }
        if (Test-UnderRoot $img) { $res[$id] = [ordered]@{ pid = $id; ppid = [int]$p.ParentProcessId; name = $p.Name; path = $img; created = $p.CreationDate; service = $null; action = $null; result = $null } }
    }
    $res
}

$sel = Get-Selected
$svcByPid = @{}
foreach ($s in @(Get-CimInstance Win32_Service -Filter 'ProcessId > 0' -Property Name, ProcessId)) { $svcByPid[[int]$s.ProcessId] = $s.Name }
$ordered = @($sel.Values | Sort-Object @{ e = { if ($sel.ContainsKey($_.ppid)) { 1 } else { 0 } } }, @{ e = { $_.created } })
foreach ($p in $ordered) {
    if ($svcByPid.ContainsKey($p.pid)) { $p.service = $svcByPid[$p.pid] }
    if ($p.service -and -not $IncludeServices) { $p.action = 'skip (hosts service ' + $p.service + ')'; continue }
    $p.action = 'stop'
    if ($DryRun) { $p.result = 'dry run'; continue }
    # Re-read the PID right before stopping: same image, same start time, or it is a different process now.
    $now = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.pid)" -Property ExecutablePath, CreationDate -ErrorAction SilentlyContinue
    if (-not $now) { $p.result = 'already gone'; continue }
    $nowImg = $now.ExecutablePath; if (-not $nowImg) { $nowImg = [AdStop]::ImagePath([uint32]$p.pid) }
    if ($now.CreationDate -ne $p.created -or -not (Test-UnderRoot $nowImg)) { $p.result = 'skipped: PID now belongs to another process'; continue }
    try { Stop-Process -Id $p.pid -Force -ErrorAction Stop; $p.result = 'stop sent' }
    catch { $p.result = 'error: ' + $_.Exception.Message }
}

$survivors = @()
if (-not $DryRun) {
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $left = Get-Selected
        $stoppable = @($left.Values | Where-Object { $IncludeServices -or -not $svcByPid.ContainsKey($_.pid) })
    } while ($stoppable.Count -and (Get-Date) -lt $deadline)
    foreach ($p in $left.Values) {
        $why = $(if ($svcByPid.ContainsKey($p.pid) -and -not $IncludeServices) { 'service host, not stopped' }
                 elseif ($sel.ContainsKey($p.pid) -and $sel[$p.pid].created -eq $p.created) { 'did not exit: ' + $sel[$p.pid].result }
                 else { 'started after the stop (respawned or relaunched)' })
        $survivors += [ordered]@{ pid = $p.pid; name = $p.name; path = $p.path; reason = $why }
    }
}

$result = [ordered]@{
    mode = $(if ($DryRun) { 'dry-run' } else { 'stop' }); roots = @($Root)
    processes = @($ordered | ForEach-Object { [ordered]@{ pid = $_.pid; ppid = $_.ppid; name = $_.name; path = $_.path; service = $_.service; action = $_.action; result = $_.result } })
    survivors = $survivors
}
if ($Json) { $result | ConvertTo-Json -Depth 5 }
else {
    Write-Host ("{0}: {1} process(es) under the root" -f $result.mode, $ordered.Count)
    foreach ($p in $result.processes) { Write-Host ("  pid {0,-6} {1,-28} {2} -> {3}" -f $p.pid, $p.name, $p.action, $p.result) }
    if ($DryRun) { Write-Host 'Dry run: nothing was stopped. Pass -Confirm to stop these processes.' }
    elseif ($survivors.Count) { Write-Host "survivors: $($survivors.Count)"; foreach ($s in $survivors) { Write-Host ("  pid {0,-6} {1,-28} {2}" -f $s.pid, $s.name, $s.reason) } }
    else { Write-Host 'survivors: none' }
}
if ($survivors.Count) { exit 2 }
exit 0
