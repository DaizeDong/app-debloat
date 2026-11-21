#Requires -Version 5.1
<#
.SYNOPSIS
  Watch one app while it starts or is used: process starts and exits along the app's own
  parent chain, file changes under its roots and data folders, and its TCP/UDP endpoints.
  Writes JSON lines.

.DESCRIPTION
  Read-only. It polls Win32_Process and tracks a process when
    - its image path is under one of -Root (reason "root"), or
    - its parent is already tracked and was created before it (reason "child"), or
    - it is the process started by -Launch (reason "launched").
  Matching by parent chain, not by process name, keeps out unrelated processes that share a
  name with something the app bundles (WebView2, node, python and so on).

  Limits, stated so nobody reads silence as proof:
    - A process that starts and exits between two polls is missed, and so is the chain below
      it if its children outlive it. When the shell is elevated, Win32_ProcessStartTrace
      events are also read, which closes most of that gap. Use Procmon for full coverage.
    - Not elevated, other users' and elevated processes have no image path; they are tracked
      only through a tracked parent.
    - FileSystemWatcher does not say which process changed a file, and it can overflow on bulk
      changes (an "overflow" line is written when that happens).
    - Connections show IP addresses; a proxy in TUN or global mode hides the real hosts.

  The output is real-run DATA: write -Out to the private companion, never into the tool repo.

.PARAMETER Root
  One or more install directories (required). Watched for file changes and used to seed
  tracking.

.PARAMETER DataDir
  Extra folders to watch for file changes (for example the app's %LOCALAPPDATA% folder). They
  do not seed process tracking.

.PARAMETER Launch
  Optional exe to start once monitoring is running. -LaunchArgs passes its arguments.

.PARAMETER Seconds
  How long to watch. Default 60.

.PARAMETER Out
  Output JSON lines path (required).

.PARAMETER PollMs
  Process poll interval. Default 500.

.PARAMETER ConnEverySeconds
  Connection poll interval. Default 2. 0 turns connection polling off.

.PARAMETER KeepPaths
  Keep the literal user profile path and user name. By default they become %USERPROFILE% and
  %USERNAME%, like inventory.ps1.

.EXAMPLE
  .\launch_monitor.ps1 -Root "$env:ProgramFiles\ExampleApp" -DataDir "$env:APPDATA\ExampleApp" `
      -Launch "$env:ProgramFiles\ExampleApp\ExampleApp.exe" -Seconds 90 -Out D:\private\launch.jsonl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Root,
    [string[]]$DataDir,
    [string]$Launch,
    [string]$LaunchArgs,
    [int]$Seconds = 60,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$PollMs = 500,
    [int]$ConnEverySeconds = 2,
    [switch]$KeepPaths
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System; using System.Collections.Concurrent; using System.Collections.Generic; using System.IO;
public sealed class AdFsTap : IDisposable {
    public readonly ConcurrentQueue<string[]> Q = new ConcurrentQueue<string[]>();
    readonly List<FileSystemWatcher> ws = new List<FileSystemWatcher>();
    public void Add(string dir) {
        var w = new FileSystemWatcher(dir);
        w.IncludeSubdirectories = true; w.InternalBufferSize = 65536;
        w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime;
        w.Created += (s, e) => Q.Enqueue(new[] { DateTime.UtcNow.ToString("o"), "created", e.FullPath, null });
        w.Changed += (s, e) => Q.Enqueue(new[] { DateTime.UtcNow.ToString("o"), "changed", e.FullPath, null });
        w.Deleted += (s, e) => Q.Enqueue(new[] { DateTime.UtcNow.ToString("o"), "deleted", e.FullPath, null });
        w.Renamed += (s, e) => Q.Enqueue(new[] { DateTime.UtcNow.ToString("o"), "renamed", e.FullPath, e.OldFullPath });
        w.Error += (s, e) => Q.Enqueue(new[] { DateTime.UtcNow.ToString("o"), "overflow", dir, e.GetException().Message });
        w.EnableRaisingEvents = true; ws.Add(w);
    }
    public void Dispose() { foreach (var w in ws) { w.EnableRaisingEvents = false; w.Dispose(); } ws.Clear(); }
}
'@

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$utf8 = New-Object Text.UTF8Encoding($false)
$outPath = [IO.Path]::GetFullPath($Out)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outPath))
$writer = New-Object IO.StreamWriter($outPath, $false, $utf8); $writer.AutoFlush = $true
$t0 = [Diagnostics.Stopwatch]::StartNew()

$redactPairs = @()
if (-not $KeepPaths) {
    if ($env:USERPROFILE) { $redactPairs += , @($env:USERPROFILE, '%USERPROFILE%') }
    if ($env:USERNAME) { $redactPairs += , @("\$env:USERNAME\", '\%USERNAME%\') }
}
function Hide([string]$s) {
    if (-not $s) { return $s }
    foreach ($p in $redactPairs) { $s = [regex]::Replace($s, [regex]::Escape($p[0]), $p[1].Replace('$', '$$'), 'IgnoreCase') }
    $s
}
function Emit([string]$type, $fields) {
    $o = [ordered]@{ ts = (Get-Date).ToUniversalTime().ToString('o'); t = [math]::Round($t0.Elapsed.TotalSeconds, 2); type = $type }
    foreach ($k in $fields.Keys) {
        $v = $fields[$k]
        if ($v -is [string]) { $v = Hide $v } elseif ($v -is [array]) { $v = @(foreach ($x in $v) { if ($x -is [string]) { Hide $x } else { $x } }) }
        $o[$k] = $v
    }
    $writer.WriteLine(($o | ConvertTo-Json -Compress -Depth 4))
}
function Norm([string]$p) {
    try { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($p.Trim('"'))).TrimEnd('\') } catch { $null }
}

$roots = @(foreach ($r in $Root) { $n = Norm $r; if ($n -and (Test-Path -LiteralPath $n -PathType Container)) { $n } else { Write-Warning "root not found, skipped: $r" } })
if (-not $roots) { $writer.Dispose(); throw 'No existing -Root directory.' }
$rootPrefixes = New-Object System.Collections.Generic.List[string]
foreach ($r in $roots) {
    $rootPrefixes.Add($r.ToLowerInvariant())
    try { $sp = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($r).ShortPath.TrimEnd('\').ToLowerInvariant(); if (-not $rootPrefixes.Contains($sp)) { $rootPrefixes.Add($sp) } } catch { }
}
function Test-UnderRoot([string]$path) {
    if (-not $path) { return $false }
    $l = $path.ToLowerInvariant()
    foreach ($p in $rootPrefixes) { if ($l.StartsWith($p + '\')) { return $true } }
    $false
}

# ---------------------------------------------------------------- file watchers
$tap = New-Object AdFsTap
$watched = @()
foreach ($d in @($roots) + @(foreach ($x in @($DataDir)) { if ($x) { Norm $x } })) {
    if (-not $d -or $watched -contains $d) { continue }
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { Write-Warning "data dir not found, not watched: $d"; continue }
    try { $tap.Add($d); $watched += $d } catch { Write-Warning "cannot watch ${d}: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- process tracking
$tracked = @{}     # pid -> @{ created; name; path; reason; parent; alive }
$seen = @{}        # pid|creation -> $true (every process already considered)
$traceParents = @{} # pid -> parent pid, from Win32_ProcessStartTrace (elevated only)
function Get-Procs { @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate -ErrorAction SilentlyContinue) }
function Consider($p, [bool]$initial, [string]$forceReason) {
    $id = [int]$p.ProcessId; $created = $p.CreationDate
    $sk = "$id|$created"; if ($seen.ContainsKey($sk)) { return }
    $seen[$sk] = $true
    if ($id -eq $PID) { return }
    $prev = $tracked[$id]
    if ($prev -and $prev.alive -and $prev.reason -eq 'child-trace') {   # already announced from the start trace; fill in the details
        $prev.created = $created; $prev.path = $p.ExecutablePath; return
    }
    $reason = $forceReason
    if (-not $reason -and (Test-UnderRoot $p.ExecutablePath)) { $reason = 'root' }
    if (-not $reason) {
        $pp = [int]$p.ParentProcessId
        if ($pp -eq 0 -and $traceParents.ContainsKey($id)) { $pp = $traceParents[$id] }
        $par = $tracked[$pp]
        if ($par -and ($null -eq $created -or $null -eq $par.created -or $par.created -le $created)) { $reason = 'child' }
    }
    if (-not $reason) { return }
    $tracked[$id] = @{ created = $created; name = $p.Name; path = $p.ExecutablePath; reason = $reason; parent = [int]$p.ParentProcessId; alive = $true }
    $parName = $null; if ($tracked[[int]$p.ParentProcessId]) { $parName = $tracked[[int]$p.ParentProcessId].name }
    Emit $(if ($initial) { 'proc_running' } else { 'proc_start' }) ([ordered]@{
        pid = $id; ppid = [int]$p.ParentProcessId; parent = $parName; name = $p.Name; path = $p.ExecutablePath
        command_line = $p.CommandLine; reason = $reason; created = $(if ($created) { $created.ToUniversalTime().ToString('o') }) })
}
function Poll-Procs([bool]$initial) {
    $all = Get-Procs
    # parents before children, so a whole new chain is caught in one poll
    $sorted = $all | Sort-Object { if ($_.CreationDate) { $_.CreationDate } else { [datetime]::MaxValue } }
    $live = @{}
    foreach ($p in $sorted) { $live[[int]$p.ProcessId] = $p.CreationDate; Consider $p $initial $null }
    foreach ($id in @($tracked.Keys)) {
        $t = $tracked[$id]; if (-not $t.alive) { continue }
        if (-not $live.ContainsKey($id) -or ($t.created -and $live[$id] -ne $t.created)) {
            $t.alive = $false
            Emit 'proc_exit' ([ordered]@{ pid = $id; name = $t.name; lifetime_s = $(if ($t.created) { [math]::Round(((Get-Date) - $t.created).TotalSeconds, 1) }) })
        }
    }
}

$traceSub = $null
if ($IsAdmin) {
    try {
        $traceSub = 'adlm-' + [guid]::NewGuid().ToString('N')
        Register-CimIndicationEvent -Query 'SELECT ProcessID, ParentProcessID, ProcessName FROM Win32_ProcessStartTrace' -SourceIdentifier $traceSub -ErrorAction Stop
    } catch { $traceSub = $null; Write-Warning "Win32_ProcessStartTrace unavailable: $($_.Exception.Message)" }
}
function Drain-Trace {
    if (-not $traceSub) { return }
    foreach ($ev in @(Get-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue)) {
        $ni = $ev.SourceEventArgs.NewEvent
        $cid = [int]$ni.ProcessID; $ppid = [int]$ni.ParentProcessID
        $traceParents[$cid] = $ppid
        if ($tracked[$ppid] -and $tracked[$ppid].alive -and -not ($tracked[$cid] -and $tracked[$cid].alive)) {
            $tracked[$cid] = @{ created = $null; name = $ni.ProcessName; path = $null; reason = 'child-trace'; parent = $ppid; alive = $true }
            Emit 'proc_start' ([ordered]@{ pid = $cid; ppid = $ppid; parent = $tracked[$ppid].name; name = $ni.ProcessName; reason = 'child-trace' })
        }
        Remove-Event -EventIdentifier $ev.EventIdentifier
    }
}

# ---------------------------------------------------------------- connections
$connSeen = @{}
function Poll-Conns {
    $ids = @($tracked.Keys | Where-Object { $tracked[$_].alive })
    if (-not $ids) { return }
    $set = @{}; foreach ($i in $ids) { $set[[int]$i] = $true }
    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $op = [int]$c.OwningProcess; if (-not $set.ContainsKey($op)) { continue }
        $k = "tcp|$op|$($c.LocalAddress):$($c.LocalPort)|$($c.RemoteAddress):$($c.RemotePort)|$($c.State)"
        if ($connSeen.ContainsKey($k)) { continue }; $connSeen[$k] = $true
        Emit 'conn' ([ordered]@{ proto = 'tcp'; pid = $op; process = $tracked[$op].name; state = $c.State.ToString()
            local = "$($c.LocalAddress):$($c.LocalPort)"; remote = "$($c.RemoteAddress):$($c.RemotePort)" })
    }
    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $op = [int]$u.OwningProcess; if (-not $set.ContainsKey($op)) { continue }
        $k = "udp|$op|$($u.LocalAddress):$($u.LocalPort)"
        if ($connSeen.ContainsKey($k)) { continue }; $connSeen[$k] = $true
        Emit 'conn' ([ordered]@{ proto = 'udp'; pid = $op; process = $tracked[$op].name; local = "$($u.LocalAddress):$($u.LocalPort)" })
    }
}

# ---------------------------------------------------------------- run
$fileCount = 0; $launched = $null
try {
    Emit 'start' ([ordered]@{ roots = $roots; watched = $watched; launch = $Launch; seconds = $Seconds; poll_ms = $PollMs
        elevated = $IsAdmin; start_trace = [bool]$traceSub })
    Poll-Procs $true
    if ($Launch) {
        $lp = Norm $Launch
        if (-not (Test-UnderRoot $lp)) { Emit 'note' ([ordered]@{ text = "launch target is not under any -Root; it and its children are tracked through the launch PID only" }) }
        $sp = @{ FilePath = $lp; PassThru = $true }
        if ($LaunchArgs) { $sp.ArgumentList = $LaunchArgs }
        $launched = Start-Process @sp
        $lpObj = Get-CimInstance Win32_Process -Filter "ProcessId=$($launched.Id)" -ErrorAction SilentlyContinue
        if ($lpObj) { Consider $lpObj $false 'launched' }
        else { $tracked[$launched.Id] = @{ created = $null; name = [IO.Path]::GetFileName($lp); path = $lp; reason = 'launched'; parent = $PID; alive = $true }
               Emit 'proc_start' ([ordered]@{ pid = $launched.Id; name = [IO.Path]::GetFileName($lp); path = $lp; reason = 'launched' }) }
    }
    $nextConn = 0.0
    while ($t0.Elapsed.TotalSeconds -lt $Seconds) {
        Drain-Trace
        Poll-Procs $false
        $item = $null
        while ($tap.Q.TryDequeue([ref]$item)) {
            $fileCount++
            $f = [ordered]@{ change = $item[1]; path = $item[2] }
            if ($item[1] -eq 'renamed') { $f.old_path = $item[3] }
            if ($item[1] -eq 'overflow') { $f.error = $item[3] }
            $o = [ordered]@{ ts = $item[0]; t = [math]::Round($t0.Elapsed.TotalSeconds, 2); type = 'file' }
            foreach ($k in $f.Keys) { $o[$k] = Hide $f[$k] }
            $writer.WriteLine(($o | ConvertTo-Json -Compress))
        }
        if ($ConnEverySeconds -gt 0 -and $t0.Elapsed.TotalSeconds -ge $nextConn) { Poll-Conns; $nextConn = $t0.Elapsed.TotalSeconds + $ConnEverySeconds }
        Start-Sleep -Milliseconds $PollMs
    }
} finally {
    $tap.Dispose()
    if ($traceSub) { Unregister-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue; Get-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue | Remove-Event }
    $alive = @($tracked.Keys | Where-Object { $tracked[$_].alive })
    Emit 'end' ([ordered]@{ tracked = $tracked.Count; still_running = $alive.Count; file_events = $fileCount; connections = $connSeen.Count })
    $writer.Dispose()
}
Write-Host ("tracked processes: {0} ({1} still running), file events: {2}, endpoints: {3}" -f $tracked.Count, $alive.Count, $fileCount, $connSeen.Count)
Write-Host "out: $outPath"
