#Requires -Version 5.1
<#
.SYNOPSIS
  One elevated, read-only evidence bundle for one app: elevated inventory, scheduled task XML
  (SYSTEM tasks included), service config and failure actions, and module lists of the app's
  processes (32-bit WOW64 modules included). Meant to run once, early, behind one UAC prompt.

.DESCRIPTION
  Refuses to run without elevation. Changes nothing outside -Out, except that with -Key it creates
  %ProgramData%\AppDebloat\<key> (admin-only ACL) and writes elevated-tasks.json there (below).
  Under a read-only instruction or a one-folder write restriction, run it without -Key.

  Writes into -Out:
    inventory-elevated.json   scripts\inventory.ps1 run elevated (sees SYSTEM tasks, other-user
                              processes, all-user BITS jobs, WMI subscriptions)
    tasks\*.xml, tasks.json   Export-ScheduledTask for every task whose actions reference a root
                              or whose path or name matches -App
    task-states.json          state baseline of the same tasks, walked folder by folder through
                              every task folder (hidden tasks included): enabled, state, last and
                              next run, last result, author, registration date, and (when the
                              TaskScheduler operational log is on) who registered, updated,
                              deleted or disabled each one and when. A later apply compares
                              against it to tell "already disabled before P0" from "changed since"
    services\<name>.txt       sc.exe qc, qfailure, qtriggerinfo and sdshow for every service
    services.json             whose binary is under a root or whose name matches -App
    modules.json              Toolhelp32 module list (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)
                              for every running process whose image is under a root
    bundle.json               what ran, counts and every failure

  With -Key <manifest id>, also writes %ProgramData%\AppDebloat\<key>\elevated-tasks.json:
  captured_at and tasks[{path, name, state, author, actions[{type, execute, class_id}]}] for every
  scheduled task outside \Microsoft\ (the folders a task-disable action can match), not only the
  ones matched above. Action arguments are left out: every local user can read this file, and
  SYSTEM task arguments can carry tokens or license keys (tasks.json under -Out keeps them).
  A non-elevated dry run of the built script cannot see SYSTEM tasks; it reads this file to print
  what this elevated enumeration found, and when. The folder is created if missing and gets the
  admin-only permissions the built script gives it (SYSTEM and Administrators full, Users read);
  a reparse point at that path is refused. Run again after the vendor adds or changes tasks.
  If the app is never debloated, nothing removes the folder: delete it by hand (elevated). The
  built script's -Uninstall removes it otherwise.

  Roots are -Root plus the roots inventory.ps1 resolved. The bundle keeps literal paths (the
  inventory still redacts its own); it is real-run DATA for the private companion only.

  If the owner declines the UAC prompt, do not retry more than once: record the exact command
  below in the run notes and continue without elevated evidence.

.PARAMETER App
  Regex for the app (ASCII preferred). Same meaning as inventory.ps1 -App.

.PARAMETER AppFile
  UTF-8 text file whose first non-empty line is the -App regex. Use it for non-ASCII names,
  which Windows PowerShell 5.1 can mangle on the command line.

.PARAMETER Root
  One or more install directories.

.PARAMETER Out
  Output directory (required, created if missing).

.PARAMETER Key
  The manifest id of the app's built script (lowercase letters, digits, dashes), which names its
  state folder %ProgramData%\AppDebloat\<key>. Pick it at P0 and keep it as the manifest id.
  Writes elevated-tasks.json there for the dry run (see above).

.PARAMETER NoInventory
  Skip the inventory run (only tasks, services and modules).

.PARAMETER NoSignature
  Passed to inventory.ps1.

.EXAMPLE
  # in an elevated 64-bit Windows PowerShell:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\elevated_readonly.ps1 -App 'ExampleApp' `
      -Root "$env:ProgramFiles\ExampleApp" -Key exampleapp -Out D:\private\exampleapp\elevated
#>
[CmdletBinding()]
param(
    [string]$App,
    [string]$AppFile,
    [string[]]$Root,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Key,
    [switch]$NoInventory,
    [switch]$NoSignature
)
$ErrorActionPreference = 'Stop'
# Same rule as the manifest id, so the folder is the one the built script uses.
if ($Key -and $Key -cnotmatch '^[a-z0-9][a-z0-9-]{1,40}$') { throw "-Key must be the manifest id (lowercase letters, digits, dashes): '$Key'" }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($App) { $argv += @('-App', "'$App'") }
    if ($AppFile) { $argv += @('-AppFile', "`"$AppFile`"") }
    foreach ($r in @($Root)) { if ($r) { $argv += @('-Root', "`"$r`"") } }
    if ($Key) { $argv += @('-Key', $Key) }
    if ($NoInventory) { $argv += '-NoInventory' }
    if ($NoSignature) { $argv += '-NoSignature' }
    $argv += @('-Out', "`"$Out`"")
    Write-Host 'Refused: elevated_readonly.ps1 must run in an elevated shell (it writes only under -Out, plus the -Key state file; elevation is for visibility).'
    Write-Host 'Run this once in an elevated 64-bit Windows PowerShell:'
    Write-Host ('  powershell ' + ($argv -join ' '))
    exit 1
}
if ($AppFile) {
    $line = @([IO.File]::ReadAllLines($AppFile, [Text.Encoding]::UTF8) | Where-Object { $_.Trim() })[0]
    if (-not $line) { throw "-AppFile is empty: $AppFile" }
    $App = $line.Trim().TrimStart([char]0xFEFF)
}
if (-not $App -and -not $Root) { throw 'Pass -App, -AppFile and/or -Root.' }
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Write-Warning '32-bit PowerShell on 64-bit Windows: module lists of 64-bit processes will be missing. Use 64-bit powershell.exe.'
}

$outDir = [IO.Path]::GetFullPath($Out)
foreach ($d in $outDir, (Join-Path $outDir 'tasks'), (Join-Path $outDir 'services')) { [void][IO.Directory]::CreateDirectory($d) }
$utf8 = New-Object Text.UTF8Encoding($false)
function Save-Json([string]$name, $obj) { [IO.File]::WriteAllText((Join-Path $outDir $name), (ConvertTo-Json -InputObject $obj -Depth 8), $utf8) }
$bundle = [ordered]@{
    schema = 'app-debloat.elevated-readonly/1'; captured_at = (Get-Date).ToUniversalTime().ToString('o')
    params = [ordered]@{ app = $App; root = @($Root) }; steps = [ordered]@{}; failures = New-Object System.Collections.Generic.List[object]
}
function Add-Fail([string]$step, [string]$target, [string]$err) { $bundle.failures.Add([ordered]@{ step = $step; target = $target; error = $err }) }
$appRx = $null; if ($App) { $appRx = New-Object regex($App, 'IgnoreCase') }

# ---------------------------------------------------------------- 1. elevated inventory
$invPath = Join-Path $outDir 'inventory-elevated.json'
$invRoots = @()
if (-not $NoInventory) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ia = @{ Out = $invPath }
        if ($App) { $ia.App = $App }
        if ($Root) { $ia.Root = $Root }
        if ($NoSignature) { $ia.NoSignature = $true }
        & (Join-Path $PSScriptRoot 'inventory.ps1') @ia | Out-Host
        # JavaScriptSerializer tolerates keys that ConvertFrom-Json in 5.1 rejects.
        Add-Type -AssemblyName System.Web.Extensions
        $js = New-Object Web.Script.Serialization.JavaScriptSerializer; $js.MaxJsonLength = [int]::MaxValue
        $inv = $js.DeserializeObject([IO.File]::ReadAllText($invPath, [Text.Encoding]::UTF8))
        foreach ($r in @($inv['roots'])) { if ($r -and $r['path']) { $invRoots += [string]$r['path'] } }
        $bundle.steps['inventory'] = [ordered]@{ file = 'inventory-elevated.json'; roots = $invRoots; ms = $sw.ElapsedMilliseconds }
    } catch { Add-Fail 'inventory' $invPath $_.Exception.Message }
}

$roots = @(foreach ($r in @($Root) + $invRoots) {
    if (-not $r) { continue }
    try { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($r.Trim('"'))).TrimEnd('\') } catch { }
}) | Sort-Object -Unique
$prefixes = New-Object System.Collections.Generic.List[string]
foreach ($r in $roots) {
    $prefixes.Add($r.ToLowerInvariant())
    try { $sp = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($r).ShortPath.TrimEnd('\').ToLowerInvariant(); if (-not $prefixes.Contains($sp)) { $prefixes.Add($sp) } } catch { }
}
$bundle.roots = @($roots)
function Test-Refs([string]$s) {
    # does a command line, path or argument string mention one of the roots?
    if (-not $s) { return $false }
    $l = [Environment]::ExpandEnvironmentVariables($s).Replace('/', '\').ToLowerInvariant()
    foreach ($p in $prefixes) { if ($l.Contains($p + '\') -or $l.Contains($p + '"') -or $l.EndsWith($p)) { return $true } }
    $false
}
function Safe-Name([string]$s) { $n = ($s -replace '[\\/:*?"<>|\s]+', '_').Trim('_'); if ($n.Length -gt 120) { $n = $n.Substring(0, 120) }; $n }

# ---------------------------------------------------------------- 2. scheduled tasks (SYSTEM included)
$allTasks = New-Object System.Collections.Generic.List[object]; $allTasksOk = $false
try {
    $taskIdx = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-ScheduledTask)) {
        $acts = @(foreach ($a in @($t.Actions)) { if ($a) { [ordered]@{ type = $a.CimClass.CimClassName -replace '^MSFT_Task', ''; execute = $a.Execute; arguments = $a.Arguments; class_id = $a.ClassId } } })
        if ($t.TaskPath -notlike '\Microsoft\*') {
            # Users can read the -Key file, so no arguments here (SYSTEM task arguments can hold tokens).
            $pubActs = @(foreach ($a in $acts) { [ordered]@{ type = $a.type; execute = $a.execute; class_id = $a.class_id } })
            $allTasks.Add([ordered]@{ path = $t.TaskPath; name = $t.TaskName; state = $t.State.ToString(); author = $t.Author; actions = $pubActs })
        }
        $why = $null
        foreach ($a in @($t.Actions)) {
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction' -and (Test-Refs "$($a.Execute) $($a.Arguments) $($a.WorkingDirectory)")) { $why = 'root'; break }
        }
        if (-not $why -and $appRx -and $appRx.IsMatch("$($t.TaskPath)$($t.TaskName) $($t.Author) $($t.Description)")) { $why = 'app' }
        if (-not $why) { continue }
        $file = (Safe-Name "$($t.TaskPath)$($t.TaskName)") + '.xml'
        try { [IO.File]::WriteAllText((Join-Path $outDir "tasks\$file"), (Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath), $utf8) }
        catch { Add-Fail 'tasks' "$($t.TaskPath)$($t.TaskName)" $_.Exception.Message; $file = $null }
        $info = $null; try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath } catch { }
        $taskIdx.Add([ordered]@{
            path = $t.TaskPath; name = $t.TaskName; match = $why; state = $t.State.ToString(); user = $t.Principal.UserId
            run_level = $t.Principal.RunLevel.ToString(); hidden = $t.Settings.Hidden; author = $t.Author; xml = $file
            actions = $acts
            last_run = $(if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString('o') } else { $null }); last_result = $(if ($info) { '0x{0:x}' -f $info.LastTaskResult } else { $null })
            next_run = $(if ($info -and $info.NextRunTime) { $info.NextRunTime.ToString('o') } else { $null })
        })
    }
    Save-Json 'tasks.json' $taskIdx.ToArray()
    $bundle.steps['tasks'] = [ordered]@{ file = 'tasks.json'; count = $taskIdx.Count }
    $allTasksOk = $true
} catch { Add-Fail 'tasks' '(all)' $_.Exception.Message }

# ---------------------------------------------------------------- 2a. task list for the built script's dry run (-Key)
# Written only after a complete enumeration, so a failed one never replaces the last good file. The folder gets the
# built script's admin-only ACL; a reparse point there is refused (icacls follows it, so it could re-ACL its target).
if ($Key) {
    $stateDir = Join-Path $env:ProgramData "AppDebloat\$Key"; $stateFile = Join-Path $stateDir 'elevated-tasks.json'
    if (-not $allTasksOk) { Add-Fail 'state_tasks' $stateFile 'task enumeration failed; file not written' }
    else {
        try {
            $noLink = { foreach ($d in (Split-Path -Parent $stateDir), $stateDir) {
                $at = $null; try { $at = [IO.File]::GetAttributes($d) } catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { }
                if ($null -ne $at -and ($at -band [IO.FileAttributes]::ReparsePoint)) { throw "$d is a reparse point; not written" } } }
            & $noLink; [void][IO.Directory]::CreateDirectory($stateDir); & $noLink
            & icacls.exe $stateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /L /Q | Out-Null
            if ($LASTEXITCODE) { throw "icacls exit $LASTEXITCODE on $stateDir (see the console for its message)" }
            if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force }   # a fresh file, never a planted link
            $doc = [ordered]@{ schema = 'app-debloat.elevated-tasks/1'; key = $Key; captured_at = $bundle.captured_at
                scope = 'every scheduled task outside \Microsoft\, enumerated elevated'; count = $allTasks.Count; tasks = $allTasks.ToArray() }
            [IO.File]::WriteAllText($stateFile, (ConvertTo-Json -InputObject $doc -Depth 6), $utf8)
            $bundle.steps['state_tasks'] = [ordered]@{ file = $stateFile; count = $allTasks.Count }
        } catch { Add-Fail 'state_tasks' $stateFile $_.Exception.Message }
    }
}

# ---------------------------------------------------------------- 2b. task state baseline (every folder, recursive)
# The state each matching task had at P0, so a later apply can tell "already disabled before P0" from "changed
# since". Walks the Task Scheduler COM tree folder by folder (hidden tasks included), independent of step 2.
try {
    $svc = New-Object -ComObject Schedule.Service; $svc.Connect()
    $stateRows = New-Object System.Collections.Generic.List[object]
    $folders = 0; $seenTasks = 0
    $stack = New-Object System.Collections.Generic.Stack[object]; $stack.Push($svc.GetFolder('\'))
    while ($stack.Count) {
        $f = $stack.Pop(); $folders++
        try { foreach ($sf in @($f.GetFolders(0))) { if ($sf) { $stack.Push($sf) } } } catch { Add-Fail 'task_states' $f.Path $_.Exception.Message }
        $tasks = @(); try { $tasks = @($f.GetTasks(1)) } catch { Add-Fail 'task_states' $f.Path $_.Exception.Message }   # 1 = TASK_ENUM_HIDDEN
        foreach ($t in $tasks) {
            if (-not $t) { continue }
            $seenTasks++
            $def = $null; try { $def = $t.Definition } catch { }
            $why = $null; $acts = @()
            if ($def) {
                foreach ($a in @($def.Actions)) {
                    if ($a.Type -eq 0) {   # TASK_ACTION_EXEC
                        $acts += [ordered]@{ type = 'Exec'; execute = $a.Path; arguments = $a.Arguments; workdir = $a.WorkingDirectory }
                        if (-not $why -and (Test-Refs "$($a.Path) $($a.Arguments) $($a.WorkingDirectory)")) { $why = 'root' }
                    } elseif ($a.Type -eq 5) { $acts += [ordered]@{ type = 'ComHandler'; class_id = $a.ClassId; data = $a.Data } }
                    else { $acts += [ordered]@{ type = "type$($a.Type)" } }
                }
            }
            $folderPath = $f.Path; if (-not $folderPath.EndsWith('\')) { $folderPath += '\' }
            $author = $null; $regDate = $null; $desc = $null
            if ($def) { try { $author = $def.RegistrationInfo.Author; $regDate = $def.RegistrationInfo.Date; $desc = $def.RegistrationInfo.Description } catch { } }
            if (-not $why -and $appRx -and $appRx.IsMatch("$($t.Path) $author $desc")) { $why = 'app' }
            if (-not $why) { continue }
            $lr = $null; try { $d = [datetime]$t.LastRunTime; if ($d.Year -gt 1999) { $lr = $d.ToString('o') } } catch { }
            $nr = $null; try { $d = [datetime]$t.NextRunTime; if ($d.Year -gt 1999) { $nr = $d.ToString('o') } } catch { }
            $stateName = @{ 0 = 'Unknown'; 1 = 'Disabled'; 2 = 'Queued'; 3 = 'Ready'; 4 = 'Running' }[[int]$t.State]
            $stateRows.Add([ordered]@{
                path = $folderPath; name = $t.Name; full_path = $t.Path; match = $why
                enabled = [bool]$t.Enabled; state = $stateName; last_run = $lr; last_result = ('0x{0:x}' -f [int64]$t.LastTaskResult); next_run = $nr
                author = $author; registered = $regDate; user = $(if ($def) { $def.Principal.UserId } else { $null }); hidden = $(if ($def) { [bool]$def.Settings.Hidden } else { $null })
                actions = $acts; events = @()
            })
        }
    }
    # Who changed a task and when, if the Task Scheduler operational log is enabled (off by default):
    # 106 registered, 140 updated, 141 deleted, 142 disabled.
    $evNote = $null
    if ($stateRows.Count) {
        try {
            $byPath = @{}; foreach ($r in $stateRows) { $byPath[$r.full_path.ToLowerInvariant()] = $r }
            foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 140, 141, 142; StartTime = (Get-Date).AddDays(-180) } -MaxEvents 5000 -ErrorAction Stop)) {
                $tn = $null; $who = $null
                try { $tn = [string]$ev.Properties[0].Value; $who = [string]$ev.Properties[1].Value } catch { }
                if (-not $tn) { continue }
                $r = $byPath[$tn.ToLowerInvariant()]; if (-not $r) { continue }
                if ($r.events.Count -lt 20) { $r.events += [ordered]@{ id = $ev.Id; time = $ev.TimeCreated.ToUniversalTime().ToString('o'); user = $who } }
            }
        } catch { $evNote = "operational log not read: $($_.Exception.Message)" }
    }
    Save-Json 'task-states.json' ([ordered]@{ captured_at = $bundle.captured_at; folders = $folders; tasks_seen = $seenTasks
        event_log = $(if ($evNote) { $evNote } else { 'read (events listed per task; empty when the log is disabled or rolled over)' })
        tasks = $stateRows.ToArray() })
    $bundle.steps['task_states'] = [ordered]@{ file = 'task-states.json'; count = $stateRows.Count; folders = $folders
        disabled = @($stateRows | Where-Object { -not $_.enabled }).Count }
} catch { Add-Fail 'task_states' '(all)' $_.Exception.Message }

# ---------------------------------------------------------------- 3. services: qc, qfailure, qtriggerinfo, sdshow
try {
    $svcIdx = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(Get-CimInstance Win32_Service)) {
        $why = $null
        if (Test-Refs $s.PathName) { $why = 'root' }
        elseif ($appRx -and $appRx.IsMatch("$($s.Name)|$($s.DisplayName)|$($s.PathName)")) { $why = 'app' }
        if (-not $why) { continue }
        $sb = New-Object Text.StringBuilder
        foreach ($q in 'qc', 'qfailure', 'qtriggerinfo', 'sdshow') {
            [void]$sb.AppendLine("===== sc.exe $q $($s.Name)")
            try { $o = & sc.exe $q $s.Name 2>&1 | Out-String; [void]$sb.AppendLine($o.TrimEnd()); [void]$sb.AppendLine("exit $LASTEXITCODE") }
            catch { [void]$sb.AppendLine("error: $($_.Exception.Message)"); Add-Fail 'services' "$q $($s.Name)" $_.Exception.Message }
        }
        $file = (Safe-Name $s.Name) + '.txt'
        [IO.File]::WriteAllText((Join-Path $outDir "services\$file"), $sb.ToString(), $utf8)
        $svcIdx.Add([ordered]@{ name = $s.Name; display_name = $s.DisplayName; match = $why; path = $s.PathName; start_mode = $s.StartMode
            state = $s.State; account = $s.StartName; pid = [int]$s.ProcessId; file = $file })
    }
    Save-Json 'services.json' $svcIdx.ToArray()
    $bundle.steps['services'] = [ordered]@{ file = 'services.json'; count = $svcIdx.Count }
} catch { Add-Fail 'services' '(all)' $_.Exception.Message }

# ---------------------------------------------------------------- 4. module lists, 32-bit included
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class AdElev {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MODULEENTRY32W {
        public uint dwSize, th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public IntPtr modBaseAddr; public uint modBaseSize; public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint f, uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool Module32FirstW(IntPtr h, ref MODULEENTRY32W e);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool Module32NextW(IntPtr h, ref MODULEENTRY32W e);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsWow64Process(IntPtr h, out bool w);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, uint f, StringBuilder s, ref uint n);
    public class Mod { public string Path; public string Base; public uint Size; }
    public static string ImagePath(uint pid, out int wow) {
        wow = -1; IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            bool w; if (IsWow64Process(h, out w)) wow = w ? 1 : 0;
            var sb = new StringBuilder(1024); uint n = 1024; return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString() : null;
        } finally { CloseHandle(h); }
    }
    public static Mod[] Modules(uint pid, out int err) {
        err = 0; IntPtr snap = new IntPtr(-1);
        for (int i = 0; i < 5; i++) {
            snap = CreateToolhelp32Snapshot(0x8 | 0x10, pid);   // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
            if (snap != new IntPtr(-1)) break;
            err = Marshal.GetLastWin32Error(); if (err != 24) return null;   // ERROR_BAD_LENGTH: retry
        }
        if (snap == new IntPtr(-1)) return null;
        err = 0; var list = new List<Mod>();
        try {
            var e = new MODULEENTRY32W(); e.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
            if (Module32FirstW(snap, ref e)) { do { list.Add(new Mod { Path = e.szExePath, Base = "0x" + e.modBaseAddr.ToInt64().ToString("x"), Size = e.modBaseSize }); } while (Module32NextW(snap, ref e)); }
        } finally { CloseHandle(snap); }
        return list.ToArray();
    }
}
'@
try {
    $modIdx = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)) {
        $id = [uint32]$p.ProcessId; if ($id -le 4) { continue }
        $wow = -1; $img = [AdElev]::ImagePath($id, [ref]$wow); if (-not $img) { $img = $p.ExecutablePath }
        if (-not (Test-Refs $img)) { continue }
        $err = 0; $mods = [AdElev]::Modules($id, [ref]$err)
        if ($null -eq $mods) { Add-Fail 'modules' "pid $id" "Toolhelp32 error $err" }
        $modIdx.Add([ordered]@{
            pid = [int]$id; ppid = [int]$p.ParentProcessId; name = $p.Name; image = $img; command_line = $p.CommandLine
            wow64 = $(if ($wow -eq 1) { $true } elseif ($wow -eq 0) { $false } else { $null }); error = $(if ($null -eq $mods) { $err } else { $null })
            modules = @(foreach ($m in @($mods)) { if ($m) { [ordered]@{ path = $m.Path; base = $m.Base; size = $m.Size } } })
        })
    }
    Save-Json 'modules.json' $modIdx.ToArray()
    $bundle.steps['modules'] = [ordered]@{ file = 'modules.json'; processes = $modIdx.Count; wow64 = @($modIdx | Where-Object { $_.wow64 }).Count }
} catch { Add-Fail 'modules' '(all)' $_.Exception.Message }

Save-Json 'bundle.json' $bundle
Write-Host ("elevated bundle: tasks {0} (state baseline {4}), services {1}, processes {2}, failures {3}" -f `
    $(if ($bundle.steps['tasks']) { $bundle.steps['tasks'].count } else { 'n/a' }),
    $(if ($bundle.steps['services']) { $bundle.steps['services'].count } else { 'n/a' }),
    $(if ($bundle.steps['modules']) { $bundle.steps['modules'].processes } else { 'n/a' }), $bundle.failures.Count,
    $(if ($bundle.steps['task_states']) { "$($bundle.steps['task_states'].count), $($bundle.steps['task_states'].disabled) disabled" } else { 'n/a' }))
if ($bundle.steps['state_tasks']) { Write-Host ("task list for the dry run: {0} ({1} tasks outside \Microsoft\)" -f $bundle.steps['state_tasks'].file, $bundle.steps['state_tasks'].count) }
Write-Host "out: $outDir"
