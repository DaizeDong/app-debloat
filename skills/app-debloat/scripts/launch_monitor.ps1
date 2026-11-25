#Requires -Version 5.1
<#
.SYNOPSIS
  Watch one app while it starts, idles or is used: process starts and exits along the app's own
  parent chain, processes of its services, file changes under its roots and data folders, its
  TCP/UDP endpoints, and established-connection counts over time. Writes JSON lines.

.DESCRIPTION
  Read-only. It polls Win32_Process and tracks a process when
    - its image path is under one of -Root (reason "root"), or
    - it runs a service whose binary (the service PathName, readable without elevation) is under
      one of -Root (reason "service", with the service name). Without elevation this is how a
      SYSTEM updater service shows up: its image path is not readable and its parent is
      services.exe, even when a user process started it through COM, or
    - its parent is tracked, still running and provably older (both creation times known, the
      parent's earlier) (reason "child"), or
    - it is the process started by -Launch (reason "launched"), or
    - its name matches -WatchNames (reason "name").
  Matching by parent chain, not by process name, keeps out unrelated processes that share a
  name with something the app bundles (WebView2, node, python and so on). A tracked process that
  has exited, or whose PID now belongs to a newer process, is never taken as a parent.

  Process lines (proc_running, proc_start, proc_detail) carry the image path, the command line
  and the creation time when they are readable, plus for a service process the service name, its
  PathName and the executable taken from it (service, service_path_name, service_image). A
  command line that opens a browser debugging endpoint (--remote-debugging-port=N or
  --remote-debugging-pipe) adds remote_debugging (port=N or pipe). Credential-like values in
  command lines become <redacted>, keeping the switch and parameter names: switches and
  parameters whose name contains token, stoken, bduss, session, password, passwd, secret, cookie
  or auth (access_token= included), or is sid or ends in _sid, -sid or .sid, JSON members with
  such names, and Cookie and Authorization headers. A bare value with no name is not recognized.

  conn lines for a TCP listener and for every UDP endpoint carry listen_scope: loopback
  (127.0.0.0/8, ::1), all (0.0.0.0, ::) or specific (one interface address). A listener on all
  interfaces is reachable from the network unless a firewall rule blocks it; loopback is not
  filtered by Windows Firewall at all.

  With -Sample, a sample line every -SampleEverySeconds lists each tracked running process with
  CPU seconds used since the previous sample (cpu_d_s, and cpu_pct as a share of all logical
  processors, the way Task Manager shows it), total CPU seconds since it started (cpu_s), working
  set and private bytes (ws_mb, priv_mb), I/O counts and bytes since the previous sample
  (read_ops, write_ops, other_ops, read_bytes, write_bytes, other_bytes) and its TCP and UDP
  socket counts (tcp_est, tcp_listen, udp), plus a total row. The numbers come from the same
  Win32_Process poll that tracks processes (poll_t is its time), so they exist without
  elevation for SYSTEM and other-user processes too. One poll takes about a second on a busy
  machine, so an interval below a few seconds is not kept. since says what the deltas cover: prev (the previous sample), start
  (the process started after it) or none (the first sample, or the first one that saw the
  process). The I/O counters count every I/O the process issued (files, network, devices); they
  are not disk traffic. A sample_summary line before end gives per process the CPU seconds and
  I/O over the window, the average CPU share and the peak working set and private bytes, plus
  totals and the peak of the summed working set. What a process used after the last sample
  before it exited is not counted.

  When the shell is elevated, Win32_ProcessStartTrace events are also read. A child of a tracked
  process found that way is announced at once with its path, command line and creation time,
  read from the process right away, so a child that exits within a second still has them. When
  they could not be read then and a later poll reads them, a proc_detail line follows.

  Limits, stated so nobody reads silence as proof:
    - Without elevation a process that starts and exits between two polls is missed, and so is
      the chain below it if its children outlive it. Use Procmon for full coverage.
    - Not elevated, other users' and elevated processes have no image path; they are tracked
      only through a tracked parent, a service binary under a root, or -WatchNames.
    - A service hosted in svchost.exe is matched by its PathName (svchost), not its ServiceDll.
    - FileSystemWatcher does not say which process changed a file, and it can overflow on bulk
      changes (an "overflow" line is written when that happens).
    - Connections show IP addresses; a proxy in TUN or global mode hides the real hosts.

  Line types: start, proc_running, proc_start, proc_detail, proc_exit, file, conn (each new
  endpoint once), conn_count (every -ConnCountEverySeconds), sample and sample_summary (with
  -Sample), note, end.

  The output is real-run DATA: write -Out to the private companion, never into the tool repo.

.PARAMETER Root
  One or more install directories (required). Watched for file changes and used to seed
  tracking.

.PARAMETER DataDir
  Extra folders to watch for file changes (for example the app's %LOCALAPPDATA% folder). They
  do not seed process tracking.

.PARAMETER Launch
  Optional exe to start once monitoring is running. -LaunchArgs passes its arguments. Refused
  when the shell is elevated: the app or updater would inherit the admin token. Elevated, leave
  it out and start the exe from a normal shell after the start line (with Start-Process
  -WorkingDirectory set to a private folder); a process under a -Root is tracked by its path.
  The exe starts in launch-cwd\ next to -Out, so debug logs it writes to its current directory
  stay with the private output instead of landing in the agent's current directory. Files that
  appear there are the app's own logs and dumps: a note line before the end line lists them.
  Summarize what matters in the ledger, then delete them before the companion is committed.

.PARAMETER Seconds
  How long to watch. Default 60. For the P1 idle capture and the P6 after-apply capture use the
  same length, at least 1200 (20 minutes): some helpers start ten minutes or more after launch.
  An agent's foreground shell call is cut off at 10 minutes, so run such a capture in the
  background and wait for its end line.

.PARAMETER Out
  Output JSON lines path (required).

.PARAMETER PollMs
  Process poll interval. Default 500.

.PARAMETER ConnEverySeconds
  Connection poll interval for the conn lines (each new endpoint once). Default 2. 0 turns it off.

.PARAMETER ConnCountEverySeconds
  Interval of the conn_count line: the number of established TCP connections per tracked
  process and in total, taken every interval, so a start-up burst can be told from a retry loop
  (reference/pipeline-field-notes.md, P6). Default 60. 0 turns it off.

.PARAMETER WatchNames
  Optional case-insensitive regex on process names, for example '^(updater|setup)\.exe$'. Every
  match is tracked (reason "name" when nothing else links it) and its line carries name_match,
  under_root (its image path or service binary lies under a -Root), the image path, and the
  service name and binary if it runs one. A generic name alone does not make a process the app's.

.PARAMETER KeepPaths
  Keep the literal user profile path and user name. By default they become %USERPROFILE% and
  %USERNAME%, like inventory.ps1.

.PARAMETER Sample
  Add resource samples (sample lines and a sample_summary line, above). Use it for the idle
  sample, for an owner-run transfer or feature test, and wherever "resource use" is a finding.
  The first sample follows the first poll (and the launch) as a baseline; a last one is taken
  when -Seconds ends.

.PARAMETER SampleEverySeconds
  Interval of the sample lines with -Sample. Default 10.

.PARAMETER Attach
  Watch an app that is already running instead of one about to start: -Launch is refused, and
  the run stops at once with an error (a note line says why) when no process is tracked after
  the first poll, so an attach to an app that is not running does not wait out -Seconds.
  Processes found running are proc_running lines; a child that was already running is tracked
  only if its parent still runs.

.EXAMPLE
  .\launch_monitor.ps1 -Root "$env:ProgramFiles\ExampleApp" -DataDir "$env:APPDATA\ExampleApp" `
      -Launch "$env:ProgramFiles\ExampleApp\ExampleApp.exe" -Seconds 1200 `
      -WatchNames '^(updater|setup)\.exe$' -Out D:\private\launch.jsonl

.EXAMPLE
  # Elevated, for the process start trace: no -Launch. Start the app from a normal shell after the start line.
  .\launch_monitor.ps1 -Root "$env:ProgramFiles\ExampleApp" -Seconds 1200 -Out D:\private\launch.jsonl

.EXAMPLE
  # The app already runs (idle sample, or the owner runs one transfer meanwhile): attach and sample.
  .\launch_monitor.ps1 -Root "$env:ProgramFiles\ExampleApp" -Attach -Sample -Seconds 300 -Out D:\private\sample.jsonl
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
    [int]$ConnCountEverySeconds = 60,
    [string]$WatchNames,
    [switch]$KeepPaths,
    [switch]$Sample,
    [int]$SampleEverySeconds = 10,
    [switch]$Attach
)
$ErrorActionPreference = 'Stop'
if ($Attach -and $Launch) { throw '-Attach watches an app that is already running; leave out -Launch.' }
if ($Sample -and $SampleEverySeconds -lt 1) { throw '-SampleEverySeconds must be at least 1.' }

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
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class AdLm {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, uint f, StringBuilder s, ref uint n);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr h, out long c, out long e, out long k, out long u);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    public class ProcInfo { public string Path; public string CommandLine; public DateTime? Created; public bool Exited; }
    // Read at once with PROCESS_QUERY_LIMITED_INFORMATION; null when the process is gone or cannot be opened.
    // Exited: it has ended but a handle (often its parent's) keeps it openable; its command line is gone then.
    // Created is local time cut to whole microseconds, the precision of Win32_Process.CreationDate.
    public static ProcInfo Info(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            var r = new ProcInfo();
            uint code; if (GetExitCodeProcess(h, out code) && code != 259) r.Exited = true;   // 259: STILL_ACTIVE
            var sb = new StringBuilder(1024); uint n = 1024;
            if (QueryFullProcessImageNameW(h, 0, sb, ref n)) r.Path = sb.ToString();
            long c, e, k, u;
            if (GetProcessTimes(h, out c, out e, out k, out u) && c > 0) { long t = DateTime.FromFileTime(c).Ticks; r.Created = new DateTime(t - t % 10, DateTimeKind.Local); }
            r.CommandLine = CommandLine(h);
            return r;
        } finally { CloseHandle(h); }
    }
    static string CommandLine(IntPtr h) {
        int len;
        NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out len);   // 60: ProcessCommandLineInformation (Windows 8.1 and later)
        if (len <= 0 || len > (1 << 20)) return null;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try {
            if (NtQueryInformationProcess(h, 60, buf, len, out len) != 0) return null;
            int bytes = Marshal.ReadInt16(buf) & 0xffff;        // UNICODE_STRING.Length
            IntPtr s = Marshal.ReadIntPtr(buf, IntPtr.Size);     // UNICODE_STRING.Buffer
            return (bytes > 0 && s != IntPtr.Zero) ? Marshal.PtrToStringUni(s, bytes / 2) : "";
        } finally { Marshal.FreeHGlobal(buf); }
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenSCManagerW(string m, string d, uint a);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenServiceW(IntPtr scm, string n, uint a);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool EnumServicesStatusExW(IntPtr scm, int level, uint type, uint state, IntPtr buf, int size, out int needed, out int count, ref int resume, string group);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryServiceConfigW(IntPtr h, IntPtr buf, int size, out int needed);
    [StructLayout(LayoutKind.Sequential)] struct ESSP { public IntPtr Name, Display; public uint Type, State, Controls, Exit, SvcExit, Check, Wait, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential)] struct QSC { public uint Type, Start, Error; public IntPtr Binary; }
    public class Svc { public string Name; public int Pid; public string PathName; }
    static readonly Dictionary<string, string> binCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public static void ResetCache() { binCache.Clear(); }
    // Running Win32 services with their process id and binary path; null when the service manager refuses.
    public static Svc[] Services() {
        IntPtr scm = OpenSCManagerW(null, null, 0x0005);   // SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
        if (scm == IntPtr.Zero) return null;
        var res = new List<Svc>();
        try {
            int needed, count, resume = 0;
            EnumServicesStatusExW(scm, 0, 0x30, 1, IntPtr.Zero, 0, out needed, out count, ref resume, null);   // size query
            int step = Marshal.SizeOf(typeof(ESSP));
            for (int round = 0; round < 64; round++) {
                int size = Math.Max(needed, step) + 4096;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try {
                    bool ok = EnumServicesStatusExW(scm, 0, 0x30, 1, buf, size, out needed, out count, ref resume, null);
                    if (!ok && Marshal.GetLastWin32Error() != 234) return null;   // 234: ERROR_MORE_DATA, call again
                    for (int i = 0; i < count; i++) {
                        var e = (ESSP)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * step), typeof(ESSP));
                        if (e.Pid == 0) continue;
                        string name = Marshal.PtrToStringUni(e.Name);
                        res.Add(new Svc { Name = name, Pid = (int)e.Pid, PathName = Binary(scm, name) });
                    }
                    if (ok) break;
                } finally { Marshal.FreeHGlobal(buf); }
            }
        } finally { CloseServiceHandle(scm); }
        return res.ToArray();
    }
    static string Binary(IntPtr scm, string name) {
        string v;
        if (binCache.TryGetValue(name, out v)) return v;
        IntPtr h = OpenServiceW(scm, name, 0x0001);   // SERVICE_QUERY_CONFIG
        if (h != IntPtr.Zero) {
            try {
                int needed; QueryServiceConfigW(h, IntPtr.Zero, 0, out needed);
                if (needed > 0 && needed < (1 << 16)) {
                    IntPtr b = Marshal.AllocHGlobal(needed);
                    try { if (QueryServiceConfigW(h, b, needed, out needed)) v = Marshal.PtrToStringUni(((QSC)Marshal.PtrToStructure(b, typeof(QSC))).Binary); }
                    finally { Marshal.FreeHGlobal(b); }
                }
            } finally { CloseServiceHandle(h); }
        }
        binCache[name] = v;
        return v;
    }
}
'@
[AdLm]::ResetCache()

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin -and $Launch) {
    throw ('-Launch from an elevated shell would start the app with the admin token, so it could update itself into ' +
        'Program Files or do its SYSTEM work directly. Run the elevated monitor without -Launch and start the app ' +
        'from a normal shell after the start line; it is tracked through its root.')
}
$WatchRx = $null; if ($WatchNames) { $WatchRx = [regex]::new($WatchNames, 'IgnoreCase') }
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
# Credential-like values in command lines become <redacted>; switch and parameter names stay.
# inventory.ps1 and elevated_readonly.ps1 carry the same rule; keep the three in step. A sid name must be
# the whole name or follow a separator (sid=, --sid, x_sid), so names such as "inside" or "consider" stay.
$SecretName = '(?:[\w.-]*?(?:token|stoken|bduss|session|password|passwd|secret|cookie|auth)[\w.-]*|(?:[\w.-]*[_.-])?sid)'
$StrongName = '[\w.-]*?(?:token|stoken|bduss|password|passwd|secret|cookie)[\w.-]*'
$SecretRx = @(
    # -name value, --name=value, /name:value. After a token, bduss, password, secret or cookie switch the next
    # word is the value even when it starts with - or / (base64 can); after a session or auth switch a
    # following switch is not taken. Only the value is matched (the name sits in the lookbehind), so a value
    # that is itself such a switch is redacted and the word after it still is too.
    [regex]::new('(?<=(?<![^\s"''(])(?:--?|/)(?:' + $StrongName + '\s+|' + $SecretName + '(?:[=:]|\s+(?=[^\s/-]))))(?<v>"[^"]*"?|''[^'']*''?|[^\s"'']+)', 'IgnoreCase'),
    # name=value in a query string or key=value list (?access_token=..., &session=...)
    [regex]::new('(?<![\w./-])(?<n>' + $SecretName + ')(?<s>=)(?<v>"[^"]*"?|[^\s"''&#;,]+)', 'IgnoreCase'),
    # "name": "value" in JSON on a command line, quotes possibly escaped
    [regex]::new('(?<n>\\?"' + $SecretName + '\\?")(?<s>\s*:\s*)(?<v>\\?"(?:[^"\\]|\\(?!"))*\\?"|[^\s,}\]]+)', 'IgnoreCase'),
    # Cookie: and Authorization: headers
    [regex]::new('(?<![\w-])(?<n>(?:set-)?cookie|authorization)(?<s>\s*:\s*)(?<v>[^"''\r\n]+)', 'IgnoreCase')
)
function Hide-Secret([string]$s) {
    if (-not $s) { return $s }
    foreach ($rx in $SecretRx) {
        $s = $rx.Replace($s, [Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $v = $m.Groups['v'].Value; $q = ''
            foreach ($c in '\"', '"', "'") { if ($v.StartsWith($c)) { $q = $c; break } }
            $close = $(if ($q -and $v.Length -gt $q.Length -and $v.EndsWith($q)) { $q } else { '' })
            $m.Groups['n'].Value + $m.Groups['s'].Value + $q + '<redacted>' + $close })
    }
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
function Format-Time($d) { if ($null -ne $d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { $null } }

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
# The executable of a service PathName: quoted, or unquoted with spaces up to the first ".exe".
function Get-ExeFromCommand([string]$c) {
    if (-not $c) { return $null }
    $c = $c.Trim()
    if ($c.StartsWith('"')) { $i = $c.IndexOf('"', 1); if ($i -gt 1) { return Norm $c.Substring(1, $i - 1) }; return Norm $c }
    $m = [regex]::Match($c, '^.*?\.exe(?=\s|$)', 'IgnoreCase')
    if ($m.Success) { return Norm $m.Value }
    Norm (($c -split '\s+')[0])
}

# ---------------------------------------------------------------- file watchers
$tap = New-Object AdFsTap
$watched = @()
foreach ($d in @($roots) + @(foreach ($x in @($DataDir)) { if ($x) { Norm $x } })) {
    if (-not $d -or $watched -contains $d) { continue }
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { Write-Warning "data dir not found, not watched: $d"; continue }
    try { $tap.Add($d); $watched += $d } catch { Write-Warning "cannot watch ${d}: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- services (pid -> service name and binary)
$svcByPid = @{}
$svcReadable = $true
function Update-Services {
    $list = [AdLm]::Services()
    if ($null -eq $list) {
        if ($script:svcReadable) { Emit 'note' ([ordered]@{ text = 'the service list could not be read; reason "service" is unavailable' }) }
        $script:svcReadable = $false; return
    }
    $svcByPid.Clear()
    foreach ($s in $list) {
        $img = Get-ExeFromCommand $s.PathName
        $row = @{ name = $s.Name; image = $img; path_name = $s.PathName; under_root = (Test-UnderRoot $img) }
        if ($svcByPid.ContainsKey($s.Pid)) { $svcByPid[$s.Pid] += , $row } else { $svcByPid[$s.Pid] = @(, $row) }
    }
}

# ---------------------------------------------------------------- process tracking
$tracked = @{}      # pid -> @{ created; name; path; reason; parent; alive; detail; recorded }
$seen = @{}         # pid|creation -> $true (every process already considered)
$live = @{}         # pid -> creation time, from the current poll
$traceParents = @{} # pid -> parent pid, from Win32_ProcessStartTrace (elevated only)
$procProps = @('ProcessId', 'ParentProcessId', 'Name', 'ExecutablePath', 'CommandLine', 'CreationDate')
if ($Sample) { $procProps += 'KernelModeTime', 'UserModeTime', 'WorkingSetSize', 'PrivatePageCount', 'ReadOperationCount', 'WriteOperationCount',
    'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount' }
$lastProcs = @()    # the latest poll, which -Sample reads
function Get-Procs { @(Get-CimInstance Win32_Process -Property $procProps -ErrorAction SilentlyContinue) }
# remote_debugging for a command line that opens a browser debugging endpoint, or $null.
function Get-DebugFlag([string]$c) {
    if (-not $c) { return $null }
    $m = [regex]::Match($c, '--remote-debugging-port[=\s]+(\d+)', 'IgnoreCase')
    if ($m.Success) { return "port=$($m.Groups[1].Value)" }
    if ($c -match '(?i)--remote-debugging-pipe') { return 'pipe' }
    $null
}
function Mark-Exit([int]$id, [string]$why) {
    $t = $tracked[$id]; $t.alive = $false
    $f = [ordered]@{ pid = $id; name = $t.name; lifetime_s = $(if ($null -ne $t.created) { [math]::Round(((Get-Date) - $t.created).TotalSeconds, 1) } else { $null }) }
    if ($why) { $f.note = $why }
    Emit 'proc_exit' $f
}
# A tracked entry that can be this process's parent: running, both creation times known, the parent's
# earlier, and its PID not taken over by a newer process in this poll.
function Get-ValidParent([int]$pp, $created) {
    $c = $tracked[$pp]
    if (-not $c -or -not $c.alive -or $null -eq $c.created -or $null -eq $created -or $c.created -gt $created) { return $null }
    if ($live.ContainsKey($pp) -and $null -ne $live[$pp] -and $live[$pp] -ne $c.created) { return $null }
    $c
}
function Consider($p, [bool]$initial, [string]$forceReason) {
    $id = [int]$p.ProcessId; $created = $p.CreationDate
    $sk = "$id|$created"; if ($seen.ContainsKey($sk)) { return }
    $seen[$sk] = $true
    if ($id -eq $PID) { return }
    $prev = $tracked[$id]
    if ($prev -and $prev.alive) {
        # The same process when the creation times match; an entry without one (the start trace could not
        # read it) matches only a process created before that entry was recorded.
        $same = $(if ($null -ne $prev.created) { $null -eq $created -or $prev.created -eq $created } else { $null -eq $created -or $created -le $prev.recorded })
        if ($same) {
            if (-not $prev.detail) {
                if ($null -eq $prev.created) { $prev.created = $created }
                $prev.path = $p.ExecutablePath; $prev.detail = $true
                $f = [ordered]@{ pid = $id; name = $p.Name; path = $p.ExecutablePath; command_line = (Hide-Secret $p.CommandLine); created = (Format-Time $created) }
                $dbg = Get-DebugFlag $p.CommandLine; if ($dbg) { $f.remote_debugging = $dbg }
                Emit 'proc_detail' $f
            }
            return
        }
        Mark-Exit $id 'PID taken over by a newer process'
    }
    $path = $p.ExecutablePath
    $svcs = $svcByPid[$id]; if (-not $svcs) { $svcs = @() }
    $pp = [int]$p.ParentProcessId
    if ($pp -eq 0 -and $traceParents.ContainsKey($id)) { $pp = $traceParents[$id] }
    $par = Get-ValidParent $pp $created
    $nameHit = [bool]($WatchRx -and $p.Name -and $WatchRx.IsMatch($p.Name))
    $reason = $forceReason
    if (-not $reason -and (Test-UnderRoot $path)) { $reason = 'root' }
    if (-not $reason) { foreach ($s in $svcs) { if ($s.under_root) { $reason = 'service'; break } } }
    if (-not $reason -and $par) { $reason = 'child' }
    if (-not $reason -and $nameHit) { $reason = 'name' }
    if (-not $reason) { return }
    $tracked[$id] = @{ created = $created; name = $p.Name; path = $path; reason = $reason; parent = $pp; alive = $true; detail = $true; recorded = Get-Date }
    $f = [ordered]@{ pid = $id; ppid = [int]$p.ParentProcessId; parent = $null; parent_reason = $null; name = $p.Name
        path = $path; command_line = (Hide-Secret $p.CommandLine); reason = $reason; created = (Format-Time $created) }
    if ($par) { $f.parent = $par.name; $f.parent_reason = $par.reason }
    $dbg = Get-DebugFlag $p.CommandLine; if ($dbg) { $f.remote_debugging = $dbg }
    if ($svcs.Count) {
        $f.service = (@($svcs | ForEach-Object { $_.name }) -join ', ')
        $f.service_image = (@($svcs | ForEach-Object { $_.image } | Select-Object -Unique) -join '; ')
        $f.service_path_name = (@($svcs | ForEach-Object { Hide-Secret $_.path_name } | Select-Object -Unique) -join '; ')
    }
    if ($nameHit) { $f.name_match = $true; $f.under_root = [bool]((Test-UnderRoot $path) -or @($svcs | Where-Object { $_.under_root }).Count) }
    Emit $(if ($initial) { 'proc_running' } else { 'proc_start' }) $f
}
function Poll-Procs([bool]$initial) {
    $all = Get-Procs
    $script:lastProcs = $all; $script:lastPollT = $t0.Elapsed.TotalSeconds; $script:lastPollWall = Get-Date
    Update-Services
    $live.Clear(); foreach ($p in $all) { $live[[int]$p.ProcessId] = $p.CreationDate }
    # parents before children, so a whole new chain is caught in one poll
    foreach ($p in ($all | Sort-Object { if ($_.CreationDate) { $_.CreationDate } else { [datetime]::MaxValue } })) { Consider $p $initial $null }
    foreach ($id in @($tracked.Keys)) {
        $t = $tracked[$id]; if (-not $t.alive) { continue }
        if (-not $live.ContainsKey($id)) { Mark-Exit $id $null }
        elseif ($null -ne $t.created -and $null -ne $live[$id] -and $live[$id] -ne $t.created) { Mark-Exit $id 'PID taken over by a newer process' }
        elseif ($null -eq $t.created -and $null -ne $live[$id] -and $live[$id] -gt $t.recorded) { Mark-Exit $id 'PID taken over by a newer process' }
    }
}

$traceSub = $null
if ($IsAdmin) {
    try {
        $traceSub = 'adlm-' + [guid]::NewGuid().ToString('N')
        Register-CimIndicationEvent -Query 'SELECT ProcessID, ParentProcessID, ProcessName FROM Win32_ProcessStartTrace' -SourceIdentifier $traceSub -ErrorAction Stop
    } catch { $traceSub = $null; Write-Warning "Win32_ProcessStartTrace unavailable: $($_.Exception.Message)" }
}
# Path, command line and creation time of one process, read at once. Win32_Process only for a running
# process whose command line could not be read. One that could not be opened (gone) or has exited returns
# at once: Win32_Process no longer lists it, and the query takes most of a second, which in a burst of
# short-lived children would stall polling.
function Get-ProcInfo([int]$id) {
    $i = [AdLm]::Info($id)
    if ($null -eq $i -or $i.Exited -or $null -ne $i.CommandLine) { return $i }
    $w = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -Property ExecutablePath, CommandLine, CreationDate -ErrorAction SilentlyContinue
    if ($w) { return [pscustomobject]@{ Path = $w.ExecutablePath; CommandLine = $w.CommandLine; Created = $w.CreationDate } }
    $i
}
function Drain-Trace {
    if (-not $traceSub) { return }
    foreach ($ev in @(Get-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue)) {
        $ni = $ev.SourceEventArgs.NewEvent
        Remove-Event -EventIdentifier $ev.EventIdentifier
        $cid = [int]$ni.ProcessID; $ppid = [int]$ni.ParentProcessID
        $traceParents[$cid] = $ppid
        $par = $tracked[$ppid]
        if (-not ($par -and $par.alive)) { continue }
        # Resolve the parent's creation time now, while it most likely still runs. A PID that belongs to a
        # newer process than the tracked one means the tracked parent is gone and this child is not its own.
        $pinfo = [AdLm]::Info($ppid)
        if ($pinfo -and $null -ne $pinfo.Created) {
            if ($null -eq $par.created) { if ($pinfo.Created -le $par.recorded) { $par.created = $pinfo.Created } else { continue } }
            elseif ($pinfo.Created -ne $par.created) { continue }
        }
        $ci = Get-ProcInfo $cid
        $cc = $(if ($ci) { $ci.Created } else { $null })
        if ($null -ne $cc -and $null -ne $par.created -and $par.created -gt $cc) { continue }
        $old = $tracked[$cid]
        if ($old -and $old.alive) {
            # A poll already announced it: the same creation time, or none because it has exited since (each
            # trace event is a new start, so a PID reused that fast is far less likely than a late event).
            if ($null -eq $cc -or $old.created -eq $cc) { continue }
            Mark-Exit $cid 'PID taken over by a newer process'
        }
        $ok = [bool]($ci -and ($ci.Path -or $ci.CommandLine))
        $tracked[$cid] = @{ created = $cc; name = $ni.ProcessName; path = $(if ($ci) { $ci.Path } else { $null }); reason = 'child-trace'; parent = $ppid; alive = $true; detail = $ok; recorded = Get-Date }
        if ($ok -and $null -ne $cc) { $seen["$cid|$cc"] = $true }
        $f = [ordered]@{ pid = $cid; ppid = $ppid; parent = $par.name; parent_reason = $par.reason; name = $ni.ProcessName
            path = $(if ($ci) { $ci.Path } else { $null }); command_line = $(if ($ci -and $null -ne $ci.CommandLine) { Hide-Secret $ci.CommandLine } else { $null }); reason = 'child-trace'; created = (Format-Time $cc)
            detail = $(if ($ok) { 'read at start' } else { 'not readable at start (exited or denied)' }) }
        $dbg = Get-DebugFlag $(if ($ci) { $ci.CommandLine } else { $null }); if ($dbg) { $f.remote_debugging = $dbg }
        Emit 'proc_start' $f
    }
}

# ---------------------------------------------------------------- connections
$connSeen = @{}
# Who can reach a bound address: loopback, all interfaces, or one interface address.
function Get-ListenScope([string]$a) {
    if ($a -eq '0.0.0.0' -or $a -eq '::') { return 'all' }
    if ($a -eq '::1' -or $a.StartsWith('127.')) { return 'loopback' }
    'specific'
}
function Poll-Conns {
    $ids = @($tracked.Keys | Where-Object { $tracked[$_].alive })
    if (-not $ids) { return }
    $set = @{}; foreach ($i in $ids) { $set[[int]$i] = $true }
    # Kept for Take-Sample: Get-NetTCPConnection can take more than a second on a busy machine.
    $script:lastTcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue); $script:lastUdp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    $script:lastConnT = $t0.Elapsed.TotalSeconds
    foreach ($c in $script:lastTcp) {
        $op = [int]$c.OwningProcess; if (-not $set.ContainsKey($op)) { continue }
        $k = "tcp|$op|$($c.LocalAddress):$($c.LocalPort)|$($c.RemoteAddress):$($c.RemotePort)|$($c.State)"
        if ($connSeen.ContainsKey($k)) { continue }; $connSeen[$k] = $true
        $f = [ordered]@{ proto = 'tcp'; pid = $op; process = $tracked[$op].name; state = $c.State.ToString()
            local = "$($c.LocalAddress):$($c.LocalPort)"; remote = "$($c.RemoteAddress):$($c.RemotePort)" }
        if ($f.state -eq 'Listen') { $f.listen_scope = Get-ListenScope "$($c.LocalAddress)" }
        Emit 'conn' $f
    }
    foreach ($u in $script:lastUdp) {
        $op = [int]$u.OwningProcess; if (-not $set.ContainsKey($op)) { continue }
        $k = "udp|$op|$($u.LocalAddress):$($u.LocalPort)"
        if ($connSeen.ContainsKey($k)) { continue }; $connSeen[$k] = $true
        Emit 'conn' ([ordered]@{ proto = 'udp'; pid = $op; process = $tracked[$op].name; local = "$($u.LocalAddress):$($u.LocalPort)"
            listen_scope = (Get-ListenScope "$($u.LocalAddress)") })
    }
}
# Established TCP connections per tracked process and in total: one count over time per line.
$countLines = 0
function Count-Conns {
    $alive = @{}; foreach ($k in @($tracked.Keys)) { if ($tracked[$k].alive) { $alive[[int]$k] = $true } }
    $by = @{}
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        $op = [int]$c.OwningProcess; if (-not $alive.ContainsKey($op)) { continue }
        if ($by.ContainsKey($op)) { $by[$op]++ } else { $by[$op] = 1 }
    }
    $total = 0; foreach ($v in $by.Values) { $total += $v }
    $rows = @(foreach ($k in @($by.Keys | Sort-Object)) { [ordered]@{ pid = $k; name = $tracked[$k].name; established = $by[$k] } })
    Emit 'conn_count' ([ordered]@{ established = $total; tracked_alive = $alive.Count; by_process = $rows })
    $script:countLines++
}

# ---------------------------------------------------------------- resource samples (-Sample)
$nCpu = [Environment]::ProcessorCount
$sampPrev = @{}             # pid -> @{ created; cpu; io } at the previous sample
$sampAgg = [ordered]@{}     # pid|created -> totals over the window
$sampleLines = 0; $sampleAt = $null; $sampleWall = $null; $firstSampleAt = $null; $peakWs = 0.0; $peakPriv = 0.0
$lastPollT = $null; $lastPollWall = $null; $lastTcp = @(); $lastUdp = @(); $lastConnT = $null
$ioNames = @('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')
$ioProps = @('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')
# One sample line from the latest poll: per tracked running process CPU, memory, I/O deltas and socket counts.
# Times are those of that poll (poll_t), not of the line, so the deltas divide by the real interval.
function Take-Sample {
    $now = $script:lastPollT; $wall = $script:lastPollWall
    if ($null -eq $now) { return }
    $dt = $(if ($null -ne $script:sampleAt) { $now - $script:sampleAt } else { $null })
    if ($null -ne $dt -and $dt -le 0) { return }   # no new poll since the last sample
    $byPid = @{}; foreach ($p in $script:lastProcs) { $byPid[[int]$p.ProcessId] = $p }
    $ids = @(foreach ($k in @($tracked.Keys | Sort-Object)) { if ($tracked[$k].alive -and $byPid.ContainsKey([int]$k)) { [int]$k } })
    $set = @{}; foreach ($i in $ids) { $set[$i] = $true }
    $est = @{}; $lis = @{}; $udp = @{}
    if ($ids.Count) {
        # The socket lists of the last connection poll when it is recent, else a fresh read.
        if ($null -eq $script:lastConnT -or $t0.Elapsed.TotalSeconds - $script:lastConnT -gt 5) {
            $script:lastTcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue); $script:lastUdp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
            $script:lastConnT = $t0.Elapsed.TotalSeconds
        }
        foreach ($c in $script:lastTcp) {
            $op = [int]$c.OwningProcess; if (-not $set.ContainsKey($op)) { continue }
            if ($c.State -eq 'Established') { $est[$op] = 1 + [int]$est[$op] } elseif ($c.State -eq 'Listen') { $lis[$op] = 1 + [int]$lis[$op] }
        }
        foreach ($u in $script:lastUdp) { $op = [int]$u.OwningProcess; if ($set.ContainsKey($op)) { $udp[$op] = 1 + [int]$udp[$op] } }
    }
    $tot = [ordered]@{ processes = 0; cpu_d_s = 0.0; cpu_pct = $null; ws_mb = 0.0; priv_mb = 0.0 }
    foreach ($n in $ioNames) { $tot[$n] = [int64]0 }
    $tot.tcp_est = 0; $tot.tcp_listen = 0; $tot.udp = 0
    $rows = New-Object System.Collections.Generic.List[object]
    $next = @{}
    foreach ($id in $ids) {
        $t = $tracked[$id]; $p = $byPid[$id]
        if ($null -ne $t.created -and $null -ne $p.CreationDate -and $p.CreationDate -ne $t.created) { continue }   # PID reused since
        $cpu = ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7
        $io = @(foreach ($n in $ioProps) { [double]$p.$n })
        $next[$id] = @{ created = $p.CreationDate; cpu = $cpu; io = $io }
        $prev = $sampPrev[$id]; $since = 'none'; $base = $null; $span = $null
        if ($prev -and $prev.created -eq $p.CreationDate) { $since = 'prev'; $base = $prev; $span = $dt }
        elseif ($null -ne $script:sampleWall -and $null -ne $p.CreationDate -and $p.CreationDate -gt $script:sampleWall) {
            $since = 'start'; $base = @{ cpu = 0.0; io = @(0.0, 0.0, 0.0, 0.0, 0.0, 0.0) }; $span = ($wall - $p.CreationDate).TotalSeconds
        }
        $ws = [math]::Round([double]$p.WorkingSetSize / 1MB, 1); $pv = [math]::Round([double]$p.PrivatePageCount / 1MB, 1)
        $r = [ordered]@{ pid = $id; name = $t.name; since = $since; cpu_s = [math]::Round($cpu, 2); cpu_d_s = $null; cpu_pct = $null; ws_mb = $ws; priv_mb = $pv }
        foreach ($n in $ioNames) { $r[$n] = $null }
        $r.tcp_est = [int]$est[$id]; $r.tcp_listen = [int]$lis[$id]; $r.udp = [int]$udp[$id]
        $ak = "$id|$($p.CreationDate)"; $a = $sampAgg[$ak]
        if (-not $a) {
            $a = [ordered]@{ pid = $id; name = $t.name; created = (Format-Time $p.CreationDate); samples = 0; span_s = 0.0; cpu_s = 0.0; cpu_pct_avg = $null; peak_ws_mb = 0.0; peak_priv_mb = 0.0 }
            foreach ($n in $ioNames) { $a[$n] = [int64]0 }
            $sampAgg[$ak] = $a
        }
        $a.samples++
        if ($ws -gt $a.peak_ws_mb) { $a.peak_ws_mb = $ws }; if ($pv -gt $a.peak_priv_mb) { $a.peak_priv_mb = $pv }
        if ($base) {
            $d = [math]::Max(0.0, $cpu - $base.cpu)
            $r.cpu_d_s = [math]::Round($d, 2); $tot.cpu_d_s += $d; $a.cpu_s += $d
            if ($span -gt 0) { $r.cpu_pct = [math]::Round(100 * $d / $span / $nCpu, 2); $a.span_s += $span }
            for ($i = 0; $i -lt $ioNames.Count; $i++) {
                $v = [int64][math]::Max(0.0, $io[$i] - $base.io[$i]); $r[$ioNames[$i]] = $v; $tot[$ioNames[$i]] += $v; $a[$ioNames[$i]] += $v
            }
        }
        $tot.processes++; $tot.ws_mb += $ws; $tot.priv_mb += $pv; $tot.tcp_est += $r.tcp_est; $tot.tcp_listen += $r.tcp_listen; $tot.udp += $r.udp
        $rows.Add($r)
    }
    $script:sampPrev = $next
    if ($dt -gt 0) { $tot.cpu_pct = [math]::Round(100 * $tot.cpu_d_s / $dt / $nCpu, 2) }
    $tot.cpu_d_s = [math]::Round($tot.cpu_d_s, 2); $tot.ws_mb = [math]::Round($tot.ws_mb, 1); $tot.priv_mb = [math]::Round($tot.priv_mb, 1)
    if ($tot.ws_mb -gt $script:peakWs) { $script:peakWs = $tot.ws_mb }; if ($tot.priv_mb -gt $script:peakPriv) { $script:peakPriv = $tot.priv_mb }
    # ToArray, not @(): Windows PowerShell 5.1 fails on @(<generic List>) inside a hashtable literal.
    Emit 'sample' ([ordered]@{ poll_t = [math]::Round($now, 2); interval_s = $(if ($null -ne $dt) { [math]::Round($dt, 2) } else { $null }); n_cpu = $nCpu; total = $tot; procs = $rows.ToArray() })
    if ($null -eq $script:firstSampleAt) { $script:firstSampleAt = $now }
    $script:sampleAt = $now; $script:sampleWall = $wall; $script:sampleLines++
}
function Write-SampleSummary {
    $win = $(if ($null -ne $script:firstSampleAt) { $script:sampleAt - $script:firstSampleAt } else { 0.0 })
    $tot = [ordered]@{ processes = $sampAgg.Count; cpu_s = 0.0; cpu_pct_avg = $null; peak_ws_mb = $script:peakWs; peak_priv_mb = $script:peakPriv }
    foreach ($n in $ioNames) { $tot[$n] = [int64]0 }
    $rows = @(foreach ($a in @($sampAgg.Values)) {
        $tot.cpu_s += $a.cpu_s; foreach ($n in $ioNames) { $tot[$n] += $a[$n] }
        if ($a.span_s -gt 0) { $a.cpu_pct_avg = [math]::Round(100 * $a.cpu_s / $a.span_s / $nCpu, 2) }
        $a.cpu_s = [math]::Round($a.cpu_s, 2); $a.span_s = [math]::Round($a.span_s, 1)
        $a
    }) | Sort-Object { - $_.cpu_s }
    if ($win -gt 0) { $tot.cpu_pct_avg = [math]::Round(100 * $tot.cpu_s / $win / $nCpu, 2) }
    $tot.cpu_s = [math]::Round($tot.cpu_s, 2)
    Emit 'sample_summary' ([ordered]@{ samples = $script:sampleLines; every_s = $SampleEverySeconds; window_s = [math]::Round($win, 1); n_cpu = $nCpu; total = $tot; procs = @($rows) })
}

# ---------------------------------------------------------------- run
$fileCount = 0; $launched = $null; $alive = @(); $launchCwd = $null; $launchCwdFiles = @()
try {
    Emit 'start' ([ordered]@{ roots = $roots; watched = $watched; launch = $Launch; attach = [bool]$Attach; seconds = $Seconds; poll_ms = $PollMs
        elevated = $IsAdmin; start_trace = [bool]$traceSub; watch_names = $WatchNames; conn_count_every_s = $ConnCountEverySeconds
        sample_every_s = $(if ($Sample) { $SampleEverySeconds } else { $null }) })
    Poll-Procs $true
    if ($Attach -and -not @($tracked.Keys | Where-Object { $tracked[$_].alive }).Count) {
        $why = '-Attach: no process of the app is running (none under the roots, none running a service binary under them, no -WatchNames match)'
        Emit 'note' ([ordered]@{ text = $why })
        throw $why
    }
    if ($Launch) {
        $lp = Norm $Launch
        if (-not (Test-UnderRoot $lp)) { Emit 'note' ([ordered]@{ text = "launch target is not under any -Root; it and its children are tracked through the launch PID only" }) }
        # A private working directory next to -Out: vendor debug logs written to the current directory land
        # there instead of in the agent's current directory (which may be a public repo).
        $launchCwd = Join-Path ([IO.Path]::GetDirectoryName($outPath)) 'launch-cwd'
        [void][IO.Directory]::CreateDirectory($launchCwd)
        Emit 'note' ([ordered]@{ text = "launch working directory: $launchCwd" })
        $sp = @{ FilePath = $lp; PassThru = $true; WorkingDirectory = $launchCwd }
        if ($LaunchArgs) { $sp.ArgumentList = $LaunchArgs }
        $launched = Start-Process @sp
        # Read at once (the Process object keeps a handle, so this works even if the launcher exits right away).
        $li = [AdLm]::Info($launched.Id)
        $lc = $(if ($li) { $li.Created } else { $null })
        if ($null -eq $lc) { try { $tk = $launched.StartTime.Ticks; $lc = New-Object datetime(($tk - $tk % 10), [DateTimeKind]::Local) } catch { } }
        Consider ([pscustomobject]@{ ProcessId = $launched.Id; ParentProcessId = $PID; Name = [IO.Path]::GetFileName($lp)
            ExecutablePath = $(if ($li -and $li.Path) { $li.Path } else { $lp }); CommandLine = $(if ($li) { $li.CommandLine } else { $null }); CreationDate = $lc }) $false 'launched'
    }
    $nextConn = 0.0; $nextCount = [double]$ConnCountEverySeconds; $nextSample = 0.0
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
        if ($ConnCountEverySeconds -gt 0 -and $t0.Elapsed.TotalSeconds -ge $nextCount) {
            Count-Conns
            while ($nextCount -le $t0.Elapsed.TotalSeconds) { $nextCount += $ConnCountEverySeconds }   # on the grid, never twice in a row
        }
        if ($Sample -and $lastPollT -ge $nextSample) {   # on the grid of poll times, which the deltas use
            Take-Sample
            while ($nextSample -le $lastPollT) { $nextSample += $SampleEverySeconds }
        }
        Start-Sleep -Milliseconds $PollMs
    }
    # A last sample at the end of the window, so the summary covers all of it.
    if ($Sample -and $null -ne $sampleAt -and $t0.Elapsed.TotalSeconds - $sampleAt -ge 1) { Poll-Procs $false; Take-Sample }
} finally {
    $tap.Dispose()
    if ($traceSub) { Unregister-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue; Get-Event -SourceIdentifier $traceSub -ErrorAction SilentlyContinue | Remove-Event }
    if ($Sample -and $sampleLines) { try { Write-SampleSummary } catch { Write-Warning "sample summary failed: $($_.Exception.Message)" } }
    $alive = @($tracked.Keys | Where-Object { $tracked[$_].alive })
    if ($launchCwd) {
        # What the app wrote to its working directory (logs, dumps): to be summarized in the ledger and deleted
        # before the companion is committed, never kept as DATA.
        try { $launchCwdFiles = @([IO.Directory]::GetFiles($launchCwd, '*', [IO.SearchOption]::AllDirectories) | ForEach-Object { $_.Substring($launchCwd.Length).TrimStart('\') }) } catch { }
        if ($launchCwdFiles.Count) {
            Emit 'note' ([ordered]@{ text = "launch working directory holds $($launchCwdFiles.Count) file(s) the app wrote (its own logs or dumps): summarize them in the ledger, then delete them before the companion is committed"
                launch_cwd = $launchCwd; files = $launchCwdFiles })
        }
    }
    Emit 'end' ([ordered]@{ tracked = $tracked.Count; still_running = $alive.Count; file_events = $fileCount; connections = $connSeen.Count; conn_counts = $countLines
        samples = $(if ($Sample) { $sampleLines } else { $null }) })
    $writer.Dispose()
}
Write-Host ("tracked processes: {0} ({1} still running), file events: {2}, endpoints: {3}, connection counts: {4}{5}" -f $tracked.Count, $alive.Count, $fileCount, $connSeen.Count, $countLines, $(if ($Sample) { ", samples: $sampleLines" } else { '' }))
if ($launchCwdFiles.Count) { Write-Host ("launch working directory {0} holds {1} file(s) the app wrote: {2}. Summarize them in the ledger, then delete them before the companion is committed." -f $launchCwd, $launchCwdFiles.Count, ($launchCwdFiles -join ', ')) }
Write-Host "out: $outPath"
