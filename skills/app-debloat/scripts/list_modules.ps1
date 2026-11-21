#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only list of the modules loaded in one or more processes, 32-bit WOW64 modules included.
  Use it in P6 to prove that a blocked DLL is no longer loaded (or that a kept one still is).

.DESCRIPTION
  Uses a Toolhelp32 snapshot with TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, the same call the
  engine and elevated_readonly.ps1 use. From 64-bit Windows PowerShell this lists the 32-bit
  modules of a WOW64 host as well, which Get-Process().Modules does not (it shows only the exe
  and the 64-bit WOW64 layer). It opens processes for query only and changes nothing.

  Processes are selected by -ProcessId (alias -Pid), by -ImagePathRegex against the full image
  path, or by -Root (image under a folder). The result is one JSON document on stdout or in -Out,
  and a short text summary on stdout when -Out is given.

  Errors per process: 5 = access denied (another user, SYSTEM or protected: rerun elevated),
  299 = partial copy (32-bit PowerShell asked about a 64-bit process: use 64-bit powershell.exe),
  998 = invalid access (isolated or VBS trustlet processes such as LsaIso; they cannot load app
  code). A process that exits during the snapshot reports error 87 or 18.

  Module paths are real-run DATA when the process belongs to the app: write -Out to the private
  companion, never into the tool repo.

.PARAMETER ProcessId
  One or more process ids. Alias -Pid.

.PARAMETER ImagePathRegex
  Case-insensitive regex matched against each process's full image path.

.PARAMETER Root
  One or more folders. A process matches when its image is under one.

.PARAMETER ModuleRegex
  Optional case-insensitive regex. When given, only matching modules are listed, and the
  summary says for each process whether any module matched.

.PARAMETER Out
  Optional JSON output path. Without it the JSON goes to stdout and nothing else is printed.

.EXAMPLE
  .\list_modules.ps1 -Pid 1234
  .\list_modules.ps1 -ImagePathRegex '\\ExampleApp\\[^\\]+\.exe$' -ModuleRegex 'exampleads\.dll$' -Out D:\private\mods.json
  .\list_modules.ps1 -Root "${env:ProgramFiles(x86)}\ExampleApp" -Out D:\private\mods.json
#>
[CmdletBinding()]
param(
    [Alias('Pid')][int[]]$ProcessId,
    [string]$ImagePathRegex,
    [string[]]$Root,
    [string]$ModuleRegex,
    [string]$Out
)
$ErrorActionPreference = 'Stop'
if (-not $ProcessId -and -not $ImagePathRegex -and -not $Root) { throw 'Pass -Pid <id>, -ImagePathRegex <regex> and/or -Root <dir>.' }
$Is32On64 = (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem)

Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class AdMods {
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
    public static string ImagePath(uint pid, out int wow, out int err) {
        wow = -1; err = 0;
        IntPtr h = OpenProcess(0x1000, false, pid);   // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) { err = Marshal.GetLastWin32Error(); return null; }
        try {
            bool w; if (IsWow64Process(h, out w)) wow = w ? 1 : 0;
            var sb = new StringBuilder(1024); uint n = 1024;
            if (QueryFullProcessImageNameW(h, 0, sb, ref n)) return sb.ToString();
            err = Marshal.GetLastWin32Error(); return null;
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
            if (Module32FirstW(snap, ref e)) {
                do { list.Add(new Mod { Path = e.szExePath, Base = "0x" + e.modBaseAddr.ToInt64().ToString("x"), Size = e.modBaseSize }); }
                while (Module32NextW(snap, ref e));
            } else { err = Marshal.GetLastWin32Error(); if (err == 18) err = 0; }   // ERROR_NO_MORE_FILES: empty list
        } finally { CloseHandle(snap); }
        return list.ToArray();
    }
}
'@

$rootPrefixes = @(foreach ($r in @($Root)) {
    if (-not $r) { continue }
    try { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($r.Trim('"'))).TrimEnd('\').ToLowerInvariant() } catch { Write-Warning "bad root: $r" }
})
$imgRx = $null; if ($ImagePathRegex) { $imgRx = New-Object regex($ImagePathRegex, 'IgnoreCase') }
$modRx = $null; if ($ModuleRegex) { $modRx = New-Object regex($ModuleRegex, 'IgnoreCase') }
$errText = @{ 5 = 'access denied'; 87 = 'process gone or invalid'; 299 = 'partial copy (32-bit caller, 64-bit target)'; 998 = 'invalid access (isolated process)' }

$wanted = @{}; foreach ($i in @($ProcessId)) { if ($i) { $wanted[[int]$i] = $true } }
$procs = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
$rows = New-Object System.Collections.Generic.List[object]
$missing = @($wanted.Keys | Where-Object { $k = $_; -not ($procs | Where-Object { [int]$_.ProcessId -eq $k }) })
foreach ($p in $procs) {
    $id = [int]$p.ProcessId
    if ($id -le 4) { continue }
    $wow = -1; $ierr = 0; $img = [AdMods]::ImagePath([uint32]$id, [ref]$wow, [ref]$ierr)
    if (-not $img) { $img = $p.ExecutablePath }
    $hit = $wanted.ContainsKey($id)
    # A hidden image path (other user, SYSTEM, protected) leaves only the process name to match against.
    if (-not $hit -and -not $img -and $imgRx -and $imgRx.IsMatch('\' + $p.Name)) { $hit = $true }
    if (-not $hit -and $img) {
        if ($imgRx -and $imgRx.IsMatch($img)) { $hit = $true }
        if (-not $hit) { $l = $img.ToLowerInvariant(); foreach ($rp in $rootPrefixes) { if ($l.StartsWith($rp + '\')) { $hit = $true; break } } }
    }
    if (-not $hit) { continue }
    $err = 0; $mods = [AdMods]::Modules([uint32]$id, [ref]$err)
    $list = @(foreach ($m in @($mods)) { if ($m) { [ordered]@{ path = $m.Path; base = $m.Base; size = $m.Size } } })
    $total = $list.Count
    if ($modRx) { $list = @($list | Where-Object { $modRx.IsMatch($_.path) }) }
    $rows.Add([ordered]@{
        pid = $id; ppid = [int]$p.ParentProcessId; name = $p.Name; image = $img
        wow64 = $(if ($wow -eq 1) { $true } elseif ($wow -eq 0) { $false } else { $null })
        error = $(if ($null -eq $mods) { $err } else { $null }); error_text = $(if ($null -eq $mods) { $errText[$err] } else { $null })
        module_count = $(if ($null -ne $mods) { $total } else { $null }); matched = $(if ($modRx -and $null -ne $mods) { $list.Count } else { $null })
        image_hidden = [bool](-not $img)
        modules = $list
    })
}

$doc = [ordered]@{
    schema = 'app-debloat.modules/1'; captured_at = (Get-Date).ToUniversalTime().ToString('o')
    host = [ordered]@{ ps_64bit = [Environment]::Is64BitProcess; os_64bit = [Environment]::Is64BitOperatingSystem
        elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    select = [ordered]@{ pid = @($ProcessId | Where-Object { $_ }); image_path_regex = $ImagePathRegex; roots = @($Root); module_regex = $ModuleRegex }
    missing_pids = @($missing)
    processes = $rows.ToArray()
}
if ($Is32On64) { $doc.note = '32-bit PowerShell on 64-bit Windows: 64-bit processes report error 299. Use 64-bit powershell.exe.' }
$json = ConvertTo-Json -InputObject $doc -Depth 6
if (-not $Out) { Write-Output $json; return }

$outFull = [IO.Path]::GetFullPath($Out)
[IO.File]::WriteAllText($outFull, $json, (New-Object Text.UTF8Encoding($false)))
if ($Is32On64) { Write-Warning $doc.note }
Write-Host ("processes: {0}, unreadable: {1}, missing pids: {2}" -f $rows.Count, @($rows | Where-Object { $null -ne $_.error }).Count, $missing.Count)
foreach ($r in $rows) {
    $bits = $(if ($r.wow64 -eq $true) { '32-bit' } elseif ($r.wow64 -eq $false) { '64-bit' } else { '?' })
    if ($null -ne $r.error) { $st = "error $($r.error) $($r.error_text)" }
    elseif ($modRx) { $st = "$($r.matched) of $($r.module_count) modules match: " + (@($r.modules | Select-Object -First 3 | ForEach-Object { Split-Path $_.path -Leaf }) -join ', ') }
    else { $st = "$($r.module_count) modules" }
    Write-Host ("  pid {0} {1} ({2}) -> {3}" -f $r.pid, $r.name, $bits, $st)
}
Write-Host "out: $outFull"
