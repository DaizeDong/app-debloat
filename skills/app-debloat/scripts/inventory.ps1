#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only inventory of one installed Windows desktop app: install roots, files, processes,
  modules, services, tasks, autostarts, COM, shell extensions, TSF, protocols, firewall,
  connections, toast AUMIDs, shortcuts, WMI, BITS. Writes one JSON snapshot.

.DESCRIPTION
  Changes nothing on the machine. Works without elevation; whatever it could not read is listed
  in "access_failures" and "notes" instead of being silently skipped.
  Every item carries a stable "key" so snapshot_diff.py can compare two snapshots.
  The snapshot is real-run DATA: write it to the private companion, never into the tool repo.

.PARAMETER App
  Regex matched against Uninstall DisplayName/Publisher, service names, COM names, task names,
  AUMIDs and so on. Example: 'Sogou|SogouInput'.

.PARAMETER Root
  One or more install directories. When omitted, roots come from Uninstall entries matching -App
  and from top-level folders under Program Files, %LOCALAPPDATA%, %APPDATA% and %ProgramData%
  whose name matches -App.

.PARAMETER Out
  Output JSON path (required). There is no default, so the tool never writes inside a repo.

.PARAMETER MaxFiles
  Cap on PE files that get version, signature and sha256 detail. Default 1500.

.PARAMETER MaxEntries
  Cap on file system entries walked per root. Default 60000.

.PARAMETER NoSignature
  Skip Authenticode checks (faster).

.PARAMETER KeepPaths
  Keep the literal user profile path and user name in the output. By default they are replaced
  with %USERPROFILE% and %USERNAME% so snapshots diff across machines.

.PARAMETER AutorunsAcceptEula
  Run Sysinternals autorunsc (if on PATH) with -accepteula. Without it, autorunsc runs only when
  its EULA was already accepted, because otherwise it opens a blocking EULA dialog.

.EXAMPLE
  .\inventory.ps1 -App 'ExampleApp' -Out "$env:TEMP\exampleapp-before.json"
  .\inventory.ps1 -Root "$env:ProgramFiles\ExampleApp" -App 'Example' -Out D:\private\inv.json
#>
[CmdletBinding()]
param(
    [string]$App,
    [string[]]$Root,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$MaxFiles = 1500,
    [int]$MaxEntries = 60000,
    [switch]$NoSignature,
    [switch]$KeepPaths,
    [switch]$AutorunsAcceptEula
)
$ToolVersion = '1.0.0'
$ErrorActionPreference = 'Stop'
if (-not $App -and -not $Root) { throw 'Pass -App <regex> and/or -Root <dir>.' }

# ---------------------------------------------------------------- native helpers (read-only)
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class AdInv {
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
    // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32: also lists 32-bit modules of WOW64 processes.
    public static string[] Modules(uint pid, out int err) {
        err = 0; IntPtr snap = IntPtr.Zero;
        for (int i = 0; i < 5; i++) {
            snap = CreateToolhelp32Snapshot(0x8 | 0x10, pid);
            if (snap != new IntPtr(-1)) break;
            err = Marshal.GetLastWin32Error(); if (err != 24) return null;   // 24 = ERROR_BAD_LENGTH, retry
        }
        if (snap == new IntPtr(-1)) return null;
        err = 0; var list = new List<string>();
        try {
            var e = new MODULEENTRY32W(); e.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
            if (Module32FirstW(snap, ref e)) { do { list.Add(e.szExePath); } while (Module32NextW(snap, ref e)); }
        } finally { CloseHandle(snap); }
        return list.ToArray();
    }
    public struct RECT { public int L, T, R, B; }
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    public class Win { public long Hwnd; public uint Pid; public string Cls; public string Title; public bool Visible; public int L, T, R, B; }
    public static Win[] Windows() {
        var res = new List<Win>();
        EnumProc cb = (h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            var t = new StringBuilder(256); GetWindowTextW(h, t, 256);
            var c = new StringBuilder(256); GetClassNameW(h, c, 256);
            RECT r; GetWindowRect(h, out r);
            res.Add(new Win { Hwnd = h.ToInt64(), Pid = pid, Cls = c.ToString(), Title = t.ToString(), Visible = IsWindowVisible(h), L = r.L, T = r.T, R = r.R, B = r.B });
            return true;
        };
        EnumWindows(cb, IntPtr.Zero); GC.KeepAlive(cb);
        return res.ToArray();
    }
}
'@

# ---------------------------------------------------------------- snapshot skeleton
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$Snap = [ordered]@{
    schema          = 'app-debloat.inventory/1'
    tool_version    = $ToolVersion
    captured_at     = (Get-Date).ToUniversalTime().ToString('o')
    host            = [ordered]@{
        os_version = [Environment]::OSVersion.Version.ToString()
        os_64bit   = [Environment]::Is64BitOperatingSystem
        ps_64bit   = [Environment]::Is64BitProcess
        ps_version = $PSVersionTable.PSVersion.ToString()
        elevated   = $IsAdmin
    }
    params          = [ordered]@{ app = $App; root = @($Root); max_files = $MaxFiles }
    roots           = New-Object System.Collections.Generic.List[object]
    related_files   = New-Object System.Collections.Generic.List[object]
    fingerprints    = [ordered]@{}
    coverage        = [ordered]@{}
    access_failures = New-Object System.Collections.Generic.List[object]
    notes           = New-Object System.Collections.Generic.List[string]
    items           = [ordered]@{}
}
if (-not $IsAdmin) {
    $Snap.notes.Add('Not elevated: other-user and SYSTEM process paths, command lines and modules, protected scheduled tasks, WMI subscriptions and all-user BITS jobs are partly or fully invisible.')
}
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $Snap.notes.Add('32-bit PowerShell on 64-bit Windows: module lists of 64-bit processes are unavailable. Use 64-bit powershell.exe.')
}

function Add-Failure([string]$section, [string]$target, [string]$err) {
    $Snap.access_failures.Add([ordered]@{ section = $section; target = $target; error = $err })
}
function Add-Item([string]$cat, $obj) {
    if (-not $Snap.items.Contains($cat)) { $Snap.items[$cat] = New-Object System.Collections.Generic.List[object] }
    $Snap.items[$cat].Add($obj)
}
function Get-Items([string]$cat) {
    # @() over a List[object] throws 'Argument types do not match' in Windows PowerShell 5.1.
    if ($Snap.items.Contains($cat)) { return ,$Snap.items[$cat].ToArray() }
    return ,@()
}
function Invoke-Section([string]$name, [scriptblock]$body) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $body } catch { Add-Failure $name "(section, line $($_.InvocationInfo.ScriptLineNumber))" $_.Exception.Message }
    $n = 0; if ($Snap.items.Contains($name)) { $n = $Snap.items[$name].Count }
    $Snap.coverage[$name] = [ordered]@{ items = $n; ms = $sw.ElapsedMilliseconds }
}
function Invoke-NativeRead([string]$exe, [string[]]$argv) {
    # Native stderr under ErrorActionPreference=Stop throws in 5.1, so relax it locally.
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = & $exe @argv 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
    [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($o) }
}
function ConvertTo-Plain($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [byte[]]) {
        $n = [Math]::Min($v.Length, 256); $hex = -join ($v[0..($n - 1)] | ForEach-Object { $_.ToString('x2') })
        if ($v.Length -gt 256) { $hex += "...(+$($v.Length - 256) bytes)" }
        return $hex
    }
    if ($v -is [string[]]) { return @($v) }
    return $v
}

# ---------------------------------------------------------------- registry (explicit 64/32-bit views)
$script:BaseKeys = @{}
function Get-BaseKey([string]$scope) {
    if (-not $script:BaseKeys.ContainsKey($scope)) {
        switch ($scope) {
            'HKLM64' { $h = 'LocalMachine'; $v = 'Registry64' }
            'HKLM32' { $h = 'LocalMachine'; $v = 'Registry32' }
            'HKCU'   { $h = 'CurrentUser';  $v = 'Registry64' }
            'HKCU32' { $h = 'CurrentUser';  $v = 'Registry32' }
        }
        $script:BaseKeys[$scope] = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, $v)
    }
    $script:BaseKeys[$scope]
}
function Open-Reg([string]$scope, [string]$path, [string]$section) {
    try { return (Get-BaseKey $scope).OpenSubKey($path, $false) }
    catch { if ($section) { Add-Failure $section "$scope\$path" $_.Exception.Message }; return $null }
}
function Open-Sub($key, [string]$name) {
    if (-not $key) { return $null }
    try { return $key.OpenSubKey($name, $false) } catch { return $null }
}
function Get-RegVal($key, [string]$name) {
    if (-not $key) { return $null }
    try { return ConvertTo-Plain ($key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')) } catch { return $null }
}
function Get-SubNames($key) { if (-not $key) { return @() }; try { return @($key.GetSubKeyNames()) } catch { return @() } }
function Get-ValNames($key) { if (-not $key) { return @() }; try { return @($key.GetValueNames()) } catch { return @() } }
function Get-SubDefault([string]$scope, [string]$path) {
    $k = Open-Reg $scope $path; if (-not $k) { return $null }
    try { return Get-RegVal $k '' } finally { $k.Close() }
}

# ---------------------------------------------------------------- reference matching
$KnownFolders = @{
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = ${env:ProgramFiles(x86)}
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = $env:ProgramW6432
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $env:SystemRoot
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = (Join-Path $env:SystemRoot 'System32')
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = (Join-Path $env:SystemRoot 'SysWOW64')
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = $env:LOCALAPPDATA
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = $env:APPDATA
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' = $env:ProgramData
}
function Expand-Ref([string]$s) {
    if (-not $s) { return '' }
    $e = [Environment]::ExpandEnvironmentVariables($s)
    foreach ($g in $KnownFolders.Keys) { if ($KnownFolders[$g]) { $e = $e.Replace($g, $KnownFolders[$g]) } }
    $e.Replace('/', '\').ToLowerInvariant()
}
$script:RootPrefixes = @()        # lower-case roots (and their 8.3 forms), no trailing slash
$script:RelatedFiles = @()        # lower-case single files the app drops into shared folders (System32 and so on)
$script:AppRx = $null; if ($App) { $script:AppRx = New-Object regex($App, 'IgnoreCase') }
$script:NameRx = $null
function Test-UnderRoot([string]$path) {
    if (-not $path) { return $false }
    $l = Expand-Ref $path
    foreach ($r in $script:RootPrefixes) { if ($l -eq $r -or $l.StartsWith($r + '\')) { return $true } }
    $script:RelatedFiles -contains $l
}
function Get-RefKind([string]$s, [switch]$Names) {
    if ([string]::IsNullOrEmpty($s)) { return $null }
    $l = Expand-Ref $s
    foreach ($r in $script:RootPrefixes) {
        if ($l.Contains($r + '\') -or $l.Contains($r + '"') -or $l.EndsWith($r)) { return 'root' }
    }
    foreach ($f in $script:RelatedFiles) { if ($l.Contains($f)) { return 'root' } }
    if ($script:AppRx -and $script:AppRx.IsMatch($s)) { return 'app' }
    if ($Names -and $script:NameRx -and $script:NameRx.IsMatch($l)) { return 'name' }
    $null
}
function Get-PathFromCommand([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd).Trim()
    if ($c.StartsWith('"')) { $i = $c.IndexOf('"', 1); if ($i -gt 1) { return $c.Substring(1, $i - 1) } }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|ime|sys|cmd|bat|ocx|ax|cpl))(?=$|[\s,"])', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $null
}

# ---------------------------------------------------------------- roots
$UnsafeRoots = @($env:SystemDrive, $env:SystemRoot, (Join-Path $env:SystemRoot 'System32'),
    (Join-Path $env:SystemRoot 'SysWOW64'), (Join-Path $env:SystemRoot 'System32\IME'), (Join-Path $env:SystemRoot 'SysWOW64\IME'),
    $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:ProgramData, $env:USERPROFILE,
    (Split-Path $env:USERPROFILE -Parent), $env:APPDATA, $env:LOCALAPPDATA, (Join-Path $env:LOCALAPPDATA 'Programs'),
    (Join-Path $env:USERPROFILE 'AppData'), (Join-Path $env:USERPROFILE 'AppData\LocalLow'), $env:TEMP, $env:PUBLIC,
    (Join-Path $env:ProgramFiles 'Common Files'), (Join-Path $env:ProgramData 'Microsoft')) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() }

function Add-Root([string]$path, [string]$role, [string]$source) {
    if (-not $path) { return }
    try {
        $p = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($path.Trim('"'))).TrimEnd('\')
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { return }
        $item = Get-Item -LiteralPath $p -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $t = @($item.Target)[0]; if ($t) { $p = ([IO.Path]::GetFullPath($t)).TrimEnd('\') }
        }
    } catch { Add-Failure 'roots' $path $_.Exception.Message; return }
    $l = $p.ToLowerInvariant()
    if ($l -match '^[a-z]:$' -or $UnsafeRoots -contains $l) { Add-Failure 'roots' $p 'refused: system or shared folder is not an app root'; return }
    foreach ($r in $Snap.roots.ToArray()) {
        $rl = $r.path.ToLowerInvariant()
        if ($l -eq $rl -or $l.StartsWith($rl + '\')) { if ($r.sources -notcontains $source) { $r.sources += $source }; return }
    }
    $sources = @($source)
    foreach ($r in $Snap.roots.ToArray()) {          # a new root that contains an existing one absorbs it
        if ($r.path.ToLowerInvariant().StartsWith($l + '\')) {
            $sources += $r.sources; if ($r.role -eq 'install') { $role = 'install' }
            [void]$Snap.roots.Remove($r)
        }
    }
    $Snap.roots.Add([ordered]@{ path = $p; role = $role; sources = @($sources | Select-Object -Unique) })
    $prefixes = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Snap.roots) {
        $prefixes.Add($r.path.ToLowerInvariant())
        try {
            $sp = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($r.path).ShortPath.TrimEnd('\').ToLowerInvariant()
            if ($sp -and -not $prefixes.Contains($sp)) { $prefixes.Add($sp) }
        } catch { }
    }
    $script:RootPrefixes = $prefixes.ToArray()
}
function Add-Related([string]$file, [string]$source) {
    # A component outside the roots: its folder becomes a 'related' root, unless that folder is shared
    # (System32, Program Files), in which case only the file itself is tracked.
    if (-not $file) { return }
    $f = [Environment]::ExpandEnvironmentVariables($file.Trim('"'))
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return }
    $d = Get-AppDirFromFile $f
    if ($d -and $UnsafeRoots -notcontains $d.TrimEnd('\').ToLowerInvariant()) { Add-Root $d 'related' $source; return }
    $l = $f.ToLowerInvariant()
    if ($script:RelatedFiles -contains $l) { return }
    $script:RelatedFiles += $l
    $Snap.related_files.Add([ordered]@{ path = $f; source = $source })
}
function Get-AppDirFromFile([string]$file) {
    if (-not $file) { return $null }
    $d = Split-Path -Path $file -Parent
    while ($d -and (Split-Path $d -Leaf) -match '^(v?\d+(\.\d+){1,3}|app-[\d.]+|uninstall|uninst|bin|bin64|x64|x86|application)$') {
        $d = Split-Path -Path $d -Parent
    }
    $d
}

Invoke-Section 'installs' {
    $paths = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($scope in 'HKLM64', 'HKLM32', 'HKCU') {
        $base = Open-Reg $scope $paths 'installs'; if (-not $base) { continue }
        foreach ($sn in Get-SubNames $base) {
            $k = (Open-Sub $base $sn); if (-not $k) { continue }
            $dn = Get-RegVal $k 'DisplayName'; $pub = Get-RegVal $k 'Publisher'
            # Localized names often miss an ASCII regex, so the install paths are matched too.
            $hay = "$sn|$dn|$pub|$(Get-RegVal $k 'InstallLocation')|$(Get-RegVal $k 'UninstallString')|$(Get-RegVal $k 'DisplayIcon')"
            $hit = $script:AppRx -and $script:AppRx.IsMatch($hay)
            if ($hit) {
                $o = [ordered]@{
                    key = "uninstall|$scope|$sn"; scope = $scope; subkey = $sn; display_name = $dn; publisher = $pub
                    display_version = Get-RegVal $k 'DisplayVersion'; install_location = Get-RegVal $k 'InstallLocation'
                    uninstall_string = Get-RegVal $k 'UninstallString'; quiet_uninstall = Get-RegVal $k 'QuietUninstallString'
                    display_icon = Get-RegVal $k 'DisplayIcon'; system_component = Get-RegVal $k 'SystemComponent'
                    install_date = Get-RegVal $k 'InstallDate'
                }
                Add-Item 'installs' $o
                if (-not $Root) {
                    if ($o.install_location) { Add-Root $o.install_location 'install' "uninstall:$sn" }
                    else {
                        $f = Get-PathFromCommand $o.uninstall_string
                        if (-not $f -and $o.display_icon) { $f = ($o.display_icon -replace ',\s*-?\d+$', '').Trim('"') }
                        Add-Root (Get-AppDirFromFile $f) 'install' "uninstall:$sn"
                    }
                }
            }
            $k.Close()
        }
        $base.Close()
    }
}
Invoke-Section 'roots' {
    foreach ($r in @($Root)) { if ($r) { Add-Root $r 'install' 'param' } }
    if ($script:AppRx) {
        $bases = @(
            @{ p = $env:ProgramFiles; role = 'install' }, @{ p = ${env:ProgramFiles(x86)}; role = 'install' },
            @{ p = (Join-Path $env:LOCALAPPDATA 'Programs'); role = 'install' }, @{ p = $env:LOCALAPPDATA; role = 'data' },
            @{ p = $env:APPDATA; role = 'data' }, @{ p = (Join-Path $env:USERPROFILE 'AppData\LocalLow'); role = 'data' },
            @{ p = $env:ProgramData; role = 'data' }, @{ p = (Join-Path $env:ProgramFiles 'Common Files'); role = 'install' },
            @{ p = (Join-Path ${env:ProgramFiles(x86)} 'Common Files'); role = 'install' })
        foreach ($b in $bases) {
            if (-not $b.p -or -not (Test-Path -LiteralPath $b.p)) { continue }
            try {
                foreach ($d in [IO.Directory]::EnumerateDirectories($b.p)) {
                    if ($script:AppRx.IsMatch((Split-Path $d -Leaf))) { Add-Root $d $b.role 'dir-name' }
                }
            } catch { Add-Failure 'roots' $b.p "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" }
        }
    }
    if ($Snap.roots.Count -eq 0) { $Snap.notes.Add('No install root resolved. Pass -Root explicitly.') }
}

# ---------------------------------------------------------------- COM classes (before file scan: adds related dirs)
$script:AppClsids = @{}
Invoke-Section 'com' {
    $scopes = @(@{ s = 'HKLM64'; p = 'SOFTWARE\Classes\CLSID' }, @{ s = 'HKLM32'; p = 'SOFTWARE\Classes\CLSID' },
                @{ s = 'HKCU'; p = 'Software\Classes\CLSID' }, @{ s = 'HKCU'; p = 'Software\Classes\WOW6432Node\CLSID' })
    foreach ($sc in $scopes) {
        $base = Open-Reg $sc.s $sc.p 'com'; if (-not $base) { continue }
        $label = $sc.s; if ($sc.p -like '*WOW6432Node*') { $label = 'HKCU32' }
        foreach ($id in Get-SubNames $base) {
            $k = $null
            try { $k = (Open-Sub $base $id) } catch { continue }
            if (-not $k) { continue }
            $name = Get-RegVal $k ''
            $srv = [ordered]@{}
            foreach ($sub in 'InprocServer32', 'LocalServer32', 'InprocHandler32') {
                $sk = $null; try { $sk = (Open-Sub $k $sub) } catch { }
                if ($sk) { $srv[$sub] = Get-RegVal $sk ''; if ($sub -eq 'InprocServer32') { $srv['ThreadingModel'] = Get-RegVal $sk 'ThreadingModel' }; $sk.Close() }
            }
            $kind = $null
            foreach ($v in @($srv['InprocServer32'], $srv['LocalServer32'])) { if (-not $kind) { $kind = Get-RefKind $v } }
            if (-not $kind -and $name -and $script:AppRx -and $script:AppRx.IsMatch($name)) { $kind = 'app' }
            if ($kind) {
                $script:AppClsids[$id.ToUpperInvariant()] = $true
                $o = [ordered]@{ key = "clsid|$label|$($id.ToUpperInvariant())"; scope = $label; clsid = $id; name = $name; match = $kind
                    inproc = $srv['InprocServer32']; local = $srv['LocalServer32']; threading = $srv['ThreadingModel']
                    progid = Get-SubDefault $sc.s "$($sc.p)\$id\ProgID"; appid = Get-RegVal $k 'AppID' }
                Add-Item 'com' $o
                foreach ($v in @($o.inproc, $o.local)) {
                    $f = Get-PathFromCommand $v; if (-not $f -and $v) { $f = $v.Trim('"') }
                    if ($f -and $kind -eq 'app' -and -not (Test-UnderRoot $f)) { Add-Related $f "com:$id" }
                }
            }
            $k.Close()
        }
        $base.Close()
    }
    $byId = @{}
    foreach ($c in (Get-Items 'com')) { if ($c) { $u = $c.clsid.ToUpperInvariant(); if (-not $byId[$u]) { $byId[$u] = @() }; $byId[$u] += $c.scope } }
    foreach ($c in (Get-Items 'com')) {
        if ($c) { $sc = $byId[$c.clsid.ToUpperInvariant()]; $c['hkcu_shadows_hklm'] = [bool](($sc -match '^HKCU').Count -and ($sc -match '^HKLM').Count) }
    }
}

# ---------------------------------------------------------------- services and drivers
$script:SvcCim = @()
Invoke-Section 'services' {
    $script:SvcCim = @(Get-CimInstance Win32_Service) + @(Get-CimInstance Win32_SystemDriver)
    foreach ($s in $script:SvcCim) {
        $svcDll = $null
        $pk = Open-Reg 'HKLM64' "SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters"
        if ($pk) { $svcDll = Get-RegVal $pk 'ServiceDll'; $pk.Close() }
        $kind = Get-RefKind $s.PathName
        if (-not $kind) { $kind = Get-RefKind $svcDll }
        if (-not $kind -and $script:AppRx -and ($script:AppRx.IsMatch($s.Name) -or ($s.DisplayName -and $script:AppRx.IsMatch($s.DisplayName)))) { $kind = 'app' }
        if (-not $kind) { continue }
        $sk = Open-Reg 'HKLM64' "SYSTEM\CurrentControlSet\Services\$($s.Name)"
        $o = [ordered]@{
            key = "service|$($s.Name.ToLowerInvariant())"; name = $s.Name; display_name = $s.DisplayName; match = $kind
            kind = $(if ($s.CimClass.CimClassName -eq 'Win32_SystemDriver') { 'driver' } else { 'service' })
            image_path = $s.PathName; service_dll = $svcDll; start_mode = $s.StartMode; state = $s.State
            delayed_auto = Get-RegVal $sk 'DelayedAutostart'; account = $s.StartName; pid = $s.ProcessId
            failure_actions_raw = Get-RegVal $sk 'FailureActions'; recovery = $null; sddl = $null
        }
        if ($sk) { $sk.Close() }
        if ($o.kind -eq 'service') {
            $q = Invoke-NativeRead 'sc.exe' @('qfailure', $s.Name, '5000')
            if ($q.Code -eq 0) {
                $rec = [ordered]@{ reset_period = $null; command_line = $null; actions = @() }
                foreach ($ln in $q.Lines) {
                    if ($ln -match 'RESET_PERIOD[^:]*:\s*(\d+)') { $rec.reset_period = [int64]$Matches[1] }
                    elseif ($ln -match 'COMMAND_LINE\s*:\s*(.*)$') { $rec.command_line = $Matches[1].Trim() }
                    elseif ($ln -match '(RESTART|RUN PROCESS|REBOOT)\s*--\s*Delay\s*=\s*(\d+)') { $rec.actions += "$($Matches[1])@$($Matches[2])ms" }
                }
                $o.recovery = $rec
            } else { Add-Failure 'services' "sc qfailure $($s.Name)" (($q.Lines -join ' ').Trim()) }
            $f = Invoke-NativeRead 'sc.exe' @('qfailureflag', $s.Name)
            if ($f.Code -eq 0) { foreach ($ln in $f.Lines) { if ($ln -match 'FAILURE_ACTIONS_ON_NONCRASH_FAILURES\s*:\s*(\S+)') { $o['failure_on_noncrash'] = $Matches[1] } } }
            $d = Invoke-NativeRead 'sc.exe' @('sdshow', $s.Name)
            if ($d.Code -eq 0) { $o.sddl = (@($d.Lines | Where-Object { $_ -match '^[DOS]:' }) -join '') }
        }
        Add-Item 'services' $o
        if ($kind -eq 'app') { $f = Get-PathFromCommand $s.PathName; if ($f -and -not (Test-UnderRoot $f)) { Add-Related $f "service:$($s.Name)" } }
    }
}

# ---------------------------------------------------------------- files
function Get-PeMachine([string]$path) {
    try {
        $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            $buf = New-Object byte[] 1024; $n = $fs.Read($buf, 0, 1024)
            if ($n -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return 'not-pe' }
            $off = [BitConverter]::ToInt32($buf, 0x3C)
            if ($off -lt 0 -or $off + 6 -gt $n) { return 'unknown' }
            switch ([BitConverter]::ToUInt16($buf, $off + 4)) { 0x14c { 'x86' } 0x8664 { 'x64' } 0xaa64 { 'arm64' } 0x1c4 { 'armnt' } default { 'other' } }
        } finally { $fs.Dispose() }
    } catch { 'unreadable' }
}
function Get-PeDetail([IO.FileInfo]$e, [string]$root, [string]$rel) {
    $o = [ordered]@{ key = "file|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $root; rel = $rel
        size = $e.Length; mtime = $e.LastWriteTimeUtc.ToString('o'); attributes = $e.Attributes.ToString()
        machine = $null; sha256 = $null; file_version = $null; product_version = $null; company = $null
        description = $null; original_name = $null; signature = $null; signer = $null; signer_thumbprint = $null }
    if ($e.Length -eq 0) { $o.machine = 'empty' } else { $o.machine = Get-PeMachine $e.FullName }
    try { $o.sha256 = (Get-FileHash -LiteralPath $e.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } catch { Add-Failure 'files' $e.FullName "hash: $($_.Exception.Message)" }
    try {
        $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($e.FullName)
        $o.file_version = $vi.FileVersion; $o.product_version = $vi.ProductVersion; $o.company = $vi.CompanyName
        $o.description = $vi.FileDescription; $o.original_name = $vi.OriginalFilename
    } catch { }
    if (-not $NoSignature -and $e.Length -gt 0) {
        try {
            $sg = Get-AuthenticodeSignature -LiteralPath $e.FullName
            $o.signature = $sg.Status.ToString()
            if ($sg.SignerCertificate) {
                $o.signer = ($sg.SignerCertificate.Subject -replace '^.*?CN=("[^"]+"|[^,]+).*$', '$1').Trim('"')
                $o.signer_thumbprint = $sg.SignerCertificate.Thumbprint
            }
        } catch { $o.signature = 'error' }
    }
    $o
}
$PeExt = '.exe', '.dll', '.ime', '.sys', '.ocx', '.ax', '.cpl', '.node'
$CfgExt = '.ini', '.json', '.yml', '.yaml', '.xml', '.cfg', '.conf', '.asar', '.cupf', '.config', '.plist', '.db'
$script:PeNames = @{}
$script:ExeNames = @{}
Invoke-Section 'files' {
    $peBudget = $MaxFiles
    foreach ($r in $Snap.roots) {
        $stats = [ordered]@{ entries = 0; files = 0; dirs = 0; bytes = 0; by_ext = @{}; truncated = $false; reparse_skipped = 0 }
        $fpParts = New-Object System.Collections.Generic.List[string]
        $stack = New-Object System.Collections.Generic.Stack[string]; $stack.Push($r.path)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try { $entries = (New-Object IO.DirectoryInfo($dir)).GetFileSystemInfos() }
            catch { Add-Failure 'files' $dir $_.Exception.Message; continue }
            foreach ($e in $entries) {
                $stats.entries++
                if ($stats.entries -gt $MaxEntries) { $stats.truncated = $true; break }
                $rel = $e.FullName.Substring($r.path.Length).TrimStart('\')
                $ext = $e.Extension.ToLowerInvariant()
                if ($e -is [IO.DirectoryInfo]) {
                    $stats.dirs++
                    if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { $stats.reparse_skipped++; continue }
                    if ($PeExt -contains $ext) {
                        # A directory named like a binary is the classic anti-reinstall placeholder.
                        $sddl = $null; try { $sddl = (Get-Acl -LiteralPath $e.FullName).Sddl } catch { }
                        Add-Item 'placeholders' ([ordered]@{ key = "placeholder|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $r.path; rel = $rel; kind = 'directory'; sddl = $sddl; attributes = $e.Attributes.ToString() })
                        if ($ext -eq '.exe') { $script:ExeNames[$e.Name.ToLowerInvariant()] = $true }
                    }
                    $stack.Push($e.FullName); continue
                }
                $stats.files++; $stats.bytes += $e.Length
                if ($stats.by_ext.ContainsKey($ext)) { $stats.by_ext[$ext]++ } else { $stats.by_ext[$ext] = 1 }
                if ($PeExt -contains $ext) {
                    $script:PeNames[$e.Name.ToLowerInvariant()] = $true
                    if ($ext -eq '.exe') { $script:ExeNames[$e.Name.ToLowerInvariant()] = $true }
                    if ($peBudget -le 0) { $stats.truncated = $true; continue }
                    $peBudget--
                    $o = Get-PeDetail $e $r.path $rel
                    if ($o.sha256) { $fpParts.Add("$($rel.ToLowerInvariant()):$($o.sha256)") }
                    Add-Item 'files' $o
                } elseif ($CfgExt -contains $ext) {
                    Add-Item 'config_files' ([ordered]@{ key = "cfg|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $r.path; rel = $rel; size = $e.Length; mtime = $e.LastWriteTimeUtc.ToString('o') })
                }
            }
            if ($stats.truncated -and $stats.entries -gt $MaxEntries) { break }
        }
        $r['stats'] = $stats
        $sorted = @($fpParts | Sort-Object)
        $sha = [Security.Cryptography.SHA256]::Create()
        $Snap.fingerprints[$r.path] = [ordered]@{
            pe_files = $sorted.Count
            sha256   = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))) | ForEach-Object { $_.ToString('x2') }))
        }
        if ($stats.truncated) { $Snap.notes.Add("Root $($r.path): scan truncated (MaxEntries=$MaxEntries or MaxFiles=$MaxFiles); fingerprint covers only hashed files.") }
    }
    foreach ($rf in $Snap.related_files) {
        $fi = New-Object IO.FileInfo($rf.path)
        $script:PeNames[$fi.Name.ToLowerInvariant()] = $true
        Add-Item 'files' (Get-PeDetail $fi $fi.DirectoryName $fi.Name)
    }
    # Name matching skips generic names and names Windows itself ships, to keep false positives down.
    $generic = 'setup.exe', 'uninst.exe', 'uninstall.exe', 'unins000.exe', 'update.exe', 'updater.exe', 'install.exe',
               'launcher.exe', 'helper.exe', 'crashpad_handler.exe', 'crashreporter.exe', 'elevate.exe', 'notification_helper.exe'
    $specific = @($script:ExeNames.Keys | Where-Object {
        $_.Length -ge 6 -and $generic -notcontains $_ -and
        -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32\$_")) -and -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot $_)) })
    if ($specific.Count) {
        $script:NameRx = New-Object regex(('(?:^|[\\/"\s=,])(' + (($specific | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?:$|["\s,])'), 'IgnoreCase')
    }
    $Snap['name_match_set'] = @($specific | Sort-Object)
}

# ---------------------------------------------------------------- processes, modules, windows
$script:AppPids = @{}
Invoke-Section 'processes' {
    $all = @(Get-CimInstance Win32_Process)
    $byPid = @{}; foreach ($p in $all) { $byPid[[int]$p.ProcessId] = $p }
    $noPath = 0; $seen = @{}
    foreach ($p in $all) {
        if (-not $p.ExecutablePath) { $noPath++ }
        $kind = $null
        if (Test-UnderRoot $p.ExecutablePath) { $kind = 'root' }
        if (-not $kind) { $kind = Get-RefKind $p.CommandLine }
        if (-not $kind -and -not $p.ExecutablePath -and $script:NameRx -and $script:NameRx.IsMatch('\' + $p.Name)) { $kind = 'name' }
        if (-not $kind) { continue }
        # Skip this inventory run itself (its command line carries -App).
        if ($p.ProcessId -eq $PID -or ($p.CommandLine -and $p.CommandLine.Contains($PSCommandPath))) { continue }
        $script:AppPids[[int]$p.ProcessId] = $p
        $parent = $byPid[[int]$p.ParentProcessId]
        # A parent created after the child is a reused PID, not the real parent.
        if ($parent -and $parent.CreationDate -and $p.CreationDate -and $parent.CreationDate -gt $p.CreationDate) { $parent = $null }
        $norm = ''; if ($p.CommandLine) { $norm = ($p.CommandLine.ToLowerInvariant() -replace '\d+', '#') }
        $k = "proc|$(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })|$norm"
        if ($seen.ContainsKey($k)) { $seen[$k]++; $k = "$k#$($seen[$k])" } else { $seen[$k] = 1 }
        Add-Item 'processes' ([ordered]@{
            key = $k; pid = [int]$p.ProcessId; name = $p.Name; path = $p.ExecutablePath; command_line = $p.CommandLine; match = $kind
            parent_pid = [int]$p.ParentProcessId; parent_name = $(if ($parent) { $parent.Name }); parent_path = $(if ($parent) { $parent.ExecutablePath })
            session = $p.SessionId; threads = $p.ThreadCount; created = $(if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') })
            machine = $(if ($p.ExecutablePath) { Get-PeMachine $p.ExecutablePath }); modules_from_roots = @(); windows = @() })
    }
    if ($noPath) { $Snap.notes.Add("processes: $noPath of $($all.Count) processes hid their image path (other user, SYSTEM or protected).") }

    # Modules: toolhelp snapshot sees 32-bit modules of WOW64 processes too. Needs same user or elevation.
    $denied = 0; $hosts = @{}
    foreach ($p in $all) {
        $pid_ = [int]$p.ProcessId; if ($pid_ -le 4) { continue }
        $err = 0; $mods = [AdInv]::Modules([uint32]$pid_, [ref]$err)
        if ($null -eq $mods) { $denied++; continue }
        $hits = @($mods | Where-Object { Test-UnderRoot $_ })
        if (-not $hits.Count) { continue }
        if ($script:AppPids.ContainsKey($pid_)) {
            foreach ($it in $Snap.items['processes']) { if ($it.pid -eq $pid_) { $it.modules_from_roots = @($hits | Where-Object { $_ -ne $p.ExecutablePath }) } }
        } else {
            $img = $(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })
            $k = "modhost|$img"; if ($hosts.ContainsKey($k)) { $hosts[$k]++; $k = "$k#$($hosts[$k])" } else { $hosts[$k] = 1 }
            Add-Item 'module_hosts' ([ordered]@{ key = $k; pid = $pid_; name = $p.Name; path = $p.ExecutablePath; modules_from_roots = $hits })
        }
    }
    if ($denied) {
        $Snap.notes.Add("modules: $denied processes refused a module snapshot (access denied or protected); DLLs injected into them are not visible.")
        if ($IsAdmin -and $script:PeNames.Count) {
            # Fallback: tasklist /m names modules (no paths) for processes the snapshot could not open.
            $t = Invoke-NativeRead 'tasklist.exe' @('/m', '/fo', 'csv', '/nh')
            foreach ($ln in $t.Lines) {
                $c = @($ln -split '","' | ForEach-Object { $_.Trim('"') }); if ($c.Count -lt 3) { continue }
                $names = @($c[2] -split ',' | Where-Object { $script:PeNames.ContainsKey($_.Trim().ToLowerInvariant()) })
                $pp = 0; if ([int]::TryParse($c[1], [ref]$pp) -and $names.Count -and -not $script:AppPids.ContainsKey($pp)) {
                    $already = $false; foreach ($h in (Get-Items 'module_hosts')) { if ($h -and $h.pid -eq $pp) { $already = $true } }
                    if (-not $already) { Add-Item 'module_hosts' ([ordered]@{ key = "modhost|$($c[0].ToLowerInvariant())|tasklist"; pid = $pp; name = $c[0]; path = $null; module_names_only = $names }) }
                }
            }
        }
    }
    try {
        foreach ($w in [AdInv]::Windows()) {
            if (-not $script:AppPids.ContainsKey([int]$w.Pid) -or -not $w.Visible) { continue }
            foreach ($it in $Snap.items['processes']) {
                if ($it.pid -eq [int]$w.Pid) { $it.windows += [ordered]@{ class = $w.Cls; title = $w.Title; rect = @($w.L, $w.T, $w.R, $w.B) } }
            }
        }
    } catch { Add-Failure 'processes' 'EnumWindows' $_.Exception.Message }
}

# ---------------------------------------------------------------- scheduled tasks
Invoke-Section 'tasks' {
    $me = "$env:USERDOMAIN\$env:USERNAME"
    foreach ($t in @(Get-ScheduledTask)) {
        $acts = @(); $kind = $null
        foreach ($a in @($t.Actions)) {
            $cls = $a.CimClass.CimClassName
            if ($cls -eq 'MSFT_TaskExecAction') {
                $acts += [ordered]@{ type = 'exec'; execute = $a.Execute; arguments = $a.Arguments; workdir = $a.WorkingDirectory }
                if (-not $kind) { $kind = Get-RefKind "$($a.Execute) $($a.Arguments) $($a.WorkingDirectory)" -Names }
            } elseif ($cls -eq 'MSFT_TaskComHandlerAction') {
                $acts += [ordered]@{ type = 'com'; class_id = $a.ClassId; data = $a.Data }
                if (-not $kind -and $a.ClassId -and $script:AppClsids.ContainsKey($a.ClassId.ToUpperInvariant())) { $kind = 'clsid' }
            } else { $acts += [ordered]@{ type = $cls } }
        }
        if (-not $kind -and $script:AppRx -and $script:AppRx.IsMatch("$($t.TaskPath)$($t.TaskName)")) { $kind = 'app' }
        if (-not $kind) { continue }
        $trig = @(foreach ($g in @($t.Triggers)) {
            if (-not $g) { continue }
            $rep = $null; try { $rep = $g.Repetition.Interval } catch { }
            [ordered]@{ type = ($g.CimClass.CimClassName -replace '^MSFT_Task', ''); enabled = $g.Enabled; repeat = $rep; delay = $(try { $g.Delay } catch { $null }) }
        })
        $uid = $t.Principal.UserId; if (-not $KeepPaths -and $uid -and ($uid -eq $env:USERNAME -or $uid -eq $me)) { $uid = '%USERNAME%' }
        Add-Item 'tasks' ([ordered]@{ key = "task|$($t.TaskPath)$($t.TaskName)".ToLowerInvariant(); path = $t.TaskPath; name = $t.TaskName
            match = $kind; state = $t.State.ToString(); user = $uid; run_level = $t.Principal.RunLevel.ToString()
            logon_type = $t.Principal.LogonType.ToString(); hidden = $t.Settings.Hidden; author = $t.Author; actions = $acts; triggers = $trig })
    }
    if (-not $IsAdmin) { $Snap.notes.Add('tasks: tasks whose security descriptor denies the current user are not enumerated.') }
}

# ---------------------------------------------------------------- Run keys and other autostarts
Invoke-Section 'autostart' {
    $approved = @{}
    foreach ($sc in 'HKCU', 'HKLM64') {
        foreach ($sub in 'Run', 'Run32', 'StartupFolder') {
            $k = Open-Reg $sc "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"
            foreach ($n in Get-ValNames $k) { $v = $k.GetValue($n); if ($v -is [byte[]] -and $v.Length) { $approved["$sc|$sub|$($n.ToLowerInvariant())"] = $(if ($v[0] % 2 -eq 0) { 'enabled' } else { 'disabled' }) } }
            if ($k) { $k.Close() }
        }
    }
    $runs = @()
    foreach ($sc in 'HKLM64', 'HKLM32', 'HKCU') {
        foreach ($p in 'Run', 'RunOnce', 'RunOnceEx', 'Policies\Explorer\Run', 'RunServices', 'RunServicesOnce') { $runs += , @($sc, "SOFTWARE\Microsoft\Windows\CurrentVersion\$p", 'run') }
    }
    $runs += , @('HKCU', 'Software\Microsoft\Windows NT\CurrentVersion\Windows', 'load')
    foreach ($r in $runs) {
        $k = Open-Reg $r[0] $r[1] 'autostart'; if (-not $k) { continue }
        foreach ($n in Get-ValNames $k) {
            if ($r[2] -eq 'load' -and $n -notin 'Load', 'Run') { continue }
            $v = Get-RegVal $k $n; $kind = Get-RefKind "$v" -Names
            if (-not $kind -and $script:AppRx -and $script:AppRx.IsMatch($n)) { $kind = 'app' }
            if (-not $kind) { continue }
            $sub = $(if ($r[0] -eq 'HKLM32') { 'Run32' } else { 'Run' })
            $ap = $approved["$(if ($r[0] -eq 'HKCU') { 'HKCU' } else { 'HKLM64' })|$sub|$($n.ToLowerInvariant())"]
            Add-Item 'run_keys' ([ordered]@{ key = "run|$($r[0])|$($r[1])|$n".ToLowerInvariant(); scope = $r[0]; path = $r[1]; name = $n; value = $v; match = $kind; startup_approved = $ap })
        }
        $k.Close()
    }
    # Winlogon, AppInit_DLLs, Active Setup StubPath (a classic per-user repair hook)
    foreach ($sc in 'HKLM64', 'HKLM32') {
        $k = Open-Reg $sc 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        foreach ($n in 'Shell', 'Userinit', 'Taskman', 'AppSetup') {
            $v = Get-RegVal $k $n; $kind = Get-RefKind "$v" -Names
            if ($kind) { Add-Item 'other_autostart' ([ordered]@{ key = "winlogon|$sc|$n".ToLowerInvariant(); kind = 'winlogon'; scope = $sc; name = $n; value = $v; match = $kind }) }
        }
        if ($k) { $k.Close() }
        $k = Open-Reg $sc 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $v = Get-RegVal $k 'AppInit_DLLs'; $kind = Get-RefKind "$v" -Names
        if ($kind) { Add-Item 'other_autostart' ([ordered]@{ key = "appinit|$sc"; kind = 'appinit_dlls'; scope = $sc; value = $v; load = Get-RegVal $k 'LoadAppInit_DLLs'; match = $kind }) }
        if ($k) { $k.Close() }
        $base = Open-Reg $sc 'SOFTWARE\Microsoft\Active Setup\Installed Components' 'autostart'
        foreach ($id in Get-SubNames $base) {
            $k = (Open-Sub $base $id); if (-not $k) { continue }
            $stub = Get-RegVal $k 'StubPath'; $nm = Get-RegVal $k ''
            $kind = Get-RefKind "$stub" -Names; if (-not $kind -and $nm -and $script:AppRx -and $script:AppRx.IsMatch($nm)) { $kind = 'app' }
            if ($kind) { Add-Item 'other_autostart' ([ordered]@{ key = "activesetup|$sc|$id".ToLowerInvariant(); kind = 'active_setup'; scope = $sc; id = $id; name = $nm; stub_path = $stub; version = Get-RegVal $k 'Version'; match = $kind }) }
            $k.Close()
        }
        if ($base) { $base.Close() }
    }
}

# ---------------------------------------------------------------- IFEO and SilentProcessExit
Invoke-Section 'ifeo' {
    foreach ($sc in 'HKLM64', 'HKLM32') {
        foreach ($p in 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
            $base = Open-Reg $sc $p 'ifeo'; if (-not $base) { continue }
            $kindName = $(if ($p -like '*SilentProcessExit') { 'silent_process_exit' } else { 'ifeo' })
            foreach ($n in Get-SubNames $base) {
                $k = (Open-Sub $base $n); if (-not $k) { continue }
                $vals = [ordered]@{}; foreach ($vn in Get-ValNames $k) { $vals[$vn] = Get-RegVal $k $vn }
                $kind = $null
                if ($script:ExeNames.ContainsKey($n.ToLowerInvariant())) { $kind = 'name' }
                elseif ($script:AppRx -and $script:AppRx.IsMatch($n)) { $kind = 'app' }
                else { foreach ($v in $vals.Values) { if (-not $kind) { $kind = Get-RefKind "$v" } } }
                $filters = @()
                foreach ($fs in Get-SubNames $k) {
                    $fk = (Open-Sub $k $fs); $fp = Get-RegVal $fk 'FilterFullPath'
                    if ($fp) { $filters += [ordered]@{ subkey = $fs; filter_full_path = $fp; debugger = Get-RegVal $fk 'Debugger' }; if (-not $kind) { $kind = Get-RefKind $fp } }
                    if ($fk) { $fk.Close() }
                }
                if ($kind -and ($vals.Count -or $filters.Count)) {
                    Add-Item 'ifeo' ([ordered]@{ key = "$kindName|$sc|$($n.ToLowerInvariant())"; kind = $kindName; scope = $sc; image = $n; values = $vals; filters = $filters; match = $kind })
                }
                $k.Close()
            }
            $base.Close()
        }
    }
}

# ---------------------------------------------------------------- shell extensions
Invoke-Section 'shell_ext' {
    $containers = '*', 'AllFilesystemObjects', 'Directory', 'Directory\Background', 'Folder', 'Drive', 'DesktopBackground', 'lnkfile'
    $types = 'ContextMenuHandlers', 'DragDropHandlers', 'PropertySheetHandlers', 'CopyHookHandlers', 'IconHandler'
    $classRoots = @(@('HKLM64', 'SOFTWARE\Classes'), @('HKLM32', 'SOFTWARE\Classes'), @('HKCU', 'Software\Classes'))
    function Test-AppClsid([string]$s) { if (-not $s) { return $false }; $m = [regex]::Match($s, '\{[0-9A-Fa-f-]{36}\}'); $m.Success -and $script:AppClsids.ContainsKey($m.Value.ToUpperInvariant()) }
    foreach ($cr in $classRoots) {
        foreach ($c in $containers) {
            foreach ($t in $types) {
                $base = Open-Reg $cr[0] "$($cr[1])\$c\shellex\$t"; if (-not $base) { continue }
                foreach ($h in Get-SubNames $base) {
                    $d = Get-SubDefault $cr[0] "$($cr[1])\$c\shellex\$t\$h"
                    if ((Test-AppClsid $h) -or (Test-AppClsid $d) -or ($script:AppRx -and $script:AppRx.IsMatch($h))) {
                        Add-Item 'shell_ext' ([ordered]@{ key = "shellex|$($cr[0])|$c|$t|$h".ToLowerInvariant(); kind = $t; scope = $cr[0]; container = $c; handler = $h; clsid = $d })
                    }
                }
                $base.Close()
            }
            $base = Open-Reg $cr[0] "$($cr[1])\$c\shell"; if (-not $base) { continue }
            foreach ($verb in Get-SubNames $base) {
                $vk = (Open-Sub $base $verb); if (-not $vk) { continue }
                $ck = Open-Reg $cr[0] "$($cr[1])\$c\shell\$verb\command"
                $cmd = Get-RegVal $ck ''; $del = Get-RegVal $ck 'DelegateExecute'; if ($ck) { $ck.Close() }
                $dex = Get-RegVal $vk 'ExplorerCommandHandler'
                $kind = Get-RefKind "$cmd" -Names
                if (-not $kind -and ((Test-AppClsid $dex) -or (Test-AppClsid $del))) { $kind = 'clsid' }
                if (-not $kind -and $script:AppRx -and $script:AppRx.IsMatch($verb)) { $kind = 'app' }
                if ($kind) { Add-Item 'shell_ext' ([ordered]@{ key = "verb|$($cr[0])|$c|$verb".ToLowerInvariant(); kind = 'verb'; scope = $cr[0]; container = $c; verb = $verb; label = Get-RegVal $vk ''; command = $cmd; explorer_command_handler = $dex; match = $kind }) }
                $vk.Close()
            }
            $base.Close()
        }
    }
    $lists = @(
        @('ShellIconOverlayIdentifiers', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers', 'subkeys'),
        @('BrowserHelperObjects', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects', 'subkeys'),
        @('PreviewHandlers', 'SOFTWARE\Microsoft\Windows\CurrentVersion\PreviewHandlers', 'values'),
        @('ShellServiceObjectDelayLoad', 'SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'values'),
        @('ShellExecuteHooks', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks', 'values'),
        @('Approved', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved', 'values'),
        @('Blocked', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked', 'values'))
    foreach ($l in $lists) {
        foreach ($sc in 'HKLM64', 'HKLM32', 'HKCU') {
            $base = Open-Reg $sc $l[1]; if (-not $base) { continue }
            if ($l[2] -eq 'subkeys') {
                foreach ($n in Get-SubNames $base) {
                    $d = Get-SubDefault $sc "$($l[1])\$n"
                    if ((Test-AppClsid $n) -or (Test-AppClsid $d) -or ($script:AppRx -and $script:AppRx.IsMatch($n))) {
                        Add-Item 'shell_ext' ([ordered]@{ key = "$($l[0])|$sc|$n".ToLowerInvariant(); kind = $l[0]; scope = $sc; name = $n; clsid = $d })
                    }
                }
            } else {
                foreach ($n in Get-ValNames $base) {
                    $v = Get-RegVal $base $n
                    if ((Test-AppClsid $n) -or (Test-AppClsid "$v") -or ($script:AppRx -and ($script:AppRx.IsMatch($n) -or $script:AppRx.IsMatch("$v")))) {
                        Add-Item 'shell_ext' ([ordered]@{ key = "$($l[0])|$sc|$n".ToLowerInvariant(); kind = $l[0]; scope = $sc; name = $n; value = $v })
                    }
                }
            }
            $base.Close()
        }
    }
}

# ---------------------------------------------------------------- ProgIDs, URL protocols, file associations
Invoke-Section 'classes' {
    $skip = 'CLSID', 'Interface', 'TypeLib', 'WOW6432Node', 'AppID', 'Record', 'Installer', 'Local Settings', 'Extensions'
    $progs = @{}; $exts = @()
    foreach ($cr in @(@('HKLM64', 'SOFTWARE\Classes'), @('HKCU', 'Software\Classes'))) {
        $base = Open-Reg $cr[0] $cr[1] 'classes'; if (-not $base) { continue }
        foreach ($n in Get-SubNames $base) {
            if ($skip -contains $n) { continue }
            if ($n.StartsWith('.')) { $exts += , @($cr[0], $cr[1], $n); continue }
            $k = $null; try { $k = (Open-Sub $base $n) } catch { continue }; if (-not $k) { continue }
            $cmd = Get-SubDefault $cr[0] "$($cr[1])\$n\shell\open\command"
            $icon = Get-SubDefault $cr[0] "$($cr[1])\$n\DefaultIcon"
            $isProto = $null -ne $k.GetValue('URL Protocol', $null)
            $kind = Get-RefKind "$cmd" -Names; if (-not $kind) { $kind = Get-RefKind "$icon" }
            if (-not $kind -and $isProto -and $script:AppRx -and $script:AppRx.IsMatch($n)) { $kind = 'app' }
            if ($kind) {
                $progs[$n.ToLowerInvariant()] = $true
                Add-Item $(if ($isProto) { 'url_protocols' } else { 'progids' }) ([ordered]@{
                    key = "$(if ($isProto) { 'proto' } else { 'progid' })|$($cr[0])|$($n.ToLowerInvariant())"; scope = $cr[0]; name = $n
                    label = Get-RegVal $k ''; command = $cmd; icon = $icon; match = $kind })
            }
            $k.Close()
        }
        $base.Close()
    }
    foreach ($e in $exts) {
        $d = Get-SubDefault $e[0] "$($e[1])\$($e[2])"
        $owp = Open-Reg $e[0] "$($e[1])\$($e[2])\OpenWithProgids"
        $ow = @(Get-ValNames $owp | Where-Object { $progs.ContainsKey($_.ToLowerInvariant()) }); if ($owp) { $owp.Close() }
        if (($d -and $progs.ContainsKey("$d".ToLowerInvariant())) -or $ow.Count) {
            Add-Item 'file_assoc' ([ordered]@{ key = "ext|$($e[0])|$($e[2])".ToLowerInvariant(); scope = $e[0]; ext = $e[2]; default = $d; open_with = $ow })
        }
    }
    $fe = Open-Reg 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts'
    foreach ($x in Get-SubNames $fe) {
        $uc = Open-Reg 'HKCU' "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$x\UserChoice"
        $pid_ = Get-RegVal $uc 'ProgId'; if ($uc) { $uc.Close() }
        if ($pid_ -and ($progs.ContainsKey($pid_.ToLowerInvariant()) -or ($script:AppRx -and $script:AppRx.IsMatch($pid_)))) {
            Add-Item 'file_assoc' ([ordered]@{ key = "userchoice|$x".ToLowerInvariant(); scope = 'HKCU'; ext = $x; user_choice = $pid_ })
        }
    }
    if ($fe) { $fe.Close() }
}

# ---------------------------------------------------------------- TSF / IME
Invoke-Section 'tsf' {
    foreach ($sc in 'HKLM64', 'HKLM32', 'HKCU') {
        $base = Open-Reg $sc 'SOFTWARE\Microsoft\CTF\TIP' 'tsf'; if (-not $base) { continue }
        foreach ($id in Get-SubNames $base) {
            $k = (Open-Sub $base $id); if (-not $k) { continue }
            $desc = Get-RegVal $k 'Description'
            $hit = $script:AppClsids.ContainsKey($id.ToUpperInvariant()) -or ($desc -and $script:AppRx -and $script:AppRx.IsMatch($desc))
            $profiles = @()
            $lp = (Open-Sub $k 'LanguageProfile')
            foreach ($lang in Get-SubNames $lp) {
                $lk = (Open-Sub $lp $lang)
                foreach ($g in Get-SubNames $lk) {
                    $gk = (Open-Sub $lk $g); $pd = Get-RegVal $gk 'Description'
                    if ($pd -and $script:AppRx -and $script:AppRx.IsMatch($pd)) { $hit = $true }
                    $profiles += [ordered]@{ lang = $lang; profile = $g; description = $pd; enable = Get-RegVal $gk 'Enable'; icon = Get-RegVal $gk 'IconFile' }
                    if ($gk) { $gk.Close() }
                }
                if ($lk) { $lk.Close() }
            }
            if ($lp) { $lp.Close() }
            if ($hit) { Add-Item 'tsf' ([ordered]@{ key = "tip|$sc|$($id.ToUpperInvariant())"; scope = $sc; clsid = $id; description = $desc; profiles = $profiles }) }
            $k.Close()
        }
        $base.Close()
    }
    $base = Open-Reg 'HKLM64' 'SYSTEM\CurrentControlSet\Control\Keyboard Layouts'
    foreach ($id in Get-SubNames $base) {
        $k = (Open-Sub $base $id); if (-not $k) { continue }
        $ime = Get-RegVal $k 'Ime File'; $txt = Get-RegVal $k 'Layout Text'
        if (($ime -and $script:PeNames.ContainsKey("$ime".ToLowerInvariant())) -or ($script:AppRx -and ($script:AppRx.IsMatch("$ime") -or $script:AppRx.IsMatch("$txt")))) {
            Add-Item 'tsf' ([ordered]@{ key = "kbdlayout|$id".ToLowerInvariant(); scope = 'HKLM64'; layout = $id; ime_file = $ime; layout_text = $txt; layout_file = Get-RegVal $k 'Layout File' })
        }
        $k.Close()
    }
    if ($base) { $base.Close() }
}

# ---------------------------------------------------------------- firewall (registry store: fast and readable unelevated)
Invoke-Section 'firewall' {
    $stores = @(@('local', 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'),
                @('policy', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'))
    foreach ($st in $stores) {
        $k = Open-Reg 'HKLM64' $st[1] 'firewall'; if (-not $k) { continue }
        foreach ($id in Get-ValNames $k) {
            $raw = "$(Get-RegVal $k $id)"; $f = @{}
            foreach ($part in $raw.Split('|')) { $i = $part.IndexOf('='); if ($i -gt 0) { $n = $part.Substring(0, $i); if ($f.ContainsKey($n)) { $f[$n] += ",$($part.Substring($i + 1))" } else { $f[$n] = $part.Substring($i + 1) } } }
            $kind = Get-RefKind $f['App'] -Names
            if (-not $kind -and $script:AppRx -and ($script:AppRx.IsMatch("$($f['Name'])") -or $script:AppRx.IsMatch("$($f['Desc'])"))) { $kind = 'app' }
            if (-not $kind) { continue }
            Add-Item 'firewall' ([ordered]@{ key = "fw|$($st[0])|$id".ToLowerInvariant(); store = $st[0]; id = $id; name = $f['Name']; action = $f['Action']
                direction = $f['Dir']; active = $f['Active']; app = $f['App']; protocol = $f['Protocol']; profile = $f['Profile']
                remote = $f['RA4']; remote_ports = $f['RPort']; match = $kind })
        }
        $k.Close()
    }
}

# ---------------------------------------------------------------- live connections of app processes
Invoke-Section 'connections' {
    if (-not $script:AppPids.Count) { return }
    $dns = @{}
    try { foreach ($d in @(Get-DnsClientCache -ErrorAction Stop)) { if ($d.Data) { if (-not $dns[$d.Data]) { $dns[$d.Data] = @() }; if ($dns[$d.Data] -notcontains $d.Entry) { $dns[$d.Data] += $d.Entry } } } }
    catch { Add-Failure 'connections' 'Get-DnsClientCache' $_.Exception.Message }
    $seen = @{}
    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $p = $script:AppPids[[int]$c.OwningProcess]; if (-not $p) { continue }
        $img = $(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })
        $listen = $c.State.ToString() -eq 'Listen'
        $k = $(if ($listen) { "tcp|$img|listen|$($c.LocalAddress):$($c.LocalPort)" } else { "tcp|$img|$($c.RemoteAddress):$($c.RemotePort)" })
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        Add-Item 'connections' ([ordered]@{ key = $k; proto = 'tcp'; pid = [int]$c.OwningProcess; process = $p.Name; state = $c.State.ToString()
            local = "$($c.LocalAddress):$($c.LocalPort)"; remote = "$($c.RemoteAddress):$($c.RemotePort)"; remote_names = @($dns["$($c.RemoteAddress)"]) })
    }
    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $p = $script:AppPids[[int]$u.OwningProcess]; if (-not $p) { continue }
        $img = $(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })
        $k = "udp|$img|$($u.LocalAddress):$($u.LocalPort)"; if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        Add-Item 'connections' ([ordered]@{ key = $k; proto = 'udp'; pid = [int]$u.OwningProcess; process = $p.Name; local = "$($u.LocalAddress):$($u.LocalPort)" })
    }
    $Snap.notes.Add('connections: a point-in-time view; use Sysmon events 3/22 or repeated snapshots for anything periodic.')
}

# ---------------------------------------------------------------- toast AUMIDs
Invoke-Section 'toast' {
    $base = Open-Reg 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'toast'
    foreach ($n in Get-SubNames $base) {
        $kind = Get-RefKind $n -Names; if (-not $kind) { continue }
        $k = (Open-Sub $base $n)
        Add-Item 'toast' ([ordered]@{ key = "toast|settings|$($n.ToLowerInvariant())"; kind = 'notification_settings'; aumid = $n
            enabled = Get-RegVal $k 'Enabled'; show_in_action_center = Get-RegVal $k 'ShowInActionCenter'; match = $kind })
        if ($k) { $k.Close() }
    }
    if ($base) { $base.Close() }
    foreach ($sc in 'HKCU', 'HKLM64') {
        $p = $(if ($sc -eq 'HKCU') { 'Software\Classes\AppUserModelId' } else { 'SOFTWARE\Classes\AppUserModelId' })
        $base = Open-Reg $sc $p; if (-not $base) { continue }
        foreach ($n in Get-SubNames $base) {
            $k = (Open-Sub $base $n); $dn = Get-RegVal $k 'DisplayName'; $icon = Get-RegVal $k 'IconUri'; $act = Get-RegVal $k 'CustomActivator'
            $kind = Get-RefKind "$n $dn" -Names; if (-not $kind) { $kind = Get-RefKind "$icon" }
            if (-not $kind -and $act -and $script:AppClsids.ContainsKey("$act".ToUpperInvariant())) { $kind = 'clsid' }
            if ($kind) { Add-Item 'toast' ([ordered]@{ key = "toast|aumid|$sc|$($n.ToLowerInvariant())"; kind = 'aumid_registration'; scope = $sc; aumid = $n; display_name = $dn; icon = $icon; custom_activator = $act; match = $kind }) }
            if ($k) { $k.Close() }
        }
        $base.Close()
    }
}

# ---------------------------------------------------------------- shortcuts (startup, start menu, desktop)
Invoke-Section 'shortcuts' {
    $sh = New-Object -ComObject WScript.Shell
    $sets = @(@('startup', [Environment]::GetFolderPath('Startup'), $true), @('startup', [Environment]::GetFolderPath('CommonStartup'), $true),
              @('start_menu', [Environment]::GetFolderPath('Programs'), $true), @('start_menu', [Environment]::GetFolderPath('CommonPrograms'), $true),
              @('desktop', [Environment]::GetFolderPath('Desktop'), $false), @('desktop', [Environment]::GetFolderPath('CommonDesktopDirectory'), $false))
    $startupTotal = 0
    foreach ($s in $sets) {
        if (-not $s[1] -or -not (Test-Path -LiteralPath $s[1])) { continue }
        $files = @(Get-ChildItem -LiteralPath $s[1] -File -Force -Recurse:$s[2] -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.lnk', '.url', '.exe', '.bat', '.cmd', '.vbs', '.js' })
        if ($s[0] -eq 'startup') { $startupTotal += $files.Count }
        foreach ($f in $files) {
            $target = $null; $args_ = $null
            try {
                if ($f.Extension -eq '.lnk') { $l = $sh.CreateShortcut($f.FullName); $target = $l.TargetPath; $args_ = $l.Arguments }
                elseif ($f.Extension -eq '.url') { $m = Select-String -LiteralPath $f.FullName -Pattern '^URL=(.*)$' | Select-Object -First 1; if ($m) { $target = $m.Matches[0].Groups[1].Value } }
                else { $target = $f.FullName }
            } catch { Add-Failure 'shortcuts' $f.FullName $_.Exception.Message }
            $kind = Get-RefKind "$target $args_" -Names
            if (-not $kind -and $s[0] -eq 'startup' -and $script:AppRx -and $script:AppRx.IsMatch($f.Name)) { $kind = 'app' }
            if (-not $kind) { continue }
            Add-Item 'shortcuts' ([ordered]@{ key = "lnk|$($s[0])|$($f.FullName.ToLowerInvariant())"; location = $s[0]; path = $f.FullName; target = $target; arguments = $args_; match = $kind })
        }
    }
    $Snap.coverage['startup_folder_total'] = $startupTotal
}

# ---------------------------------------------------------------- WMI subscriptions
Invoke-Section 'wmi' {
    try {
        $cons = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
        $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop)
        $binds = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)
        $Snap.coverage['wmi_totals'] = [ordered]@{ consumers = $cons.Count; filters = $filters.Count; bindings = $binds.Count }
        foreach ($c in $cons) {
            $text = ''; foreach ($pn in 'CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'ScriptFileName', 'Name') { if ($c.CimInstanceProperties[$pn]) { $text += " $($c.CimInstanceProperties[$pn].Value)" } }
            $kind = Get-RefKind $text -Names; if (-not $kind) { continue }
            Add-Item 'wmi' ([ordered]@{ key = "wmi|$($c.CimClass.CimClassName)|$($c.Name)".ToLowerInvariant(); class = $c.CimClass.CimClassName; name = $c.Name; text = $text.Trim(); match = $kind })
        }
    } catch {
        Add-Failure 'wmi' 'root\subscription' $_.Exception.Message
    }
}

# ---------------------------------------------------------------- BITS
Invoke-Section 'bits' {
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        $jobs = $(if ($IsAdmin) { @(Get-BitsTransfer -AllUsers -ErrorAction Stop) } else { @(Get-BitsTransfer -ErrorAction Stop) })
        if (-not $IsAdmin) { $Snap.notes.Add('bits: only the current user''s jobs are visible without elevation.') }
        foreach ($j in $jobs) {
            $files = @($j.FileList | ForEach-Object { "$($_.RemoteName) -> $($_.LocalName)" })
            $kind = Get-RefKind "$($j.DisplayName) $($j.Description) $($files -join ' ')" -Names; if (-not $kind) { continue }
            Add-Item 'bits' ([ordered]@{ key = "bits|$($j.DisplayName)".ToLowerInvariant(); name = $j.DisplayName; owner_is_me = ($j.OwnerAccount -like "*$env:USERNAME"); state = $j.JobState.ToString(); files = $files; match = $kind })
        }
    } catch { Add-Failure 'bits' 'Get-BitsTransfer' $_.Exception.Message }
}

# ---------------------------------------------------------------- AppX packages
Invoke-Section 'appx' {
    if (-not $script:AppRx) { return }
    foreach ($p in @(Get-AppxPackage -ErrorAction SilentlyContinue)) {
        if ($script:AppRx.IsMatch("$($p.Name) $($p.Publisher)") -or (Test-UnderRoot $p.InstallLocation)) {
            Add-Item 'appx' ([ordered]@{ key = "appx|$($p.Name)".ToLowerInvariant(); name = $p.Name; version = $p.Version.ToString(); publisher = $p.Publisher; install_location = $p.InstallLocation })
        }
    }
}

# ---------------------------------------------------------------- optional Sysinternals autorunsc
Invoke-Section 'autoruns' {
    $exe = Get-Command autorunsc64.exe, autorunsc.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) { $Snap.notes.Add('autoruns: autorunsc not on PATH; native queries only.'); return }
    $eula = Open-Reg 'HKCU' 'Software\Sysinternals\Autoruns'; $accepted = (Get-RegVal $eula 'EulaAccepted') -eq 1; if ($eula) { $eula.Close() }
    if (-not $accepted -and -not $AutorunsAcceptEula) { $Snap.notes.Add('autoruns: EULA not yet accepted; rerun with -AutorunsAcceptEula (writes the Sysinternals EULA flag).'); return }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("autoruns-" + [guid]::NewGuid().ToString('N') + '.csv')
    $argv = @('-nobanner', '-a', '*', '-c', '-h', '-s', '-o', $tmp); if ($AutorunsAcceptEula) { $argv = @('-accepteula') + $argv }
    $r = Invoke-NativeRead $exe.Source $argv
    try {
        if (-not (Test-Path -LiteralPath $tmp)) { Add-Failure 'autoruns' $exe.Source "no output (exit $($r.Code))"; return }
        $rows = @(Get-Content -LiteralPath $tmp -Encoding Unicode | ConvertFrom-Csv)
        $Snap.coverage['autoruns_rows'] = $rows.Count
        foreach ($row in $rows) {
            $kind = Get-RefKind "$($row.'Image Path') $($row.'Launch String')" -Names
            if (-not $kind -and $script:AppRx -and $script:AppRx.IsMatch("$($row.Entry) $($row.Company) $($row.Description)")) { $kind = 'app' }
            if (-not $kind) { continue }
            Add-Item 'autoruns' ([ordered]@{ key = "autoruns|$($row.Category)|$($row.'Entry Location')|$($row.Entry)".ToLowerInvariant(); category = $row.Category
                location = $row.'Entry Location'; entry = $row.Entry; enabled = $row.Enabled; image = $row.'Image Path'; launch = $row.'Launch String'
                signer = $row.Signer; sha256 = $row.'SHA-256'; match = $kind })
        }
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- write
$outFull = [IO.Path]::GetFullPath($Out)
$dir = Split-Path $outFull -Parent; if (-not (Test-Path -LiteralPath $dir)) { throw "Output directory does not exist: $dir" }
$json = $Snap | ConvertTo-Json -Depth 12
if (-not $KeepPaths) {
    $esc = $env:USERPROFILE.TrimEnd('\').Replace('\', '\\')
    $json = [regex]::Replace($json, [regex]::Escape($esc), '%USERPROFILE%', 'IgnoreCase')
}
[IO.File]::WriteAllText($outFull, $json, (New-Object Text.UTF8Encoding($false)))
$total = 0; foreach ($c in $Snap.items.Keys) { $total += $Snap.items[$c].Count }
Write-Host ("inventory: {0} roots, {1} items in {2} categories, {3} access failures -> {4}" -f $Snap.roots.Count, $total, $Snap.items.Count, $Snap.access_failures.Count, $outFull)
foreach ($c in $Snap.items.Keys) { Write-Host ("  {0,-16} {1}" -f $c, $Snap.items[$c].Count) }
