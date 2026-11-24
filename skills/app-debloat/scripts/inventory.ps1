#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only inventory of one installed Windows desktop app: install roots, files, processes,
  modules, services, tasks, autostarts, COM, shell extensions (with their effective merged-HKCR
  state and overlay ranks), Explorer namespace entries, TSF, protocols, default-app claims,
  ShellNew, browser hosts and extensions, Office and WPS add-ins, dormant payloads, plain settings,
  firewall, connections, UPnP mappings, DevTools ports, DNS cache names, toast AUMIDs, shortcuts,
  pins, SendTo, sensor consent, WMI, BITS, and signs of a pending, staged or half-applied update.
  Writes one JSON snapshot.

.DESCRIPTION
  Changes nothing on the machine. Works without elevation; whatever it could not read is listed
  in "access_failures" and "notes" instead of being silently skipped. The upnp section asks the
  local gateway for its port mappings (SSDP discovery plus read calls, at most 20 s).
  Every item carries a stable "key" so snapshot_diff.py can compare two snapshots.
  Besides -App, the DisplayName of every matched Uninstall entry (and its Publisher, compared
  whole) is used to match tasks, toast AUMIDs, AppX packages, firewall rules, namespace entries,
  add-ins and pins, so localized names are found without -AppFile (match = uninstall_name).
  With -Root and no -App, Uninstall entries whose paths point into a root are matched too.
  Items with match = external or unlisted (browser section), policy or list (browser policy lists,
  Office AddinList and DoNotDisableAddinList) are not tied to the app: they are side-loaded
  extensions or policy entries that any app could have planted, listed because they are rare and
  because the levers must not collide with them.
  The agent's own processes are left out of "processes": this run and its shells, command lines
  that name this skill's scripts folder or an agent shell snapshot, and helper shells (bash,
  powershell, cmd, python, node) that descend from the same agent session. Counts per reason are
  in "self_excluded".
  Credential-like values in recorded command lines (processes[].command_line and the item key
  built from it, tasks[].actions[].arguments, shortcut arguments, Run key values, service
  recovery commands) become <redacted>, keeping the switch and parameter names: switches and
  parameters whose name contains token, stoken, bduss, session, password, passwd, secret, cookie
  or auth (access_token= included), JSON members with such names, and Cookie and Authorization
  headers. A bare value with no name is not recognized. The same rule covers ProgID, ShellNew,
  add-in and policy commands and URLs. In the settings section a key whose name looks like a
  credential is written as <redacted> (numbers too), and a string value that looks like a key or
  token (long, no spaces, high entropy) as <opaque len=N>; a URL stays readable, with its
  credential-like query values redacted.
  The snapshot is real-run DATA: write it to the private companion, never into the tool repo.

.PARAMETER App
  Regex matched against Uninstall DisplayName/Publisher, service names, COM names, task names,
  AUMIDs and so on. Example: 'Sogou|SogouInput'. Keep it ASCII: Windows PowerShell 5.1 often
  receives non-ASCII arguments in the wrong code page, and the mangled regex silently matches
  nothing. The script warns when -App holds non-ASCII characters; use -AppFile or -Root instead.
  The pattern actually used is recorded in params.app.

.PARAMETER AppFile
  UTF-8 text file holding the -App regex, for non-ASCII names. Blank lines and lines starting
  with # are ignored; several remaining lines are joined with '|'. Cannot be combined with -App.

.PARAMETER Root
  One or more install directories. When omitted, roots come from Uninstall entries matching -App
  and from top-level folders under Program Files, %LOCALAPPDATA%, %APPDATA% and %ProgramData%
  whose name matches -App.

.PARAMETER DataDir
  One or more data folders (role data) added on top of the roots found from -Root, -App and the
  Uninstall entries, for example a profile folder with an unrelated name or a folder that
  launch_monitor.ps1 saw the app write. They are walked like roots, so their files, plain
  settings, staged installers and DevToolsActivePort files are covered. A -DataDir or -Root that is
  not a folder is listed in access_failures; both are recorded in params.

.PARAMETER Out
  Output JSON path (required). There is no default, so the tool never writes inside a repo.

.PARAMETER MaxFiles
  Cap on PE files per root that get version, signature and sha256 detail. Default 1500. The PE
  files of each root are sorted by relative path before the cap applies, so two snapshots of the
  same tree hash the same set; roots[].capped is true when the cap cut the list.

.PARAMETER MaxEntries
  Cap on file system entries walked per root (in sorted order). Default 60000.

.PARAMETER NoSignature
  Skip Authenticode checks (faster).

.PARAMETER KeepPaths
  Keep the literal user profile path and user name in the output. By default they are replaced
  with %USERPROFILE% and %USERNAME% so snapshots diff across machines.

.PARAMETER AutorunsAcceptEula
  Run Sysinternals autorunsc with -accepteula. Without it, autorunsc runs only when its EULA was
  already accepted, because otherwise it opens a blocking EULA dialog.

.PARAMETER AutorunsPath
  autorunsc64.exe / autorunsc.exe, or the folder holding it. Without it the script looks on PATH,
  then in %LOCALAPPDATA%\Programs\Sysinternals (where setup_re_backend.ps1 installs it). The
  binary runs only when its Authenticode signature is valid and signed by Microsoft.

.EXAMPLE
  .\inventory.ps1 -App 'ExampleApp' -Out "$env:TEMP\exampleapp-before.json"
  .\inventory.ps1 -Root "$env:ProgramFiles\ExampleApp" -App 'Example' -Out D:\private\inv.json
  .\inventory.ps1 -AppFile D:\private\app-pattern.txt -Out D:\private\inv.json
  .\inventory.ps1 -Root "$env:LOCALAPPDATA\Contoso" -DataDir "$env:APPDATA\ContosoLogs" -Out D:\private\inv.json
#>
[CmdletBinding()]
param(
    [string]$App,
    [string]$AppFile,
    [string[]]$Root,
    [string[]]$DataDir,
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$MaxFiles = 1500,
    [int]$MaxEntries = 60000,
    [switch]$NoSignature,
    [switch]$KeepPaths,
    [switch]$AutorunsAcceptEula,
    [string]$AutorunsPath
)
$ToolVersion = '1.4.0'
$ErrorActionPreference = 'Stop'
$AppSource = $null
if ($AppFile) {
    if ($App) { throw 'Pass -App or -AppFile, not both.' }
    $appFull = (Resolve-Path -LiteralPath $AppFile).ProviderPath
    $lines = [IO.File]::ReadAllText($appFull, [Text.Encoding]::UTF8) -split "`r?`n"
    $parts = @($lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    if (-not $parts.Count) { throw "-AppFile $AppFile holds no pattern." }
    $App = $parts -join '|'; $AppSource = 'file'
} elseif ($App) { $AppSource = 'param' }
if (-not $App -and -not $Root) { throw 'Pass -App <regex>, -AppFile <utf8 file> and/or -Root <dir> (-DataDir only adds to them).' }
$AppNonAscii = [bool]($App -and $AppSource -eq 'param' -and $App -match '[^\x00-\x7F]')
if ($AppNonAscii) {
    Write-Warning ("-App contains non-ASCII characters and arrived as '{0}'. Windows PowerShell 5.1 often receives such arguments in the wrong code page, so the regex may match nothing. Use an ASCII pattern, -AppFile <utf8 file> or -Root." -f $App)
}

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
    // Last write time of an open registry key (FILETIME UTC), 0 when unknown. RegistryKey does not expose it.
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryInfoKeyW(Microsoft.Win32.SafeHandles.SafeRegistryHandle h, IntPtr cls, IntPtr clsLen, IntPtr res,
        IntPtr subKeys, IntPtr maxSub, IntPtr maxCls, IntPtr values, IntPtr maxValName, IntPtr maxVal, IntPtr secDesc, out long lastWrite);
    public static long KeyLastWrite(Microsoft.Win32.RegistryKey k) {
        if (k == null) return 0; long ft;
        try { return RegQueryInfoKeyW(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) == 0 ? ft : 0; } catch { return 0; }
    }
    // Chromium extension id of a .crx file: CRX3 signed_header_data.crx_id, else sha256 of the first public key.
    static string MapId(byte[] d) { var sb = new StringBuilder(); for (int i = 0; i < 16; i++) { sb.Append((char)('a' + (d[i] >> 4))); sb.Append((char)('a' + (d[i] & 15))); } return sb.ToString(); }
    static string IdFromKey(byte[] key) { using (var sha = System.Security.Cryptography.SHA256.Create()) { return MapId(sha.ComputeHash(key)); } }
    static ulong Varint(byte[] b, ref int p) { ulong v = 0; int s = 0; while (p < b.Length) { byte x = b[p++]; v |= (ulong)(x & 0x7f) << s; if ((x & 0x80) == 0) return v; s += 7; if (s > 63) break; } throw new Exception("bad varint"); }
    // Length-delimited fields of one protobuf message: field number -> list of payloads.
    static Dictionary<int, List<byte[]>> Fields(byte[] b) {
        var r = new Dictionary<int, List<byte[]>>(); int p = 0;
        while (p < b.Length) {
            ulong tag = Varint(b, ref p); int f = (int)(tag >> 3); int wt = (int)(tag & 7);
            if (wt == 0) { Varint(b, ref p); } else if (wt == 1) { p += 8; } else if (wt == 5) { p += 4; }
            else if (wt == 2) { int n = (int)Varint(b, ref p); if (n < 0 || p + n > b.Length) throw new Exception("bad length"); var x = new byte[n]; Buffer.BlockCopy(b, p, x, 0, n); p += n; if (!r.ContainsKey(f)) r[f] = new List<byte[]>(); r[f].Add(x); }
            else throw new Exception("bad wire type");
        }
        return r;
    }
    public static string CrxId(string path) {
        try {
            using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete)) {
                var h = new byte[16]; if (fs.Read(h, 0, 16) < 12 || h[0] != 'C' || h[1] != 'r' || h[2] != '2' || h[3] != '4') return null;
                uint ver = BitConverter.ToUInt32(h, 4), n = BitConverter.ToUInt32(h, 8);
                if (n == 0 || n > (1 << 20)) return null;
                var buf = new byte[n]; fs.Position = ver == 2 ? 16 : 12;
                int got = 0; while (got < n) { int k = fs.Read(buf, got, (int)n - got); if (k <= 0) return null; got += k; }
                if (ver == 2) return IdFromKey(buf);
                if (ver != 3) return null;
                var top = Fields(buf);
                if (top.ContainsKey(10000)) { var sd = Fields(top[10000][0]); if (sd.ContainsKey(1) && sd[1][0].Length == 16) return MapId(sd[1][0]); }
                if (top.ContainsKey(2)) { var proof = Fields(top[2][0]); if (proof.ContainsKey(1)) return IdFromKey(proof[1][0]); }
                return null;
            }
        } catch { return null; }
    }
    // Shannon entropy in bits per byte (or per char) of the first n units: encrypted or packed data is near 8.
    public static double Entropy(byte[] b, int n) {
        n = Math.Min(n, b.Length); if (n <= 0) return 0; var c = new int[256];
        for (int i = 0; i < n; i++) c[b[i]]++;
        double e = 0; foreach (int x in c) { if (x > 0) { double p = (double)x / n; e -= p * Math.Log(p, 2); } }
        return e;
    }
    public static double StrEntropy(string s) {
        if (string.IsNullOrEmpty(s)) return 0; var c = new Dictionary<char, int>();
        foreach (char ch in s) { int v; c.TryGetValue(ch, out v); c[ch] = v + 1; }
        double e = 0; foreach (int x in c.Values) { double p = (double)x / s.Length; e -= p * Math.Log(p, 2); }
        return e;
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
    params          = [ordered]@{ app = $App; app_source = $AppSource; app_non_ascii = $AppNonAscii; root = @($Root); data_dir = @($DataDir); max_files = $MaxFiles; max_entries = $MaxEntries }
    roots           = New-Object System.Collections.Generic.List[object]
    related_files   = New-Object System.Collections.Generic.List[object]
    fingerprints    = [ordered]@{}
    coverage        = [ordered]@{}
    access_failures = New-Object System.Collections.Generic.List[object]
    notes           = New-Object System.Collections.Generic.List[string]
    self_excluded   = [ordered]@{}
    items           = [ordered]@{}
}
if (-not $IsAdmin) {
    $Snap.notes.Add('Not elevated: other-user and SYSTEM process paths, command lines and modules, protected scheduled tasks, WMI subscriptions and all-user BITS jobs are partly or fully invisible.')
}
if ($AppNonAscii) {
    $Snap.notes.Add('params: -App held non-ASCII characters; check params.app against what was typed. A mangled pattern matches nothing; rerun with -AppFile or -Root.')
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
# Credential-like values in command lines become <redacted>; switch and parameter names stay.
# The same rule is in launch_monitor.ps1 and elevated_readonly.ps1.
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
function Get-KeyTime($key) {
    # Last write of the key itself (one of its values or direct subkeys), UTC ISO 8601; $null when unknown.
    $ft = 0; try { $ft = [AdInv]::KeyLastWrite($key) } catch { }
    if ($ft -gt 0) { try { return [DateTime]::FromFileTimeUtc($ft).ToString('o') } catch { } }
    $null
}
function Get-KeyTimeAt([string]$scope, [string]$path) {
    $k = Open-Reg $scope $path; if (-not $k) { return $null }
    try { return Get-KeyTime $k } finally { $k.Close() }
}
function ConvertFrom-FileTime($v) {
    try { $n = [int64]$v; if ($n -gt 0) { return [DateTime]::FromFileTimeUtc($n).ToString('o') } } catch { }
    $null
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
# DisplayName of each matched Uninstall entry (set after the roots resolve) and its Publisher, compared whole.
$script:UninstallNameRx = $null
$script:PublisherNames = @()
function Get-NameKind([string]$s) {
    if (-not $s) { return $null }
    if ($script:AppRx -and $script:AppRx.IsMatch($s)) { return 'app' }
    if ($script:UninstallNameRx -and $script:UninstallNameRx.IsMatch($s)) { return 'uninstall_name' }
    $null
}
function Test-Publisher([string]$s) { $s -and $script:PublisherNames -contains $s.Trim().ToLowerInvariant() }
function Get-ListenScope([string]$addr) {
    if (-not $addr) { return $null }
    if ($addr -match '^(127\.|::1$|::ffff:127\.)') { return 'loopback' }
    if ($addr -in '0.0.0.0', '::') { return 'all' }
    'specific'
}
function Compare-Version([string]$a, [string]$b) {
    # -1, 0 or 1 for two dotted versions (missing parts count as 0); $null when either has no number.
    $pa = @([regex]::Matches("$a", '\d+') | Select-Object -First 4 | ForEach-Object { [int64]$_.Value })
    $pb = @([regex]::Matches("$b", '\d+') | Select-Object -First 4 | ForEach-Object { [int64]$_.Value })
    if (-not $pa.Count -or -not $pb.Count) { return $null }
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = $(if ($i -lt $pa.Count) { $pa[$i] } else { 0 }); $y = $(if ($i -lt $pb.Count) { $pb[$i] } else { 0 })
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    0
}

# ---------------------------------------------------------------- plain-text and JSON readers (read-only)
Add-Type -AssemblyName System.Web.Extensions
$script:JsonReader = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:JsonReader.MaxJsonLength = [int]::MaxValue; $script:JsonReader.RecursionLimit = 512
function Get-FileBytes([string]$path, [long]$max) {
    # Shared read: the app may hold the file open for writing.
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        if ($fs.Length -gt $max) { throw "larger than $max bytes" }
        $b = New-Object byte[] ([int]$fs.Length); $n = 0
        while ($n -lt $b.Length) { $k = $fs.Read($b, $n, $b.Length - $n); if ($k -le 0) { break }; $n += $k }
        return ,$b
    } finally { $fs.Dispose() }
}
function Get-FileHead([string]$path, [int]$max) {
    # The first $max bytes (the whole file when shorter), shared read like Get-FileBytes.
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $b = New-Object byte[] ([int][Math]::Min([long]$max, $fs.Length)); $n = 0
        while ($n -lt $b.Length) { $k = $fs.Read($b, $n, $b.Length - $n); if ($k -le 0) { break }; $n += $k }
        if ($n -lt $b.Length) { [Array]::Resize([ref]$b, $n) }
        return ,$b
    } finally { $fs.Dispose() }
}
function ConvertFrom-Bytes([byte[]]$b) {
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
    if ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($b, 2, $b.Length - 2) }
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
    if ($b.Length -ge 4 -and $b[0] -ne 0 -and $b[1] -eq 0 -and $b[3] -eq 0) { return [Text.Encoding]::Unicode.GetString($b) }   # UTF-16 LE, no BOM
    try { return (New-Object Text.UTF8Encoding($false, $true)).GetString($b) } catch { return [Text.Encoding]::Default.GetString($b) }
}
function Read-JsonText([string]$text) { ,$script:JsonReader.DeserializeObject($text) }
function Get-JPath($obj, [string[]]$keys) {
    # Walk nested JSON objects (Dictionary[string,object]); $null when a step is missing.
    $cur = $obj
    foreach ($k in $keys) {
        if ($cur -isnot [Collections.Generic.IDictionary[string, object]] -or -not $cur.ContainsKey($k)) { return $null }
        $cur = $cur[$k]
    }
    ,$cur
}
function Read-JsonFile([string]$path, [long]$max = 5MB) { Read-JsonText (ConvertFrom-Bytes (Get-FileBytes $path $max)) }
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
    # A Windows binary that hosts the app's class (shell32.dll for a shell namespace folder) is not the app's file:
    # tracking it would make every reference to it look like the app.
    if ($f.ToLowerInvariant().StartsWith($env:SystemRoot.ToLowerInvariant() + '\')) {
        $co = $null; try { $co = [Diagnostics.FileVersionInfo]::GetVersionInfo($f).CompanyName } catch { }
        if ("$co" -match '^Microsoft Corporation$') { return }
    }
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

$script:UninstallOther = New-Object System.Collections.Generic.List[object]   # entries -App missed; matched by root path later
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
            $o = [ordered]@{
                key = "uninstall|$scope|$sn"; scope = $scope; subkey = $sn; display_name = $dn; publisher = $pub
                display_version = Get-RegVal $k 'DisplayVersion'; install_location = Get-RegVal $k 'InstallLocation'
                uninstall_string = Get-RegVal $k 'UninstallString'; quiet_uninstall = Get-RegVal $k 'QuietUninstallString'
                display_icon = Get-RegVal $k 'DisplayIcon'; system_component = Get-RegVal $k 'SystemComponent'
                install_date = Get-RegVal $k 'InstallDate'; match = 'app'
            }
            if (-not $hit) { $script:UninstallOther.Add($o) }
            if ($hit) {
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
    foreach ($r in @($Root)) {
        if (-not $r) { continue }
        $rp = $null; try { $rp = [Environment]::ExpandEnvironmentVariables($r.Trim('"')) } catch { }
        if (-not $rp -or -not (Test-Path -LiteralPath $rp -PathType Container)) { Add-Failure 'roots' $r '-Root is not a folder'; continue }
        Add-Root $r 'install' 'param'
    }
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
    foreach ($d in @($DataDir)) {
        if (-not $d) { continue }
        # Add-Root drops a missing folder without a word; a -DataDir the caller named must not vanish that way.
        $dx = $null; try { $dx = [Environment]::ExpandEnvironmentVariables($d.Trim('"')) } catch { }
        if (-not $dx -or -not (Test-Path -LiteralPath $dx -PathType Container)) { Add-Failure 'roots' $d '-DataDir is not a folder'; continue }
        Add-Root $d 'data' 'param-data'
    }
    if ($Snap.roots.Count -eq 0) { $Snap.notes.Add('No install root resolved. Pass -Root explicitly.') }
}

# ---------------------------------------------------------------- names from the Uninstall entries
function Get-CleanName([string]$n) {
    # '<Name> 1.2.3 (x64)' -> '<Name>'. Short ASCII names (under 4 letters) are too generic to match on.
    if (-not $n) { return $null }
    $c = $n.Trim() -replace '\s*\((x64|x86|amd64|arm64|64[- ]?bit|32[- ]?bit)\)\s*$', '' -replace '\s+(x64|x86|64[- ]?bit|32[- ]?bit)$', ''
    $c = ($c -replace '\s*[vV]?\d+(\.\d+){1,3}\s*$', '').Trim(' ', '-', '_')
    if ($c -match '[^\x00-\x7F]') { if ($c.Length -lt 2) { return $null } } elseif ($c.Length -lt 4) { return $null }
    $c
}
Invoke-Section 'name_match' {
    # With -Root and no -App the installs section matched nothing: take the entries whose paths point into a root.
    foreach ($o in $script:UninstallOther) {
        foreach ($v in @($o.install_location, $o.uninstall_string, $o.display_icon, $o.quiet_uninstall)) {
            if ($v -and ((Test-UnderRoot "$v".Trim('"')) -or (Get-RefKind "$v") -eq 'root')) { $o.match = 'root'; Add-Item 'installs' $o; break }
        }
    }
    $Snap.coverage['installs'] = [ordered]@{ items = (Get-Items 'installs').Count; ms = $Snap.coverage['installs'].ms }
    $names = @(); $pubs = @()
    foreach ($u in (Get-Items 'installs')) {
        if (-not $u) { continue }
        $c = Get-CleanName "$($u.display_name)"; if ($c -and $names -notcontains $c) { $names += $c }
        if ($u.publisher -and "$($u.publisher)".Trim().Length -ge 2) { $p = "$($u.publisher)".Trim().ToLowerInvariant(); if ($pubs -notcontains $p) { $pubs += $p } }
    }
    # A publisher counts only while it is exclusive to the matched installs: a vendor with other products on the
    # machine (or Microsoft, which signs half of Windows) would pull in tasks and packages that are not the app.
    $other = @{}; foreach ($o in $script:UninstallOther) { if ($o.match -ne 'root' -and $o.publisher) { $other["$($o.publisher)".Trim().ToLowerInvariant()] = $true } }
    $shared = @($pubs | Where-Object { $other.ContainsKey($_) })
    $pubs = @($pubs | Where-Object { -not $other.ContainsKey($_) })
    if ($names.Count) { $script:UninstallNameRx = New-Object regex((($names | ForEach-Object { [regex]::Escape($_) }) -join '|'), 'IgnoreCase') }
    $script:PublisherNames = $pubs
    $Snap['uninstall_names'] = $names
    $Snap['uninstall_publishers'] = [ordered]@{ used = $pubs; not_used_shared = $shared }
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
                    elseif ($ln -match 'COMMAND_LINE\s*:\s*(.*)$') { $rec.command_line = Hide-Secret $Matches[1].Trim() }
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
    if (@((Get-Items 'services') | Where-Object { $_ -and $_.kind -eq 'service' -and $_.start_mode -eq 'Manual' }).Count) {
        $Snap.notes.Add('services: Manual services run on demand (the app can start them itself or through COM activation), so Manual + Stopped does not mean unused; check the service log or a Procmon trace of an app launch.')
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
$script:SpecificExes = @{}   # the app's exe names that are specific enough to match on (name_match_set)
$script:RuntimeRx = '^$'
# Pending-update probe: folders that look like update staging, and the package types staged there.
$UpdateDirRx = New-Object regex('(^|\\)[^\\]*(update|upgrade|patch|download|staging|pending|newver|installer|setup|package)[^\\]*\\', 'IgnoreCase')
$PackageExt = '.msi', '.msp', '.cab', '.zip', '.7z', '.rar'
$StagedExeRx = New-Object regex('setup|install|full|delta|patch|\d+[._]\d+[._]\d+', 'IgnoreCase')
function Add-Pending([string]$kind, [IO.FileSystemInfo]$e, [string]$root, [string]$rel, [string]$pair) {
    $o = [ordered]@{ key = "pending|$kind|$($e.FullName.ToLowerInvariant())"; kind = $kind; path = $e.FullName; root = $root; rel = $rel
        size = $(if ($e -is [IO.FileInfo]) { $e.Length }); mtime = $e.LastWriteTimeUtc.ToString('o'); file_version = $null; pair = $pair; pair_version = $null }
    try { if ($e -is [IO.FileInfo]) { $o.file_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($e.FullName).FileVersion } } catch { }
    try { if ($pair) { $o.pair_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($pair).FileVersion } } catch { }
    Add-Item 'pending_update' $o
}
# Dormant payloads: packages and add-ins the app ships but has not (yet) registered.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$DormantExt = '.msix', '.msixbundle', '.appx', '.appxbundle', '.vsto', '.xll', '.wll', '.xla', '.xlam', '.ppa', '.ppam', '.dotm', '.crx', '.xpi'
$script:BundledExtIds = @{}     # browser extension id -> bundled .crx/.xpi path
$script:BundledPackages = @{}   # package identity name (lower case) -> bundled .msix/.appx path
function Read-XmlText([string]$text) {
    # No DTD processing and no resolver: the file comes from a vendor folder.
    if (-not $text) { return $null }
    $st = New-Object Xml.XmlReaderSettings; $st.DtdProcessing = [Xml.DtdProcessing]::Ignore; $st.XmlResolver = $null
    $rd = [Xml.XmlReader]::Create((New-Object IO.StringReader($text)), $st)
    try { $d = New-Object Xml.XmlDocument; $d.XmlResolver = $null; $d.Load($rd); return ,$d } finally { $rd.Close() }
}
function Read-ZipText([string]$zip, [string[]]$names, [long]$max = 4MB) {
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($n in $names) {
            $en = $z.GetEntry($n); if (-not $en) { continue }
            if ($en.Length -gt $max) { throw "$n is larger than $max bytes" }
            $s = $en.Open()
            try { $ms = New-Object IO.MemoryStream; $s.CopyTo($ms); return (ConvertFrom-Bytes $ms.ToArray()) } finally { $s.Dispose() }
        }
    } finally { $z.Dispose() }
    $null
}
function Get-XAttr($doc, [string]$xpath, [string]$attr) {
    $n = $doc.SelectSingleNode($xpath); if (-not $n) { return $null }
    if ($attr) { return $n.GetAttribute($attr) }
    $n.InnerText
}
function Add-Dormant([IO.FileInfo]$e, [string]$root, [string]$rel, [string]$ext) {
    $kind = $(if ($ext -in '.crx', '.xpi') { 'browser_extension' } elseif ($ext -in '.msix', '.msixbundle', '.appx', '.appxbundle') { 'app_package' } else { 'office_addin' })
    $o = [ordered]@{ key = "dormant|$($e.FullName.ToLowerInvariant())"; kind = $kind; ext = $ext; path = $e.FullName; root = $root; rel = $rel; size = $e.Length }
    try {
        if ($ext -eq '.crx') {
            $id = [AdInv]::CrxId($e.FullName); $o['extension_id'] = $id; if ($id) { $script:BundledExtIds[$id] = $e.FullName }
        } elseif ($ext -eq '.xpi') {
            $id = $null; $m = $null; $t = Read-ZipText $e.FullName @('manifest.json')
            if ($t) { $m = Read-JsonText $t }
            foreach ($k in 'browser_specific_settings', 'applications') { if (-not $id) { $id = Get-JPath $m @($k, 'gecko', 'id') } }
            if (-not $id -and $e.BaseName -match '@|^\{[0-9A-Fa-f-]{36}\}$') { $id = $e.BaseName }
            $o['extension_id'] = $id; if ($id) { $script:BundledExtIds[$id.ToLowerInvariant()] = $e.FullName }
        } elseif ($ext -in '.msix', '.appx') {
            $x = Read-XmlText (Read-ZipText $e.FullName @('AppxManifest.xml'))
            if ($x) {
                $pk = "/*[local-name()='Package']"
                $o['identity'] = Get-XAttr $x "$pk/*[local-name()='Identity']" 'Name'
                $o['identity_publisher'] = Get-XAttr $x "$pk/*[local-name()='Identity']" 'Publisher'
                $o['identity_version'] = Get-XAttr $x "$pk/*[local-name()='Identity']" 'Version'
                $o['display_name'] = Get-XAttr $x "$pk/*[local-name()='Properties']/*[local-name()='DisplayName']"
                $o['publisher_display_name'] = Get-XAttr $x "$pk/*[local-name()='Properties']/*[local-name()='PublisherDisplayName']"
                $o['sparse'] = "$(Get-XAttr $x "$pk/*[local-name()='Properties']/*[local-name()='AllowExternalContent']")" -eq 'true'
                # Extension categories (fileExplorerContextMenus, comServer, appService, startupTask ...) and capabilities.
                $o['extensions'] = @($x.SelectNodes("//*[local-name()='Extension']") | ForEach-Object { $_.GetAttribute('Category') } | Where-Object { $_ } | Sort-Object -Unique)
                $o['capabilities'] = @($x.SelectNodes("$pk/*[local-name()='Capabilities']/*") | ForEach-Object { $_.GetAttribute('Name') } | Where-Object { $_ } | Sort-Object -Unique)
            }
        } elseif ($ext -in '.msixbundle', '.appxbundle') {
            $x = Read-XmlText (Read-ZipText $e.FullName @('AppxMetadata/AppxBundleManifest.xml'))
            if ($x) {
                $o['identity'] = Get-XAttr $x "/*[local-name()='Bundle']/*[local-name()='Identity']" 'Name'
                $o['identity_publisher'] = Get-XAttr $x "/*[local-name()='Bundle']/*[local-name()='Identity']" 'Publisher'
                $o['identity_version'] = Get-XAttr $x "/*[local-name()='Bundle']/*[local-name()='Identity']" 'Version'
                $o['packages'] = @($x.SelectNodes("//*[local-name()='Packages']/*[local-name()='Package']") | ForEach-Object { $_.GetAttribute('FileName') } | Where-Object { $_ } | Sort-Object -Unique)
            }
        } elseif ($ext -eq '.vsto') {
            $x = Read-XmlText (ConvertFrom-Bytes (Get-FileBytes $e.FullName 2MB))
            if ($x) { $o['identity'] = Get-XAttr $x "//*[local-name()='assemblyIdentity']" 'name'; $o['identity_version'] = Get-XAttr $x "//*[local-name()='assemblyIdentity']" 'version' }
        }
    } catch { $o['detail_error'] = $_.Exception.Message }
    if ($o['identity'] -and $kind -eq 'app_package') { $script:BundledPackages["$($o['identity'])".ToLowerInvariant()] = $e.FullName }
    Add-Item 'dormant_payloads' $o
}
# Files the later sections read: plain settings and SQLite candidates, DevToolsActivePort, every .exe (staged installers).
$SettingsExt = '.ini', '.json', '.xml', '.cfg', '.conf', '.config', '.db', '.sqlite', '.sqlite3', '.db3'
$SettingsNames = 'preferences', 'secure preferences', 'local state'
$script:SettingsFiles = New-Object System.Collections.Generic.List[object]
$script:DevToolsFiles = New-Object System.Collections.Generic.List[object]
$script:AllExes = New-Object System.Collections.Generic.List[object]
Invoke-Section 'files' {
    foreach ($r in $Snap.roots) {
        $stats = [ordered]@{ entries = 0; files = 0; dirs = 0; bytes = 0; by_ext = [ordered]@{}; pe_total = 0; pe_hashed = 0
            capped = $false; entries_truncated = $false; truncated = $false; reparse_skipped = 0 }
        $pe = New-Object System.Collections.Generic.List[object]
        $stack = New-Object System.Collections.Generic.Stack[string]; $stack.Push($r.path)
        while ($stack.Count -gt 0 -and -not $stats.entries_truncated) {
            $dir = $stack.Pop()
            try { $entries = (New-Object IO.DirectoryInfo($dir)).GetFileSystemInfos() }
            catch { Add-Failure 'files' $dir $_.Exception.Message; continue }
            $sortKeys = [string[]]@($entries | ForEach-Object { $_.Name.ToLowerInvariant() })
            # Non-generic overload: the generic one infers its item type from the first call (a folder holding only
            # folders gives DirectoryInfo[]) and then fails on every folder that holds files.
            if ($entries.Length -gt 1) { [Array]::Sort([Array]$sortKeys, [Array]$entries, [Collections.IComparer][StringComparer]::Ordinal) }
            $names = @{}; foreach ($e in $entries) { $names[$e.Name.ToLowerInvariant()] = $true }
            $subdirs = New-Object System.Collections.Generic.List[string]
            foreach ($e in $entries) {
                $stats.entries++
                if ($stats.entries -gt $MaxEntries) { $stats.entries_truncated = $true; break }
                $rel = $e.FullName.Substring($r.path.Length).TrimStart('\')
                $ext = $e.Extension.ToLowerInvariant()
                $lname = $e.Name.ToLowerInvariant()
                if ($e -is [IO.DirectoryInfo]) {
                    $stats.dirs++
                    if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { $stats.reparse_skipped++; continue }
                    if ($PeExt -contains $ext) {
                        # A directory named like a binary is the classic anti-reinstall placeholder.
                        $sddl = $null; try { $sddl = (Get-Acl -LiteralPath $e.FullName).Sddl } catch { }
                        Add-Item 'placeholders' ([ordered]@{ key = "placeholder|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $r.path; rel = $rel; kind = 'directory'; sddl = $sddl; attributes = $e.Attributes.ToString() })
                        if ($ext -eq '.exe') { $script:ExeNames[$lname] = $true }
                    }
                    $subdirs.Add($e.FullName); continue
                }
                $stats.files++; $stats.bytes += $e.Length
                if ($e.Length -eq 0 -and ($e.Attributes -band [IO.FileAttributes]::ReadOnly)) {
                    # A 0-byte read-only file is the placeholder that replaces a component folder (dir-placeholder-file).
                    $sddl = $null; try { $sddl = (Get-Acl -LiteralPath $e.FullName).Sddl } catch { }
                    Add-Item 'placeholders' ([ordered]@{ key = "placeholder|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $r.path; rel = $rel; kind = 'file'; sddl = $sddl; attributes = $e.Attributes.ToString() })
                }
                $extKey = $(if ($ext) { $ext } else { '(none)' })
                if ($stats.by_ext.Contains($extKey)) { $stats.by_ext[$extKey]++ } else { $stats.by_ext[$extKey] = 1 }
                if ($DormantExt -contains $ext -and $e.Length -gt 0) { Add-Dormant $e $r.path $rel $ext }
                if ($SettingsExt -contains $ext -or $SettingsNames -contains $lname) { $script:SettingsFiles.Add([pscustomobject]@{ e = $e; root = $r.path; rel = $rel }) }
                elseif ($lname -eq 'devtoolsactiveport') { $script:DevToolsFiles.Add([pscustomobject]@{ e = $e; root = $r.path; rel = $rel }) }
                if ($ext -eq '.exe') { $script:AllExes.Add([pscustomobject]@{ e = $e; root = $r.path; rel = $rel; role = $r.role }) }
                # Half-applied update: X.new / X.old next to X, or a new_X.exe / X_new.exe swap next to X.exe.
                # Only binaries, packages and configs count: Chromium's LevelDB keeps a 'LOG.old' in every store.
                $baseExt = $(if ($ext -eq '.new' -or $ext -eq '.old') { [IO.Path]::GetExtension($lname.Substring(0, $lname.Length - $ext.Length)) })
                if ($baseExt -and ($PeExt -contains $baseExt -or $PackageExt -contains $baseExt -or $CfgExt -contains $baseExt -or $baseExt -in '.pak', '.dat', '.bin')) {
                    $base = $e.FullName.Substring(0, $e.FullName.Length - $ext.Length)
                    Add-Pending $(if ($ext -eq '.new') { 'sibling_new' } else { 'sibling_old' }) $e $r.path $rel $(if ($names.ContainsKey([IO.Path]::GetFileName($base).ToLowerInvariant())) { $base })
                } else {
                    $m = [regex]::Match($lname, '^new[_.-](.+)$|^(.+?)[_.-]new(\.[^.]+)$')
                    if ($m.Success -and ($PeExt -contains $ext -or $ext -eq '.asar')) {
                        $other = $(if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value + $m.Groups[3].Value })
                        if ($names.ContainsKey($other)) { Add-Pending 'swap' $e $r.path $rel (Join-Path $e.DirectoryName $other) }
                    }
                }
                if ($UpdateDirRx.IsMatch($rel) -and (($PackageExt -contains $ext) -or ($ext -eq '.exe' -and $StagedExeRx.IsMatch($lname)))) {
                    Add-Pending 'staged' $e $r.path $rel $null
                }
                if ($PeExt -contains $ext) {
                    $script:PeNames[$lname] = $true
                    if ($ext -eq '.exe') { $script:ExeNames[$lname] = $true }
                    $pe.Add([pscustomobject]@{ e = $e; rel = $rel; sort = $rel.ToLowerInvariant() })
                } elseif ($CfgExt -contains $ext) {
                    Add-Item 'config_files' ([ordered]@{ key = "cfg|$($e.FullName.ToLowerInvariant())"; path = $e.FullName; root = $r.path; rel = $rel; size = $e.Length; mtime = $e.LastWriteTimeUtc.ToString('o') })
                }
            }
            for ($i = $subdirs.Count - 1; $i -ge 0; $i--) { $stack.Push($subdirs[$i]) }   # walk in name order
        }
        # Sort per root before capping, so the same tree always hashes the same set.
        $pe.Sort([Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.sort, $b.sort) })
        $sortedPe = $pe.ToArray()
        $stats.pe_total = $sortedPe.Count
        $fpParts = New-Object System.Collections.Generic.List[string]
        foreach ($p in $sortedPe) {
            if ($stats.pe_hashed -ge $MaxFiles) { $stats.capped = $true; break }
            $stats.pe_hashed++
            $o = Get-PeDetail $p.e $r.path $p.rel
            if ($o.sha256) { $fpParts.Add("$($p.sort):$($o.sha256)") }
            Add-Item 'files' $o
        }
        $stats.truncated = $stats.capped -or $stats.entries_truncated
        $r['stats'] = $stats
        $r['capped'] = $stats.truncated
        $sorted = @($fpParts | Sort-Object)   # same ordering as tool_version 1.0.0, so fingerprints stay comparable
        $sha = [Security.Cryptography.SHA256]::Create()
        $Snap.fingerprints[$r.path] = [ordered]@{
            pe_files = $sorted.Count
            capped   = $stats.truncated
            sha256   = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))) | ForEach-Object { $_.ToString('x2') }))
        }
        if ($stats.capped) { $Snap.notes.Add("Root $($r.path): $($stats.pe_total) PE files, only the first $MaxFiles by path are hashed (MaxFiles); fingerprint covers only those.") }
        if ($stats.entries_truncated) { $Snap.notes.Add("Root $($r.path): walk stopped at MaxEntries=$MaxEntries; files, config files and placeholders past that point are missing.") }
    }
    foreach ($rf in $Snap.related_files) {
        $fi = New-Object IO.FileInfo($rf.path)
        $script:PeNames[$fi.Name.ToLowerInvariant()] = $true
        Add-Item 'files' (Get-PeDetail $fi $fi.DirectoryName $fi.Name)
    }
    # Name matching skips generic names and names Windows itself ships, to keep false positives down.
    $generic = 'setup.exe', 'uninst.exe', 'uninstall.exe', 'unins000.exe', 'update.exe', 'updater.exe', 'install.exe',
               'launcher.exe', 'helper.exe', 'crashpad_handler.exe', 'crashreporter.exe', 'elevate.exe', 'notification_helper.exe'
    # Bundled runtimes and tools share their names with unrelated installs (a bundled node.exe would pull in
    # every Node.js shortcut, firewall rule and file association), so they never match by name. A reference
    # to the bundled copy still matches, because Get-RefKind checks the resolved roots before names.
    $script:RuntimeRx = '^(node|nodejs|python[\d.]*|pythonw[\d.]*|py|pyw|java|javaw|javaws|jre|git|git-.+|bash|sh|perl|ruby|rubyw|php|php-cgi|lua|luajit|' +
                 'dotnet|electron|chrome|chromium|msedge|msedgewebview2|cefsharp\.browsersubprocess|qtwebengineprocess|' +
                 'cmd|powershell|pwsh|conhost|rundll32|regsvr32|wscript|cscript|mshta|curl|wget|aria2c|7z|7za|7zg|unzip|' +
                 'ffmpeg|ffprobe|ffplay|adb|fastboot|openssl|sqlite3|vc_redist\.x(86|64)|vcredist_x(86|64))\.exe$'
    $runtime = @($script:ExeNames.Keys | Where-Object { $_ -match $script:RuntimeRx } | Sort-Object)
    $specific = @($script:ExeNames.Keys | Where-Object {
        $_.Length -ge 6 -and $generic -notcontains $_ -and $_ -notmatch $script:RuntimeRx -and
        -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32\$_")) -and -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot $_)) })
    if ($specific.Count) {
        $script:NameRx = New-Object regex(('(?:^|[\\/"\s=,])(' + (($specific | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?:$|["\s,])'), 'IgnoreCase')
    }
    $Snap['name_match_set'] = @($specific | Sort-Object)
    $Snap['name_match_excluded_runtimes'] = $runtime
    foreach ($x in $specific) { $script:SpecificExes[$x] = $true }
    if ((Get-Items 'dormant_payloads').Count) { $Snap.coverage['dormant_payloads'] = [ordered]@{ items = (Get-Items 'dormant_payloads').Count } }
}

# ---------------------------------------------------------------- pending update: Uninstall version vs. file version
# The .new/.old siblings, swaps and staged packages are collected during the file walk above.
function Test-VersionMatch([string]$a, [string]$b) {
    # Equal when one dotted version is a prefix of the other after trailing zeros are dropped ('8.0.5' ~ '8.0.5.0').
    $pa = @([regex]::Matches("$a", '\d+') | ForEach-Object { [int64]$_.Value }); $pb = @([regex]::Matches("$b", '\d+') | ForEach-Object { [int64]$_.Value })
    if (-not $pa.Count -or -not $pb.Count) { return $false }
    while ($pa.Count -gt 1 -and $pa[-1] -eq 0) { $pa = @($pa[0..($pa.Count - 2)]) }
    while ($pb.Count -gt 1 -and $pb[-1] -eq 0) { $pb = @($pb[0..($pb.Count - 2)]) }
    $n = [Math]::Min($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) { if ($pa[$i] -ne $pb[$i]) { return $false } }
    $true
}
function Get-SignerName($sig) {
    if (-not $sig -or -not $sig.SignerCertificate) { return $null }
    ($sig.SignerCertificate.Subject -replace '^.*?CN=("[^"]+"|[^,]+).*$', '$1').Trim('"')
}
Invoke-Section 'pending_update' {
    $vendors = @()   # per install: the installed version (Uninstall or main exe, whichever is newer) and who signs it
    foreach ($u in (Get-Items 'installs')) {
        if (-not $u -or -not $u.display_version) { continue }
        $cands = @()
        $icon = $(if ($u.display_icon) { ("$($u.display_icon)" -replace ',\s*-?\d+$', '').Trim('"') })
        if ($icon -and $icon -match '\.exe$') { $cands += [Environment]::ExpandEnvironmentVariables($icon) }
        if (-not $cands.Count -and $u.install_location) {
            $loc = [Environment]::ExpandEnvironmentVariables("$($u.install_location)".Trim('"'))
            if (Test-Path -LiteralPath $loc -PathType Container) {
                $cands += @(Get-ChildItem -LiteralPath $loc -Filter *.exe -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '^(unins|uninst|uninstall|setup|update|updater|crash)' } | ForEach-Object { $_.FullName })
            }
        }
        $seen = @(); $ok = $false
        $vendor = @{ version = "$($u.display_version)"; uninstall_key = "$($u.scope)\$($u.subkey)"; companies = @(); signers = @(); exes = @()
            names = @(Get-CleanName "$($u.display_name)" | Where-Object { $_ }) }
        foreach ($c in $cands) {
            $fv = $null; $pv = $null; $exists = Test-Path -LiteralPath $c -PathType Leaf
            if ($exists) {
                try {
                    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($c); $fv = $vi.FileVersion; $pv = $vi.ProductVersion
                    if ($vi.CompanyName) { $vendor.companies += $vi.CompanyName.Trim() }
                } catch { }
                $vendor.exes += $c.ToLowerInvariant()
                foreach ($v in @($pv, $fv)) { if ((Compare-Version $v $vendor.version) -gt 0) { $vendor.version = $v } }
                if (-not $NoSignature) { try { $sn = Get-SignerName (Get-AuthenticodeSignature -LiteralPath $c); if ($sn) { $vendor.signers += $sn } } catch { } }
            }
            $seen += [ordered]@{ path = $c; exists = $exists; file_version = $fv; product_version = $pv }
            if ((Test-VersionMatch $u.display_version $fv) -or (Test-VersionMatch $u.display_version $pv)) { $ok = $true }
        }
        if ($vendor.companies.Count -or $vendor.signers.Count -or $vendor.names.Count) { $vendors += $vendor }
        if (-not $cands.Count) { continue }
        if (-not $ok) {
            Add-Item 'pending_update' ([ordered]@{ key = "pending|version|$($u.scope)|$($u.subkey)".ToLowerInvariant(); kind = 'version_mismatch'
                uninstall_key = "$($u.scope)\$($u.subkey)"; display_version = $u.display_version; main_exe = $seen })
        }
    }
    # Staged installer: an .exe from the same vendor with a newer version than the installed one, outside the
    # in-place install tree (a data root, an update-like folder, or a setup-like name). A netdisk app's in-app
    # downloader stages its full setup under a hash name in the profile, which the name-based 'staged' check misses.
    $setupRx = New-Object regex('setup|install|updat|upgrad|patch', 'IgnoreCase')
    $staged = 0
    foreach ($x in $script:AllExes) {
        if (-not $vendors.Count) { break }
        $p = $x.e.FullName; $pl = $p.ToLowerInvariant()
        $vi = $null; try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($p) } catch { continue }
        $ver = $(if ($vi.ProductVersion) { $vi.ProductVersion } else { $vi.FileVersion })
        $co = "$($vi.CompanyName)".Trim()
        $setupLike = $setupRx.IsMatch("$($vi.FileDescription)|$($vi.ProductName)|$($vi.OriginalFilename)")
        if (-not ($x.role -ne 'install' -or $UpdateDirRx.IsMatch($x.rel) -or $setupLike)) { continue }
        $prod = Get-CleanName "$($vi.ProductName)"
        foreach ($vd in $vendors) {
            if ($vd.exes -contains $pl -or (Compare-Version $ver $vd.version) -le 0) { continue }
            # Same version line (major equal or one up): bundled tools such as Chromium helpers carry their own
            # much higher version numbers.
            $ma = [regex]::Match("$ver", '\d+'); $mb = [regex]::Match("$($vd.version)", '\d+')
            if ($ma.Success -and $mb.Success -and ([int64]$ma.Value - [int64]$mb.Value) -notin 0, 1) { continue }
            # The setup can come from a sister company of the app's vendor, so its product name equal to the
            # Uninstall DisplayName counts as the vendor too.
            $byName = [bool]($prod -and $vd.names -contains $prod)
            $sig = $null; $signer = $null
            if (-not $NoSignature -and $vd.signers.Count) {
                try { $sig = Get-AuthenticodeSignature -LiteralPath $p; $signer = Get-SignerName $sig } catch { }
                if (-not $sig -or $sig.Status -ne 'Valid' -or ($vd.signers -notcontains $signer -and -not $byName)) { continue }
                $by = $(if ($vd.signers -contains $signer) { 'signer' } else { 'product_name' })
            } elseif ($co -and $vd.companies -contains $co) { $by = 'company' } elseif ($byName) { $by = 'product_name' } else { continue }
            Add-Item 'pending_update' ([ordered]@{ key = "pending|staged_installer|$pl"; kind = 'staged_installer'; path = $p; root = $x.root; rel = $x.rel
                size = $x.e.Length; mtime = $x.e.LastWriteTimeUtc.ToString('o'); file_version = $vi.FileVersion; product_version = $vi.ProductVersion
                product_name = $vi.ProductName; description = $vi.FileDescription; company = $co; signer = $signer; vendor_match = $by
                installed_version = $vd.version; uninstall_key = $vd.uninstall_key; setup_like = $setupLike })
            $staged++; break
        }
    }
    if (-not $vendors.Count -and $script:AllExes.Count) { $Snap.notes.Add('pending_update: no matched Uninstall entry with a version, so staged installers (newer exes of the same vendor) were not checked.') }
    if ((Get-Items 'pending_update').Count) {
        $Snap.notes.Add('pending_update: signs of a half-applied or staged update (see items.pending_update). Settle it before P1: record it as an L-RI entry and ask the owner before finishing the vendor''s own swap.')
    }
}

# ---------------------------------------------------------------- processes, modules, windows
$script:AppPids = @{}
$script:DebugPorts = @{}   # pid -> DevTools port (or 'pipe') from the command line
Invoke-Section 'processes' {
    $all = @(Get-CimInstance Win32_Process)
    $byPid = @{}; foreach ($p in $all) { $byPid[[int]$p.ProcessId] = $p }
    $noPath = 0; $seen = @{}
    # This inventory run is not the app: skip this PowerShell, its children, and the shells that launched it
    # (their command lines carry -App). Ancestors inside a root are kept.
    $self = @{ ([int]$PID) = $true }
    $kids = @{}; foreach ($p in $all) { $pp = [int]$p.ParentProcessId; if (-not $kids[$pp]) { $kids[$pp] = @() }; $kids[$pp] += $p }
    $queue = New-Object System.Collections.Generic.Queue[int]; $queue.Enqueue([int]$PID)
    while ($queue.Count) {
        $cur = $queue.Dequeue(); $curP = $byPid[$cur]
        foreach ($c in @($kids[$cur])) {
            if (-not $c -or $self.ContainsKey([int]$c.ProcessId)) { continue }
            if ($curP -and $curP.CreationDate -and $c.CreationDate -and $c.CreationDate -lt $curP.CreationDate) { continue }   # reused PID
            $self[[int]$c.ProcessId] = $true; $queue.Enqueue([int]$c.ProcessId)
        }
    }
    # Ancestors that bind the agent session (its shells and the agent host), not desktop-wide hosts: a helper
    # shell that descends from one of them is a sibling of this run, so it belongs to the agent as well.
    $genericHostRx = '^(explorer|svchost|services|wininit|winlogon|userinit|sihost|smss|csrss|system|runtimebroker|taskhostw|windowsterminal|openconsole|conhost)\.exe$'
    $anchors = @{}
    $cur = $byPid[[int]$PID]
    for ($i = 0; $cur -and $i -lt 16; $i++) {
        $par = $byPid[[int]$cur.ParentProcessId]
        if (-not $par -or $self.ContainsKey([int]$par.ProcessId)) { break }
        if ($par.CreationDate -and $cur.CreationDate -and $par.CreationDate -gt $cur.CreationDate) { break }   # reused PID
        if (-not (Test-UnderRoot $par.ExecutablePath)) {
            $self[[int]$par.ProcessId] = $true
            if ($par.Name -notmatch $genericHostRx) { $anchors[[int]$par.ProcessId] = $true }
        }
        $cur = $par
    }
    function Test-SessionChild($p) {
        $c = $p
        for ($j = 0; $c -and $j -lt 16; $j++) {
            $pp = $byPid[[int]$c.ParentProcessId]
            if (-not $pp) { return $false }
            if ($pp.CreationDate -and $c.CreationDate -and $pp.CreationDate -gt $c.CreationDate) { return $false }   # reused PID
            if ($anchors.ContainsKey([int]$pp.ProcessId)) { return $true }
            $c = $pp
        }
        $false
    }
    # Command lines naming this skill's scripts folder or an agent shell snapshot belong to the agent.
    $selfCmdRx = @('[\\/]skills[\\/]+app-debloat[\\/]+scripts[\\/]', '[\\/]shell-snapshots[\\/]')
    if ($PSScriptRoot) {
        $sr = $PSScriptRoot.TrimEnd('\')
        $selfCmdRx += [regex]::Escape($sr)
        $selfCmdRx += [regex]::Escape($sr.Replace('\', '/'))
        if ($sr -match '^([A-Za-z]):\\(.*)$') { $selfCmdRx += [regex]::Escape('/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\', '/')) }   # Git Bash form
    }
    $selfCmd = New-Object regex(($selfCmdRx -join '|'), 'IgnoreCase')
    $selfReasons = [ordered]@{}
    function Add-SelfSkip([string]$reason, $p) {
        if (-not $selfReasons.Contains($reason)) { $selfReasons[$reason] = [ordered]@{ count = 0; names = @() } }
        $selfReasons[$reason].count++
        if ($selfReasons[$reason].names -notcontains $p.Name) { $selfReasons[$reason].names += $p.Name }
    }
    $skippedSelf = 0
    $helperRx = '^(powershell|pwsh|cmd|bash|sh|python[\d.]*|pythonw[\d.]*|py|node|wscript|cscript|conhost|wsl|wt|windowsterminal)\.exe$'
    foreach ($p in $all) {
        if (-not $p.ExecutablePath) { $noPath++ }
        if ($self.ContainsKey([int]$p.ProcessId)) { $skippedSelf++; Add-SelfSkip 'this_run' $p; continue }
        $kind = $null
        if (Test-UnderRoot $p.ExecutablePath) { $kind = 'root' }
        if (-not $kind) { $kind = Get-RefKind $p.CommandLine }
        if (-not $kind -and -not $p.ExecutablePath -and $script:NameRx -and $script:NameRx.IsMatch('\' + $p.Name)) { $kind = 'name' }
        if (-not $kind) { continue }
        if ($p.CommandLine -and $PSCommandPath -and $p.CommandLine.Contains($PSCommandPath)) { $skippedSelf++; Add-SelfSkip 'inventory_run' $p; continue }   # another inventory run
        if (-not (Test-UnderRoot $p.ExecutablePath)) {   # an app binary is never the agent's own
            if ($p.CommandLine -and $selfCmd.IsMatch($p.CommandLine)) { $skippedSelf++; Add-SelfSkip 'skill_or_shell_snapshot' $p; continue }
            if ($p.Name -match $helperRx -and $anchors.Count -and (Test-SessionChild $p)) { $skippedSelf++; Add-SelfSkip 'agent_session_shell' $p; continue }
        }
        $script:AppPids[[int]$p.ProcessId] = $p
        $parent = $byPid[[int]$p.ParentProcessId]
        # A parent created after the child is a reused PID, not the real parent.
        if ($parent -and $parent.CreationDate -and $p.CreationDate -and $parent.CreationDate -gt $p.CreationDate) { $parent = $null }
        $cmd = Hide-Secret $p.CommandLine   # the key is built from it too, so no token reaches the snapshot
        $norm = ''; if ($cmd) { $norm = ($cmd.ToLowerInvariant() -replace '\d+', '#') }
        $k = "proc|$(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })|$norm"
        if ($seen.ContainsKey($k)) { $seen[$k]++; $k = "$k#$($seen[$k])" } else { $seen[$k] = 1 }
        # An embedded browser started with a DevTools endpoint: any local process (or web page via DNS rebinding) can drive it.
        $rdp = $null
        if ($cmd -match '--remote-debugging-port[=\s]+"?(\d+)') { $rdp = [int]$Matches[1] } elseif ($cmd -match '--remote-debugging-pipe') { $rdp = 'pipe' }
        if ($null -ne $rdp) { $script:DebugPorts[[int]$p.ProcessId] = $rdp }
        Add-Item 'processes' ([ordered]@{
            key = $k; pid = [int]$p.ProcessId; name = $p.Name; path = $p.ExecutablePath; command_line = $cmd; match = $kind
            parent_pid = [int]$p.ParentProcessId; parent_name = $(if ($parent) { $parent.Name }); parent_path = $(if ($parent) { $parent.ExecutablePath })
            session = $p.SessionId; threads = $p.ThreadCount; created = $(if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') })
            machine = $(if ($p.ExecutablePath) { Get-PeMachine $p.ExecutablePath }); modules_from_roots = @(); windows = @()
            # A shell or script host outside the roots that matched only on its command line is usually an analyst helper.
            helper_suspect = [bool](-not (Test-UnderRoot $p.ExecutablePath) -and $p.Name -match $helperRx) })
        if ($null -ne $rdp) { $Snap.items['processes'][$Snap.items['processes'].Count - 1]['remote_debugging_port'] = $rdp }
    }
    if ($script:DebugPorts.Count) { $Snap.notes.Add("processes: $($script:DebugPorts.Count) app processes run with --remote-debugging-port or --remote-debugging-pipe (see processes[].remote_debugging_port and items.devtools).") }
    if ($skippedSelf) {
        $Snap.self_excluded = $selfReasons
        $Snap.notes.Add("processes: skipped $skippedSelf processes of the agent itself (this run, its children and launching shells; other inventory runs; command lines naming the skill's scripts folder or an agent shell snapshot; helper shells of the same agent session). Counts per reason: self_excluded.")
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
                $acts += [ordered]@{ type = 'exec'; execute = $a.Execute; arguments = (Hide-Secret $a.Arguments); workdir = $a.WorkingDirectory }
                if (-not $kind) { $kind = Get-RefKind "$($a.Execute) $($a.Arguments) $($a.WorkingDirectory)" -Names }
            } elseif ($cls -eq 'MSFT_TaskComHandlerAction') {
                $acts += [ordered]@{ type = 'com'; class_id = $a.ClassId; data = $a.Data }
                if (-not $kind -and $a.ClassId -and $script:AppClsids.ContainsKey($a.ClassId.ToUpperInvariant())) { $kind = 'clsid' }
            } else { $acts += [ordered]@{ type = $cls } }
        }
        if (-not $kind) { $kind = Get-NameKind "$($t.TaskPath)$($t.TaskName)" }
        if (-not $kind -and (Test-Publisher "$($t.Author)")) { $kind = 'uninstall_publisher' }
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
            Add-Item 'run_keys' ([ordered]@{ key = "run|$($r[0])|$($r[1])|$n".ToLowerInvariant(); scope = $r[0]; path = $r[1]; name = $n; value = (Hide-Secret $v); match = $kind; startup_approved = $ap })
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
                if ($script:ExeNames.ContainsKey($n.ToLowerInvariant()) -and $n.ToLowerInvariant() -notmatch $script:RuntimeRx) { $kind = 'name' }
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
    # Tolerates a vendor-mangled value such as '{GUID}-' or '{GUID-}', which still names the app's class.
    function Test-AppClsid([string]$s) { if (-not $s) { return $false }; $m = [regex]::Match($s, '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'); $m.Success -and $script:AppClsids.ContainsKey('{' + $m.Value.ToUpperInvariant() + '}') }
    foreach ($cr in $classRoots) {
        # SystemFileAssociations\<.ext or perceived type> adds menu verbs and handlers per file type (for example
        # SystemFileAssociations\.pdf\shell\<verb>); Explorer merges them with the ProgID's own verbs.
        $sfa = Open-Reg $cr[0] "$($cr[1])\SystemFileAssociations"
        $sfaContainers = @(Get-SubNames $sfa | ForEach-Object { "SystemFileAssociations\$_" }); if ($sfa) { $sfa.Close() }
        foreach ($c in @($containers) + $sfaContainers) {
            $sx = Open-Reg $cr[0] "$($cr[1])\$c\shellex"; $hasShellex = [bool]$sx; if ($sx) { $sx.Close() }
            foreach ($t in $types) {
                if (-not $hasShellex) { break }
                $base = Open-Reg $cr[0] "$($cr[1])\$c\shellex\$t"; if (-not $base) { continue }
                foreach ($h in Get-SubNames $base) {
                    $d = Get-SubDefault $cr[0] "$($cr[1])\$c\shellex\$t\$h"
                    if ((Test-AppClsid $h) -or (Test-AppClsid $d) -or ($script:AppRx -and $script:AppRx.IsMatch($h))) {
                        Add-Item 'shell_ext' ([ordered]@{ key = "shellex|$($cr[0])|$c|$t|$h".ToLowerInvariant(); kind = $t; scope = $cr[0]; container = $c; handler = $h; clsid = $d
                            last_write = Get-KeyTimeAt $cr[0] "$($cr[1])\$c\shellex\$t\$h" })
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
                if ($kind) { Add-Item 'shell_ext' ([ordered]@{ key = "verb|$($cr[0])|$c|$verb".ToLowerInvariant(); kind = 'verb'; scope = $cr[0]; container = $c; verb = $verb; label = Get-RegVal $vk ''; command = $cmd; explorer_command_handler = $dex
                    last_write = Get-KeyTime $vk; match = $kind }) }
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
    $overlayOrder = @{}   # scope -> every overlay identifier in registry enumeration order (the order Explorer loads them)
    foreach ($l in $lists) {
        foreach ($sc in 'HKLM64', 'HKLM32', 'HKCU') {
            $base = Open-Reg $sc $l[1]; if (-not $base) { continue }
            if ($l[2] -eq 'subkeys') {
                foreach ($n in Get-SubNames $base) {
                    $d = Get-SubDefault $sc "$($l[1])\$n"
                    if ($l[0] -eq 'ShellIconOverlayIdentifiers') { if (-not $overlayOrder[$sc]) { $overlayOrder[$sc] = @() }; $overlayOrder[$sc] += , @($n, "$d".Trim()) }
                    if ((Test-AppClsid $n) -or (Test-AppClsid $d) -or ($script:AppRx -and $script:AppRx.IsMatch($n))) {
                        Add-Item 'shell_ext' ([ordered]@{ key = "$($l[0])|$sc|$n".ToLowerInvariant(); kind = $l[0]; scope = $sc; name = $n; clsid = $d
                            last_write = Get-KeyTimeAt $sc "$($l[1])\$n" })
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

    # Effective state in the merged HKCR view Explorer sees: an HKCU\Software\Classes key overrides the HKLM
    # one with the same path. Vendors often disable a handler per user by mangling the HKCU CLSID (a trailing
    # '-'), so the HKLM registration alone says nothing about whether the menu shows.
    $blocked = @{}
    foreach ($sc in 'HKLM64', 'HKCU') {
        $bk = Open-Reg $sc 'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
        foreach ($n in Get-ValNames $bk) { $blocked[$n.ToUpperInvariant()] = $sc }
        if ($bk) { $bk.Close() }
    }
    function Get-MergedKey([string]$view, [string]$rel) {
        $hk = Open-Reg 'HKCU' "Software\Classes\$rel"
        if ($hk) { return @{ key = $hk; source = 'HKCU' } }
        $lm = $(if ($view -eq '32') { 'HKLM32' } else { 'HKLM64' })
        $k = Open-Reg $lm "SOFTWARE\Classes\$rel"
        if ($k) { return @{ key = $k; source = $lm } }
        $null
    }
    function Test-ClsidRegistered([string]$view, [string]$id) {
        $paths = @(@('HKCU', "Software\Classes\CLSID\$id"))
        if ($view -eq '32') { $paths += , @('HKCU', "Software\Classes\WOW6432Node\CLSID\$id"); $paths += , @('HKLM32', "SOFTWARE\Classes\CLSID\$id") }
        else { $paths += , @('HKLM64', "SOFTWARE\Classes\CLSID\$id") }
        foreach ($p in $paths) { $k = Open-Reg $p[0] $p[1]; if ($k) { $k.Close(); return $true } }
        $false
    }
    $guidRx = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    foreach ($it in (Get-Items 'shell_ext')) {
        if (-not $it -or -not $it.Contains('container')) { continue }
        $view = $(if ($it.scope -eq 'HKLM32') { '32' } else { '64' })
        if ($it.kind -eq 'verb') {
            $mk = Get-MergedKey $view "$($it.container)\shell\$($it.verb)"
            if (-not $mk) { $it['effective'] = [ordered]@{ view = $view; source = $null; state = 'absent' }; continue }
            $flags = @(Get-ValNames $mk.key | Where-Object { $_ -in 'LegacyDisable', 'ProgrammaticAccessOnly', 'Extended' })
            $dex = Get-RegVal $mk.key 'ExplorerCommandHandler'; $mk.key.Close()
            $state = 'shown'
            if ($flags -contains 'Extended') { $state = 'extended-only' }
            if ($flags -contains 'LegacyDisable' -or $flags -contains 'ProgrammaticAccessOnly') { $state = 'hidden' }
            if ($dex -and $blocked.ContainsKey("$dex".Trim().ToUpperInvariant())) { $state = 'blocked' }
            $it['effective'] = [ordered]@{ view = $view; source = $mk.source; flags = $flags; explorer_command_handler = $dex; state = $state }
            continue
        }
        $mk = Get-MergedKey $view "$($it.container)\shellex\$($it.kind)\$($it.handler)"
        if (-not $mk) { $it['effective'] = [ordered]@{ view = $view; source = $null; state = 'absent' }; continue }
        $val = Get-RegVal $mk.key ''; $mk.key.Close()
        $cand = $(if ("$val".Trim()) { "$val".Trim() } else { "$($it.handler)" })
        $clsid = $null
        if ($cand -match $guidRx) {
            $clsid = $cand.ToUpperInvariant()
            if ($blocked.ContainsKey($clsid)) { $state = 'blocked' }
            elseif (Test-ClsidRegistered $view $clsid) { $state = 'active' }
            else { $state = 'unregistered' }
        } elseif ($cand -match '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}') { $state = 'disabled-mangled' }   # e.g. '{...}-' written by the vendor's own toggle
        else { $state = 'no-clsid' }
        $it['effective'] = [ordered]@{ view = $view; source = $mk.source; value = $val; clsid = $clsid; state = $state }
    }

    # Overlay ranking. Explorer loads overlay identifiers in registry enumeration order (sorted by name, so the
    # leading spaces vendors add jump the queue) into 15 image-list slots, 4 of which Windows keeps, so only the
    # first 11 handlers that load get an overlay. A handler whose CLSID is unregistered or Blocked is not counted.
    $overlayLimit = 11
    foreach ($sc in 'HKLM64', 'HKLM32') {
        $order = $overlayOrder[$sc]; if (-not $order) { continue }
        $view = $(if ($sc -eq 'HKLM32') { '32' } else { '64' })
        $appNames = @{}
        foreach ($it in (Get-Items 'shell_ext')) { if ($it -and $it.kind -eq 'ShellIconOverlayIdentifiers' -and $it.scope -eq $sc) { $appNames[$it.name] = $it } }
        $rows = @(); $lr = 0
        foreach ($pair in $order) {
            $id = "$($pair[1])".ToUpperInvariant()
            $ok = $id -match $guidRx -and -not $blocked.ContainsKey($id) -and (Test-ClsidRegistered $view $id)
            if ($ok) { $lr++ }
            $rows += [pscustomobject]@{ name = $pair[0]; rank = $rows.Count + 1; loadable_rank = $(if ($ok) { $lr } else { $null }); app = $appNames.ContainsKey($pair[0]) }
        }
        $loaded = @($rows | Where-Object { $_.loadable_rank -and $_.loadable_rank -le $overlayLimit } | ForEach-Object { $_.name })
        $without = @($rows | Where-Object { $_.loadable_rank -and -not $_.app } | Select-Object -First $overlayLimit | ForEach-Object { $_.name })
        $victims = @($without | Where-Object { $loaded -notcontains $_ })
        foreach ($row in $rows) {
            if (-not $row.app) { continue }
            $it = $appNames[$row.name]
            $it['rank'] = $row.rank; $it['loadable_rank'] = $row.loadable_rank; $it['slot_limit'] = $overlayLimit; $it['overlay_count'] = $rows.Count
            $it['loaded'] = [bool]($row.loadable_rank -and $row.loadable_rank -le $overlayLimit)
            $it['dropped'] = [bool]($row.loadable_rank -and $row.loadable_rank -gt $overlayLimit)
            # Other handlers that would load if every app overlay in this view were removed.
            if ($it['loaded']) { $it['pushes_out'] = $victims } else { $it['pushes_out'] = @() }
        }
    }
    # Get-Items returns the list as one object; the parentheses unroll it so Where-Object sees each item.
    if (@((Get-Items 'shell_ext') | Where-Object { $_ -and $_.kind -eq 'ShellIconOverlayIdentifiers' -and $_.scope -eq 'HKCU' }).Count) {
        $Snap.notes.Add('shell_ext: per-user (HKCU) overlay identifiers are listed without a rank; only the HKLM views are ranked.')
    }
}

# ---------------------------------------------------------------- ProgIDs, URL protocols, file associations
$script:AppProgs = @{}   # lower-case ProgIDs and URL protocols whose command or icon points at the app
$script:ClassExts = New-Object System.Collections.Generic.List[object]
function Test-AppProgId([string]$p) { $p -and ($script:AppProgs.ContainsKey($p.ToLowerInvariant()) -or (Get-NameKind $p)) }
Invoke-Section 'classes' {
    # last_write on every hit is the key's own write time: a UserChoice written in the same second as the
    # install was set by the installer, not picked by the owner.
    $skip = 'CLSID', 'Interface', 'TypeLib', 'WOW6432Node', 'AppID', 'Record', 'Installer', 'Local Settings', 'Extensions'
    $progs = $script:AppProgs; $exts = $script:ClassExts; $seen64 = @{}
    foreach ($cr in @(@('HKLM64', 'SOFTWARE\Classes'), @('HKCU', 'Software\Classes'), @('HKLM32', 'SOFTWARE\Classes'))) {
        $base = Open-Reg $cr[0] $cr[1] 'classes'; if (-not $base) { continue }
        $names = Get-SubNames $base
        if ($cr[0] -eq 'HKLM64') { foreach ($n in $names) { $seen64[$n.ToLowerInvariant()] = $true } }
        foreach ($n in $names) {
            if ($skip -contains $n) { continue }
            # HKLM\SOFTWARE\Classes is shared by both views (only CLSID, Interface and a few others are redirected),
            # so the 32-bit view adds just the names the 64-bit view lacks.
            if ($cr[0] -eq 'HKLM32' -and $seen64.ContainsKey($n.ToLowerInvariant())) { continue }
            if ($n.StartsWith('.')) { $exts.Add(@($cr[0], $cr[1], $n)); continue }
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
                    label = Get-RegVal $k ''; command = (Hide-Secret $cmd); icon = $icon; match = $kind; last_write = Get-KeyTime $k })
            }
            $k.Close()
        }
        $base.Close()
    }
    foreach ($e in $exts) {
        $ek = Open-Reg $e[0] "$($e[1])\$($e[2])"; if (-not $ek) { continue }
        $d = Get-RegVal $ek ''
        $owp = Open-Sub $ek 'OpenWithProgids'
        $ow = @(Get-ValNames $owp | Where-Object { $progs.ContainsKey($_.ToLowerInvariant()) }); if ($owp) { $owp.Close() }
        $owl = Open-Sub $ek 'OpenWithList'   # subkeys named after exe files
        $owlHits = @(Get-SubNames $owl | Where-Object { $script:SpecificExes.ContainsKey($_.ToLowerInvariant()) }); if ($owl) { $owl.Close() }
        if (($d -and $progs.ContainsKey("$d".ToLowerInvariant())) -or $ow.Count -or $owlHits.Count) {
            Add-Item 'file_assoc' ([ordered]@{ key = "ext|$($e[0])|$($e[2])".ToLowerInvariant(); scope = $e[0]; ext = $e[2]; default = $d; open_with = $ow
                open_with_list = $owlHits; last_write = Get-KeyTime $ek })
        }
        $ek.Close()
    }
    $feRel = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts'
    $fe = Open-Reg 'HKCU' $feRel
    foreach ($x in Get-SubNames $fe) {
        $xk = Open-Sub $fe $x; if (-not $xk) { continue }
        $uc = Open-Sub $xk 'UserChoice'; $pid_ = Get-RegVal $uc 'ProgId'; $ucTime = Get-KeyTime $uc; if ($uc) { $uc.Close() }
        # Windows 11 24H2 and later also keep UserChoiceLatest\ProgId.
        $ul = Open-Sub $xk 'UserChoiceLatest\ProgId'; $pidL = Get-RegVal $ul 'ProgId'; $ulTime = Get-KeyTime $ul; if ($ul) { $ul.Close() }
        if ((Test-AppProgId "$pid_") -or (Test-AppProgId "$pidL")) {
            Add-Item 'file_assoc' ([ordered]@{ key = "userchoice|$x".ToLowerInvariant(); scope = 'HKCU'; ext = $x; user_choice = $pid_; last_write = $ucTime
                user_choice_latest = $pidL; latest_last_write = $ulTime })
        }
        $owp = Open-Sub $xk 'OpenWithProgids'
        $ow = @(Get-ValNames $owp | Where-Object { $progs.ContainsKey($_.ToLowerInvariant()) }); if ($owp) { $owp.Close() }
        $owl = Open-Sub $xk 'OpenWithList'   # values a, b, c ... hold exe names, MRUList their order
        $owlHits = @(Get-ValNames $owl | Where-Object { $_ -ne 'MRUList' } | ForEach-Object { "$(Get-RegVal $owl $_)" } | Where-Object { $_ -and $script:SpecificExes.ContainsKey($_.ToLowerInvariant()) })
        if ($owl) { $owl.Close() }
        if ($ow.Count -or $owlHits.Count) {
            Add-Item 'file_assoc' ([ordered]@{ key = "fileexts|$x".ToLowerInvariant(); scope = 'HKCU'; ext = $x; open_with = $ow; open_with_list = $owlHits; last_write = Get-KeyTime $xk })
        }
        $xk.Close()
    }
    if ($fe) { $fe.Close() }
    $ua = Open-Reg 'HKCU' 'Software\Microsoft\Windows\Shell\Associations\UrlAssociations'
    foreach ($proto in Get-SubNames $ua) {
        $pk = Open-Sub $ua $proto; if (-not $pk) { continue }
        $uc = Open-Sub $pk 'UserChoice'; $pid_ = Get-RegVal $uc 'ProgId'; $ucTime = Get-KeyTime $uc; if ($uc) { $uc.Close() }
        $ul = Open-Sub $pk 'UserChoiceLatest\ProgId'; $pidL = Get-RegVal $ul 'ProgId'; $ulTime = Get-KeyTime $ul; if ($ul) { $ul.Close() }
        if ((Test-AppProgId "$pid_") -or (Test-AppProgId "$pidL")) {
            Add-Item 'file_assoc' ([ordered]@{ key = "urlchoice|$proto".ToLowerInvariant(); scope = 'HKCU'; protocol = $proto; user_choice = $pid_; last_write = $ucTime
                user_choice_latest = $pidL; latest_last_write = $ulTime })
        }
        $pk.Close()
    }
    if ($ua) { $ua.Close() }
}

# ---------------------------------------------------------------- ShellNew (Explorer's New menu)
Invoke-Section 'shell_new' {
    # Explorer reads .ext\ShellNew and .ext\<default ProgID>\ShellNew.
    foreach ($e in $script:ClassExts) {
        $ek = Open-Reg $e[0] "$($e[1])\$($e[2])"; if (-not $ek) { continue }
        $d = "$(Get-RegVal $ek '')"
        foreach ($sub in @('ShellNew', $(if ($d) { "$d\ShellNew" }))) {
            if (-not $sub) { continue }
            $sn = Open-Sub $ek $sub; if (-not $sn) { continue }
            $vals = [ordered]@{}
            foreach ($vn in Get-ValNames $sn) { $v = Get-RegVal $sn $vn; if ($v -is [string]) { $v = Hide-Secret $v }; $vals[$vn] = $v }
            $kind = $null
            foreach ($vn in 'Command', 'FileName', 'IconPath', 'Handler') { if (-not $kind -and $vals.Contains($vn)) { $kind = Get-RefKind "$($vals[$vn])" -Names } }
            if (-not $kind -and $d -and $script:AppProgs.ContainsKey($d.ToLowerInvariant())) { $kind = 'progid' }
            foreach ($vn in 'ItemName', 'MenuText') { if (-not $kind -and $vals.Contains($vn)) { $kind = Get-RefKind "$($vals[$vn])"; if (-not $kind) { $kind = Get-NameKind "$($vals[$vn])" } } }
            if ($kind) {
                $pg = $(if ($sub -eq 'ShellNew') { $null } else { $d })
                Add-Item 'shell_new' ([ordered]@{ key = "shellnew|$($e[0])|$($e[2])|$pg".ToLowerInvariant(); scope = $e[0]; ext = $e[2]; progid = $pg
                    values = $vals; last_write = Get-KeyTime $sn; match = $kind })
            }
            $sn.Close()
        }
        $ek.Close()
    }
}

# ---------------------------------------------------------------- default-app claims outside the ProgIDs
Invoke-Section 'default_apps' {
    $progs = $script:AppProgs
    function Get-AssocList($key) {
        @(Get-ValNames $key | Where-Object { $_ } | ForEach-Object { "$_=$(Get-RegVal $key $_)" } | Sort-Object)
    }
    # HKLM\SOFTWARE\RegisteredApplications and SOFTWARE\Clients are shared by both registry views, so a 32-bit
    # row identical to its 64-bit row is the same key seen twice and is left out.
    $seen64 = @{}
    function Test-Shared([string]$sc, [string]$id, [string]$sig) {
        if ($sc -eq 'HKLM64') { $seen64[$id] = $sig; return $false }
        $sc -eq 'HKLM32' -and $seen64.ContainsKey($id) -and $seen64[$id] -eq $sig
    }
    # RegisteredApplications -> Capabilities: what Default Apps offers for this app (FileAssociations, URLAssociations).
    foreach ($sc in 'HKCU', 'HKLM64', 'HKLM32') {
        $ra = Open-Reg $sc 'Software\RegisteredApplications'; if (-not $ra) { continue }
        foreach ($n in Get-ValNames $ra) {
            $cap = "$(Get-RegVal $ra $n)".TrimStart('\'); if (-not $cap) { continue }
            $ck = Open-Reg $sc $cap; $capTime = Get-KeyTime $ck
            $fa = Open-Sub $ck 'FileAssociations'; $faList = @(Get-AssocList $fa); $faTime = Get-KeyTime $fa; if ($fa) { $fa.Close() }
            $uk = Open-Sub $ck 'URLAssociations'; $uaList = @(Get-AssocList $uk); $uaTime = Get-KeyTime $uk; if ($uk) { $uk.Close() }
            $appName = Get-RegVal $ck 'ApplicationName'; $icon = Get-RegVal $ck 'ApplicationIcon'
            if ($ck) { $ck.Close() }
            $kind = Get-NameKind $n; if (-not $kind) { $kind = Get-NameKind "$appName" }
            if (-not $kind) { $kind = Get-RefKind "$appName $icon" -Names }
            if (-not $kind) { foreach ($a in @($faList) + @($uaList)) { $pv = ($a -split '=', 2)[1]; if ($pv -and $progs.ContainsKey($pv.ToLowerInvariant())) { $kind = 'progid'; break } } }
            if (-not $kind) { continue }
            if (Test-Shared $sc "regapp|$n" "$cap|$appName|$icon|$($faList -join ',')|$($uaList -join ',')|$faTime|$uaTime|$capTime") { continue }
            Add-Item 'default_apps' ([ordered]@{ key = "regapp|$sc|$n".ToLowerInvariant(); kind = 'registered_application'; scope = $sc; name = $n
                capabilities = $cap; application_name = $appName; icon = $icon; file_associations = $faList; url_associations = $uaList
                last_write = $capTime; associations_last_write = $faTime; url_associations_last_write = $uaTime; match = $kind })
        }
        $ra.Close()
    }
    # StartMenuInternet: the browser list of Default Apps.
    foreach ($sc in 'HKCU', 'HKLM64', 'HKLM32') {
        $rel = 'Software\Clients\StartMenuInternet'
        $smi = Open-Reg $sc $rel; if (-not $smi) { continue }
        foreach ($n in Get-SubNames $smi) {
            $cmd = Get-SubDefault $sc "$rel\$n\shell\open\command"; $icon = Get-SubDefault $sc "$rel\$n\DefaultIcon"; $label = Get-SubDefault $sc "$rel\$n"
            $kind = Get-RefKind "$cmd $icon" -Names; if (-not $kind) { $kind = Get-NameKind "$n|$label" }
            $lw = Get-KeyTimeAt $sc "$rel\$n"
            if ($kind -and -not (Test-Shared $sc "smi|$n" "$cmd|$icon|$label|$lw")) {
                Add-Item 'default_apps' ([ordered]@{ key = "startmenuinternet|$sc|$n".ToLowerInvariant(); kind = 'start_menu_internet'; scope = $sc; name = $n
                    label = $label; command = (Hide-Secret $cmd); icon = $icon; last_write = $lw; match = $kind })
            }
        }
        $smi.Close()
    }
    # Applications\<exe>: the Open With entry of an exe, with the types it claims.
    foreach ($cr in @(@('HKCU', 'Software\Classes'), @('HKLM64', 'SOFTWARE\Classes'))) {
        $rel = "$($cr[1])\Applications"
        $ak = Open-Reg $cr[0] $rel; if (-not $ak) { continue }
        foreach ($exe in Get-SubNames $ak) {
            $el = $exe.ToLowerInvariant()
            $cmd = Get-SubDefault $cr[0] "$rel\$exe\shell\open\command"
            $kind = Get-RefKind "$cmd" -Names
            if (-not $kind -and $script:SpecificExes.ContainsKey($el)) { $kind = 'name' }
            if (-not $kind) { $kind = Get-NameKind $exe }
            if (-not $kind) { continue }
            $k = Open-Sub $ak $exe; $st = Open-Sub $k 'SupportedTypes'; $types = @(Get-ValNames $st | Sort-Object); if ($st) { $st.Close() }
            Add-Item 'default_apps' ([ordered]@{ key = "application|$($cr[0])|$el".ToLowerInvariant(); kind = 'application'; scope = $cr[0]; exe = $exe
                friendly_name = Get-RegVal $k 'FriendlyAppName'; command = (Hide-Secret $cmd); supported_types = $types
                no_open_with = [bool]($k -and $null -ne $k.GetValue('NoOpenWith', $null)); last_write = Get-KeyTime $k; match = $kind })
            if ($k) { $k.Close() }
        }
        $ak.Close()
    }
    # ApplicationAssociationToasts: '<ProgID>_<type>' marks a handler as already announced, so the
    # "new app can open this" prompt never shows. A vendor pre-writing these hides its takeover.
    # Its entries are values, so each carries the one write time of the whole key.
    $at = Open-Reg 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts'; $atTime = Get-KeyTime $at
    foreach ($n in Get-ValNames $at) {
        $i = $n.LastIndexOf('_'); if ($i -le 0) { continue }
        $pg = $n.Substring(0, $i); $ty = $n.Substring($i + 1); $kind = $null
        if ($progs.ContainsKey($pg.ToLowerInvariant())) { $kind = 'progid' }
        elseif ($pg -match '^Applications\\(.+)$' -and $script:SpecificExes.ContainsKey($Matches[1].ToLowerInvariant())) { $kind = 'name' }
        else { $kind = Get-NameKind $pg }
        if ($kind) {
            Add-Item 'default_apps' ([ordered]@{ key = "assoc_toast|$($n.ToLowerInvariant())"; kind = 'association_toast'; scope = 'HKCU'; name = $n
                progid = $pg; type = $ty; value = Get-RegVal $at $n; last_write = $atTime; match = $kind })
        }
    }
    if ($at) { $at.Close() }
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
            if (-not $kind) { $kind = Get-NameKind "$($f['Name'])"; if (-not $kind) { $kind = Get-NameKind "$($f['Desc'])" } }
            if (-not $kind) { continue }
            # Edge traversal lets unsolicited traffic in through NAT (Teredo); Defer hands that choice to the app or user.
            $edge = $(if ("$($f['Edge'])" -eq 'TRUE') { 'true' } elseif ($f['Defer']) { "defer_$("$($f['Defer'])".ToLowerInvariant())" } else { $null })
            $inPublic = "$($f['Dir'])" -eq 'In' -and "$($f['Action'])" -eq 'Allow' -and "$($f['Active'])" -ne 'FALSE' -and
                (-not $f['Profile'] -or "$($f['Profile'])" -match 'Public')
            Add-Item 'firewall' ([ordered]@{ key = "fw|$($st[0])|$id".ToLowerInvariant(); store = $st[0]; id = $id; name = $f['Name']; action = $f['Action']
                direction = $f['Dir']; active = $f['Active']; app = $f['App']; protocol = $f['Protocol']; profile = $f['Profile']
                remote = $f['RA4']; remote_ports = $f['RPort']; match = $kind; local_ports = $f['LPort']; edge_traversal = $edge
                inbound_allow_public = [bool]$inPublic })
        }
        $k.Close()
    }
}

# ---------------------------------------------------------------- live connections of app processes
$script:DnsRows = $null
function Get-DnsRows {
    if ($null -eq $script:DnsRows) {
        $script:DnsRows = @()
        try { $script:DnsRows = @(Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Data }) }
        catch { Add-Failure 'dns_cache' 'Get-DnsClientCache' $_.Exception.Message }
    }
    ,$script:DnsRows
}
function Test-FakeIp([string]$ip) { $ip -match '^198\.(18|19)\.' }   # 198.18.0.0/15: the usual fake-IP range of TUN-mode proxies
$script:RemoteIps = @{}
$script:AppListenPorts = @{}   # 'tcp|port' / 'udp|port' -> process name, for the upnp and devtools sections
Invoke-Section 'connections' {
    if (-not $script:AppPids.Count) { return }
    $dns = @{}
    foreach ($d in (Get-DnsRows)) { if (-not $dns[$d.Data]) { $dns[$d.Data] = @() }; if ($dns[$d.Data] -notcontains $d.Entry) { $dns[$d.Data] += $d.Entry } }
    $seen = @{}
    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $p = $script:AppPids[[int]$c.OwningProcess]; if (-not $p) { continue }
        $img = $(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })
        $listen = $c.State.ToString() -eq 'Listen'
        $k = $(if ($listen) { "tcp|$img|listen|$($c.LocalAddress):$($c.LocalPort)" } else { "tcp|$img|$($c.RemoteAddress):$($c.RemotePort)" })
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        if (-not $listen -and "$($c.RemoteAddress)" -notmatch '^(0\.0\.0\.0|::|127\.|::1$)') { $script:RemoteIps["$($c.RemoteAddress)"] = $true }
        $co = [ordered]@{ key = $k; proto = 'tcp'; pid = [int]$c.OwningProcess; process = $p.Name; state = $c.State.ToString()
            local = "$($c.LocalAddress):$($c.LocalPort)"; remote = "$($c.RemoteAddress):$($c.RemotePort)"; remote_names = @($dns["$($c.RemoteAddress)"] | Where-Object { $_ }) }
        if ($listen) {
            $co['listen_scope'] = Get-ListenScope "$($c.LocalAddress)"; $script:AppListenPorts["tcp|$($c.LocalPort)"] = $p.Name
            if ($script:DebugPorts.ContainsKey([int]$c.OwningProcess)) { $co['devtools'] = "$($script:DebugPorts[[int]$c.OwningProcess])" -eq "$($c.LocalPort)" }
        }
        Add-Item 'connections' $co
    }
    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $p = $script:AppPids[[int]$u.OwningProcess]; if (-not $p) { continue }
        $img = $(if ($p.ExecutablePath) { $p.ExecutablePath.ToLowerInvariant() } else { $p.Name.ToLowerInvariant() })
        $k = "udp|$img|$($u.LocalAddress):$($u.LocalPort)"; if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        Add-Item 'connections' ([ordered]@{ key = $k; proto = 'udp'; pid = [int]$u.OwningProcess; process = $p.Name; local = "$($u.LocalAddress):$($u.LocalPort)"
            listen_scope = Get-ListenScope "$($u.LocalAddress)" })
        $script:AppListenPorts["udp|$($u.LocalPort)"] = $p.Name
    }
    $wide = @((Get-Items 'connections') | Where-Object { $_ -and $_['listen_scope'] -eq 'all' }).Count
    if ($wide) { $Snap.notes.Add("connections: $wide app sockets listen on all interfaces (listen_scope = all); other machines on the network can reach them unless a firewall rule blocks inbound traffic.") }
    $Snap.notes.Add('connections: a point-in-time view; use Sysmon events 3/22 or repeated snapshots for anything periodic.')
}

# ---------------------------------------------------------------- DNS cache: names behind the remote addresses
Invoke-Section 'dns_cache' {
    # The resolver cache is machine-wide: a name here was looked up by some process, not necessarily the app.
    $rows = Get-DnsRows; $fake = 0; $seen = @{}
    foreach ($d in $rows) {
        $data = "$($d.Data)"
        $m = $null
        if ($script:RemoteIps.ContainsKey($data)) { $m = 'remote' }
        elseif ($script:AppRx -and ($script:AppRx.IsMatch("$($d.Entry)") -or $script:AppRx.IsMatch("$($d.Name)"))) { $m = 'app' }
        if (Test-FakeIp $data) { $fake++ }
        if (-not $m) { continue }
        $k = "dns|$("$($d.Entry)".ToLowerInvariant())|$data"; if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        Add-Item 'dns_cache' ([ordered]@{ key = $k; entry = $d.Entry; record_name = $d.Name; type = "$($d.Type)"; data = $data; match = $m })
    }
    $fakeRemote = @($script:RemoteIps.Keys | Where-Object { Test-FakeIp $_ }).Count
    $Snap.coverage['dns_cache_rows'] = $rows.Count
    $Snap.notes.Add('dns_cache: a proxy in TUN or fake-IP mode hides the real hosts; connections then point at the proxy (often 198.18.0.0/15) and the cache can hold fake addresses. Use the proxy''s own connection log or Sysmon event 22 for real host names.')
    if ($fake -or $fakeRemote) {
        $Snap.notes.Add("dns_cache: $fake cache entries and $fakeRemote remote addresses are in 198.18.0.0/15; a TUN-mode proxy is probably active, so remote addresses here are not the vendor's hosts.")
    }
}

# ---------------------------------------------------------------- toast AUMIDs
Invoke-Section 'toast' {
    $base = Open-Reg 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' 'toast'
    foreach ($n in Get-SubNames $base) {
        # The AUMID of an unpackaged app is often its localized display name, which only the Uninstall name matches.
        $kind = Get-RefKind $n -Names; if (-not $kind) { $kind = Get-NameKind $n }; if (-not $kind) { continue }
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
            $kind = Get-RefKind "$n $dn" -Names; if (-not $kind) { $kind = Get-RefKind "$icon" }; if (-not $kind) { $kind = Get-NameKind "$n|$dn" }
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
    # Taskbar and Start pins live as .lnk files under Quick Launch\User Pinned (TaskBar, StartMenu, ImplicitAppShortcuts).
    $ql = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch'
    $sets = @(@('startup', [Environment]::GetFolderPath('Startup'), $true), @('startup', [Environment]::GetFolderPath('CommonStartup'), $true),
              @('start_menu', [Environment]::GetFolderPath('Programs'), $true), @('start_menu', [Environment]::GetFolderPath('CommonPrograms'), $true),
              @('desktop', [Environment]::GetFolderPath('Desktop'), $false), @('desktop', [Environment]::GetFolderPath('CommonDesktopDirectory'), $false),
              @('sendto', [Environment]::GetFolderPath('SendTo'), $false), @('pinned', (Join-Path $ql 'User Pinned'), $true), @('quick_launch', $ql, $false))
    $byName = 'startup', 'sendto', 'pinned', 'quick_launch'
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
            if (-not $kind -and $byName -contains $s[0]) { $kind = Get-NameKind $f.Name }
            if (-not $kind) { continue }
            Add-Item 'shortcuts' ([ordered]@{ key = "lnk|$($s[0])|$($f.FullName.ToLowerInvariant())"; location = $s[0]; path = $f.FullName; target = $target; arguments = (Hide-Secret $args_); match = $kind })
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
    # Packaged parts of a desktop app (a sparse package for the Windows 11 context menu, a notification or AI
    # package) carry a hashed name such as 1A2B3C4D.Contoso_..., so the manifest's DisplayName and the .msix files
    # bundled under the roots are matched as well as the package name and publisher.
    $useNames = [bool]($script:AppRx -or $script:UninstallNameRx -or $script:PublisherNames.Count)
    if (-not $useNames -and -not $script:BundledPackages.Count -and -not $script:RootPrefixes.Count) { return }
    $families = @()
    $dnRx = New-Object regex('<(?:\w+:)?DisplayName>([^<]*)</', 'IgnoreCase'); $pdnRx = New-Object regex('<(?:\w+:)?PublisherDisplayName>([^<]*)</', 'IgnoreCase')
    foreach ($p in @(Get-AppxPackage -ErrorAction SilentlyContinue)) {
        # AppxPackage property getters are slow, so each is read once.
        $pn = "$($p.Name)"; $loc = "$($p.InstallLocation)"; $fw = [bool]$p.IsFramework
        $kind = $null
        if ($script:AppRx -and $script:AppRx.IsMatch("$pn $($p.Publisher)")) { $kind = 'app' }
        elseif ($loc -and (Test-UnderRoot $loc)) { $kind = 'root' }
        # A bundled framework (VCLibs, .NET Native) is a shared dependency, not the app's own package.
        elseif (-not $fw -and $script:BundledPackages.ContainsKey($pn.ToLowerInvariant())) { $kind = 'bundled_msix' }
        $dn = $null; $pdn = $null; $exts = @(); $x = $null; $text = $null
        $mf = $(if ($loc) { Join-Path $loc 'AppxManifest.xml' } else { $null })
        if ($mf -and ($kind -or ($useNames -and -not $fw))) {
            try { $text = [IO.File]::ReadAllText($mf) } catch { }
            if ($text) {
                $m = $dnRx.Match($text); if ($m.Success) { $dn = [Net.WebUtility]::HtmlDecode($m.Groups[1].Value) }
                $m = $pdnRx.Match($text); if ($m.Success) { $pdn = [Net.WebUtility]::HtmlDecode($m.Groups[1].Value) }
            }
            if (-not $kind) { $kind = Get-NameKind "$dn"; if (-not $kind -and (Test-Publisher "$pdn")) { $kind = 'uninstall_publisher' } }
        }
        if (-not $kind) { continue }
        if ($text) { try { $x = Read-XmlText $text } catch { } }
        if ($x) { $exts = @($x.SelectNodes("//*[local-name()='Extension']") | ForEach-Object { $_.GetAttribute('Category') } | Where-Object { $_ } | Sort-Object -Unique) }
        $families += "$($p.PackageFamilyName)"
        Add-Item 'appx' ([ordered]@{ key = "appx|$pn".ToLowerInvariant(); name = $pn; version = $p.Version.ToString(); publisher = $p.Publisher
            install_location = $p.InstallLocation; display_name = $dn; publisher_display_name = $pdn; family = $p.PackageFamilyName
            signature_kind = "$($p.SignatureKind)"; extensions = $exts; bundled_source = $script:BundledPackages[$pn.ToLowerInvariant()]; match = $kind })
    }
    # Toast settings of those packages are keyed by '<family>!<app id>', which the toast section cannot know.
    $known = @{}; foreach ($t in (Get-Items 'toast')) { if ($t) { $known[$t.key] = $true } }
    $base = Open-Reg 'HKCU' 'Software\Microsoft\Windows\CurrentVersion\Notifications\Settings'
    foreach ($n in Get-SubNames $base) {
        $fam = ($n -split '!', 2)[0]
        if ($families -notcontains $fam) { continue }
        $tk = "toast|settings|$($n.ToLowerInvariant())"; if ($known.ContainsKey($tk)) { continue }
        $k = (Open-Sub $base $n)
        Add-Item 'toast' ([ordered]@{ key = $tk; kind = 'notification_settings'; aumid = $n
            enabled = Get-RegVal $k 'Enabled'; show_in_action_center = Get-RegVal $k 'ShowInActionCenter'; match = 'appx' })
        if ($k) { $k.Close() }
    }
    if ($base) { $base.Close() }
}

# ---------------------------------------------------------------- browsers: native messaging hosts, extensions, policies, profiles
$BrowserDefs = @(
    @{ id = 'chrome'; reg = 'Google\Chrome'; policy = 'Google\Chrome'; data = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
    @{ id = 'edge'; reg = 'Microsoft\Edge'; policy = 'Microsoft\Edge'; data = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
    @{ id = 'chromium'; reg = 'Chromium'; policy = 'Chromium'; data = (Join-Path $env:LOCALAPPDATA 'Chromium\User Data') },
    @{ id = 'brave'; reg = 'BraveSoftware\Brave-Browser'; policy = 'BraveSoftware\Brave'; data = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') },
    @{ id = 'firefox'; reg = 'Mozilla'; policy = 'Mozilla\Firefox'; data = (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles') })
$ExtLocation = @{ 1 = 'internal'; 2 = 'external_pref'; 3 = 'external_registry'; 4 = 'unpacked'; 5 = 'component'; 6 = 'external_pref_download'
    7 = 'external_policy_download'; 8 = 'command_line'; 9 = 'external_policy'; 10 = 'external_component' }
$JsonDict = [Collections.Generic.IDictionary[string, object]]
Invoke-Section 'browser' {
    # Extension ids that belong to the app: bundled .crx/.xpi, origins of the app's native hosts, its registry installs.
    $appIds = @{}; foreach ($id in $script:BundledExtIds.Keys) { $appIds[$id] = 'bundled' }
    function Get-ExtIdKind([string]$id) { if ($id -and $appIds.ContainsKey($id.ToLowerInvariant())) { 'app_id' } }
    # HKCU (and the stray HKCU\Software\WOW6432Node copy some installers write) and both HKLM views.
    $places = @(@('HKCU', 'Software'), @('HKCU', 'Software\WOW6432Node'), @('HKLM64', 'SOFTWARE'), @('HKLM32', 'SOFTWARE'))
    foreach ($b in $BrowserDefs) {
        foreach ($pl in $places) {
            $rel = "$($pl[1])\$($b.reg)\NativeMessagingHosts"
            $base = Open-Reg $pl[0] $rel; if (-not $base) { continue }
            foreach ($n in Get-SubNames $base) {
                $mf = "$(Get-SubDefault $pl[0] "$rel\$n")"; $hostPath = $null; $origins = @(); $desc = $null; $mfOk = $false
                $mfx = $(if ($mf) { [Environment]::ExpandEnvironmentVariables($mf.Trim('"')) } else { $null })
                if ($mfx -and (Test-Path -LiteralPath $mfx -PathType Leaf)) {
                    $mfOk = $true
                    try {
                        $j = Read-JsonFile $mfx 1MB
                        $hostPath = "$(Get-JPath $j @('path'))"
                        if ($hostPath -and -not [IO.Path]::IsPathRooted($hostPath)) { $hostPath = Join-Path (Split-Path $mfx -Parent) $hostPath }
                        foreach ($f in 'allowed_origins', 'allowed_extensions') { $ao = Get-JPath $j @($f); foreach ($x in @($ao)) { if ($x) { $origins += "$x" } } }
                        $desc = Get-JPath $j @('description')
                    } catch { Add-Failure 'browser' $mfx $_.Exception.Message }
                }
                $kind = Get-RefKind "$mf $hostPath" -Names; if (-not $kind) { $kind = Get-NameKind "$n|$desc" }
                if (-not $kind) { continue }
                foreach ($o in $origins) {
                    $id = $(if ($o -match '^chrome-extension://([a-p]{32})') { $Matches[1] } elseif ($o -notmatch '://') { $o.ToLowerInvariant() })
                    if ($id -and -not $appIds.ContainsKey($id)) { $appIds[$id] = "native_host:$n" }
                }
                Add-Item 'browser' ([ordered]@{ key = "nmh|$($b.id)|$($pl[0])|$($pl[1])|$n".ToLowerInvariant(); kind = 'native_host'; browser = $b.id
                    scope = $pl[0]; reg_path = "$rel\$n"; name = $n; manifest = $mf; manifest_exists = $mfOk; host_path = $hostPath
                    host_exists = [bool]($hostPath -and (Test-Path -LiteralPath $hostPath)); allowed_origins = @($origins | Sort-Object); description = $desc
                    last_write = Get-KeyTimeAt $pl[0] "$rel\$n"; match = $kind })
            }
            $base.Close()
        }
    }
    # External extensions in the registry: Chromium <browser>\Extensions\<id> (update_url or path), Firefox values id = path.
    foreach ($b in $BrowserDefs) {
        $sub = $(if ($b.id -eq 'firefox') { 'Mozilla\Firefox\Extensions' } else { "$($b.reg)\Extensions" })
        foreach ($pl in $places) {
            $rel = "$($pl[1])\$sub"; $base = Open-Reg $pl[0] $rel; if (-not $base) { continue }
            $entries = @()
            if ($b.id -eq 'firefox') { foreach ($vn in Get-ValNames $base) { $entries += , @($vn, $null, "$(Get-RegVal $base $vn)", $null) } }
            else {
                foreach ($id in Get-SubNames $base) {
                    $k = Open-Sub $base $id
                    $entries += , @($id, (Hide-Secret "$(Get-RegVal $k 'update_url')"), "$(Get-RegVal $k 'path')", (Get-RegVal $k 'version'))
                    if ($k) { $k.Close() }
                }
            }
            foreach ($en in $entries) {
                $kind = Get-ExtIdKind $en[0]
                if (-not $kind) { $kind = Get-RefKind "$($en[2]) $($en[1])" -Names }
                if (-not $kind) { $kind = Get-NameKind "$($en[1])" }
                if ($kind) { if (-not $appIds.ContainsKey($en[0].ToLowerInvariant())) { $appIds[$en[0].ToLowerInvariant()] = 'registry' } } else { $kind = 'external' }
                Add-Item 'browser' ([ordered]@{ key = "extreg|$($b.id)|$($pl[0])|$($pl[1])|$($en[0])".ToLowerInvariant(); kind = 'external_extension'; browser = $b.id
                    scope = $pl[0]; reg_path = "$rel\$($en[0])"; extension_id = $en[0]; update_url = $en[1]; path = $(if ($en[2]) { $en[2] } else { $null }); version = $en[3]
                    bundled = $script:BundledExtIds[$en[0].ToLowerInvariant()]; last_write = Get-KeyTimeAt $pl[0] $(if ($b.id -eq 'firefox') { $rel } else { "$rel\$($en[0])" }); match = $kind })
            }
            $base.Close()
        }
    }
    # Extension policies. Every entry is listed (match = policy when it is not the app's): a block lever must
    # take a free index, and any force-install entry shows "Managed by your organization" in the browser.
    $seenPol = @{}
    foreach ($b in $BrowserDefs) {
        $lists = $(if ($b.id -eq 'firefox') { 'Extensions\Install', 'Extensions\Uninstall', 'Extensions\Locked' }
            else { 'ExtensionInstallForcelist', 'ExtensionInstallBlocklist', 'ExtensionInstallAllowlist', 'ExtensionInstallBlacklist', 'ExtensionInstallWhitelist' })
        foreach ($sc in 'HKCU', 'HKLM64', 'HKLM32') {
            $rel = "SOFTWARE\Policies\$($b.policy)"
            $pk = Open-Reg $sc $rel; if (-not $pk) { continue }
            foreach ($list in $lists) {
                $lk = Open-Sub $pk $list; if (-not $lk) { continue }
                foreach ($vn in Get-ValNames $lk) {
                    $v = "$(Get-RegVal $lk $vn)"
                    $dk = "$(if ($sc -eq 'HKCU') { 'u' } else { 'm' })|$($b.id)|$list|$vn|$v"; if ($seenPol.ContainsKey($dk)) { continue }; $seenPol[$dk] = $true
                    if ($b.id -eq 'firefox') {
                        # A Firefox list value is one URL or path (Install) or one add-on id (Uninstall, Locked), with no ';'.
                        $t = $v.Trim()
                        if ($t -match '^(\{[0-9A-Fa-f-]{36}\}|[A-Za-z0-9._+-]+@[A-Za-z0-9._-]+)$') { $id = $t; $url = $null }
                        else { $id = $null; $url = $(if ($t) { Hide-Secret $t } else { $null }) }
                    } else { $parts = $v -split ';', 2; $id = $parts[0].Trim(); $url = $(if ($parts.Count -gt 1) { Hide-Secret $parts[1].Trim() } else { $null }) }
                    $kind = Get-ExtIdKind $id; if (-not $kind) { $kind = Get-RefKind "$v" -Names }; if (-not $kind) { $kind = 'policy' }
                    Add-Item 'browser' ([ordered]@{ key = "policy|$($b.id)|$sc|$list|$vn".ToLowerInvariant(); kind = 'policy_list'; browser = $b.id; scope = $sc
                        list = $list; index = $vn; extension_id = $id; update_url = $url; match = $kind })
                }
                $lk.Close()
            }
            # ExtensionSettings: one JSON string value, or a subkey with one JSON value per id ('*' included).
            # Firefox's ADMX writes the value as REG_MULTI_SZ, which comes back as one string per line.
            $jsons = @(); $es = Get-RegVal $pk 'ExtensionSettings'; if ($es -is [array]) { $es = $es -join "`n" }; if ($es -is [string]) { $jsons += , @('(value)', $es) }
            $esk = Open-Sub $pk 'ExtensionSettings'
            foreach ($vn in Get-ValNames $esk) { $ev = Get-RegVal $esk $vn; if ($ev -is [array]) { $ev = $ev -join "`n" }; $jsons += , @($vn, "$ev") }; if ($esk) { $esk.Close() }
            foreach ($js in $jsons) {
                $j = $null; try { $j = Read-JsonText $js[1] } catch { Add-Failure 'browser' "$sc\$rel\ExtensionSettings" $_.Exception.Message; continue }
                $map = $(if ($js[0] -eq '(value)') { $j } else { $d = New-Object 'Collections.Generic.Dictionary[string,object]'; $d[$js[0]] = $j; $d })
                if ($map -isnot $JsonDict) { continue }
                foreach ($id in @($map.Keys)) {
                    $e = $map[$id]
                    $dk = "$(if ($sc -eq 'HKCU') { 'u' } else { 'm' })|$($b.id)|ExtensionSettings|$id"; if ($seenPol.ContainsKey($dk)) { continue }; $seenPol[$dk] = $true
                    $url = "$(Get-JPath $e @('update_url'))"; if (-not $url) { $url = "$(Get-JPath $e @('install_url'))" }
                    $kind = Get-ExtIdKind $id; if (-not $kind) { $kind = Get-RefKind $url -Names }; if (-not $kind) { $kind = 'policy' }
                    Add-Item 'browser' ([ordered]@{ key = "policy|$($b.id)|$sc|extensionsettings|$id".ToLowerInvariant(); kind = 'policy_settings'; browser = $b.id; scope = $sc
                        list = 'ExtensionSettings'; extension_id = $id; installation_mode = "$(Get-JPath $e @('installation_mode'))"; update_url = $(if ($url) { Hide-Secret $url } else { $null }); match = $kind })
                }
            }
            $pk.Close()
        }
    }
    # Profiles. Chromium keeps each extension's install location in Secure Preferences or Preferences
    # (extensions.settings); one that is not from the store, not a component, or loaded from a path outside
    # the profile was side-loaded. A folder under Extensions with no settings entry is listed as unlisted.
    foreach ($b in $BrowserDefs) {
        if ($b.id -eq 'firefox' -or -not (Test-Path -LiteralPath $b.data -PathType Container)) { continue }
        foreach ($pd in @([IO.Directory]::GetDirectories($b.data))) {
            if (-not (Test-Path -LiteralPath (Join-Path $pd 'Preferences') -PathType Leaf)) { continue }
            $prof = Split-Path $pd -Leaf; $settings = @{}
            foreach ($fn in 'Secure Preferences', 'Preferences') {
                $f = Join-Path $pd $fn; if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
                try {
                    $es = Get-JPath (Read-JsonFile $f 64MB) @('extensions', 'settings')
                    if ($es -is $JsonDict) { foreach ($id in $es.Keys) { if (-not $settings.ContainsKey($id)) { $settings[$id] = $es[$id] } } }
                } catch { Add-Failure 'browser' $f $_.Exception.Message }
            }
            $extDir = Join-Path $pd 'Extensions'; $folderIds = @()
            if (Test-Path -LiteralPath $extDir -PathType Container) { $folderIds = @([IO.Directory]::GetDirectories($extDir) | ForEach-Object { Split-Path $_ -Leaf } | Where-Object { $_ -match '^[a-p]{32}$' }) }
            # Read for every profile (one key): skipping it when no app id is known made every item a false "not in MACs".
            $macs = @{}
            $mk = Open-Reg 'HKCU' "Software\$($b.reg)\PreferenceMACs\$prof\extensions.settings"; foreach ($vn in Get-ValNames $mk) { $macs[$vn] = $true }; if ($mk) { $mk.Close() }
            foreach ($id in @(@($settings.Keys) + $folderIds | Sort-Object -Unique)) {
                $s = $settings[$id]; $locN = $null; $path = $null; $fromStore = $null; $dr = $null; $name = $null; $byDefault = $false
                if ($s -is $JsonDict) {
                    try { $l = Get-JPath $s @('location'); if ($null -ne $l) { $locN = [int]$l } } catch { }
                    $path = "$(Get-JPath $s @('path'))"; $fromStore = Get-JPath $s @('from_webstore'); $dr = Get-JPath $s @('disable_reasons'); $name = Get-JPath $s @('manifest', 'name')
                    $byDefault = (Get-JPath $s @('was_installed_by_default')) -eq $true
                }
                $abs = [bool]($path -and [IO.Path]::IsPathRooted($path))
                $kind = Get-ExtIdKind $id
                if (-not $kind -and $abs) { $kind = Get-RefKind $path -Names }
                # Component extensions (5, 10) live in the browser's own folder and default apps come with the browser.
                if (-not $kind -and $locN -notin 5, 10 -and -not $byDefault) {
                    if ($null -eq $s) { $kind = 'unlisted' }
                    elseif ($null -ne $locN -and $locN -ne 1) { $kind = 'external' }
                    elseif ($abs -and -not $path.StartsWith($pd, [StringComparison]::OrdinalIgnoreCase)) { $kind = 'external' }
                }
                if (-not $kind) { continue }
                if (-not $name) {
                    $vd = $(if ($abs) { $path } else { Join-Path $extDir $id })
                    $mfp = $null
                    if (Test-Path -LiteralPath (Join-Path $vd 'manifest.json')) { $mfp = Join-Path $vd 'manifest.json' }
                    elseif (Test-Path -LiteralPath $vd -PathType Container) {
                        $last = @([IO.Directory]::GetDirectories($vd) | Sort-Object)[-1]; if ($last) { $mfp = Join-Path $last 'manifest.json' }
                    }
                    if ($mfp -and (Test-Path -LiteralPath $mfp -PathType Leaf)) { try { $name = Get-JPath (Read-JsonFile $mfp 2MB) @('name') } catch { } }
                }
                Add-Item 'browser' ([ordered]@{ key = "profile_ext|$($b.id)|$($prof.ToLowerInvariant())|$id"; kind = 'profile_extension'; browser = $b.id; profile = $prof
                    extension_id = $id; name = $(if ($name) { "$name" } else { $null }); location = $(if ($null -ne $locN) { $ExtLocation[$locN] } else { $null }); location_code = $locN
                    from_webstore = $fromStore; path = $(if ($abs) { $path } else { $null }); in_settings = $null -ne $s; in_folder = $folderIds -contains $id
                    disable_reasons = $dr; in_preference_macs = $macs.ContainsKey($id); bundled = $script:BundledExtIds[$id]; match = $kind })
            }
        }
    }
    # Firefox: extensions.json per profile; location winreg-app-* means installed through the registry.
    $ffd = ($BrowserDefs | Where-Object { $_.id -eq 'firefox' }).data
    if (Test-Path -LiteralPath $ffd -PathType Container) {
        foreach ($pd in @([IO.Directory]::GetDirectories($ffd))) {
            $ej = Join-Path $pd 'extensions.json'; if (-not (Test-Path -LiteralPath $ej -PathType Leaf)) { continue }
            $addons = $null; try { $addons = Get-JPath (Read-JsonFile $ej 64MB) @('addons') } catch { Add-Failure 'browser' $ej $_.Exception.Message; continue }
            foreach ($a in @($addons)) {
                if ($a -isnot $JsonDict) { continue }
                $id = "$(Get-JPath $a @('id'))"; $loc = "$(Get-JPath $a @('location'))"; $path = "$(Get-JPath $a @('path'))"
                $kind = Get-ExtIdKind $id; if (-not $kind -and $path) { $kind = Get-RefKind $path -Names }
                if (-not $kind -and $loc -notin 'app-profile', 'app-builtin', 'app-builtin-addons', 'app-system-defaults', 'app-system-addons') { $kind = 'external' }
                if (-not $kind) { continue }
                Add-Item 'browser' ([ordered]@{ key = "profile_ext|firefox|$((Split-Path $pd -Leaf).ToLowerInvariant())|$($id.ToLowerInvariant())"; kind = 'profile_extension'
                    browser = 'firefox'; profile = (Split-Path $pd -Leaf); extension_id = $id; name = "$(Get-JPath $a @('defaultLocale', 'name'))"; location = $loc
                    path = $(if ($path) { $path } else { $null }); active = Get-JPath $a @('active'); bundled = $script:BundledExtIds[$id.ToLowerInvariant()]; match = $kind })
            }
        }
    }
    $Snap['app_extension_ids'] = [ordered]@{}; foreach ($k in @($appIds.Keys | Sort-Object)) { $Snap['app_extension_ids'][$k] = $appIds[$k] }
}

# ---------------------------------------------------------------- Office and WPS add-ins
function Get-Utf16Strings([byte[]]$b) {
    # Readable UTF-16 runs in a binary value (Resiliency\DisabledItems holds the add-in path that way).
    if (-not $b -or $b.Length -lt 8) { return $null }
    $t = [Text.Encoding]::Unicode.GetString($b, 0, $b.Length - ($b.Length % 2))
    $bad = [string][char]0xFFFD   # what undecodable bytes become
    (@([regex]::Split($t, ('[\x00-\x1F' + $bad + ']+')) | Where-Object { $_.Length -ge 4 }) -join ' | ')
}
Invoke-Section 'office_addins' {
    function Get-ProgIdClsid([string]$progid) {
        foreach ($p in @(@('HKCU', "Software\Classes\$progid\CLSID"), @('HKLM64', "SOFTWARE\Classes\$progid\CLSID"), @('HKLM32', "SOFTWARE\Classes\$progid\CLSID"))) {
            $v = Get-SubDefault $p[0] $p[1]; if ($v) { return "$v".Trim().ToUpperInvariant() }
        }
        $null
    }
    $appProgIds = @{}
    # Registered add-ins: Office\<app>\Addins\<ProgID> (COM and VSTO; Manifest is the .vsto path for VSTO).
    foreach ($pl in @(@('HKCU', 'Software\Microsoft\Office'), @('HKCU', 'Software\WOW6432Node\Microsoft\Office'), @('HKLM64', 'SOFTWARE\Microsoft\Office'), @('HKLM32', 'SOFTWARE\Microsoft\Office'))) {
        $ok = Open-Reg $pl[0] $pl[1]; if (-not $ok) { continue }
        foreach ($app in Get-SubNames $ok) {
            $ak = Open-Sub $ok "$app\Addins"; if (-not $ak) { continue }
            foreach ($pg in Get-SubNames $ak) {
                $k = Open-Sub $ak $pg; if (-not $k) { continue }
                $fn = Get-RegVal $k 'FriendlyName'; $ds = Get-RegVal $k 'Description'; $mf = "$(Get-RegVal $k 'Manifest')"
                $clsid = Get-ProgIdClsid $pg
                $kind = Get-RefKind $mf -Names; if (-not $kind) { $kind = Get-NameKind "$pg|$fn|$ds" }
                if (-not $kind -and $clsid -and $script:AppClsids.ContainsKey($clsid)) { $kind = 'clsid' }
                if ($kind) {
                    $appProgIds[$pg.ToLowerInvariant()] = $true
                    Add-Item 'office_addins' ([ordered]@{ key = "addin|$($pl[0])|$($pl[1])|$app|$pg".ToLowerInvariant(); kind = 'addin'; scope = $pl[0]
                        reg_path = "$($pl[1])\$app\Addins\$pg"; office_app = $app; progid = $pg; friendly_name = $fn; description = $ds
                        load_behavior = Get-RegVal $k 'LoadBehavior'; manifest = (Hide-Secret $mf); clsid = $clsid; last_write = Get-KeyTime $k; match = $kind })
                }
                $k.Close()
            }
            $ak.Close()
        }
        $ok.Close()
    }
    # Resiliency lists and the AddinList policy. Every policy or allow-list entry is kept (the AddinList lever
    # writes there); DisabledItems and CrashingAddinList entries only when they name the app. Excel also loads
    # the files named by Options\OPEN, OPEN1 ... at startup.
    foreach ($pl in @(@('HKCU', 'Software\Microsoft\Office'), @('HKCU', 'Software\Policies\Microsoft\Office'), @('HKLM64', 'SOFTWARE\Policies\Microsoft\Office'), @('HKLM32', 'SOFTWARE\Policies\Microsoft\Office'))) {
        $isPolicy = $pl[1] -like '*Policies*'
        $ok = Open-Reg $pl[0] $pl[1]; if (-not $ok) { continue }
        foreach ($ver in @(Get-SubNames $ok | Where-Object { $_ -match '^\d+\.\d$' })) {
            $vk = Open-Sub $ok $ver; if (-not $vk) { continue }
            foreach ($app in Get-SubNames $vk) {
                foreach ($list in 'AddinList', 'DoNotDisableAddinList', 'DisabledItems', 'CrashingAddinList') {
                    $lk = Open-Sub $vk "$app\Resiliency\$list"; if (-not $lk) { continue }
                    foreach ($vn in Get-ValNames $lk) {
                        $raw = $null; try { $raw = $lk.GetValue($vn) } catch { }
                        $val = $(if ($raw -is [byte[]]) { Get-Utf16Strings $raw } else { "$raw" })
                        $kind = $(if ($appProgIds.ContainsKey($vn.ToLowerInvariant())) { 'progid' })
                        if (-not $kind) { $kind = Get-NameKind $vn }; if (-not $kind) { $kind = Get-RefKind "$val" -Names }; if (-not $kind) { $kind = Get-NameKind "$val" }
                        if (-not $kind) { if ($list -in 'DisabledItems', 'CrashingAddinList') { continue }; $kind = $(if ($isPolicy) { 'policy' } else { 'list' }) }
                        Add-Item 'office_addins' ([ordered]@{ key = "resiliency|$($pl[0])|$($pl[1])|$ver|$app|$list|$vn".ToLowerInvariant(); kind = 'resiliency'
                            scope = $pl[0]; policy = $isPolicy; office_version = $ver; office_app = $app; list = $list; name = $vn; value = (Hide-Secret $val); match = $kind })
                    }
                    $lk.Close()
                }
            }
            if (-not $isPolicy) {
                $xo = Open-Sub $vk 'Excel\Options'
                foreach ($vn in @(Get-ValNames $xo | Where-Object { $_ -match '^OPEN\d*$' })) {
                    $v = "$(Get-RegVal $xo $vn)"; $kind = Get-RefKind $v -Names; if (-not $kind) { $kind = Get-NameKind $v }
                    if ($kind) { Add-Item 'office_addins' ([ordered]@{ key = "excel_open|$($pl[0])|$ver|$vn".ToLowerInvariant(); kind = 'excel_open'; scope = $pl[0]; office_version = $ver; name = $vn; value = (Hide-Secret $v); match = $kind }) }
                }
                if ($xo) { $xo.Close() }
            }
            $vk.Close()
        }
        $ok.Close()
    }
    # Startup folders: a template or add-in file there loads into Word or Excel at start. Listed when its name
    # matches the app; the total per folder is in coverage.office_startup_files.
    $startupCounts = [ordered]@{}
    foreach ($sf in @(@('word_startup', (Join-Path $env:APPDATA 'Microsoft\Word\STARTUP')), @('excel_xlstart', (Join-Path $env:APPDATA 'Microsoft\Excel\XLSTART')))) {
        if (-not (Test-Path -LiteralPath $sf[1] -PathType Container)) { continue }
        $sfFiles = @(Get-ChildItem -LiteralPath $sf[1] -File -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.Name.StartsWith('~$') })   # ~$ files are Office lock files
        $startupCounts[$sf[0]] = $sfFiles.Count
        foreach ($f in $sfFiles) {
            $kind = Get-NameKind $f.Name; if (-not $kind) { continue }
            Add-Item 'office_addins' ([ordered]@{ key = "startup_file|$($f.FullName.ToLowerInvariant())"; kind = 'startup_file'; folder = $sf[0]; path = $f.FullName; size = $f.Length; match = $kind })
        }
    }
    $Snap.coverage['office_startup_files'] = $startupCounts
    # WPS Office: add-in registrations sit under keys named Addins, AddinsWL, ComAddins or JsAddons below
    # Software\Kingsoft\Office (layout differs by version, so the tree is walked, at most 4 levels and 3000 keys).
    foreach ($pl in @(@('HKCU', 'Software\Kingsoft\Office'), @('HKLM64', 'SOFTWARE\Kingsoft\Office'), @('HKLM32', 'SOFTWARE\Kingsoft\Office'))) {
        $q = New-Object System.Collections.Generic.Queue[object]; $q.Enqueue(@($pl[1], 0)); $visited = 0
        while ($q.Count -and $visited -lt 3000) {
            $cur = $q.Dequeue(); $visited++
            $ck = Open-Reg $pl[0] $cur[0]; if (-not $ck) { continue }
            if ((Split-Path $cur[0] -Leaf) -match '^(com)?add-?ins?(wl)?$|^jsaddons?$') {
                foreach ($sub in Get-SubNames $ck) {
                    $sk = Open-Sub $ck $sub; $vals = [ordered]@{}; foreach ($vn in Get-ValNames $sk) { $v = Get-RegVal $sk $vn; if ($v -is [string]) { $v = Hide-Secret $v }; $vals[$vn] = $v }
                    $clsid = Get-ProgIdClsid $sub
                    $kind = Get-RefKind "$($vals.Values -join ' ')" -Names; if (-not $kind) { $kind = Get-NameKind "$sub|$($vals.Values -join '|')" }
                    if (-not $kind -and $clsid -and $script:AppClsids.ContainsKey($clsid)) { $kind = 'clsid' }
                    if ($kind) { Add-Item 'office_addins' ([ordered]@{ key = "wps|$($pl[0])|$($cur[0])|$sub".ToLowerInvariant(); kind = 'wps_addin'; scope = $pl[0]; reg_path = "$($cur[0])\$sub"; name = $sub; values = $vals; clsid = $clsid; match = $kind }) }
                    if ($sk) { $sk.Close() }
                }
                foreach ($vn in Get-ValNames $ck) {
                    $v = "$(Get-RegVal $ck $vn)"; $kind = Get-NameKind $vn; if (-not $kind) { $kind = Get-RefKind $v -Names }
                    if (-not $kind) { $c2 = Get-ProgIdClsid $vn; if ($c2 -and $script:AppClsids.ContainsKey($c2)) { $kind = 'clsid' } }
                    if ($kind) { Add-Item 'office_addins' ([ordered]@{ key = "wps|$($pl[0])|$($cur[0])|=$vn".ToLowerInvariant(); kind = 'wps_addin_value'; scope = $pl[0]; reg_path = $cur[0]; name = $vn; value = (Hide-Secret $v); match = $kind }) }
                }
            } elseif ($cur[1] -lt 4) { foreach ($sub in Get-SubNames $ck) { $q.Enqueue(@("$($cur[0])\$sub", $cur[1] + 1)) } }
            $ck.Close()
        }
    }
}

# ---------------------------------------------------------------- Explorer namespace (This PC, navigation pane, desktop)
Invoke-Section 'shell_namespace' {
    $exp = 'Software\Microsoft\Windows\CurrentVersion\Explorer'
    $containers = 'MyComputer\NameSpace', 'Desktop\NameSpace', 'MyComputer\NameSpace\DelegateFolders', 'Desktop\NameSpace\DelegateFolders', 'ControlPanel\NameSpace', 'NetworkNeighborhood\NameSpace'
    function Get-ClsidInfo([string]$view, [string]$id) {
        # A shell32-hosted folder (Instance\CLSID plus InitPropertyBag) has no server in the app root, so the com
        # section cannot see it; its icon and TargetFolderPath still point at the app.
        $paths = @(@('HKCU', "Software\Classes\CLSID\$id"))
        if ($view -eq '32') { $paths += , @('HKCU', "Software\Classes\WOW6432Node\CLSID\$id"); $paths += , @('HKLM32', "SOFTWARE\Classes\CLSID\$id") }
        else { $paths += , @('HKLM64', "SOFTWARE\Classes\CLSID\$id") }
        foreach ($p in $paths) {
            $k = Open-Reg $p[0] $p[1]; if (-not $k) { continue }
            try {
                $ik = Open-Sub $k 'Instance'; $inst = Get-RegVal $ik 'CLSID'; if ($ik) { $ik.Close() }
                $pb = Open-Sub $k 'Instance\InitPropertyBag'; $tgt = Get-RegVal $pb 'TargetFolderPath'; $tkf = Get-RegVal $pb 'TargetKnownFolder'; if ($pb) { $pb.Close() }
                return [ordered]@{ source = $p[0]; name = Get-RegVal $k ''; inproc = Get-SubDefault $p[0] "$($p[1])\InprocServer32"; icon = Get-SubDefault $p[0] "$($p[1])\DefaultIcon"
                    instance_clsid = $inst; target = $tgt; target_known_folder = $tkf; pinned = Get-RegVal $k 'System.IsPinnedToNameSpaceTree'; last_write = Get-KeyTime $k }
            } finally { $k.Close() }
        }
        $null
    }
    $sysRoot = $env:SystemRoot.ToLowerInvariant() + '\'
    function Get-NsKind([string]$id, $info, [string]$label) {
        if ($script:AppClsids.ContainsKey($id)) { return 'clsid' }
        if ($info) {
            # Windows' own hosts and icon libraries (shell32.dll, imageres.dll) say nothing about the owner.
            $refs = @("$($info.inproc)", "$($info.icon)", "$($info.target)" | Where-Object { $_ -and -not (Expand-Ref $_).StartsWith($sysRoot) })
            $k = Get-RefKind ($refs -join ' ') -Names; if ($k) { return $k }
            if ($info.target -and (Test-UnderRoot "$($info.target)")) { return 'root' }
            $k = Get-NameKind "$($info.name)"; if ($k) { return $k }
        }
        Get-NameKind $label
    }
    $linked = @{}; $appIds = @{}
    foreach ($sc in 'HKCU', 'HKLM64', 'HKLM32') {
        $view = $(if ($sc -eq 'HKLM32') { '32' } else { '64' })
        foreach ($c in $containers) {
            $base = Open-Reg $sc "$exp\$c"; if (-not $base) { continue }
            foreach ($id in Get-SubNames $base) {
                if ($id -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
                $u = $id.ToUpperInvariant(); if (-not $linked[$u]) { $linked[$u] = @() }; $linked[$u] += "$sc\$c"
                $label = Get-SubDefault $sc "$exp\$c\$id"; $info = Get-ClsidInfo $view $u
                $kind = Get-NsKind $u $info "$label"; if (-not $kind) { continue }
                $appIds[$u] = $true
                Add-Item 'shell_namespace' ([ordered]@{ key = "ns_link|$sc|$c|$u".ToLowerInvariant(); kind = 'link'; scope = $sc; container = $c; clsid = $u; label = $label
                    registered = [bool]$info; clsid_source = $info.source; name = $info.name; inproc = $info.inproc; icon = $info.icon; target_folder = $info.target
                    pinned_to_tree = $info.pinned; last_write = Get-KeyTimeAt $sc "$exp\$c\$id"; match = $kind })
            }
            $base.Close()
        }
    }
    # Per-user CLSIDs that are pinned to the navigation pane or point a folder at the app, linked or not.
    foreach ($p in @(@('HKCU', 'Software\Classes\CLSID', '64'), @('HKCU', 'Software\Classes\WOW6432Node\CLSID', '32'))) {
        $base = Open-Reg $p[0] $p[1]; if (-not $base) { continue }
        foreach ($id in Get-SubNames $base) {
            $k = Open-Sub $base $id; if (-not $k) { continue }
            $pinned = Get-RegVal $k 'System.IsPinnedToNameSpaceTree'
            $pb = Open-Sub $k 'Instance\InitPropertyBag'; $tgt = Get-RegVal $pb 'TargetFolderPath'; if ($pb) { $pb.Close() }
            $k.Close()
            if ($null -eq $pinned -and -not $tgt) { continue }
            $u = $id.ToUpperInvariant(); $info = Get-ClsidInfo $p[2] $u
            $kind = Get-NsKind $u $info ''; if (-not $kind) { continue }
            $appIds[$u] = $true
            Add-Item 'shell_namespace' ([ordered]@{ key = "ns_clsid|$($p[1])|$u".ToLowerInvariant(); kind = 'clsid'; scope = 'HKCU'; view = $p[2]; clsid = $u; name = $info.name
                state = $(if ($linked[$u]) { 'linked' } else { 'registered_only' }); linked_in = @($linked[$u] | Where-Object { $_ }); pinned_to_tree = $pinned
                target_folder = $tgt; icon = $info.icon; inproc = $info.inproc; instance_clsid = $info.instance_clsid; last_write = $info.last_write; match = $kind })
        }
        $base.Close()
    }
    # HideDesktopIcons: whether those CLSIDs show on the desktop (0 shown, 1 hidden).
    foreach ($sc in 'HKCU', 'HKLM64') {
        foreach ($panel in 'NewStartPanel', 'ClassicStartMenu') {
            $hk = Open-Reg $sc "$exp\HideDesktopIcons\$panel"
            foreach ($vn in Get-ValNames $hk) {
                if (-not $appIds.ContainsKey($vn.ToUpperInvariant())) { continue }
                Add-Item 'shell_namespace' ([ordered]@{ key = "ns_hide|$sc|$panel|$($vn.ToUpperInvariant())".ToLowerInvariant(); kind = 'hide_desktop_icon'; scope = $sc
                    panel = $panel; clsid = $vn.ToUpperInvariant(); hidden = Get-RegVal $hk $vn })
            }
            if ($hk) { $hk.Close() }
        }
    }
}

# ---------------------------------------------------------------- UPnP port mappings on the gateway (read-only)
Invoke-Section 'upnp' {
    # SSDP discovery of the gateway, then its static port-mapping list; a P2P engine (BitTorrent, PCDN) opens
    # inbound ports this way. Run in its own STA runspace and waited on for at most 20 s.
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'STA'; $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        $col = (New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection
        if ($null -eq $col) { return 'no-gateway' }
        foreach ($m in $col) { [pscustomobject]@{ ext = $m.ExternalPort; proto = "$($m.Protocol)"; int = $m.InternalPort; client = "$($m.InternalClient)"; enabled = $m.Enabled; desc = "$($m.Description)" } }
    })
    $h = $ps.BeginInvoke()
    if (-not $h.AsyncWaitHandle.WaitOne(20000)) { $Snap.coverage['upnp_gateway'] = 'timeout'; $Snap.notes.Add('upnp: the gateway did not answer within 20 s; mappings not read.'); return }
    $res = @()
    try { $res = @($ps.EndInvoke($h)) } catch { Add-Failure 'upnp' 'HNetCfg.NATUPnP' $_.Exception.Message; return } finally { $ps.Dispose(); $rs.Dispose() }
    if ($res.Count -eq 1 -and "$($res[0])" -eq 'no-gateway') { $Snap.coverage['upnp_gateway'] = 'none'; return }
    $local = @{}; try { foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)) { $local["$($a.IPAddress)"] = $true } } catch { }
    $mine = 0
    foreach ($m in $res) {
        if (-not $local.ContainsKey("$($m.client)")) { continue }   # another device on the network
        $mine++
        $kind = Get-NameKind "$($m.desc)"
        if (-not $kind -and $script:AppListenPorts.ContainsKey("$("$($m.proto)".ToLowerInvariant())|$($m.int)")) { $kind = 'port' }
        if (-not $kind) { $kind = 'local' }
        Add-Item 'upnp' ([ordered]@{ key = "upnp|$("$($m.proto)".ToLowerInvariant())|$($m.ext)"; protocol = $m.proto; external_port = $m.ext; internal_port = $m.int
            internal_client = $m.client; enabled = $m.enabled; description = $m.desc; match = $kind })
    }
    $Snap.coverage['upnp_gateway'] = [ordered]@{ found = $true; mappings = $res.Count; to_this_machine = $mine }
}

# ---------------------------------------------------------------- DevToolsActivePort files under the roots
Invoke-Section 'devtools' {
    # A Chromium or CEF runtime started with --remote-debugging-port writes this file into its profile; while the
    # port listens, any local process can drive the embedded browser.
    $listeners = $null
    foreach ($f in $script:DevToolsFiles) {
        $port = $null; $listen = $null; $owner = $null
        try { $first = ((ConvertFrom-Bytes (Get-FileBytes $f.e.FullName 64KB)) -split "`r?`n")[0].Trim(); if ($first -match '^\d{1,5}$') { $port = [int]$first } } catch { }
        if ($port) {
            if ($null -eq $listeners) { $listeners = @{}; foreach ($ep in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()) { $listeners[$ep.Port] = $true } }
            $listen = $listeners.ContainsKey($port)
            if ($listen) {
                $l = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
                if ($l.Count) { $op = [int]$l[0].OwningProcess; $owner = $(if ($script:AppPids.ContainsKey($op)) { $script:AppPids[$op].Name } else { try { (Get-Process -Id $op -ErrorAction Stop).ProcessName } catch { "pid $op" } }) }
            }
        }
        Add-Item 'devtools' ([ordered]@{ key = "devtools|$($f.e.FullName.ToLowerInvariant())"; kind = 'active_port_file'; path = $f.e.FullName; root = $f.root; rel = $f.rel
            port = $port; mtime = $f.e.LastWriteTimeUtc.ToString('o'); listening = $listen; listener = $owner })
    }
}

# ---------------------------------------------------------------- sensor consent (location, microphone, webcam)
Invoke-Section 'consent_store' {
    # Windows records every unpackaged exe that used a sensor under ConsentStore\<capability>\NonPackaged, with
    # its path ('#' for '\') and the last start and stop of use. There is no per-app switch for these apps.
    $rel = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
    $global = [ordered]@{}
    foreach ($sc in 'HKCU', 'HKLM64') {
        foreach ($cap in 'location', 'microphone', 'webcam') {
            $np = Open-Reg $sc "$rel\$cap\NonPackaged"; if (-not $np) { continue }
            $global["$sc|$cap"] = Get-RegVal $np 'Value'
            foreach ($sub in Get-SubNames $np) {
                $path = $sub.Replace('#', '\')
                $kind = $(if (Test-UnderRoot $path) { 'root' } else { Get-RefKind $path -Names }); if (-not $kind) { continue }
                $k = Open-Sub $np $sub
                Add-Item 'consent_store' ([ordered]@{ key = "consent|$sc|$cap|$($path.ToLowerInvariant())"; scope = $sc; capability = $cap; path = $path
                    value = Get-RegVal $k 'Value'; last_used_start = ConvertFrom-FileTime (Get-RegVal $k 'LastUsedTimeStart')
                    last_used_stop = ConvertFrom-FileTime (Get-RegVal $k 'LastUsedTimeStop'); match = $kind })
                if ($k) { $k.Close() }
            }
            $np.Close()
        }
    }
    $Snap.coverage['consent_nonpackaged_switch'] = $global
}

# ---------------------------------------------------------------- plain settings files under the roots (read-only)
$SettingTermRx = New-Object regex(('autorun|autostart|autolaunch|autoboot|selfstart|startup|rightmenu|contextmenu|shellmenu|default(reader|player|app|browser|viewer|pdf)|' +
    'addin|plugin|extension|improve|telemetry|report|advert|popup|tray|background|exit|close|p2p|pcdn|upload|share|clipboard|mycomputer|namespace|' +
    'update|upgrade|notif|float|recommend|promot|upnp|torrent|magnet|urischeme|protocol|assoc|widget|deskbar|toolbar|hotkey|startmenu|desktopicon|' +
    'shortcut|crash|feedback|statistic|analytic|tracking|privacy'), 'IgnoreCase')
# Whole words after camelCase and snake_case are split ('showAdv', 'is_ad'), so 'address' or 'download' do not match.
$SettingWordRx = New-Object regex('(?<![A-Za-z0-9])(ad|ads|adv|ai|bt|dht|push|boot|promo)(?![A-Za-z0-9])', 'IgnoreCase')
# UI layout and package manifest XML (skins, windows, menus, AppxManifest, .vsto) is not settings.
$UiXmlPathRx = New-Object regex('\\(skins?|themes?|layouts?|styles?|xaml)\\', 'IgnoreCase')
$UiXmlRootRx = New-Object regex('(Wnd|Window|Dialog|Dlg|Layout|Skin|Theme|Menu)$|^(assembly|Package|Bundle|svg|Project|ResourceDictionary|Strings?|Resources?)$', 'IgnoreCase')
$VolatileWordRx = New-Object regex('(?<![A-Za-z0-9])(time|timestamp|date|ts|stamp|count|counts|counter|times|last|expire|expires|expiry|ttl|nonce|salt|seed|seq)(?![A-Za-z0-9])', 'IgnoreCase')
# Object keys that are URLs, paths or site patterns hold per-site data, not switches (Chromium zoom levels, content settings).
$UrlKeyRx = New-Object regex('://|^[A-Za-z]:[\\/]|^\[\*\.\]|,|[\\/]|^(file|https?|chrome-extension):', 'IgnoreCase')
# String tables and translations (crashrpt_lang.ini, strings.json, zh-CN.json ...) hold UI text, not switches.
$LangFileRx = New-Object regex('(^|[_.-])(lang|language|locale|i18n|l10n)([_.-]|$)|(locali[sz]|strings?|translations?|messages)([_.-]|$)|^[a-z]{2}([_-][A-Za-z]{2,4})?\.(json|ini|xml)$', 'IgnoreCase')
# Folders named after a culture (de, zh-CN, sr-Latn-RS ...) hold one translated copy each.
$CultureDirs = @{}; foreach ($c in [Globalization.CultureInfo]::GetCultures([Globalization.CultureTypes]::AllCultures)) { if ($c.Name) { $CultureDirs[$c.Name.ToLowerInvariant()] = $true } }
function Test-CultureDir([string]$rel) {
    $parts = $rel.ToLowerInvariant().Split('\'); for ($i = 0; $i -lt $parts.Count - 1; $i++) { if ($CultureDirs.ContainsKey($parts[$i])) { return $true } }
    $CultureDirs.ContainsKey([IO.Path]::GetFileNameWithoutExtension($parts[-1]))   # strings\de.json, sr-Latn-RS.json
}
$ProfileRx = $(if ($KeepPaths) { $null } else { New-Object regex(([regex]::Escape($env:USERPROFILE.TrimEnd('\')) -replace '\\\\', '(?:\\|/|~1)'), 'IgnoreCase') })
function Hide-Profile([string]$s) { if ($ProfileRx -and $s) { return $ProfileRx.Replace($s, '%USERPROFILE%') }; $s }
$SecretKeyRx = New-Object regex('token|stoken|bduss|session|password|passwd|secret|cookie|auth|credential|api_?key|private_?key|signature', 'IgnoreCase')
$SettingsSkipRx = New-Object regex(('\\(node_modules|_locales|locales?|i18n|lang|languages|strings|Cache|Code Cache|GPUCache|DawnCache|DawnGraphiteCache|DawnWebGPUCache|' +
    'GrShaderCache|ShaderCache|IndexedDB|Local Storage|Session Storage|Service Worker|blob_storage|WebStorage|Crashpad|crx_cache|component_crx_cache|' +
    'extensions_crx_cache|Dictionaries|optimization_guide_model_store|Safe Browsing|segmentation_platform|WidevineCdm)\\|\\Extensions\\[a-p]{32}\\'), 'IgnoreCase')
# The per-key walk runs compiled: a PowerShell loop over every element of a few hundred files takes tens of seconds.
Add-Type -ReferencedAssemblies 'System', 'System.Xml' -TypeDefinition @'
using System; using System.Collections.Generic; using System.Globalization; using System.Text;
using System.Text.RegularExpressions; using System.Xml;
public static class AdSet {
    static Regex Term, Word, Vol, UrlKey;
    static readonly Regex Camel = new Regex("([a-z0-9])([A-Z])");
    static readonly Regex NonAlnum = new Regex("[^A-Za-z0-9]");
    // 'date' at the end means a timestamp, except in 'update' (AutoUpdate, silent_update are switches).
    static readonly Regex VolEnd = new Regex("(time|stamp|(?<!up)date)$|^last", RegexOptions.IgnoreCase);
    static readonly Regex Switchy = new Regex("^(enabled?|disabled?|on|off|show|visible|switch|state|mode|status|allowed|active)$", RegexOptions.IgnoreCase);
    static readonly Regex IdKey = new Regex("^[A-Za-z0-9+=_-]+$");
    public static void Init(Regex term, Regex word, Regex vol, Regex urlKey) { Term = term; Word = word; Vol = vol; UrlKey = urlKey; }
    public static bool SettingName(string n) {
        if (string.IsNullOrEmpty(n)) return false;
        return Term.IsMatch(NonAlnum.Replace(n, "")) || Word.IsMatch(Camel.Replace(n, "$1 $2"));
    }
    public static bool VolatileName(string n) {
        if (string.IsNullOrEmpty(n)) return false;
        return Vol.IsMatch(Camel.Replace(n, "$1 $2")) || VolEnd.IsMatch(n);
    }
    public class Hit { public string Name; public string Leaf; public object Value; public string Section; public string Key; }
    static double Ent(string s) {
        var c = new Dictionary<char, int>(); foreach (char ch in s) { int v; c.TryGetValue(ch, out v); c[ch] = v + 1; }
        double e = 0; foreach (int x in c.Values) { double p = (double)x / s.Length; e -= p * Math.Log(p, 2); } return e;
    }
    // An id or hash used as an object key (per-site cohorts, profile hashes): data, not a switch.
    static bool IdLike(string k) {
        if (k.Length < 16 || !IdKey.IsMatch(k)) return false;
        bool digit = false; foreach (char ch in k) if (char.IsDigit(ch)) { digit = true; break; }
        return digit && Ent(k) >= 3.5;
    }
    public static List<Hit> JsonHits(object root, bool leafOnly, int max, out bool capped) {
        var hits = new List<Hit>(); bool cap = false; WalkJson(root, "", "", "", leafOnly, max, hits, ref cap, 0); capped = cap; return hits;
    }
    static void WalkJson(object node, string ptr, string leaf, string parent, bool leafOnly, int max, List<Hit> hits, ref bool capped, int depth) {
        if (hits.Count >= max) { capped = true; return; }
        var d = node as IDictionary<string, object>;
        if (d != null) {
            if (depth > 12) return;
            foreach (var kv in d) {
                string k = kv.Key, p = ptr + "/" + k.Replace("~", "~0").Replace("/", "~1");
                if (p == "/extensions/settings" || p.StartsWith("/profile/content_settings") || p.StartsWith("/protection/macs") || UrlKey.IsMatch(k) || IdLike(k)) continue;
                // Runtime state the browser rewrites on every launch, exit and crash: not a setting, and noise in every diff.
                if (leafOnly && (p == "/profile/exit_type" || p == "/profile/exited_cleanly" || p == "/user_experience_metrics/stability" || p.StartsWith("/user_experience_metrics/stability/", StringComparison.Ordinal)
                    || p.StartsWith("/variations_", StringComparison.Ordinal))) continue;
                WalkJson(kv.Value, p, k, leaf, leafOnly, max, hits, ref capped, depth + 1);
                if (capped) return;
            }
            return;
        }
        // In a browser's own Local State and Preferences a matching parent counts only for a plain switch name.
        if (!(SettingName(leaf) || ((!leafOnly || Switchy.IsMatch(leaf)) && SettingName(parent)))) return;
        if (VolatileName(leaf)) return;
        object v = node; var arr = node as object[];
        if (arr != null) {
            bool scalar = true; foreach (var x in arr) if (x is IDictionary<string, object> || x is object[]) { scalar = false; break; }
            if (scalar) {
                var sb = new StringBuilder("[");
                for (int i = 0; i < arr.Length && i < 10; i++) { if (i > 0) sb.Append(", "); sb.Append(Convert.ToString(arr[i], CultureInfo.InvariantCulture)); }
                if (arr.Length > 10) sb.Append(", ..."); v = sb.Append("]").ToString();
            } else v = "[" + arr.Length + " items]";
        }
        hits.Add(new Hit { Name = ptr, Leaf = leaf, Value = v });
    }
    // <add key="X" value="Y"/>, <setting name="X" value="Y"/>, <item name="X">Y</item>, the .NET user.config form
    // <setting name="X"><value>Y</value></setting>, switch-named attributes and text-only elements.
    // Path step of an element: its local name, plus [n] (1-based) when its parent has several children of that name.
    static string Seg(XmlNode n, Dictionary<XmlNode, string> segs) {
        string s; if (segs.TryGetValue(n, out s)) return s;
        XmlNode p = n.ParentNode;
        if (p == null || p.NodeType != XmlNodeType.Element) { segs[n] = n.LocalName; return n.LocalName; }
        var count = new Dictionary<string, int>(); var idx = new Dictionary<string, int>();
        foreach (XmlNode c in p.ChildNodes) if (c.NodeType == XmlNodeType.Element) { int v; count.TryGetValue(c.LocalName, out v); count[c.LocalName] = v + 1; }
        foreach (XmlNode c in p.ChildNodes) {
            if (c.NodeType != XmlNodeType.Element) continue;
            if (count[c.LocalName] > 1) { int v; idx.TryGetValue(c.LocalName, out v); idx[c.LocalName] = ++v; segs[c] = c.LocalName + "[" + v + "]"; }
            else segs[c] = c.LocalName;
        }
        return segs[n];
    }
    public static List<Hit> XmlHits(XmlDocument doc, int maxEl, int max, out bool capped) {
        var hits = new List<Hit>(); capped = false; int seen = 0; var segs = new Dictionary<XmlNode, string>();
        foreach (XmlNode node in doc.SelectNodes("//*")) {
            var el = node as XmlElement; if (el == null) continue;
            if (hits.Count >= max || ++seen > maxEl) { capped = true; break; }
            // Repeated elements get a sibling index so their keys stay distinct. The [@key='X'] form names the
            // element by its key, so there the element's own step has no index (inserting a sibling moves no key).
            string ppath = ""; XmlNode n = el.ParentNode; int dd = 1;
            while (n != null && n.NodeType == XmlNodeType.Element && dd < 12) { ppath = "/" + Seg(n, segs) + ppath; n = n.ParentNode; dd++; }
            string epath = ppath + "/" + Seg(el, segs);
            string pname = (el.ParentNode != null && el.ParentNode.NodeType == XmlNodeType.Element) ? el.ParentNode.LocalName : null;
            string kn = el.HasAttribute("key") ? el.GetAttribute("key") : (el.HasAttribute("name") ? el.GetAttribute("name") : null);
            bool textOnly = el.ChildNodes.Count == 1 && el.FirstChild.NodeType == XmlNodeType.Text;
            XmlNode valueChild = (el.ChildNodes.Count == 1 && el.FirstChild.NodeType == XmlNodeType.Element && el.FirstChild.LocalName == "value") ? el.FirstChild : null;
            if (!string.IsNullOrEmpty(kn) && (el.HasAttribute("value") || valueChild != null || !el.HasChildNodes || textOnly)) {
                if ((SettingName(kn) || SettingName(el.LocalName)) && !VolatileName(kn)) {
                    string v = el.HasAttribute("value") ? el.GetAttribute("value") : (valueChild != null ? valueChild.InnerText : el.InnerText);
                    hits.Add(new Hit { Name = ppath + "/" + el.LocalName + "[@" + (el.HasAttribute("key") ? "key" : "name") + "='" + kn + "']", Leaf = kn, Value = v });
                }
                continue;
            }
            foreach (XmlAttribute at in el.Attributes) {
                if (at.Name.StartsWith("xmlns")) continue;
                if ((SettingName(at.LocalName) || SettingName(el.LocalName)) && !VolatileName(at.LocalName)) hits.Add(new Hit { Name = epath + "/@" + at.LocalName, Leaf = at.LocalName, Value = at.Value });
            }
            if (textOnly && (SettingName(el.LocalName) || SettingName(pname)) && !VolatileName(el.LocalName)) hits.Add(new Hit { Name = epath, Leaf = el.LocalName, Value = el.InnerText });
        }
        if (hits.Count > max) { hits.RemoveRange(max, hits.Count - max); capped = true; }
        return hits;
    }
    static string SectionOf(string t) { return (t.Length > 2 && t[0] == '[' && t[t.Length - 1] == ']') ? t.Substring(1, t.Length - 2).Trim() : null; }
    public static List<Hit> IniHits(string text, int max, out bool capped) {
        var hits = new List<Hit>(); capped = false; string sec = "", tag = "";
        string[] lines = text.Split('\n');
        // A section that appears more than once gets its occurrence number in the key name, so its keys stay distinct.
        var count = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase); var occ = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (string ln in lines) { string s = SectionOf(ln.Trim()); if (s != null) { int c; count.TryGetValue(s, out c); count[s] = c + 1; } }
        foreach (string ln in lines) {
            string t = ln.Trim(); if (t.Length == 0 || t[0] == ';' || t[0] == '#') continue;
            string st = SectionOf(t);
            if (st != null) { sec = st; tag = st; if (count[st] > 1) { int c; occ.TryGetValue(st, out c); occ[st] = ++c; tag = st + "[" + c + "]"; } continue; }
            int i = t.IndexOf('='); if (i <= 0) continue;
            string k = t.Substring(0, i).Trim(), v = t.Substring(i + 1).Trim();
            if ((SettingName(k) || SettingName(sec)) && !VolatileName(k)) {
                if (hits.Count >= max) { capped = true; break; }
                hits.Add(new Hit { Name = tag + "/" + k, Leaf = k, Value = v, Section = sec, Key = k });
            }
        }
        return hits;
    }
}
'@
[AdSet]::Init($SettingTermRx, $SettingWordRx, $VolatileWordRx, $UrlKeyRx)
function Test-EpochNumber([double]$d) {
    # Unix seconds or milliseconds, Chromium microseconds since 1601, FILETIME ticks: a timestamp, not a switch.
    ($d -ge 1e9 -and $d -lt 1e10) -or ($d -ge 1e12 -and $d -lt 1e13) -or ($d -ge 1.1e16 -and $d -lt 1.5e16) -or ($d -ge 1.1e17 -and $d -lt 1.5e17)
}
function Format-SettingValue([string]$name, $v) {
    if ($null -eq $v -or $v -is [bool]) { return $v }
    $isNum = $v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [double]
    # A number under a credential-like name (a numeric PIN or uin) is redacted like a string; 0 and 1 are switches.
    if ($SecretKeyRx.IsMatch($name) -and "$v" -notmatch '^(true|false|0|1|on|off|yes|no|)$') { return '<redacted>' }
    if ($isNum) {
        if (Test-EpochNumber ([double]$v)) { return '<epoch>' }
        return $v
    }
    $s = "$v"
    if ($s -match '^\d{10,18}$' -and (Test-EpochNumber ([double]$s))) { return '<epoch>' }
    $s = Hide-Secret $s
    # A URL is an endpoint the levers need, not an opaque token; Hide-Secret already redacted ?token= style values.
    if ($s.Length -ge 20 -and $s -notmatch '^[a-z][a-z0-9+.-]*://' -and $s -match '^[A-Za-z0-9+/=_.:-]+$' -and $s -notmatch '^[\d.]+$' -and [AdInv]::StrEntropy($s) -ge 3.5) { return "<opaque len=$($s.Length)>" }
    if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + "...(+$($s.Length - 300))" }
    $s
}
Invoke-Section 'settings' {
    # Keys whose name looks like a switch (autorun, context menu, default reader, add-in, plugin, extension,
    # telemetry, report, ad, popup, tray, background, exit or close, P2P, upload, share, clipboard, This PC,
    # update ...) in INI, JSON (Local State and Preferences too) and XML files. Values are what the file holds
    # now; timestamps and counters are skipped. Encrypted or packed files are listed as opaque, SQLite stores
    # as sqlite (not opened). String tables, translations, UI layouts and browser internals are skipped.
    # Caps: 800 files, 200 keys per file, 4000 keys in all, 10 s.
    $maxFiles = 800; $perFile = 200; $maxKeys = 4000
    # Inside an embedded Chromium or CEF user-data folder (the one holding Local State) only Local State, Preferences
    # and Secure Preferences are settings; component downloads (<Component>\<version>\...), the profiles' other
    # files and the browser's SQLite stores are browser state. Vendor files directly in that folder are kept.
    $chromeRoots = @($script:SettingsFiles | Where-Object { $_.e.Name -eq 'Local State' } | ForEach-Object { $_.e.DirectoryName.ToLowerInvariant() + '\' })
    $profileDirs = @($script:SettingsFiles | Where-Object { $_.e.Name -eq 'Preferences' } | ForEach-Object { $_.e.DirectoryName.ToLowerInvariant() + '\' })
    function Test-BrowserState($f) {
        if ($SettingsNames -contains $f.e.Name.ToLowerInvariant()) { return $false }
        $full = $f.e.FullName.ToLowerInvariant()
        foreach ($p in $profileDirs) { if ($full.StartsWith($p)) { return $true } }
        foreach ($r in $chromeRoots) {
            if (-not $full.StartsWith($r)) { continue }
            $rest = $full.Substring($r.Length)
            if ($rest -match '^[^\\]+\\\d+(\.\d+)+\\' -or $f.e.Extension -in '.db', '.sqlite', '.sqlite3', '.db3') { return $true }
        }
        $false
    }
    # XML over 512 KB is data (catalogs, lens tables, update file lists), not settings.
    $files = @($script:SettingsFiles | Where-Object { -not $SettingsSkipRx.IsMatch('\' + $_.rel) -and -not $LangFileRx.IsMatch($_.e.Name) -and -not (Test-CultureDir $_.rel) -and
        -not ($_.e.Extension -in '.xml', '.config' -and ($_.e.Length -gt 512KB -or $UiXmlPathRx.IsMatch('\' + $_.rel))) -and -not (Test-BrowserState $_) } |
        Sort-Object @{ Expression = { ($_.rel.Split('\')).Count } }, @{ Expression = { $_.rel.ToLowerInvariant() } })
    if ($files.Count -gt $maxFiles) { $Snap.notes.Add("settings: $($files.Count) candidate files, only the $maxFiles nearest the roots were read.") ; $files = $files[0..($maxFiles - 1)] }
    $script:SetCount = 0; $cappedFiles = 0
    function Add-Setting($f, [string]$format, [string]$name, $value, [hashtable]$extra) {
        if ($script:SetCount -ge $maxKeys) { return $false }
        $name = Hide-Profile $name; if ($value -is [string]) { $value = Hide-Profile $value }
        $o = [ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|$($name.ToLowerInvariant())"; kind = 'key'; file = $f.e.FullName; root = $f.root; rel = $f.rel
            format = $format; name = $name; value = $value }
        if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
        Add-Item 'settings' $o; $script:SetCount++; $true
    }
    $budget = [Diagnostics.Stopwatch]::StartNew(); $done = 0
    foreach ($f in $files) {
        # Time budget: files nearest the roots come first, so a stop here drops the deep ones.
        if ($budget.ElapsedMilliseconds -gt 10000) { $Snap.notes.Add("settings: stopped at the 10 s budget after $done of $($files.Count) files (nearest the roots first); the deeper ones were not read."); break }
        $done++
        $ext = $f.e.Extension.ToLowerInvariant(); $b = $null; $limit = 5MB
        try {
            # A store needs only its 16-byte SQLite header and 4 KB for the entropy test, not the whole file.
            $isDb = $ext -in '.db', '.sqlite', '.sqlite3', '.db3'
            if ($isDb) { $b = Get-FileHead $f.e.FullName 4096 } else { $b = Get-FileBytes $f.e.FullName $limit }
        } catch {
            if ("$($_.Exception.Message)" -match 'larger than') { Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'skipped'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length; reason = "larger than $($limit / 1MB) MB" }) }
            else { Add-Failure 'settings' $f.e.FullName $_.Exception.Message }
            continue
        }
        if ($isDb) {
            if ($b.Length -ge 16 -and [Text.Encoding]::ASCII.GetString($b, 0, 15) -eq 'SQLite format 3') {
                Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'sqlite'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length })
            } elseif ($b.Length -ge 64 -and [AdInv]::Entropy($b, 4096) -gt 7.2) {
                Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'opaque'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length; reason = 'high entropy' })
            }
            continue
        }
        if ($b.Length -eq 0) { continue }
        $ent = [AdInv]::Entropy($b, 4096)
        $utf16 = $b.Length -ge 2 -and (($b[0] -eq 0xFF -and $b[1] -eq 0xFE) -or ($b[0] -eq 0xFE -and $b[1] -eq 0xFF) -or ($b.Length -ge 4 -and $b[1] -eq 0 -and $b[3] -eq 0))
        if ($ent -gt 7.2 -or (-not $utf16 -and [Array]::IndexOf($b, [byte]0) -ge 0 -and [Array]::IndexOf($b, [byte]0) -lt [Math]::Min($b.Length, 4096))) {
            Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'opaque'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length
                reason = $(if ($ent -gt 7.2) { 'high entropy (encrypted or packed)' } else { 'binary' }) })
            continue
        }
        $text = ConvertFrom-Bytes $b
        $fmt = $(if ($ext -eq '.json' -or $ext -eq '') { 'json' } elseif ($ext -in '.xml', '.config') { 'xml' } else { 'ini' })
        $capped = $false; $hits = $null
        if ($fmt -eq 'json') {
            $j = $null; try { $j = Read-JsonText $text } catch {
                Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'opaque'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length; reason = 'unparseable json' })
                continue
            }
            $hits = [AdSet]::JsonHits($j, ($SettingsNames -contains $f.e.Name.ToLowerInvariant()), $perFile, [ref]$capped)
        } elseif ($fmt -eq 'xml') {
            $x = $null; try { $x = Read-XmlText $text } catch {
                Add-Item 'settings' ([ordered]@{ key = "setting|$($f.e.FullName.ToLowerInvariant())|(file)"; kind = 'opaque'; path = $f.e.FullName; root = $f.root; rel = $f.rel; size = $f.e.Length; reason = 'unparseable xml' })
                continue
            }
            if (-not $x -or -not $x.DocumentElement -or $UiXmlRootRx.IsMatch($x.DocumentElement.LocalName)) { continue }
            $hits = [AdSet]::XmlHits($x, 3000, $perFile, [ref]$capped)
        } else {
            $hits = [AdSet]::IniHits($text, $perFile, [ref]$capped)
        }
        foreach ($h in $hits) {
            $extra = $(if ($fmt -eq 'ini') { @{ section = $h.Section; ini_key = $h.Key } } else { $null })
            [void](Add-Setting $f $fmt $h.Name (Format-SettingValue $h.Leaf $h.Value) $extra)
        }
        if ($capped) { $cappedFiles++ }
    }
    if ($cappedFiles) { $Snap.notes.Add("settings: $cappedFiles files had more than $perFile matching keys; only the first $perFile of each are listed.") }
    if ($script:SetCount -ge $maxKeys) { $Snap.notes.Add("settings: stopped at $maxKeys keys in all.") }
    $Snap.coverage['settings_files'] = $files.Count
}

# ---------------------------------------------------------------- optional Sysinternals autorunsc
Invoke-Section 'autoruns' {
    # Same lookup as setup_re_backend.ps1 -Doctor: per name, PATH first, then the Sysinternals folder it installs.
    $names = $(if ([Environment]::Is64BitOperatingSystem) { 'autorunsc64.exe', 'autorunsc.exe' } else { 'autorunsc.exe' })
    $dirs = @((Join-Path $env:LOCALAPPDATA 'Programs\Sysinternals'))
    $exePath = $null
    if ($AutorunsPath) {
        if (Test-Path -LiteralPath $AutorunsPath -PathType Leaf) { $exePath = (Resolve-Path -LiteralPath $AutorunsPath).ProviderPath }
        elseif (Test-Path -LiteralPath $AutorunsPath -PathType Container) { $dirs = @((Resolve-Path -LiteralPath $AutorunsPath).ProviderPath) }
        else { Add-Failure 'autoruns' $AutorunsPath '-AutorunsPath does not exist'; return }
    }
    if (-not $exePath) {
        foreach ($n in $names) {
            if (-not $AutorunsPath) {
                $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($c) { $exePath = $c.Source; break }
            }
            foreach ($d in $dirs) { $f = Join-Path $d $n; if (Test-Path -LiteralPath $f -PathType Leaf) { $exePath = $f; break } }
            if ($exePath) { break }
        }
    }
    if (-not $exePath) { $Snap.notes.Add('autoruns: autorunsc not found on PATH, in %LOCALAPPDATA%\Programs\Sysinternals or via -AutorunsPath; native queries only. setup_re_backend.ps1 -Install -Component sysinternals installs it.'); return }
    $sig = Get-AuthenticodeSignature -LiteralPath $exePath
    if ($sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'Microsoft Corporation') {
        Add-Failure 'autoruns' $exePath "not run: signature $($sig.Status), signer '$($sig.SignerCertificate.Subject)'"; return
    }
    $exe = [pscustomobject]@{ Source = $exePath }
    $Snap.coverage['autoruns_exe'] = $exePath
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
function Repair-EmptyKeys($node, [int]$depth) {
    # Windows PowerShell 5.1 ConvertFrom-Json rejects an empty property name ("Invalid object passed in"),
    # e.g. a registry default value or an extensionless file count, so every empty key becomes "(none)".
    if ($null -eq $node -or $depth -gt 24 -or $node -is [string]) { return }
    if ($node -is [Collections.IDictionary]) {
        foreach ($k in @($node.Keys | Where-Object { [string]::IsNullOrEmpty([string]$_) })) { $v = $node[$k]; $node.Remove($k); $node['(none)'] = $v }
        foreach ($k in @($node.Keys)) { Repair-EmptyKeys $node[$k] ($depth + 1) }
    } elseif ($node -is [Collections.IEnumerable]) {
        foreach ($x in $node) { Repair-EmptyKeys $x ($depth + 1) }
    }
}
Repair-EmptyKeys $Snap 0
$json = $Snap | ConvertTo-Json -Depth 12
if (-not $KeepPaths) {
    $esc = $env:USERPROFILE.TrimEnd('\').Replace('\', '\\')
    $json = [regex]::Replace($json, [regex]::Escape($esc), '%USERPROFILE%', 'IgnoreCase')
}
[IO.File]::WriteAllText($outFull, $json, (New-Object Text.UTF8Encoding($false)))
$total = 0; foreach ($c in $Snap.items.Keys) { $total += $Snap.items[$c].Count }
Write-Host ("inventory: {0} roots, {1} items in {2} categories, {3} access failures -> {4}" -f $Snap.roots.Count, $total, $Snap.items.Count, $Snap.access_failures.Count, $outFull)
foreach ($c in $Snap.items.Keys) { Write-Host ("  {0,-16} {1}" -f $c, $Snap.items[$c].Count) }
