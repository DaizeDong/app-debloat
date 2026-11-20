#Requires -Version 5.1
<#
.SYNOPSIS
  Report or set up the reverse-engineering backends app-debloat uses (REA + Ghidra, fallbacks, frida, Sysinternals).

.DESCRIPTION
  -Doctor (default) is read-only: it reports which backends are usable and which tier the
  pipeline should run on (A = REA + Ghidra, B = ReVa / pyghidra-mcp, C = pefile + capstone + LIEF).
  -Install is an explicit opt-in. It installs only into a user-writable root
  (default %LOCALAPPDATA%\Programs), verifies every download against a published SHA-256 or an
  Authenticode signature, never touches Program Files, services, tasks or the firewall, and never
  installs Sysmon as a service (it prints that command instead).
  Pins: rea-agents 6.9.0, Ghidra 12.1.4, Temurin JDK 21, Node.js 22 LTS (>= 22.23.4).

.PARAMETER Install
  Install the pieces named by -Component.

.PARAMETER Component
  Any of: node, rea, jdk, ghidra, pymods, sysinternals. Default: rea, jdk, ghidra.

.PARAMETER Root
  Install root. Must be under %LOCALAPPDATA% or %USERPROFILE%.

.PARAMETER RegisterMcp
  With -Install: register REA with Claude Code (claude mcp add) at -McpScope (user or local, never project).

.PARAMETER JdkViaWinget
  Use winget (Temurin 21, --scope user) instead of the verified Adoptium zip. The MSI may still ask for elevation.

.PARAMETER Json
  Emit the doctor report as JSON.

.EXAMPLE
  .\setup_re_backend.ps1                          # doctor
  .\setup_re_backend.ps1 -Json > re-doctor.json
  .\setup_re_backend.ps1 -Install -Component node,rea,jdk,ghidra -RegisterMcp
#>
[CmdletBinding()]
param(
    [switch]$Doctor,
    [switch]$Install,
    [ValidateSet('node', 'rea', 'jdk', 'ghidra', 'pymods', 'sysinternals')]
    [string[]]$Component = @('rea', 'jdk', 'ghidra'),
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'Programs'),
    [switch]$RegisterMcp,
    [ValidateSet('user', 'local')][string]$McpScope = 'user',
    [switch]$JdkViaWinget,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Pin = @{
    ReaVersion    = '6.9.0'
    ReaRepo       = 'github.com/morluto/rea'
    NodeMin22     = [version]'22.23.4'
    GhidraVersion = '12.1.4'
    GhidraZip     = 'ghidra_12.1.4_PUBLIC_20260921.zip'
    GhidraUrl     = 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'
    GhidraSha256  = 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
    JdkMajor      = 21
    PyModules     = @('pefile', 'capstone', 'lief', 'frida', 'frida_tools', 'procmon_parser')
}

# ---------- helpers ----------
function Invoke-Native {
    # Runs a native command, returns @{Code; Out}; stderr is merged and never throws under EAP=Stop.
    param([string]$Exe, [string[]]$Arguments)
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
        return @{ Code = $LASTEXITCODE; Out = ($out -join "`n") }
    } catch {
        return @{ Code = -1; Out = "$_" }
    } finally { $ErrorActionPreference = $old }
}

function Find-Exe {
    param([string[]]$Names, [string[]]$ExtraDirs = @())
    foreach ($n in $Names) {
        $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
        foreach ($d in $ExtraDirs) {
            if ($d -and (Test-Path -LiteralPath (Join-Path $d $n))) { return (Join-Path $d $n) }
        }
    }
    return $null
}

function Get-UserEnv([string]$Name) {
    $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not $v) { $v = [Environment]::GetEnvironmentVariable($Name, 'User') }
    return $v
}

function Assert-UserRoot([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Install root is empty.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed = @($env:LOCALAPPDATA, $env:USERPROFILE) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
    $deny = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot, $env:ProgramData) | Where-Object { $_ }
    foreach ($d in $deny) { if ($full -like "$d*") { throw "Refusing install root under $d : $full" } }
    if ($full.Length -le 3) { throw "Refusing drive root: $full" }
    foreach ($a in $allowed) { if ($full -ne $a -and $full -like "$a\*") { return $full } }
    throw "Install root must be a subfolder of %LOCALAPPDATA% or %USERPROFILE%: $full"
}

function Get-Download {
    param([string]$Url, [string]$OutFile)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (Test-Path -LiteralPath $curl) {
        $r = Invoke-Native $curl @('-fsSL', '--retry', '3', '-o', $OutFile, $Url)
        if ($r.Code -ne 0) { throw "Download failed ($($r.Code)): $Url`n$($r.Out)" }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    }
}

function Assert-Sha256([string]$File, [string]$Expected) {
    $h = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $Expected.ToLowerInvariant()) { throw "SHA-256 mismatch for $File`n expected $Expected`n actual   $h" }
    Write-Host "  sha256 ok  $h"
}

function Expand-Zip([string]$Zip, [string]$Dest) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($Zip, $Dest)
}

function Get-JavaInfo([string]$JavaExe) {
    if (-not $JavaExe -or -not (Test-Path -LiteralPath $JavaExe)) { return $null }
    $r = Invoke-Native $JavaExe @('-version')
    $m = [regex]::Match($r.Out, 'version "(\d+)(?:\.(\d+))?[^"]*"')
    if (-not $m.Success) { return @{ Exe = $JavaExe; Major = 0; Raw = $r.Out } }
    $major = [int]$m.Groups[1].Value
    if ($major -eq 1) { $major = [int]$m.Groups[2].Value }
    return @{ Exe = $JavaExe; Major = $major; Raw = ($r.Out -split "`n")[0] }
}

function Find-Jdk21 {
    $cands = @()
    foreach ($v in @((Get-UserEnv 'APP_DEBLOAT_JAVA_HOME'), (Get-UserEnv 'JAVA_HOME'))) { if ($v) { $cands += $v } }
    foreach ($base in @($Root, (Join-Path $env:ProgramFiles 'Eclipse Adoptium'), (Join-Path $env:ProgramFiles 'Microsoft'), (Join-Path $env:ProgramFiles 'Java'))) {
        if (Test-Path -LiteralPath $base) {
            $cands += Get-ChildItem -LiteralPath $base -Directory -Filter 'jdk-21*' -ErrorAction SilentlyContinue | ForEach-Object FullName
        }
    }
    foreach ($c in $cands) {
        $j = Get-JavaInfo (Join-Path $c 'bin\java.exe')
        if ($j -and $j.Major -ge $Pin.JdkMajor -and (Test-Path -LiteralPath (Join-Path $c 'bin\javac.exe'))) { return @{ Home = $c; Info = $j } }
    }
    return $null
}

function Get-GhidraInfo([string]$Dir) {
    if (-not $Dir) { return $null }
    $props = Join-Path $Dir 'Ghidra\application.properties'
    if (-not (Test-Path -LiteralPath $props)) { return $null }
    $kv = @{}
    Get-Content -LiteralPath $props | ForEach-Object { if ($_ -match '^\s*([\w.]+)\s*=\s*(.*)$') { $kv[$Matches[1]] = $Matches[2].Trim() } }
    return @{
        Dir        = $Dir
        Version    = $kv['application.version']
        JavaMin    = $kv['application.java.min']
        Headless   = Test-Path -LiteralPath (Join-Path $Dir 'support\analyzeHeadless.bat')
        Decompiler = Test-Path -LiteralPath (Join-Path $Dir 'Ghidra\Features\Decompiler\os\win_x86_64\decompile.exe')
    }
}

function Find-Ghidra {
    $g = Get-GhidraInfo (Get-UserEnv 'GHIDRA_INSTALL_DIR')
    if ($g) { $g['Source'] = 'GHIDRA_INSTALL_DIR'; return $g }
    if (Test-Path -LiteralPath $Root) {
        foreach ($d in (Get-ChildItem -LiteralPath $Root -Directory -Filter 'ghidra_*_PUBLIC' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $g = Get-GhidraInfo $d.FullName
            if ($g) { $g['Source'] = 'scan'; return $g }
        }
    }
    return $null
}

function Test-NodeForRea([version]$v) {
    if ($v.Major -eq 22) { return $v -ge $Pin.NodeMin22 }
    if ($v.Major -eq 24) { return $v -ge [version]'24.22.1' }
    if ($v.Major -eq 26) { return $v -ge [version]'26.12.1' }
    return $v.Major -gt 26
}

function Find-Node {
    $dirs = @()
    $p = Get-UserEnv 'APP_DEBLOAT_NODE'
    if ($p) { $dirs += (Split-Path -Parent $p) }
    if (Test-Path -LiteralPath $Root) { $dirs += Get-ChildItem -LiteralPath $Root -Directory -Filter 'node-v*-win-x64' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | ForEach-Object FullName }
    $exe = Find-Exe @('node.exe') $dirs
    if ($p -and (Test-Path -LiteralPath $p)) { $exe = $p }
    if (-not $exe) { return $null }
    $r = Invoke-Native $exe @('--version')
    $v = [version]($r.Out.Trim().TrimStart('v'))
    return @{ Exe = $exe; Version = $v; ReaOk = (Test-NodeForRea $v) }
}

function Find-Rea {
    $mjs = Get-UserEnv 'APP_DEBLOAT_REA'
    if (-not $mjs) { $mjs = Join-Path $Root 'rea\node_modules\rea-agents\scripts\rea.mjs' }
    if (Test-Path -LiteralPath $mjs) {
        $pkg = Get-Content -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $mjs)) 'package.json') -Raw | ConvertFrom-Json
        return @{ Mjs = $mjs; Version = $pkg.version; Repo = "$($pkg.repository.url)"; Kind = 'managed' }
    }
    $cmd = Find-Exe @('rea.cmd', 'rea.ps1', 'rea')
    if ($cmd) { return @{ Mjs = $null; Cmd = $cmd; Version = '?'; Repo = '?'; Kind = 'PATH' } }
    return $null
}

# ---------- doctor ----------
$Report = New-Object System.Collections.Generic.List[object]
function Add-Row([string]$Area, [string]$Item, [string]$Status, [string]$Detail) {
    $Report.Add([pscustomobject]@{ area = $Area; item = $Item; status = $Status; detail = $Detail })
}

function Invoke-Doctor {
    $node = Find-Node
    if ($node) {
        $st = 'ok'; if (-not $node.ReaOk) { $st = 'warn' }
        Add-Row 'runtime' 'node' $st "$($node.Version) at $($node.Exe); REA needs 22.x>=22.23.4, 24.x>=24.22.1 or 26.12.1+"
        $npm = Find-Exe @('npm.cmd') @((Split-Path -Parent $node.Exe))
        if ($npm) { Add-Row 'runtime' 'npm' 'ok' (Invoke-Native $npm @('--version')).Out.Trim() } else { Add-Row 'runtime' 'npm' 'missing' '' }
    } else { Add-Row 'runtime' 'node' 'missing' 'needed for REA (-Install -Component node)' }

    $rea = Find-Rea
    if ($rea) {
        $st = 'ok'
        if ($rea.Kind -eq 'managed' -and $rea.Repo -notmatch [regex]::Escape($Pin.ReaRepo)) { $st = 'fail' }
        Add-Row 'tier-A' 'rea' $st "$($rea.Kind) v$($rea.Version) repo=$($rea.Repo) $($rea.Mjs)$($rea.Cmd)"
    } else { Add-Row 'tier-A' 'rea' 'missing' "pin rea-agents@$($Pin.ReaVersion)" }

    $jdk = Find-Jdk21
    if ($jdk) { Add-Row 'tier-A' 'jdk21' 'ok' "$($jdk.Info.Raw) at $($jdk.Home)" }
    else {
        $any = Get-JavaInfo ((Find-Exe @('java.exe')))
        $d = 'no full JDK 21+ found'; if ($any) { $d += "; PATH java is major $($any.Major) ($($any.Exe))" }
        Add-Row 'tier-A' 'jdk21' 'missing' $d
    }

    $gh = Find-Ghidra
    if ($gh) {
        $st = 'ok'
        if ($gh.Version -ne $Pin.GhidraVersion -or -not $gh.Headless -or -not $gh.Decompiler) { $st = 'warn' }
        Add-Row 'tier-A' 'ghidra' $st "$($gh.Version) (java.min $($gh.JavaMin)) via $($gh.Source) at $($gh.Dir); headless=$($gh.Headless) decompiler=$($gh.Decompiler)"
    } else { Add-Row 'tier-A' 'ghidra' 'missing' "GHIDRA_INSTALL_DIR unset and no ghidra_*_PUBLIC under $Root" }

    if ($rea -and $node -and $node.ReaOk -and $rea.Mjs -and $jdk -and $gh) {
        $env:GHIDRA_INSTALL_DIR = $gh.Dir; $env:JAVA_HOME = $jdk.Home; $env:REA_ANALYSIS_PROVIDER = 'ghidra'
        $r = Invoke-Native $node.Exe @($rea.Mjs, 'doctor', '--provider', 'ghidra', '--json')
        $st = 'ok'; if ($r.Code -ne 0) { $st = 'fail' }
        Add-Row 'tier-A' 'rea doctor' $st ("exit $($r.Code); " + ($r.Out -replace '\s+', ' ').Substring(0, [Math]::Min(300, ($r.Out -replace '\s+', ' ').Length)))
    }

    foreach ($n in @('mcp-reva', 'pyghidra-mcp')) {
        $e = Find-Exe @("$n.exe", $n)
        if ($e) { Add-Row 'tier-B' $n 'ok' $e } else { Add-Row 'tier-B' $n 'missing' '' }
    }

    $py = Get-UserEnv 'APP_DEBLOAT_PYTHON'
    if (-not $py) { $py = Find-Exe @('python.exe') }
    if ($py) {
        # No -I: the modules usually live in the user site; cwd is dropped from sys.path instead.
        # Single quotes only: Windows PowerShell 5.1 mangles embedded double quotes in native arguments.
        $code = "import sys;sys.path=[p for p in sys.path if p not in ('','.')]`nimport importlib,json`nr={}`n" +
                "for m in ['" + ($Pin.PyModules -join "','") + "']:`n" +
                " try:`n  x=importlib.import_module(m);r[m]=str(getattr(x,'__version__','present'))`n" +
                " except Exception: r[m]=None`nprint(json.dumps(r))"
        $r = Invoke-Native $py @('-c', $code)
        try { $mods = ($r.Out -split "`n" | Select-Object -Last 1) | ConvertFrom-Json } catch { $mods = $null }
        Add-Row 'python' 'interpreter' 'ok' $py
        foreach ($m in $Pin.PyModules) {
            $v = $null; if ($mods) { $v = $mods.$m }
            $tier = 'tier-C'; if ($m -like 'frida*') { $tier = 'dynamic' }; if ($m -eq 'procmon_parser') { $tier = 'dynamic' }
            if ($v) { Add-Row $tier "py:$m" 'ok' $v } else { Add-Row $tier "py:$m" 'missing' '' }
        }
    } else { Add-Row 'python' 'interpreter' 'missing' 'set APP_DEBLOAT_PYTHON or put python.exe on PATH' }

    $fr = Find-Exe @('frida.exe', 'frida')
    if ($fr) { Add-Row 'dynamic' 'frida CLI' 'ok' ("$((Invoke-Native $fr @('--version')).Out.Trim()) at $fr") } else { Add-Row 'dynamic' 'frida CLI' 'missing' 'pip install --user frida-tools' }

    $sysDir = Join-Path $Root 'Sysinternals'
    foreach ($t in @(@('autorunsc64.exe', 'autorunsc.exe'), @('Procmon64.exe', 'Procmon.exe'), @('Sysmon64.exe', 'Sysmon.exe'), @('sigcheck64.exe', 'sigcheck.exe'))) {
        $e = Find-Exe $t @($sysDir)
        if ($e) {
            $sig = Get-AuthenticodeSignature -LiteralPath $e
            $st = 'ok'; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { $st = 'fail' }
            Add-Row 'dynamic' $t[1] $st "$e (signature $($sig.Status))"
        } else { Add-Row 'dynamic' $t[1] 'missing' "-Install -Component sysinternals puts it in $sysDir" }
    }
    $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc) { Add-Row 'dynamic' 'sysmon service' 'ok' "$($svc.Name) $($svc.Status)" } else { Add-Row 'dynamic' 'sysmon service' 'missing' 'optional; install needs admin (see reference/re-backends.md)' }

    foreach ($n in @('capa', 'floss')) {
        $e = Find-Exe @("$n.exe", $n)
        if ($e) { Add-Row 'prefilter' $n 'ok' $e } else { Add-Row 'prefilter' $n 'missing' 'optional' }
    }

    $cfg = Join-Path $(if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { $env:USERPROFILE }) '.claude.json'
    if (Test-Path -LiteralPath $cfg) {
        $raw = Get-Content -LiteralPath $cfg -Raw
        if ($raw -match '"rea"\s*:\s*\{') { Add-Row 'mcp' 'claude code: rea' 'ok' "registered in $cfg (user or local scope)" }
        else { Add-Row 'mcp' 'claude code: rea' 'missing' 'use -Install -RegisterMcp or claude mcp add --scope user' }
    }
    if (Test-Path -LiteralPath (Join-Path (Get-Location) '.mcp.json')) {
        if ((Get-Content -LiteralPath (Join-Path (Get-Location) '.mcp.json') -Raw) -match '"rea"') {
            Add-Row 'mcp' 'project .mcp.json' 'warn' 'rea is registered at project scope here; move it to user/local scope'
        }
    }

    $ok = { param($area, $item) @($Report | Where-Object { $_.area -eq $area -and $_.item -eq $item -and $_.status -eq 'ok' }).Count -gt 0 }
    $tier = 'none'
    if ((& $ok 'tier-C' 'py:pefile') -and (& $ok 'tier-C' 'py:capstone')) { $tier = 'C' }
    if ($gh -and $jdk -and ((& $ok 'tier-B' 'mcp-reva') -or (& $ok 'tier-B' 'pyghidra-mcp'))) { $tier = 'B' }
    $reaDoc = @($Report | Where-Object { $_.item -eq 'rea doctor' })
    if ($reaDoc.Count -gt 0 -and $reaDoc[0].status -eq 'ok') { $tier = 'A' }
    Add-Row 'summary' 'static tier' $(if ($tier -eq 'none') { 'fail' } else { 'ok' }) $tier
    $dyn = @($Report | Where-Object { $_.area -eq 'dynamic' -and $_.status -eq 'ok' } | ForEach-Object item) -join ', '
    Add-Row 'summary' 'dynamic tools' $(if ($dyn) { 'ok' } else { 'warn' }) $dyn

    if ($Json) { $Report | ConvertTo-Json -Depth 3 }
    else { $Report | Format-Table -AutoSize -Wrap area, item, status, detail | Out-String -Width 220 | Write-Output }
}

# ---------- install ----------
function Install-Node {
    $idx = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -UseBasicParsing
    $rel = $idx | Where-Object { $_.version -like 'v22.*' -and $_.lts -and $_.files -contains 'win-x64-zip' } | Select-Object -First 1
    if (-not $rel) { throw 'No Node 22 LTS release with a win-x64 zip found.' }
    $v = [version]$rel.version.TrimStart('v')
    if (-not (Test-NodeForRea $v)) { throw "Newest Node 22 LTS ($v) is older than $($Pin.NodeMin22)." }
    $name = "node-$($rel.version)-win-x64"
    $dest = Join-Path $Root $name
    if (Test-Path -LiteralPath $dest) { Write-Host "node: $dest exists"; return (Join-Path $dest 'node.exe') }
    $tmp = Join-Path $env:TEMP "app-debloat-node-$PID"; New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp "$name.zip"
    Get-Download "https://nodejs.org/dist/$($rel.version)/$name.zip" $zip
    Get-Download "https://nodejs.org/dist/$($rel.version)/SHASUMS256.txt" (Join-Path $tmp 'SHASUMS256.txt')
    $line = Get-Content -LiteralPath (Join-Path $tmp 'SHASUMS256.txt') | Where-Object { $_ -match "\s$([regex]::Escape("$name.zip"))$" }
    if (-not $line) { throw "No SHASUMS256 entry for $name.zip" }
    Assert-Sha256 $zip (($line -split '\s+')[0])
    Expand-Zip $zip $Root
    Remove-Item -LiteralPath $tmp -Recurse -Force
    $exe = Join-Path $dest 'node.exe'
    [Environment]::SetEnvironmentVariable('APP_DEBLOAT_NODE', $exe, 'User')
    Write-Host "node: $exe (APP_DEBLOAT_NODE set for the user)"
    return $exe
}

function Install-Rea {
    $node = Find-Node
    if (-not $node -or -not $node.ReaOk) { throw 'REA needs Node 22.x>=22.23.4 / 24.x>=24.22.1 / 26.12.1+. Add -Component node.' }
    $npm = Find-Exe @('npm.cmd') @((Split-Path -Parent $node.Exe))
    $prefix = Join-Path $Root 'rea'
    New-Item -ItemType Directory -Force -Path $prefix | Out-Null
    $view = Invoke-Native $npm @('view', "rea-agents@$($Pin.ReaVersion)", 'repository.url', 'maintainers', 'dist.integrity', '--json')
    if ($view.Code -ne 0 -or $view.Out -notmatch [regex]::Escape($Pin.ReaRepo)) { throw "npm metadata does not point at $($Pin.ReaRepo):`n$($view.Out)" }
    # --ignore-scripts: no dependency lifecycle scripts run (only the optional frida binding needs one; we use standalone frida).
    $r = Invoke-Native $npm @('install', '--prefix', $prefix, "rea-agents@$($Pin.ReaVersion)", '--ignore-scripts', '--no-fund', '--no-audit', '--save-exact')
    Write-Host $r.Out
    if ($r.Code -ne 0) { throw 'npm install rea-agents failed.' }
    $sig = Invoke-Native $npm @('audit', 'signatures', '--prefix', $prefix)
    Write-Host $sig.Out
    if ($sig.Code -ne 0) { throw 'npm audit signatures failed: registry signature or provenance did not verify.' }
    $mjs = Join-Path $prefix 'node_modules\rea-agents\scripts\rea.mjs'
    [Environment]::SetEnvironmentVariable('APP_DEBLOAT_REA', $mjs, 'User')
    Write-Host "rea: $mjs (APP_DEBLOAT_REA set for the user)"
}

function Install-Jdk {
    if ($JdkViaWinget) {
        $wg = Find-Exe @('winget.exe')
        if (-not $wg) { throw 'winget not found.' }
        $r = Invoke-Native $wg @('install', '--id', 'EclipseAdoptium.Temurin.21.JDK', '--exact', '--scope', 'user', '--silent', '--accept-package-agreements', '--accept-source-agreements')
        Write-Host $r.Out; if ($r.Code -ne 0) { throw 'winget install failed.' }
        return
    }
    $api = "https://api.adoptium.net/v3/assets/latest/$($Pin.JdkMajor)/hotspot?os=windows&architecture=x64&image_type=jdk&vendor=eclipse"
    $a = (Invoke-RestMethod -Uri $api -UseBasicParsing)[0]
    $pkg = $a.binary.package
    $dest = Join-Path $Root $a.release_name
    if (Test-Path -LiteralPath $dest) { Write-Host "jdk: $dest exists" }
    else {
        $tmp = Join-Path $env:TEMP "app-debloat-jdk-$PID"; New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $zip = Join-Path $tmp $pkg.name
        Get-Download $pkg.link $zip
        Assert-Sha256 $zip $pkg.checksum
        Expand-Zip $zip $Root
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    [Environment]::SetEnvironmentVariable('APP_DEBLOAT_JAVA_HOME', $dest, 'User')
    Write-Host "jdk: $dest (APP_DEBLOAT_JAVA_HOME set; JAVA_HOME left alone)"
}

function Install-Ghidra {
    $dest = Join-Path $Root "ghidra_$($Pin.GhidraVersion)_PUBLIC"
    if (-not (Test-Path -LiteralPath $dest)) {
        $tmp = Join-Path $env:TEMP "app-debloat-ghidra-$PID"; New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $zip = Join-Path $tmp $Pin.GhidraZip
        Write-Host "ghidra: downloading $($Pin.GhidraZip) (~570 MB)"
        Get-Download $Pin.GhidraUrl $zip
        Assert-Sha256 $zip $Pin.GhidraSha256
        Expand-Zip $zip $Root
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    if (-not (Get-GhidraInfo $dest)) { throw "Ghidra layout not found at $dest" }
    [Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', $dest, 'User')
    Write-Host "ghidra: $dest (GHIDRA_INSTALL_DIR set for the user)"
}

function Install-PyMods {
    $py = Get-UserEnv 'APP_DEBLOAT_PYTHON'; if (-not $py) { $py = Find-Exe @('python.exe') }
    if (-not $py) { throw 'No python.exe; set APP_DEBLOAT_PYTHON.' }
    # Never --upgrade: an existing frida may be pinned on purpose (frida 17 dropped the Java bridge). Install only what is missing.
    $need = @(); foreach ($pm in @(@('pefile','pefile'), @('capstone','capstone'), @('lief','lief'), @('frida','frida-tools'), @('procmon_parser','procmon-parser'))) { $chk = Invoke-Native $py @('-c', ('import ' + $pm[0])); if ($chk.Code -ne 0) { $need += $pm[1] } }
    if (-not $need) { Write-Host '  python modules already present; nothing upgraded'; return }
    $r = Invoke-Native $py (@('-m', 'pip', 'install', '--user') + $need)
    Write-Host $r.Out; if ($r.Code -ne 0) { throw 'pip install failed.' }
}

function Install-Sysinternals {
    $dir = Join-Path $Root 'Sysinternals'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($z in @('Autoruns', 'ProcessMonitor', 'Sysmon', 'Sigcheck')) {
        $tmp = Join-Path $env:TEMP "app-debloat-si-$PID-$z"; New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $zip = Join-Path $tmp "$z.zip"
        Get-Download "https://download.sysinternals.com/files/$z.zip" $zip
        Expand-Zip $zip (Join-Path $tmp 'x')
        foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $tmp 'x') -File -Filter '*.exe')) {
            $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw "Bad signature on $($f.Name): $($sig.Status)" }
            Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $dir $f.Name) -Force
        }
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    Write-Host "sysinternals: $dir (all binaries Authenticode-valid, Microsoft signer)"
    Write-Host '  Sysmon is NOT installed as a service. If you want it (admin, machine-wide):'
    Write-Host "  & '$dir\Sysmon64.exe' -accepteula -i <your-config.xml>"
}

function Register-ReaMcp {
    $node = Find-Node; $rea = Find-Rea; $jdk = Find-Jdk21; $gh = Find-Ghidra
    if (-not ($node -and $rea -and $rea.Mjs -and $jdk -and $gh)) { throw 'Need node, rea, jdk21 and ghidra before -RegisterMcp.' }
    $claude = Find-Exe @('claude.exe', 'claude.cmd')
    if (-not $claude) { throw 'claude CLI not found.' }
    $null = Invoke-Native $claude @('mcp', 'remove', 'rea', '--scope', $McpScope)
    $r = Invoke-Native $claude @('mcp', 'add', '--scope', $McpScope, 'rea',
        '-e', 'REA_ANALYSIS_PROVIDER=ghidra', '-e', "GHIDRA_INSTALL_DIR=$($gh.Dir)", '-e', "JAVA_HOME=$($jdk.Home)",
        '-e', 'REA_MCP_INPUT_SCHEMA_PROFILE=compact', '--', $node.Exe, $rea.Mjs, 'mcp')
    Write-Host $r.Out; if ($r.Code -ne 0) { throw 'claude mcp add failed.' }
    Write-Host 'Set MCP_TIMEOUT=60000 and MCP_TOOL_TIMEOUT=900000 in the environment that starts Claude Code (cold Ghidra import).'
}

# ---------- main ----------
if ($Install) {
    $Root = Assert-UserRoot $Root
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    foreach ($c in @('node', 'jdk', 'ghidra', 'rea', 'pymods', 'sysinternals')) {
        if ($Component -notcontains $c) { continue }
        Write-Host "== $c"
        switch ($c) {
            'node' { $null = Install-Node }
            'jdk' { Install-Jdk }
            'ghidra' { Install-Ghidra }
            'rea' { Install-Rea }
            'pymods' { Install-PyMods }
            'sysinternals' { Install-Sysinternals }
        }
    }
    if ($RegisterMcp) { Register-ReaMcp }
    Write-Host '== doctor'
}
Invoke-Doctor
