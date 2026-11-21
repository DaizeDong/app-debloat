#Requires -Version 5.1
<#
.SYNOPSIS
  Capture the app's own top-level windows to PNG with PrintWindow, DPI-aware, without sending
  any input. Writes one PNG per window and a JSON index.

.DESCRIPTION
  Read-only toward the target: it never activates, restores, moves, clicks or types into a
  window. It only enumerates visible top-level windows, keeps those whose owning process image
  path matches -ImagePathRegex or lies under -Root, and asks each one to paint itself into a
  bitmap (PrintWindow with PW_RENDERFULLCONTENT, which also renders Chromium, Electron and
  DirectComposition content).

  The script makes its own process per-monitor DPI aware (v2, falling back to per-monitor and
  then system aware) to enumerate windows in physical pixels, then switches its thread to each
  window's own DPI awareness while capturing it. A capturer whose awareness differs from the
  window's gets cropped output (aware window, unaware capturer) or a small image in a black
  canvas (unaware window, aware capturer). The index records both awareness values; a
  DPI-unaware window is captured at its logical size.

  Minimized and cloaked windows cannot paint and are listed with a skip reason. A capture that
  comes back as one flat color is marked "blank" (common for windows that are hidden behind
  the GPU compositor or still loading); retake it later rather than trusting it.

  Window titles and screenshots are real-run DATA: write -Out to the private companion, never
  into the tool repo.

.PARAMETER ImagePathRegex
  Case-insensitive regex matched against the full image path of each window's process.

.PARAMETER Root
  One or more install or data directories. A window matches when its process image is under one.

.PARAMETER Out
  Output directory (required, created if missing).

.PARAMETER Tag
  Optional prefix for file names, for example 'before' or 'after-t60'.

.PARAMETER MinSize
  Skip windows narrower or shorter than this many pixels. Default 16.

.PARAMETER BubbleTitleRegex
  Extra case-insensitive title regex for known side-effect bubbles. Built in: Chromium's
  "Restore pages?" / "didn't shut down correctly" bubble (English and Chinese), which appears
  after stop_app.ps1 force-closed a Chromium-based app. A small window (under 700x400 physical
  pixels) whose title matches gets tags = ['restore_pages_bubble'] in the index and in the
  console line, so it is not read as a new popup. It is still captured.

.EXAMPLE
  .\shot_windows.ps1 -Root "$env:LOCALAPPDATA\ExampleApp" -Out D:\private\shots -Tag before
  .\shot_windows.ps1 -ImagePathRegex '\\ExampleApp\\[^\\]+\.exe$' -Out D:\private\shots
#>
[CmdletBinding()]
param(
    [string]$ImagePathRegex,
    [string[]]$Root,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Tag,
    [int]$MinSize = 16,
    [string]$BubbleTitleRegex
)
$ErrorActionPreference = 'Stop'
if (-not $ImagePathRegex -and -not $Root) { throw 'Pass -ImagePathRegex <regex> and/or -Root <dir>.' }

Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System; using System.Collections.Generic; using System.Drawing; using System.Drawing.Imaging;
using System.Runtime.InteropServices; using System.Text;
public static class AdShot {
    [DllImport("user32.dll", SetLastError = true)] static extern bool SetProcessDpiAwarenessContext(IntPtr v);
    [DllImport("shcore.dll")] static extern int SetProcessDpiAwareness(int v);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern IntPtr GetThreadDpiAwarenessContext();
    [DllImport("user32.dll")] static extern int GetAwarenessFromDpiAwarenessContext(IntPtr c);
    [DllImport("user32.dll")] static extern bool IsProcessDPIAware();
    public static string SetDpi() {
        try { if (SetProcessDpiAwarenessContext(new IntPtr(-4))) return "per-monitor-v2"; } catch (EntryPointNotFoundException) { }
        try { if (SetProcessDpiAwareness(2) == 0) return "per-monitor"; } catch (Exception) { }
        try { if (SetProcessDPIAware()) return "system"; } catch (Exception) { }
        return "unchanged";
    }
    public static string CurrentDpi() {
        try {
            int a = GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext());
            return a == 2 ? "per-monitor" : a == 1 ? "system" : a == 0 ? "unaware" : "unknown";
        } catch (Exception) { try { return IsProcessDPIAware() ? "system" : "unaware"; } catch (Exception) { return "unknown"; } }
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, uint pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, uint f, StringBuilder s, ref uint n);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static string ImagePath(uint pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);   // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) return null;
        try { var sb = new StringBuilder(1024); uint n = 1024; return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString() : null; }
        finally { CloseHandle(h); }
    }

    public struct RECT { public int L, T, R, B; }
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int cb);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr h, int a, out int v, int cb);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);

    public class Win { public long Hwnd; public uint Pid; public string Cls; public string Title; public bool Iconic; public bool Cloaked; public int L, T, R, B; public int VL, VT, VR, VB; }
    public static Win[] VisibleTopLevel() {
        var res = new List<Win>();
        EnumProc cb = (h, l) => {
            if (!IsWindowVisible(h)) return true;
            uint pid; GetWindowThreadProcessId(h, out pid);
            var t = new StringBuilder(512); GetWindowTextW(h, t, 512);
            var c = new StringBuilder(256); GetClassNameW(h, c, 256);
            RECT r; GetWindowRect(h, out r);
            RECT v; if (DwmGetWindowAttribute(h, 9, out v, Marshal.SizeOf(typeof(RECT))) != 0) v = r;   // DWMWA_EXTENDED_FRAME_BOUNDS
            int cloak = 0; DwmGetWindowAttribute(h, 14, out cloak, 4);                                     // DWMWA_CLOAKED
            res.Add(new Win { Hwnd = h.ToInt64(), Pid = pid, Cls = c.ToString(), Title = t.ToString(), Iconic = IsIconic(h), Cloaked = cloak != 0,
                L = r.L, T = r.T, R = r.R, B = r.B, VL = v.L, VT = v.T, VR = v.R, VB = v.B });
            return true;
        };
        EnumWindows(cb, IntPtr.Zero); GC.KeepAlive(cb);
        return res.ToArray();
    }

    [DllImport("user32.dll")] static extern IntPtr GetWindowDpiAwarenessContext(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr SetThreadDpiAwarenessContext(IntPtr c);
    static string AwarenessName(int a) { return a == 2 ? "per-monitor" : a == 1 ? "system" : a == 0 ? "unaware" : "unknown"; }

    // Paints the window into a bitmap, crops the invisible resize border and drop shadow, saves PNG.
    // The calling thread temporarily takes the window's own DPI awareness, so PrintWindow renders
    // at the size the window itself draws at: a DPI-unaware window comes out at its logical size
    // instead of a small image in the corner of a physical-size black canvas.
    // Returns null on success, else an error string. blank = every sampled pixel has one color.
    public static string Capture(long hwnd, Win w, string path, out bool blank, out uint flagsUsed, out string windowDpi) {
        blank = false; flagsUsed = 0; windowDpi = "unknown";
        IntPtr h = new IntPtr(hwnd);
        IntPtr old = IntPtr.Zero;
        try {
            IntPtr c = GetWindowDpiAwarenessContext(h);
            windowDpi = AwarenessName(GetAwarenessFromDpiAwarenessContext(c));
            old = SetThreadDpiAwarenessContext(c);
        } catch (EntryPointNotFoundException) { }
        try { return CaptureIn(h, w, path, out blank, out flagsUsed); }
        finally { if (old != IntPtr.Zero) SetThreadDpiAwarenessContext(old); }
    }
    static string CaptureIn(IntPtr h, Win w, string path, out bool blank, out uint flagsUsed) {
        blank = false; flagsUsed = 0;
        RECT r; if (!GetWindowRect(h, out r)) return "GetWindowRect failed";   // in the window's own coordinates now
        int ww = r.R - r.L, wh = r.B - r.T;
        if (ww <= 0 || wh <= 0) return "empty rect";
        // w.* are physical (enumerated per-monitor aware); scale the visible frame into this space.
        double sx = (w.R - w.L) > 0 ? (double)ww / (w.R - w.L) : 1.0, sy = (w.B - w.T) > 0 ? (double)wh / (w.B - w.T) : 1.0;
        using (var bmp = new Bitmap(ww, wh, PixelFormat.Format32bppArgb)) {
            bool ok = false;
            foreach (uint f in new uint[] { 2, 0 }) {   // PW_RENDERFULLCONTENT, then plain
                using (var g = Graphics.FromImage(bmp)) {
                    g.Clear(Color.Black);
                    IntPtr hdc = g.GetHdc();
                    try { ok = PrintWindow(h, hdc, f); } finally { g.ReleaseHdc(hdc); }
                }
                if (ok) { flagsUsed = f; break; }
            }
            if (!ok) return "PrintWindow failed";
            int cx = Math.Max(0, (int)Math.Round((w.VL - w.L) * sx)), cy = Math.Max(0, (int)Math.Round((w.VT - w.T) * sy));
            int cw = Math.Min(ww - cx, (int)Math.Round((w.VR - w.VL) * sx)), ch = Math.Min(wh - cy, (int)Math.Round((w.VB - w.VT) * sy));
            if (cw <= 0 || ch <= 0) { cx = 0; cy = 0; cw = ww; ch = wh; }
            using (var crop = bmp.Clone(new Rectangle(cx, cy, cw, ch), PixelFormat.Format32bppArgb)) {
                int first = crop.GetPixel(0, 0).ToArgb(); blank = true;
                for (int y = 0; y < 24 && blank; y++) for (int x = 0; x < 24; x++) {
                    if (crop.GetPixel(x * (cw - 1) / 23, y * (ch - 1) / 23).ToArgb() != first) { blank = false; break; }
                }
                crop.Save(path, ImageFormat.Png);
            }
        }
        return null;
    }
}
'@

$dpiSet = [AdShot]::SetDpi()
$dpiNow = [AdShot]::CurrentDpi()
if ($dpiNow -ne 'per-monitor') { Write-Warning "DPI awareness is '$dpiNow' (set: $dpiSet). Captures on a scaled display may be cropped or scaled." }

$rootPrefixes = @(foreach ($r in @($Root)) {
    if (-not $r) { continue }
    try { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($r.Trim('"'))).TrimEnd('\').ToLowerInvariant() } catch { Write-Warning "bad root: $r" }
})
$rx = $null; if ($ImagePathRegex) { $rx = New-Object regex($ImagePathRegex, 'IgnoreCase') }
function Test-Match([string]$img) {
    if (-not $img) { return $false }
    if ($rx -and $rx.IsMatch($img)) { return $true }
    $l = $img.ToLowerInvariant()
    foreach ($p in $rootPrefixes) { if ($l.StartsWith($p + '\')) { return $true } }
    $false
}

# Chromium's crash-restore bubble ("Restore pages?" / "... didn't shut down correctly"), also in zh-CN and zh-TW.
# The Chinese alternatives are .NET \u escapes, so this file stays ASCII.
$restoreRx = New-Object regex(('restore pages|did(n''t| not) shut down correctly|\u6062\u590d(\u9875\u9762|\u7f51\u9875)|\u6062\u5fa9(\u9801\u9762|\u7db2\u9801)|\u672a\u6b63\u786e\u5173\u95ed|\u672a\u6b63\u78ba\u95dc\u9589' +
    $(if ($BubbleTitleRegex) { '|' + $BubbleTitleRegex } else { '' })), 'IgnoreCase')
function Get-WindowTags($w) {
    $tags = @()
    $vw = $w.VR - $w.VL; $vh = $w.VB - $w.VT
    if ($w.Title -and $vw -lt 700 -and $vh -lt 400 -and $restoreRx.IsMatch($w.Title)) { $tags += 'restore_pages_bubble' }
    ,$tags
}

$outDir = [IO.Path]::GetFullPath($Out)
[void][IO.Directory]::CreateDirectory($outDir)
$prefix = $(if ($Tag) { ($Tag -replace '[^\w.-]', '_') + '_' } else { '' })

$imgCache = @{}
$index = New-Object System.Collections.Generic.List[object]
$seq = 0
foreach ($w in [AdShot]::VisibleTopLevel()) {
    if ($w.Pid -eq $PID) { continue }
    if (-not $imgCache.ContainsKey($w.Pid)) { $imgCache[$w.Pid] = [AdShot]::ImagePath($w.Pid) }
    $img = $imgCache[$w.Pid]
    if (-not (Test-Match $img)) { continue }
    $seq++
    $e = [ordered]@{
        hwnd = ('0x{0:x}' -f $w.Hwnd); pid = [int]$w.Pid; image = $img; class = $w.Cls; title = $w.Title
        rect = @($w.L, $w.T, $w.R, $w.B); visible_rect = @($w.VL, $w.VT, $w.VR, $w.VB)
        window_dpi = $null; file = $null; blank = $null; print_flags = $null; skipped = $null; error = $null
        tags = @(Get-WindowTags $w)
    }
    if ($w.Iconic) { $e.skipped = 'minimized (restoring it would be input; not done)' }
    elseif ($w.Cloaked) { $e.skipped = 'cloaked by DWM' }
    elseif (($w.R - $w.L) -lt $MinSize -or ($w.B - $w.T) -lt $MinSize) { $e.skipped = "smaller than $MinSize px" }
    else {
        $cls = ($w.Cls -replace '[^\w.-]', '_'); if ($cls.Length -gt 40) { $cls = $cls.Substring(0, 40) }
        $name = '{0}{1:d2}_{2}_{3}.png' -f $prefix, $seq, $w.Pid, $cls
        $blank = $false; $flags = [uint32]0; $wdpi = $null
        try {
            $err = [AdShot]::Capture($w.Hwnd, $w, (Join-Path $outDir $name), [ref]$blank, [ref]$flags, [ref]$wdpi)
            $e.window_dpi = $wdpi
            if ($err) { $e.error = $err } else { $e.file = $name; $e.blank = $blank; $e.print_flags = $(if ($flags -eq 2) { 'PW_RENDERFULLCONTENT' } else { 'none' }) }
        } catch { $e.error = $_.Exception.Message }
    }
    $index.Add($e)
}

$doc = [ordered]@{
    schema = 'app-debloat.shots/1'; captured_at = (Get-Date).ToUniversalTime().ToString('o')
    dpi_awareness = $dpiNow; dpi_set = $dpiSet
    match = [ordered]@{ image_path_regex = $ImagePathRegex; roots = @($Root); bubble_title_regex = $BubbleTitleRegex }
    tag_meaning = [ordered]@{ restore_pages_bubble = 'Chromium crash-restore bubble, a side effect of a forced close (stop_app.ps1); not a new popup' }
    windows = $index.ToArray()
}
$idxPath = Join-Path $outDir ($prefix + 'index.json')
[IO.File]::WriteAllText($idxPath, ($doc | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))

$shot = @($index | Where-Object { $_.file }).Count
$blankN = @($index | Where-Object { $_.blank }).Count
$bubbleN = @($index | Where-Object { $_.tags -contains 'restore_pages_bubble' }).Count
Write-Host ("windows matched: {0}, captured: {1}, blank: {2}, skipped or failed: {3}, restore-pages bubbles: {4}, dpi: {5}" -f $index.Count, $shot, $blankN, ($index.Count - $shot), $bubbleN, $dpiNow)
foreach ($e in $index) {
    $state = $(if ($e.file) { $e.file + $(if ($e.blank) { ' (blank)' } else { '' }) } elseif ($e.skipped) { 'skipped: ' + $e.skipped } else { 'error: ' + $e.error })
    $tagText = $(if (@($e.tags).Count) { ' [' + (@($e.tags) -join ', ') + ': side effect of a forced close, not a new popup]' } else { '' })
    Write-Host ("  pid {0} {1} '{2}' -> {3}{4}" -f $e.pid, $e.class, $e.title, $state, $tagText)
}
Write-Host "index: $idxPath"
