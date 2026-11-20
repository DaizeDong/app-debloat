# Hook for the synthetic ContosoPinyin component gate. The fake loader reads Components\components.json
# and starts only entries with "enabled": true. A real app's gate may be encrypted: then Plan derives the
# key at run time from the user's own install and nothing secret is ever written into the script.
function Set-ContosoComponents([string]$path, [string[]]$ids, [bool]$enabled) {
    Assert-AdPathSafe $path
    $cfg = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    foreach ($c in @($cfg.components)) { if ($ids -contains $c.id) { $c.enabled = $enabled } }
    $tmp = "$path.adtmp"
    [IO.File]::WriteAllText($tmp, ($cfg | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
    [IO.File]::Replace($tmp, $path, [NullString]::Value)
}
$Hooks['contoso-components'] = @{
    Plan = {
        param($Ctx, $Action)
        $path = Expand-AdPath '{root}\Components\components.json'
        Assert-AdPathSafe $path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
        $want = @(AdGet (AdGet $Action 'args') 'disable' @())
        $on = @(@(([IO.File]::ReadAllText($path) | ConvertFrom-Json).components) | Where-Object { $want -contains $_.id -and $_.enabled } | ForEach-Object { $_.id })
        if (-not $on) { return }
        @{ Key = 'components.json'; Desc = "Turn off components in ${path}: $($on -join ', ')"; Data = @{ path = $path; ids = $on }
           Original = @{ enabled = $on }; After = [ordered]@{ disabled = $on } }
    }
    Apply = { param($Ctx, $Data, $Item) Set-ContosoComponents $Data.path @($Data.ids) $false }
    # Restore only while every component the hook turned off is still off; anything else is someone else's change.
    Undo  = {
        param($Ctx, $Data, $Original, $Entry)
        if (-not (Test-Path -LiteralPath $Data.path -PathType Leaf)) { return "GONE $($Data.path) no longer exists" }
        $ids = @($Original.enabled)
        $now = @{}; foreach ($c in @(([IO.File]::ReadAllText($Data.path) | ConvertFrom-Json).components)) { $now[$c.id] = [bool]$c.enabled }
        $off = @($ids | Where-Object { $now.ContainsKey($_) -and -not $now[$_] })
        $on = @($ids | Where-Object { $now.ContainsKey($_) -and $now[$_] })
        if ($on.Count -eq $ids.Count) { return "SKIP components $($ids -join ', ') are already on" }
        if ($off.Count -ne $ids.Count) { return "CONFLICT $($Data.path): $(@($ids | Where-Object { $off -notcontains $_ }) -join ', ') changed since the hook turned them off; left as is" }
        Set-ContosoComponents $Data.path $ids $true
    }
}
