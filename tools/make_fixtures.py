#!/usr/bin/env python3
"""Generate the synthetic examples under examples/ (FIXTURE class) and, optionally, fake install trees.

Everything here is invented: ContosoPinyin and FabrikamDrive do not exist, CLSIDs and domains are
made up, and every "binary" in a fake tree is a few bytes of text. Never paste a real inventory,
journal or manifest from a real machine into this file; real runs belong in the private companion.

Usage:
  python tools/make_fixtures.py                      # write examples/ (manifests, hooks, built scripts)
  python tools/make_fixtures.py --fake-root DIR      # also build fake installs under DIR and print the
                                                     # environment variables that point the scripts at them
  python tools/make_fixtures.py --no-build           # write manifests only (no PowerShell needed)
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "app-debloat"
ENGINE = SKILL / "scripts" / "DebloatEngine.ps1"
TEMPLATE = SKILL / "templates" / "app-debloat.template.ps1"
EXAMPLES = REPO / "examples"


def act(id_, type_, category, rationale, reapply=True, evidence="observed", **fields):
    """One manifest action. evidence is the weakest ledger status behind it; anything below observed or
    anchored must name its enabling option in `when` and stays inactive by default."""
    a = {"id": id_, "type": type_, "category": category, "rationale": rationale, "evidence": evidence,
         "reversible": True, "reapply": reapply}
    a.update(fields)
    return a


CONTOSO = {
    "schema": 2,
    "id": "contoso-pinyin",
    "name": "Contoso Pinyin IME",
    "taskPrefix": "ContosoPinyin",
    "profile": "ime",
    "riskTier": "normal",
    "installRoot": {
        "envVar": "CONTOSOPINYIN_ROOT",
        "uninstall": {"displayName": "^Contoso Pinyin", "publisher": "^Contoso"},
        "service": {"name": "ContosoPinyinSvc", "levelsUp": 2},
        "candidates": ["%ProgramFiles(x86)%\\ContosoPinyin", "%ProgramFiles%\\ContosoPinyin"],
        "mustContain": ["Components"],
        # Checked for every candidate, -InstallRoot and the env var included. A real manifest adds
        # "signer": {"files": [...], "subject": "<vendor regex>"}; these synthetic files are unsigned.
        "identity": {"text": [{"file": "Components\\components.json", "regex": "\"id\"\\s*:\\s*\"Core\""}]},
    },
    "versionDir": {
        "pattern": "^\\d+(\\.\\d+){3}$",
        "mustContain": "ContosoTool.exe",
        "registry": {"path": "HKLM\\SOFTWARE\\WOW6432Node\\ContosoPinyin", "name": "Version"},
    },
    "pathVars": {
        "userData": {"envVar": "CONTOSOPINYIN_USERDATA", "default": "%USERPROFILE%\\AppData\\LocalLow\\ContosoPinyin.users"},
        "sharedData": {"envVar": "CONTOSOPINYIN_SHARED", "default": "%ProgramData%\\ContosoPinyin"},
        "pdfDir": {"envVar": "CONTOSOPINYIN_PDFDIR", "default": "%LOCALAPPDATA%\\ContosoPDF"},
    },
    "allowedRoots": ["{userData}", "{sharedData}", "{pdfDir}"],
    "version": {
        "sources": [
            {"source": "registry", "path": "HKLM\\SOFTWARE\\WOW6432Node\\ContosoPinyin", "name": "Version"},
            {"source": "dirname"},
        ],
        "supported": {"versions": ["12.4.0.1234", "12.3.9.1000"]},
    },
    "core": {
        "files": ["{ver}\\ContosoTool.exe", "{ver}\\ContosoCloud.exe", "{ver}\\ContosoImeBroker.exe"],
        # Must survive, but set-type actions (ini-set here) may edit its content; core.files may not be touched at all.
        "preserve": ["{sharedData}\\cloud.ini"],
        "processes": ["ContosoTool.exe", "ContosoCloud.exe", "ContosoImeBroker.exe", "ctfmon.exe"],
        "restartable": ["ContosoTool.exe", "ContosoCloud.exe"],
        "services": [],
        "probe": "type pinyin in a test window launched by the skill; read the committed text back",
    },
    "options": [
        {"name": "NoSync", "default": False, "help": "Also stop account and dictionary sync (blocks ContosoUserSync.exe)."},
        {"name": "BlockNet", "default": False, "help": "Also firewall ContosoTool.exe (it fetches skins and cell dictionaries too)."},
        {"name": "RemoveSdkDlls", "default": False,
         "help": "Replace the beacon and remote-config SDK DLLs. Promote by: a frida LoadLibrary trace showing typing works without them."},
        {"name": "RemoveAiFolders", "default": False,
         "help": "Replace the AI and pet component folders. Promote by: a typing probe with the folders renamed."},
    ],
    "actions": [
        act("svc-repair", "service-disable", "repair", ["L-R1"], target=["ContosoPinyinSvc"], stop=True),
        act("task-toolkit", "task-disable", "promo", ["L-P2"], target=["\\ContosoPinyin\\ContosoToolkits*"]),
        act("component-gate", "hook", "ai", ["L-G1"], hook="contoso-components",
            args={"disable": ["AiChat", "Pet", "GameCenter", "BizCenter"]}),
        act("updater-files", "file-placeholder-dir", "updater", ["L-R2", "L-R3"], createIfMissing=True,
            target=["{ver}\\ContosoUpdate.exe", "{ver}\\ContosoDownload.exe", "{root}\\Components\\ContosoComMgr.exe"]),
        act("sdk-dlls", "file-placeholder-dir", "telemetry", ["L-T1"], evidence="inferred", when="RemoveSdkDlls",
            evidenceNote="loaded by ContosoTool.exe per import xrefs; core independence not yet probed",
            target=["{ver}\\beacon_sdk.dll", "{ver}\\remote_cfg.dll", "{root}\\Components\\biz_center\\*\\ad_sdk.dll"],
            stopHosts=["{ver}\\ContosoTool.exe", "{ver}\\ContosoCloud.exe"]),
        act("ai-dirs", "dir-placeholder-file", "ai", ["L-A1"], checkLoaded=True, evidence="hypothesis", when="RemoveAiFolders",
            evidenceNote="folder names suggest AI add-ons; no load or launch edge anchored",
            target=["{root}\\Components\\AiChat", "{root}\\Components\\Pet", "{sharedData}\\AiCache"],
            stopHosts=["{ver}\\ContosoTool.exe"]),
        act("pdf-lock", "acl-deny-write", "promo", ["L-P3"], principal="CurrentUser", emptyFirst=True,
            createIfMissing=True, target=["{pdfDir}"]),
        act("shellext", "shellext-block", "promo", ["L-P4"], clsids=["{0C0A0000-1111-4222-8333-444455556666}"],
            handlerMatch="^\\s*ContosoShellExt", label="Contoso Pinyin context menu"),
        act("toast", "toast-off", "ad", ["L-A2"], target=["Contoso.Pinyin.Toast*", "Contoso.Pinyin.Toast.Biz"]),
        act("store-switches", "reg-set", "ad", ["L-A3"], target="HKCU\\Software\\ContosoPinyin\\Settings", kind="DWord",
            values={"AiChatEnable": 0, "PopupEnable": 0, "PetAutorun": 0}),
        act("biz-protocol", "reg-delete-key", "promo", ["L-P5"], target=["HKLM\\SOFTWARE\\Classes\\contosobiz"]),
        act("ifeo", "ifeo-block", "updater", ["L-R2", "L-R4"],
            target=["ContosoComMgr.exe", "ContosoUpdate.exe", "ContosoBizLauncher.exe", "ContosoAiChat.exe"]),
        act("env-ini", "preboot-file-edit", "ad", ["L-G2"], target=["{userData}\\*\\env.ini"], section="Setting",
            set={"AutoUpdate": "2", "EnableAdsDispatch": "0", "AiChatSwitch": "0"}, dropFromSections=["SyncMode"]),
        act("cloud-autocheck", "ini-set", "updater", ["L-R5"], path="{sharedData}\\cloud.ini", section="Update",
            key="AutoCheck", value="0", onlyWhenNotRunning=["{ver}\\ContosoCloud.exe"]),
        act("sync", "ifeo-block", "telemetry", ["L-T2"], when="NoSync", target=["ContosoUserSync.exe"]),
        act("net", "firewall-block-program", "telemetry", ["L-T3"], when="BlockNet", target=["{ver}\\ContosoTool.exe"]),
    ],
}

FABRIKAM = {
    "schema": 2,
    "id": "fabrikam-drive",
    "name": "Fabrikam Drive",
    "taskPrefix": "FabrikamDrive",
    "profile": "electron-netdisk",
    "riskTier": "normal",
    "installRoot": {
        "envVar": "FABRIKAMDRIVE_ROOT",
        "uninstall": {"displayName": "^Fabrikam Drive"},
        "candidates": ["%LOCALAPPDATA%\\Programs\\FabrikamDrive"],
        "mustContain": ["FabrikamDrive.exe", "resources\\app.asar"],
        "identity": {"text": [{"file": "resources\\build-info.json", "regex": "\"name\"\\s*:\\s*\"fabrikam-drive\""}]},
    },
    "pathVars": {
        "updaterCache": {"envVar": "FABRIKAMDRIVE_UPDATERCACHE", "default": "%LOCALAPPDATA%\\fabrikam-drive-updater"},
        "appData": {"envVar": "FABRIKAMDRIVE_APPDATA", "default": "%APPDATA%\\FabrikamDrive"},
    },
    "allowedRoots": ["{updaterCache}", "{appData}"],
    "version": {
        "sources": [
            {"source": "uninstall"},
            {"source": "file", "path": "{root}\\FabrikamDrive.exe"},
            {"source": "text", "path": "{root}\\resources\\build-info.json", "regex": "\"version\"\\s*:\\s*\"([^\"]+)\""},
        ],
        "supported": {"versions": ["5.3.1"]},
    },
    "core": {
        "files": ["{root}\\FabrikamDrive.exe", "{root}\\FabrikamDriveHost.exe", "{root}\\resources\\app.asar"],
        "preserve": ["{appData}\\settings.json"],
        "processes": ["FabrikamDrive.exe", "FabrikamDriveHost.exe"],
        "restartable": [],
        "services": ["FabrikamDriveSyncSvc"],
        "probe": "sign in with a test account, upload and download a small file",
    },
    "options": [
        {"name": "KeepAi", "default": False, "help": "Keep the AI assistant plugin."},
        {"name": "BlockHosts", "default": False, "help": "Also sink ad and telemetry hosts in the hosts file (discouraged: flagged by security products)."},
        {"name": "RemoveUpdaterExe", "default": False,
         "help": "Replace FabrikamUpdate.exe with a placeholder. Promote by: start the client with the updater renamed and confirm sign-in and transfers."},
        {"name": "BlockReporter", "default": False,
         "help": "Firewall FabrikamReport.exe. Promote by: a Sysmon 22 capture showing it contacts only telemetry hosts."},
    ],
    "actions": [
        act("updater-task", "task-disable", "updater", ["L-R1"], target=["\\FabrikamDrive\\FabrikamDriveUpdateTask*"]),
        # Chromium-style updaters register their tasks in a vendor folder tree; taskPath searches it with subfolders.
        act("updater-system-tasks", "task-disable", "updater", ["L-R6"], taskPath="\\FabrikamUpdaterSystem\\",
            target=["FabrikamUpdater*"]),
        # A failure that is understood and cannot be fixed is recorded, so every run reports it as a WARN with this
        # reason instead of a new failure, and -Install can still register the watch task. `targets` limits it to the
        # one service the security suite protects; a failure of the other service stays a FAIL.
        act("updater-svc", "service-disable", "updater", ["L-R2"],
            target=["FabrikamDriveUpdateSvc", "FabrikamDriveElevationSvc"], stop=True,
            knownFailure={"reason": "a security suite vetoes the start-type change (access denied, protection level NONE)",
                          "ref": "L-R2", "targets": ["FabrikamDriveElevationSvc"]}),
        act("updater-config", "file-placeholder-dir", "updater", ["L-R3"], createIfMissing=True,
            target=["{root}\\resources\\app-update.yml"]),
        act("updater-cache", "acl-deny-write", "updater", ["L-R4"], principal="CurrentUser", emptyFirst=True,
            createIfMissing=True, target=["{updaterCache}"]),
        act("updater-exe", "file-placeholder-dir", "updater", ["L-R5"], evidence="hypothesis", when="RemoveUpdaterExe",
            evidenceNote="client tolerance of a missing updater is untested", target=["{root}\\FabrikamUpdate.exe"]),
        act("ad-helpers", "file-placeholder-dir", "ad", ["L-A1"],
            target=["{root}\\ad_helper.exe", "{root}\\resources\\plugins\\promo_popup.exe"]),
        act("ai-plugin", "dir-placeholder-file", "ai", ["L-A2"], unless="KeepAi",
            target=["{root}\\resources\\plugins\\ai-assistant"]),
        act("shellext", "shellext-block", "promo", ["L-P1"], clsids=["{FAB00000-CCCC-4DDD-8EEE-FFFF00001111}"],
            handlerMatch="^FabrikamDrive", label="Fabrikam Drive context menu"),
        act("toast", "toast-off", "ad", ["L-A3"], target=["com.fabrikam.drive*"]),
        act("settings", "reg-set", "ad", ["L-A4"], target="HKCU\\Software\\Fabrikam\\Drive", kind="DWord",
            values={"ShowPromotions": 0, "AiAssistantEnabled": 0}),
        act("promo-banner", "json-set", "ad", ["L-A5"], path="{appData}\\settings.json", pointer="/promotions/showBanner",
            value=False, onlyWhenNotRunning=["{root}\\FabrikamDrive.exe"]),
        act("ai-entry", "json-set", "ai", ["L-A6"], unless="KeepAi", path="{appData}\\settings.json",
            pointer="/ai/assistant/enabled", value=False, onlyWhenNotRunning=["{root}\\FabrikamDrive.exe"]),
        act("report-net", "firewall-block-program", "telemetry", ["L-T1"], evidence="inferred", when="BlockReporter",
            evidenceNote="name and strings suggest crash and usage reports only", target=["{root}\\FabrikamReport.exe"]),
        act("ifeo", "ifeo-block", "updater", ["L-R5", "L-A1"], target=["FabrikamUpdate.exe", "FabrikamAdHelper.exe"]),
        act("promo-cache", "reg-delete-key", "promo", ["L-P2"], reapply=False, effect="reset",
            target=["HKCU\\Software\\Fabrikam\\Drive\\PromoCache"]),
        act("hosts", "hosts-block", "telemetry", ["L-T2"], reapply=False, when="BlockHosts", acknowledgeFlagging=True,
            target=["ads.fabrikam-drive.example", "telemetry.fabrikam-drive.example"]),
    ],
}

CONTOSO_HOOKS = r"""# Hook for the synthetic ContosoPinyin component gate. The fake loader reads Components\components.json
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
"""

FIXTURES = [
    ("contoso-pinyin", CONTOSO, CONTOSO_HOOKS),
    ("fabrikam-drive", FABRIKAM, None),
]


def write(path: Path, text: str, bom=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + data)


def build(manifest: Path, hooks, out: Path):
    q = lambda p: "'" + str(p).replace("'", "''") + "'"
    cmd = (f". {q(ENGINE)}; New-AppScript -ManifestPath {q(manifest)} -OutFile {q(out)} -TemplatePath {q(TEMPLATE)}"
           + (f" -HooksPath {q(hooks)}" if hooks else "") + " | Out-Null")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                       capture_output=True, text=True)
    if r.returncode or r.stderr.strip():
        sys.exit(f"build failed for {out.name}:\n{r.stdout}\n{r.stderr}")


def fake_tree(root: Path):
    """Synthetic installs for dry-run tests. Files are short text, not executables."""
    def f(p, body="synthetic placeholder, not a program\n"):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    c = root / "contoso"
    pf = c / "ProgramFiles" / "ContosoPinyin"
    ver = pf / "12.4.0.1234"
    for n in ["ContosoTool.exe", "ContosoCloud.exe", "ContosoImeBroker.exe", "ContosoUpdate.exe",
              "ContosoBizLauncher.exe", "beacon_sdk.dll", "remote_cfg.dll"]:
        f(ver / n)
    f(pf / "12.3.9.1000" / "ContosoTool.exe")          # older version dir: must not be picked
    f(pf / "Components" / "ContosoComMgr.exe")
    f(pf / "Components" / "AiChat" / "aichat_core_synthetic.dll")
    f(pf / "Components" / "Pet" / "pet_synthetic.dll")
    f(pf / "Components" / "biz_center" / "3.1.0" / "ad_sdk.dll")
    f(pf / "Components" / "components.json", json.dumps({"components": [
        {"id": "Core", "enabled": True}, {"id": "AiChat", "enabled": True}, {"id": "Pet", "enabled": True},
        {"id": "GameCenter", "enabled": False}, {"id": "BizCenter", "enabled": True}]}, indent=2))
    ud = c / "LocalLow" / "ContosoPinyin.users" / "u0001"
    ud.mkdir(parents=True, exist_ok=True)
    ini = "[Setting]\r\nAutoUpdate=1\r\nEnableAdsDispatch=1\r\nFontSize=14\r\n\r\n[SyncMode]\r\nEnableAdsDispatch=1\r\nFontSize=1\r\n"
    (ud / "env.ini").write_bytes(b"\xff\xfe" + ini.encode("utf-16-le"))
    f(c / "ProgramData" / "ContosoPinyin" / "AiCache" / "model_synthetic.bin")
    (c / "ProgramData" / "ContosoPinyin" / "cloud.ini").write_bytes(b"[Update]\r\nAutoCheck=1\r\nChannel=stable\r\n")
    f(c / "LocalAppData" / "ContosoPDF" / "pdf_viewer.exe")

    d = root / "fabrikam"
    app = d / "Programs" / "FabrikamDrive"
    for n in ["FabrikamDrive.exe", "FabrikamDriveHost.exe", "FabrikamUpdate.exe", "ad_helper.exe", "FabrikamReport.exe"]:
        f(app / n)
    f(app / "resources" / "app.asar")
    f(app / "resources" / "app-update.yml", "provider: generic\nurl: https://updates.fabrikam-drive.example/\n")
    f(app / "resources" / "build-info.json", json.dumps({"name": "fabrikam-drive", "version": "5.3.1"}))
    f(app / "resources" / "plugins" / "promo_popup.exe")
    f(app / "resources" / "plugins" / "ai-assistant" / "index.js", "// synthetic\n")
    f(d / "LocalAppData" / "fabrikam-drive-updater" / "pending" / "FabrikamDrive-Setup-5.4.0.exe")
    f(d / "Roaming" / "FabrikamDrive" / "settings.json",
      '{\n  "promotions": { "showBanner": true, "lastShown": "2030-01-01" },\n  "window": { "width": 1200 }\n}\n')

    return {
        "CONTOSOPINYIN_ROOT": str(pf),
        "CONTOSOPINYIN_USERDATA": str(c / "LocalLow" / "ContosoPinyin.users"),
        "CONTOSOPINYIN_SHARED": str(c / "ProgramData" / "ContosoPinyin"),
        "CONTOSOPINYIN_PDFDIR": str(c / "LocalAppData" / "ContosoPDF"),
        "FABRIKAMDRIVE_ROOT": str(app),
        "FABRIKAMDRIVE_UPDATERCACHE": str(d / "LocalAppData" / "fabrikam-drive-updater"),
        "FABRIKAMDRIVE_APPDATA": str(d / "Roaming" / "FabrikamDrive"),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fake-root", type=Path, help="also create synthetic install trees under this folder")
    ap.add_argument("--no-build", action="store_true", help="skip building the single-file scripts")
    ap.add_argument("--out", type=Path, help="write every fixture flat into this folder instead of examples/ "
                                               "(used by the fleet-guards data_boundary reproducibility check)")
    a = ap.parse_args()

    for key, manifest, hooks in FIXTURES:
        d = a.out if a.out else EXAMPLES / key
        mpath = d / f"{key}.manifest.json"
        write(mpath, json.dumps(manifest, indent=2) + "\n")
        hpath = None
        if hooks:
            hpath = d / f"{key}.hooks.ps1"
            write(hpath, hooks, bom=True)
        if not a.no_build:
            build(mpath, hpath, d / f"{manifest['taskPrefix']}Debloat.ps1")
        print(f"wrote {d}")

    if a.fake_root:
        env = fake_tree(a.fake_root.resolve())
        print("\nfake installs created; point the scripts at them with:")
        for k, v in env.items():
            print(f"  $env:{k} = '{v}'")
        (a.fake_root / "env.json").write_text(json.dumps(env, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
