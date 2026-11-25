# Profiles: How to Pick One

A profile encodes what is DIFFERENT for one kind of app: where the junk lives, how it comes back, what gates it, what is core, which levers are safe, and how to prove core function still works. The pipeline (P0 to P7) is the same for every app; the profile only changes the answers to the per-app checkpoints. Load exactly one primary profile at P0, plus at most one secondary profile when the app straddles two kinds (for example a netdisk client built on Electron).

## Decision Table (P0)

Answer in order; the first match is the primary profile.

| Question (Check on Disk, Not from Memory) | Primary Profile |
|---|---|
| Registered as a TSF text service (`HKLM\SOFTWARE\Microsoft\CTF\TIP\{CLSID}`) or ships `*.ime` files | `ime.md` |
| Publisher is Tencent, or it ships `QQProtect`, `QPCore`, `WeixinUpdate.exe`, a QQNT `versions\config.json` | `tencent-im.md` |
| Talks to device firmware or a vendor ACPI/WMI driver (fan, power mode, keyboard light, battery limit), or was preinstalled by the PC maker | `oem-utility.md` |
| Cloud drive or download manager (sync engine, transfer queue, browser hand-off protocol) | `netdisk-downloader.md` |
| Office or PDF suite (document editor, file associations, cloud docs namespace) | `office-suite.md` |
| Ships a whole Chromium browser under its own brand: `<version>\` folder beside the exe, `chrome_elf.dll`, `User Data\Local State` (Quark 7.x) | `chromium-fork.md` |
| Main window is Chromium: `resources\app.asar`, `*.pak` + `libcef.dll`, `app-update.yml`, Squirrel `Update.exe` | `electron-cef-app.md` |
| None of the above | this file, section "No Profile Fits" |

Secondary profile: if the primary is netdisk, office, IM or OEM and the UI is Electron/CEF, also read `electron-cef-app.md` for the updater and resource gates. Record both in the analysis ledger.

Quick evidence commands (read-only):

```powershell
# Electron / CEF markers under a resolved install root
# (-Include with -LiteralPath does not filter on PS 5.1, so filter by name)
Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(app\.asar|app-update\.yml|libcef\.dll|Update\.exe)$|\.pak$' } | Select-Object FullName
# TSF registration
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\CTF\TIP' | ForEach-Object { (Get-ItemProperty "$($_.PSPath)\LanguageProfile\*\*" -ErrorAction SilentlyContinue).Description }
# Publisher of every exe in the root
Get-ChildItem -LiteralPath $root -Recurse -Filter *.exe | ForEach-Object { (Get-AuthenticodeSignature -LiteralPath $_.FullName).SignerCertificate.Subject } | Sort-Object -Unique
```

## What Every Profile States, and What the Pipeline Does with It

| Profile Section | Feeds Pipeline Step |
|---|---|
| Architecture and Where the Junk Lives | P1 inventory scope |
| Launch, Persistence and Re-Install Vectors | P1 snapshot list, P3 vector matrix |
| Gates | P2 gate hunt |
| Core: Do Not Touch | P0 core-function contract, P4 classification |
| Levers (Use / Avoid) | P4 plan, P5 script primitives |
| Integrity and Ban Risk | P0 risk tier (normal or out-of-process only) |
| Verification Probes | P6 core-function probe |
| Public Projects and Recipes | P2/P3 hypotheses only, every claim re-verified on the installed version |

Risk tiers used by every profile:

- **normal**: in-install-dir changes allowed (placeholders, ACL on vendor files), after the integrity probe passed.
- **out-of-process only**: no file in the install root is renamed, replaced, patched or ACL-locked; only services, tasks, IFEO on helper names, firewall rules by program path, updater staging dirs outside the install root, and vendor settings. Mandatory for account-bound apps with a documented ban history (Tencent IM) and whenever the integrity probe shows a self-check, self-repair or forced logout.

## Lever Order (Shared by All Profiles)

Least likely to be flagged or reverted first:

1. Vendor setting or vendor config gate (persisted where the app actually reads it).
2. Same-name placeholder plus deny-write ACL on helper binaries and updater staging dirs.
3. Disable (never delete) vendor services; record original start type and recovery actions.
4. Disable (never delete) scheduled tasks.
5. Outbound firewall rule by program path for a helper that has no core duty.
6. IFEO `Debugger` for vendor-unique helper names only, pointing at a path that does not exist (the engine's `ifeo-block`); re-read after a delay because Defender can remove it.

Never in any profile: binary patching, redistributing modified installers, extracted keys or decrypted configs in the public repo, hosts entries for shared CDNs or Microsoft domains, `sc delete`, disabling Defender, killing processes by name.

## No Profile Fits

Treat the app as unknown and derive the profile answers yourself during P1 to P3. Typical cases: download accelerators (Thunder/Xunlei), image viewers and compressors from portal vendors (2345 family), translation clients (Youdao Dictionary; see "Translation Clients" below), driver-update utilities, game launchers.

Checklist for an unknown app:

- **Junk inventory**: every process it starts in 30 minutes of normal use plus one reboot; for each, signer, parent, command line, window titles (popups map to PIDs by enumerating top-level windows).
- **Persistence**: `autorunsc` diff before and after install and after a day of use; include services with recovery actions, tasks (including those registered under a GUID name), Run keys in both views, Shell extensions, protocol handlers, file associations, IFEO keys the vendor wrote itself, WMI subscriptions.
- **Re-install vectors**: own updater exe, a "repair" or "diagnose" exe, a SYSTEM service that writes the install dir, a per-user install under `%APPDATA%` that needs no admin to rewrite, MSIX/Store wrapper, scheduled "check" task, the main exe downloading a full installer on start.
- **Gates**: look for plain ini/json/yml next to the exe first, then registry under `HKCU\Software\<Vendor>`, then resource archives (zip skins, pak, asar), then encrypted blobs (high entropy, base64, fixed header).
- **Installer verbs**: the main exe often asks its own installer to plant things on request: a right-click entry, a default-reader takeover, Office add-ins, a browser plugin, an autostart value, shortcut AppUserModelIDs. List the verbs (`scripts/strscan.py --set verbs` on the installer and the main exe; `whole` hits are the likely verbs), map each to the keys it writes (`pe_triage.py --grep <verb>` for the call site, or one capture), and note which in-app switch fires it. That table is the fastest map of what a "core" installer can do.
- **Environment switches**: vendor `<PREFIX>_DISABLE_*` names read by the main exe (`strscan.py --set env`) can turn off an auto-update, a crash reporter or a login popup. Lever: `reg-set` on `HKCU\Environment`, read at the next logon, after one probe that shows the effect. Never set one that disables a signature or integrity check.
- **Cross-app sweep**: `pipeline.md` P1 steps 5 and 6 (browser hosts and extensions, Office add-ins, Explorer namespace and overlays, defaults, listeners, P2P), even when nothing in the UI hints at them.
- **Core contract**: one sentence per core feature and one probe per sentence before any change.
- **Ban risk**: does any core feature need a server account? If yes, ask the owner for explicit consent for this app and default to out-of-process only until the integrity probe says otherwise.

Example sources for this bucket (hypotheses only):

- Youdao Dictionary client internals and update checks: https://blog.xlab.app/p/12f6b614/ (unverified for current versions).
- Generic reversible OS-level primitives (ideas only, AGPL, do not copy code): https://github.com/undergroundwires/privacy.sexy
- Declarative tweak manifest with original values: https://github.com/ChrisTitusTech/winutil (`config/tweaks.json`).
- Lock-not-delete against self-repair, independent confirmation: https://github.com/ArabidopsisDev/SogouFucker and https://www.v2ex.com/t/678665
- Persistence inventory: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns and https://github.com/last-byte/PersistenceSniper
- Ad and tracker domain seeds (hypotheses, never pasted into hosts): https://github.com/privacy-protection-tools/anti-AD

## Translation Clients

Notes from one run on a Youdao Dictionary desktop build; unverified for other versions and other vendors, and they contain no keys.

- Per-user install under `%LOCALAPPDATA%` with no services; everything it needs to update itself runs as the user, without UAC.
- The data dir may be spelled differently from the product name (Youdao uses `Yodao`), so search both spellings, for example `-App 'Youdao|Yodao'`.
- The updater stages a new version in a timestamped folder (`updaters\<timestamp>`) and swaps it in later; an interrupted swap can leave the app unable to start (`pipeline.md` P0 step 7).
- The AI helper lives in its own folder (`Application\Stable`) and is started by the main client.
- The installer may rewrite the AppUserModelID of Start Menu and Desktop shortcuts, including other apps' shortcuts. That is a write outside its own roots (`pipeline.md` P3).
- Ads and AI prompts are drawn in-process from server config; see the next section.
- The client's own diagnostic log (Youdao: `Yodao\DeskDict\logs\diagnostic\diagnostic.log` under the per-user data dir, JSON lines with a `level` field) is the best P6 evidence that blocked parts cause no errors (`pipeline-field-notes.md`). Summarize it; do not copy it into DATA.
- Lookup, OCR and document translation need typed input. Under a no-input rule they go to the owner's after-reboot list.
- Its intrusions were capability-style: the main exe asks its installer (verbs above) to add a right-click entry on every file and folder, take the PDF default "with tamper protection", register Office add-ins and install a browser extension through the browser's external-extension keys. All were off in that run, each behind a plain key in the per-user `config.ini`. Those keys are the levers (`ini-set` with `onlyWhenNotRunning`, since the main exe rewrites the file from memory at start and exit; list the file in `core.preserve`). Off and anchored, such an action does nothing until something flips the key; set `reapply`.
- Native messaging hosts were registered for Chrome (HKCU) and Edge (HKLM, 32-bit view) although the install is per-user; the HKLM one needs an elevated `-Apply` and `view: 32` (`levers.md`, Native Messaging Host).
- An input assistant that watches and types into other apps, a clipboard watcher and a desktop floating ball each had their own plain key; word grab injects hook DLLs only while it is on (`pipeline.md` P1 step 8).
- The embedded browser's debugging port sat behind a server whitelist (`electron-cef-app.md`, Gates).

## Remote Config Popups

Many popups, promotion tabs and AI prompts are switched on by a config the app downloads at start, not by any local file.

- **Find the key**: capture the config response or its cache in the user data dir, note when and where the popup appears, and match its URL, text, campaign ID or interval (for example a minimum-hours-between-popups field set to 0) against the config keys. Confirm with one toggle test before writing it in the ledger as a gate.
- **Editing the cache is not durable**: the next fetch overwrites it, and some apps verify it. Do not plan an action on the cache; at most record it as an inferred gate.
- **Durable options**: an in-app switch that the config honors, a per-binary firewall rule when the config comes from a helper exe (not the main exe), or network-level blocking of the config host. Network-level blocking (router, DNS filter or proxy rule) is the owner's opt-in and lives outside the script; vendor config hosts are often shared with core features.
- **Otherwise it is a residual**: `plan.md` section 5 names the config source, the popups it drives, and the probe that shows them.

## Out of Scope for Every Profile

Uninstalling the app, recommending a replacement app, cracking or bypassing paid tiers, malware cleanup, browser ad blocking, Windows-wide debloat. Where a profile mentions a community alternative (for example an open-source replacement for an OEM utility), it is a note for the owner, not a lever the skill applies.
