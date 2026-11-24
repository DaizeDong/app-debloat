# Profile: Electron and CEF Desktop Apps

Apps whose UI is Chromium: Electron (`resources\app.asar`, `app-update.yml` or Squirrel `Update.exe`) or CEF (`libcef.dll`, `*.pak`, a vendor host exe). Often the secondary profile for a netdisk, IM or office app. Older Electron-based Quark netdisk builds are the reference case for updater drift; Quark 7.x is a Chromium fork, see `chromium-fork.md`. Baidu Netdisk 8.x uses an Electron UI (`netdisk-downloader.md`).

## Architecture and Where the Junk Lives

- **Main process plus Chromium children** (`--type=renderer`, `gpu-process`, `utility`). Children are core; never block by the main exe name because children share it.
- **App code** in `resources\app.asar` (Electron) or vendor `*.pak` / zip resources (CEF). Ads, banners, AI side panels, "recommended" tabs and promo windows are usually just JS/HTML views and remote URLs loaded at runtime, so most junk is in the same process as core UI.
- **Native helpers** next to the main exe: updater, crash reporter, a tray or "assistant" exe, a second updater for a bundled product (some builds of vendor suites ship one per product, unverified per version), shell extension DLLs, a protocol handler.
- **Install scope**: per-user installs under `%LOCALAPPDATA%\Programs\<app>` or `%LOCALAPPDATA%\<app>` can be rewritten by the app without UAC. Machine-wide installs under `%ProgramFiles%` need an elevated updater or a service.

## Launch, Persistence and Re-Install Vectors

| Vector | Where to look | Proof it is blocked |
|---|---|---|
| electron-updater (NSIS) | `resources\app-update.yml` (feed URL, `publisherName`), staging in `%LOCALAPPDATA%\<name>-updater\pending` | No new files in the staging dir after a forced "check for updates"; version unchanged after restart |
| Squirrel.Windows | `%LOCALAPPDATA%\<app>\Update.exe`, `app-<version>` sibling dirs, `packages\RELEASES` | No new `app-*` dir after a check; `Update.exe --checkForUpdate` style runs fail |
| Vendor native updater | `*Update*.exe`, `*Upgrade*.exe`, versioned plugin dirs under `%APPDATA%` | Process never starts (Sysmon 1 / Procmon) |
| Main exe downloads a full installer | Network from the main process to CDN, large files in `%TEMP%` | No large download; installer never runs |
| Startup | Run key, Startup folder shortcut, scheduled task named after the app | autorunsc diff clean |
| Shell integration | Context menu handlers, `Explorer\MyComputer\NameSpace` and `Desktop\NameSpace` entries, file associations re-taken on update | Explorer shows none after reboot |

Staging paths drift between versions (the Electron-based Quark client moved its update path between v2.6.5 and v4.1.7: https://www.52pojie.cn/thread-2056012-1-1.html). Never hard-code: resolve the staging dir from the updater config, the strings in the updater, or a Procmon capture of one real check.

## Gates

- **`app-update.yml`**: the electron-updater feed. Pointing `url` at an unreachable loopback address is the common community lever for the Electron-based Quark 3.x (below). It is a file in the install dir, so it needs the normal risk tier, and an update or repair rewrites it.
- **Local settings**: `%APPDATA%\<app>\` JSON or LevelDB (`Local Storage\leveldb`), `Preferences`, and vendor ini. Plain JSON and ini files are set with the engine's `json-set` and `ini-set` actions while the app is closed. Look for `autoUpdate`, `autoLaunch`, `floatBall`, `takeOverBrowser`, `showInMyComputer` keys. Prefer the vendor setting when it is persisted and honored after restart.
- **Remote config**: feature flags fetched at start (often JSON from a config host). Junk that appears without any local change is server-driven; only behavior probes and network-level blocks touch it (see `generic.md`, "Remote Config Popups").
- **ASAR integrity**: Electron can verify `app.asar` header hashes at startup and terminate on mismatch. Windows support from Electron 30 when the `EnableEmbeddedAsarIntegrityValidation` fuse is on; usually paired with `OnlyLoadAppFromAsar`. Read the fuses with `npx @electron/fuses read --app <exe>` (read-only). Even when the fuse is off, editing `app.asar` is a binary patch for our purposes.
- **Update signature check**: electron-updater verifies Authenticode of downloaded NSIS updates against `publisherName` in `app-update.yml`. Not a lever; it means a spoofed feed will not install anything, so a dead feed is enough.
- **Web bundles**: the UI's html and js (`app.asar`, `*.pak`, a resources folder of html pages) hold the settings keys, their defaults and the labels the owner sees. `scripts/strscan.py --set settings` over them, plus a `--keywords-file` with the UI labels, maps each key to its menu path for the Settings Map (`pipeline.md` P2 step 6). Chromium `.pak` entries compressed with brotli are scanned only when the `brotli` Python module is importable; the output counts the skipped ones. Ad and fingerprinting SDKs in the bundle show up the same way (a `--keyword` per SDK name). Reading a bundle is fine; editing it is patching.
- **Debugging port**: an embedded Chromium can open a remote debugging port, sometimes only when a server switch allows it. Any local process (and, bound to all interfaces, the network) can then drive the UI and read its session. Detect it with `remote_debugging` on `launch_monitor.ps1` proc lines, a `DevToolsActivePort` file in the profile newer than the last run, `strscan.py --set devtools` for the switch strings, and the listener's `listen_scope`. Windows Firewall does not filter loopback, so a loopback port has no firewall lever; unless a local switch gates it, record the port and its server switch as a residual.

## Core: Do Not Touch

- The main exe, all Chromium child processes, `resources\app.asar` / `*.pak`, `libcef.dll` / `ffmpeg.dll` / ICU data.
- The protocol handler if a core flow needs it (netdisk "open in client" from the browser).
- The sync or transfer engine process when it is a separate exe.
- User data dirs (`%APPDATA%\<app>`): back them up in the journal before editing any setting file inside.

## Levers

Use:

1. Vendor settings for auto-update, autostart, floating widget, browser takeover, Explorer namespace. Verify they persist across restart.
2. Updater staging dir neutralized: delete the staging dir and put a same-name read-only file there, or keep the dir and add a deny-write ACE for the user. This is outside the install root, so it is allowed even in the out-of-process tier.
3. IFEO or placeholder on vendor-unique updater exes (not on the main exe name, which children share).
4. Outbound firewall rule by program path for the native updater exe only.
5. Feed URL in `app-update.yml` pointed at an unreachable loopback, normal tier only, re-asserted by P7 because repairs rewrite it.
6. `Shell Extensions\Blocked` for context menu CLSIDs; remove only the vendor namespace keys the journal recorded.

Avoid:

- Editing `app.asar` or `*.pak` (integrity fuse, signature, and it pins you to one version).
- Firewall-blocking the main exe (kills login, sync, core content).
- Launch flags such as `--disable-*` injected via shortcuts: the app is often started by other paths.
- Blocking shared CDNs in hosts.
- Running an old version offline as the plan; version pinning is the owner's choice, not a lever.

## Integrity, Anti-Tamper and Ban Risk

- Tier normally "normal" for accountless or low-risk accounts; netdisk and IM accounts follow their own profile.
- Integrity probe: rename a non-critical file in `resources` (for example a locale `.pak` the owner does not use), start, observe self-check, repair download or refusal, restore.
- ASAR integrity fuse on: anything inside `app.asar` is off limits even in the normal tier.

## Verification Probes

- App starts, main window renders, login state survives restart (no forced re-login).
- The core flow from the contract works end to end (see the domain profile: list/upload/download for a netdisk, send-to-self for IM).
- Forced "check for updates" in the UI: staging dir stays empty, no updater process, version string unchanged after a full restart.
- Reboot: no autostart unless the contract keeps it; no tray widget; Explorer namespace gone.
- Process tree after 10 minutes idle: only main plus Chromium children plus contract-approved helpers.

## Public Projects and Recipes

- Quark netdisk 3.x update block (point `app-update.yml` `url` at loopback, make `%LOCALAPPDATA%\quark-cloud-drive-updater` read-only or replace `pending` with a file; install offline first): https://meta.appinn.net/t/topic/72072, https://blog.csdn.net/lingzhentaor/article/details/148290929, https://www.mydigit.cn/thread-536690-1-1.html (community, version-specific, unverified on 4.x and later; does not apply to Quark 7.x, which is a Chromium fork: `chromium-fork.md`).
- Quark staging path drift between versions: https://www.52pojie.cn/thread-2056012-1-1.html
- Electron ASAR integrity and fuses: https://www.electronjs.org/docs/latest/tutorial/asar-integrity and https://www.electron.build/docs/tutorials/adding-electron-fuses/
- electron-updater update signature verification: https://www.electron.build/docs/features/security
- Electron autoUpdater (Squirrel / MSIX selection on Windows): https://www.electronjs.org/docs/latest/api/auto-updater/
- REA can inspect Electron/ASAR desktop apps read-only (`inspect_desktop_application`): https://github.com/morluto/rea
