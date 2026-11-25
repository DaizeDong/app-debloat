# Profile: Office and PDF Suites

Document suites and PDF tools that bundle a cloud drive, a home page with feeds, template and membership upsell, notifications, AI assistants and an aggressive updater. WPS Office is the reference case; the structure also fits PDF editors and other suites that take over file associations.

## Architecture and Where the Junk Lives

WPS Office (Windows), as reported by community sources; verify on the installed version:

- **Editors**: `wps.exe` (Writer), `et.exe` (Spreadsheets), `wpp.exe` (Presentation), PDF component. Core. Ads and AI panels inside the editor are part of the same process.
- **Home and web views**: an embedded CEF host (`promecefpluginhost.exe` and "W Prome CEF SubProcess" children) that renders the home page, feeds and promo panels. It is restarted by the main process when killed (https://blog.csdn.net/m0_74042991/article/details/157176092).
- **Cloud docs**: `wpscloudsvr.exe` / `wpscloudsvrimp.dll` (tray icon, sync, and historically ad delivery), Explorer namespace entries ("WPS cloud docs" under `Explorer\MyComputer\NameSpace` and `Explorer\Desktop\NameSpace`, CLSID reported as `{5FCD4425-CA3A-48F4-A57C-B8A75C32ACB1}`).
- **Notifier and center**: `wpscenter.exe`, `wtoolex\wpsnotify.exe` (hot news popups, task-bar bubbles).
- **Updater**: `wtoolex\wpsupdate.exe`, `WpsUpdateTask` scheduled task, `WpsUpdateService` service.
- **Config tool**: `ksomisc.exe` ("Configuration and repair tool"), the official switch panel.
- **OEM config**: `office6\cfgs\oem.ini` and `cfgs\oeminfo` (branding, feature flags; enterprise builds carry more). The format is documented by the community at https://github.com/ShinjoKurumi/WPSOfficeConf.
- Install scope: often per-user under `%LOCALAPPDATA%\Kingsoft\WPS Office\<version>\` (writable without UAC) or `%ProgramFiles(x86)%\Kingsoft\WPS Office\<version>\`. Versioned dirs mean placeholders in an old dir stop working after an update.

## Launch, Persistence and Re-Install Vectors

| Vector | Form | Note |
|---|---|---|
| Update task and service | `WpsUpdateTask`, `WpsUpdateService` | Deleted tasks come back on restart (https://blog.csdn.net/BerryKiki/article/details/129928689); disable and lock instead |
| Updater exe | `wtoolex\wpsupdate.exe` | Community lever is a same-name dummy file (same source) |
| CEF host watchdog | Main process restarts the web host | Not a vector to fight; the host is shared by core UI |
| Cloud service | `WPSCloudService`, `wpscloudsvr.exe` autostart | Optional if cloud docs are not in the contract |
| File associations | Update re-takes `.docx/.xlsx/.pptx/.pdf` | Config tool has "re-associate on upgrade" off switch (https://bbs.wps.cn/topic/14841) |
| Explorer integration | Namespace items, context menus, "upload to cloud" verbs | Re-registered by repair |
| Repair from config tool | Restores removed components | P7 must re-assert |

## Gates

- **Config tool switches** (`ksomisc.exe`, Advanced): update settings (auto-update off, no re-association on upgrade), other options ("WPS hotspots and ad push" off). Official and supported; community posts say the ad switch disappeared after WPS dropped third-party commercial ads in late 2023 (https://bbs.wps.cn/topic/14841, https://bbs.wps.cn/topic/31390). Verify what the installed build shows.
- **In-app settings**: notifications, hot news, recommendations, startup page, "keep running after exit", cloud auto-sync, startup with Windows.
- **`oem.ini` / cfgs**: feature flags and branding. Editing them is an in-install-dir change and may be overwritten on update; normal tier only.
- **Windows notification settings** per app (AUMID) for toast ads.
- **Server switches**: home feed and promo content; local changes do not reach them.

## Core: Do Not Touch

- Editors and their shared libraries, the PDF component if in the contract, fonts and templates the owner uses.
- The CEF host when the home page or account panels are part of the contract (it is shared UI plumbing).
- License and activation state (enterprise or education builds): never edit `oem.ini` keys related to licensing; that is circumvention, out of scope.
- Document files, recent list, backup and autosave folders.

## Levers

Use:

1. Config tool: auto-update off, re-association on upgrade off, ad/hot-news options off where present.
2. In-app: hot news, recommendations, notifications, startup, "keep running after exit" off; cloud sync off if not in the contract.
3. Windows notifications off for the vendor AUMIDs (the owner can still see in-app messages).
4. Disable `WpsUpdateTask` and `WpsUpdateService`; placeholder plus deny-write on `wpsupdate.exe` in the current version dir (normal tier), or IFEO on the updater name.
5. Notifier exes (`wpsnotify.exe`, `wpscenter.exe`): placeholder or IFEO after confirming they are not needed for editing.
6. Explorer namespace and context menu: remove only the journaled vendor keys; `Shell Extensions\Blocked` for vendor shell extension CLSIDs.
7. Outbound firewall rule by program path for `wpscloudsvr.exe` only if cloud docs are not in the contract (community and the WPS handbook note it breaks cloud sync: https://wpsoffice.dev/guides/disable-ads.html).

Avoid:

- Killing or blocking the CEF host (it respawns and core panels break).
- Firewall-blocking the editors (login, templates, online fonts, license checks fail).
- Downloading "pure", "green" or "education" builds from third parties as a lever (out of scope, supply-chain risk).
- hosts entries for vendor CDNs shared by templates and fonts.
- Deleting `oeminfo` or OEM folders on enterprise builds without knowing what they gate.

## Integrity, Anti-Tamper and Ban Risk

- Account optional; enterprise accounts carry policy risk, not ban risk. Ask the owner if the install is managed by an employer; if so, stop: changes to managed software are the admin's call.
- Integrity probe: rename one notifier exe in the version dir, start an editor, check for repair prompts or self-heal; restore.
- Updates create a new version dir; the P7 task must resolve the current dir from the Uninstall key or the newest version folder, then re-assert.

## Verification Probes

Use synthetic documents only.

1. Create `app-debloat-probe.docx` from the agent: open it in Writer via the command line, confirm the window title, close.
2. Same for a spreadsheet and a presentation if in the contract.
3. Save-as round trip: open a synthetic file, save as PDF (if in the contract) via the suite's command-line or automation interface where available; confirm the output exists and is non-empty.
4. File associations: `.docx` and `.xlsx` open in the program the owner chose in the contract (read `HKCU\...\FileExts\<ext>\UserChoice`, read-only).
5. Cloud docs (only if in the contract): sign-in state unchanged.
6. One hour idle plus a reboot: no hot-news or promo window (enumerate top-level windows by PID), no updater process, version dir unchanged.

## Public Projects and Recipes

- WPS official guidance (settings, notifications, startup) and its view on hosts/registry tricks: https://www.wps.cn/article/qyhoxotC.html
- WPS official blog on firewall-blocking cloud helper exes: https://www.wps.com/blog/how-to-disable-annoying-ads-in-wps-office
- Config tool switches and their history: https://bbs.wps.cn/topic/14841, https://bbs.wps.cn/topic/31390
- Updater block (task, config tool, `wpsupdate.exe` dummy): https://blog.csdn.net/BerryKiki/article/details/129928689
- Cloud docs tray and namespace removal, `wpscloudsvrimp.dll`: https://blog.csdn.net/super_strings/article/details/106530019 (2019 build, partly stale).
- CEF host respawn and service list: https://blog.csdn.net/m0_74042991/article/details/157176092
- `oem.ini` format: https://github.com/ShinjoKurumi/WPSOfficeConf (for reading gates only; never for licensing keys).
- Older firewall and proxy methods (2017, stale, hosts list contains cloud hosts): https://zhivkosk.wordpress.com/2017/10/12/remove-ads-in-wps-office
