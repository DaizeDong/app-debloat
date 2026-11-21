# Profile: Netdisk Clients and Download Managers

Cloud drive clients (Baidu Netdisk, Quark, Aliyun Drive, 115 and similar) and download accelerators (Thunder/Xunlei style). Account bound, long-running transfer engines, heavy self-update. If the UI is Electron/CEF, also load `electron-cef-app.md`; if the client is part of a Chromium-fork browser (Quark 7.x), load `chromium-fork.md` as the primary profile and this one as the secondary.

## Architecture and Where the Junk Lives

- **UI shell** (often Electron, CEF or a DirectUI skin engine) that shows banners, membership upsell, splash ads, "recommended" feeds, AI side panels; Quark 7.x is a Chromium-fork browser with the drive inside it (`chromium-fork.md`); Baidu 8.x is Electron (below).
- **Transfer and sync engine**: a separate host process (Baidu: `baidunetdiskhost.exe`) or a kernel DLL. Core.
- **Browser hand-off helper**: a local listener or protocol handler that lets the web page start a client download (Baidu: `YunDetectService.exe`, which also listens on a local port). Core if the owner starts downloads from the browser.
- **Updaters**: one or more, often per-user so they can rewrite the client without UAC (Baidu: `AutoUpdate\` folder, `kernelUpdate.exe`, `autoDiagnoseUpdate.exe`; Quark 7.x: SYSTEM updater services woken by the browser exe, see `chromium-fork.md`).
- **Sync-space and Explorer integration**: virtual drive or "My Computer" namespace item, context menu extensions, file associations for media.
- **Bundled services**: a utility service (Baidu: `BaiduNetdiskUtility`), sometimes an MSIX/Store launcher that starts the desktop exe and its helpers.

Baidu Netdisk installs per-user by default under `%APPDATA%\baidu\BaiduNetdisk` with settings in `%APPDATA%\baidunetdisk` (per the uninstall test at https://mole.fit/windows/tested-apps/baidu-netdisk). Never assume; resolve the root from the Uninstall key.

## Baidu Netdisk 8.x

Observed in one run on one 8.x build; unverified for other builds.

- **UI is Electron**: `Unite.exe` with `resources\app.asar` hosts the window; skin-zip recipes for 7.x do not apply. Feature plugins run in separate plugin host processes whose command line carries a `plugin_id`; map each host to its plugin from that argument, not from the exe name, which they share.
- **`kernelUpdate` is started by the kernel plugin host**, not by the UI or a task, so blocking only the `AutoUpdate` folder leaves this path open.
- **Forced full package on launch**: the client downloaded a full cab package (about 800 MB, marked as a forced update level) on the first start, which confirms the community report in the vector table for this build. The first observed launch can therefore change the fingerprint; follow `pipeline.md` P0 step 7.
- **`PersonalSetting.xml` is encrypted**: settings cannot be edited as text. Prefer the in-app switches, then verify them by behavior.
- **`BaiduNetdiskUtility` SYSTEM service reads its config from a user-writable path.** Any process running as the user could change what a SYSTEM service does, which is a local privilege escalation risk. Tell the owner even if the plan does not touch it; disabling the service (if not in the contract) also removes that risk.
- **Module checks across bitness**: some hosts are 32-bit. A 64-bit `tasklist /m` misses their modules; use the module lists from `scripts/elevated_readonly.ps1` or the inventory before deciding a DLL is unused.

## Launch, Persistence and Re-Install Vectors

| Vector | Typical form | Notes |
|---|---|---|
| Own updater dir | `AutoUpdate\` (Baidu), `AutoUpdate\Download\MainApp` holds a downloaded full package | A community report says new builds download a ~400 MB cab on every start until the dir is locked (https://www.bilibili.com/opus/790781351497302041, unverified) |
| Kernel or diagnose updater | `kernelUpdate.exe`, `autoDiagnoseUpdate.exe` | Separate path from the UI updater; deleting `AutoUpdate` alone is not enough (https://meta.appinn.net/t/topic/72072) |
| electron-updater | `app-update.yml` + `%LOCALAPPDATA%\<name>-updater\pending` | Older Electron-based Quark builds; path drifts per version |
| Run key / task | Autostart of the client and the hand-off helper | |
| Service | Utility service with SYSTEM rights | Disable, never delete |
| Self-written IFEO keys | The vendor may create IFEO entries for its own host exe (the brief flags `baidunetdiskhost.exe`) | Record before touching; do not remove vendor IFEO keys blindly |
| MSIX/Store wrapper | Store package that launches the desktop exe | Permissions on the MSIX do not constrain the desktop exe |
| Shell integration | Context menu, sync-space namespace, media associations re-taken on update | |

## Gates

- **Skin and layout resources**: DirectUI skins as zip of XML (Baidu: `skin\duiengineskin.zip`, `xml\MainPanel\TitlePanel.xml`, `TransPanel\TransLeftPanel.xml` hold top and transfer-panel ad slots, per https://github.com/mustvvvics/BaiduNetdisk-RemoveAD for 7.26). Editing them is an in-install-dir change: normal tier only, after the integrity probe, and the client may restore them (reported at https://blog.csdn.net/weixin_42398822/article/details/117827360).
- **Settings**: auto-update, autostart, floating ball, clipboard link detection, browser takeover, "show in My Computer". Prefer them when they persist.
- **Server switches**: splash ads, popups and membership prompts are fetched at runtime; local edits do not reach them. Community proxy rules that block specific image CDNs exist (https://github.com/217heidai/adblockfilters/issues/217) but those hosts are shared with web content; treat as owner opt-in, never as default.
- **Updater configs**: `app-update.yml` for Electron clients.

## Core: Do Not Touch

- The main client exe, the transfer host process, the kernel DLLs and the engine's working dirs.
- The browser hand-off helper if browser-started downloads are in the contract (blocking it breaks "open in client"; https://blog.csdn.net/qq_42114504/article/details/125834778 notes it can be disabled at startup while the client still starts it on demand).
- Download destination folders and any `.downloading` partial files.
- Login tokens and the user data dir.

## Levers

Use:

1. Vendor settings off (autostart, floating ball, clipboard monitor, browser takeover, Explorer item).
2. Updater exes and dirs: same-name placeholder plus deny-write ACE on the updater folder and its download subfolder (normal tier), or IFEO / program-path firewall rule on the updater exes (out-of-process tier). Cover every updater, not just the one in the UI.
3. Disable the utility service if it is not in the contract; record start type and recovery actions.
4. Disable autostart Run entries and tasks for helpers.
5. `Shell Extensions\Blocked` for context menu handlers; remove only journaled namespace entries.

Avoid:

- Firewall-blocking the main exe or the transfer host (login and transfers die).
- Deleting the updater instead of locking it (the client re-downloads it).
- Blocking shared CDNs in hosts (they also serve file content and other apps).
- Anything that touches speed limits, membership checks or paid features. That is circumvention, out of scope.
- Running a downgraded client offline as the plan. Version pinning is the owner's decision; if they choose it, the lever list above is what keeps it pinned.

## Integrity, Anti-Tamper and Ban Risk

- Account bound. Ask the owner for explicit consent for this app before P4. Use a throwaway or secondary account and a VM snapshot for the first run when possible.
- No public evidence of bans for disabling updaters or editing skins was found; treat as unverified, not as safe.
- Integrity probe: rename one non-critical resource (an unused skin image), restart, watch for repair downloads or a refusal; restore.
- Old clients can be refused by the server at login; that is a forced update, not a lever failure. Record it.

## Verification Probes

Use a dedicated test folder and a synthetic file (for example 1 MB of random bytes named `app-debloat-probe.bin`), never the owner's files.

1. Client starts, stays logged in after restart.
2. List the root and one subfolder of the account (UI or an exposed local API if one exists).
3. Upload the probe file to a dedicated test folder; confirm it appears with the right size.
4. Download it back to a temp folder; compare SHA-256.
5. Delete the probe file from the cloud and the local copy.
6. If in the contract: start a download from the web page and confirm the client picks it up.
7. Forced update check: no updater process, staging dir unchanged, version unchanged after restart and reboot.
8. After 10 minutes idle: no popup windows (enumerate top-level windows by PID), no updater network traffic.

## Public Projects and Recipes

- Baidu Netdisk update block by renaming `AutoUpdate`, `kernelUpdate.exe`, `autoDiagnoseUpdate.exe`, optionally plus "Don't run specified Windows applications" policy: https://zhuanlan.zhihu.com/p/1991531504124306894, https://www.cnblogs.com/GiveCookies/p/18597165, https://zhuanlan.zhihu.com/p/645259468 (community, version-specific).
- Baidu background residue (utility service, `YunDetectService.exe`, `kernelUpdate`, MSIX launcher, `AutoUpdate\Download\MainApp` lock): https://www.bilibili.com/opus/790781351497302041 (unverified).
- Two update paths, deleting the folder is not enough: https://meta.appinn.net/t/topic/72072
- Baidu skin ad slots: https://github.com/mustvvvics/BaiduNetdisk-RemoveAD (7.26, likely stale).
- Quark 7.x: `chromium-fork.md`. Older Electron-based Quark recipes: `electron-cef-app.md` and https://www.52pojie.cn/thread-2056012-1-1.html for staging path drift.
- Process and data locations for Baidu Netdisk 8.8.8: https://mole.fit/windows/tested-apps/baidu-netdisk
- Thunder/Xunlei: no vetted public recipe found; treat with the "No Profile Fits" checklist in `generic.md` plus this profile.
