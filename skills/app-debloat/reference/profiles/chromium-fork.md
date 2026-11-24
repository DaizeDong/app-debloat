# Profile: Chromium-Fork Browsers

Desktop apps that ship a whole Chromium browser under their own brand and hang other products off it: cloud drive, AI assistant, file viewer, search. Quark 7.x on Windows is the reference case (facts below were observed in one run on one 7.x build; treat them as unverified for other builds). Use this profile instead of `electron-cef-app.md` when the main exe is a browser (`chrome_elf.dll`, `<version>\` folder next to the exe, `Local State` and `Default\Preferences` in the user data dir) rather than an Electron app with `app.asar`. If a cloud drive is one of the products, also read `netdisk-downloader.md` as the secondary profile.

## Architecture and Where the Junk Lives

- **Main exe plus a versioned folder**: `<root>\<app>.exe` and `<root>\<version>\` holding the Chromium DLLs and resources. Children (`--type=renderer`, `gpu-process`, `utility`, `crashpad-handler`) share the main exe name, so nothing may be blocked by that name.
- **User data dir** under `%LOCALAPPDATA%\<vendor>\<app>\User Data` with `Local State` (browser-wide) and `Default\Preferences` plus `Default\Secure Preferences` (per profile).
- **Updater**: one or more SYSTEM services and their exes (Quark 7.x had four updater services), plus scheduled wake tasks. The services look idle in a snapshot (`Manual`, `Stopped`) but the main exe starts them on every launch.
- **Remote config**: a large key-value config fetched at start and cached in the user data dir (Quark: `cms_config`, several hundred keys). It drives popups, promotion tabs, the default home page and feature flags.
- **AI agent runtime in-process**: the AI assistant is a browser feature backed by bundled runtimes (Quark ships `node.exe` and a Python runtime). It runs inside or under the main exe, so there is no separate exe to block without breaking the browser.
- **Shell integration**: context menu handlers, "open with" registrations, a default-browser nag, sometimes a desktop or taskbar shortcut rewrite.
- **Several Uninstall entries** can share one `InstallLocation` (Quark: browser and cloud drive). Resolve the root once and note every entry.

## Launch, Persistence and Re-Install Vectors

| Vector | Form | Notes |
|---|---|---|
| Updater services woken by the main exe | SYSTEM services set to Manual, started by the main exe or by COM | Manual is not off (see `levers.md`, Service Disable). Confirm the wake in a launch capture or the updater's log |
| Wake tasks | Scheduled tasks that start the updater on a timer or at logon, some as SYSTEM | Non-elevated `Get-ScheduledTask` hides SYSTEM tasks; use `scripts/elevated_readonly.ps1`. They live in vendor subfolders such as `\<Vendor>UpdaterSystem\<Vendor>Updater\`, not in the root |
| Older updater service versions | Earlier versions of the updater service left installed next to the current one | One may be protected by a security suite, so its config change is denied per item (`safety.md`, Antivirus). Woken, an inactive version may uninstall itself (Updater Versions below) |
| Exe swap on launch | A staged `new_<app>.exe` is renamed over `<app>.exe` when the app starts | The fingerprint changes during P1 without any installer running |
| Old version folder cleanup | The previous `<version>\` folder is deleted on the next start | Any action targeting a fixed version path drifts; resolve by name |
| Installer or repair re-run | Full installer from the vendor CDN | Rewrites services, tasks and shortcuts |
| Shell extensions re-registered on update | Context menu CLSIDs under HKLM and HKCU | |
| Native messaging host rewritten at every launch | The main exe writes `NativeMessagingHosts\<name>` for Chrome and Edge (HKCU) at each start, pointing at a host manifest JSON in the version folder | A key delete is back at the next launch; placeholder the manifest JSON or the host exe (`levers.md`, Native Messaging Host). Dangling HKLM keys from an older install can stay behind too |
| In-app update downloader | The main process stages a full installer of the next version under the user data dir and offers it with a prompt | Outside the blocked updater services; `levers.md`, In-App Update Downloaders |
| Autostart value rewritten at every start | The Run value comes back each launch | `reg-set` kind `Binary` in the StartupApproved key of the Run value's hive: `StartupApproved\Run`, or HKLM `StartupApproved\Run32` for a `WOW6432Node` Run value (`levers.md`, Config Gate Off) |

## Updater Versions

Chromium-style updaters keep one folder per version (`<updater root>\<version>\updater.exe`) and record which one is active in `prefs.json` in the updater's data folder (`active_version`). An inactive version that is woken uninstalls itself when `active_version` is newer than its own. Observed in one run, as the user and without elevation: starting `<old version>\updater.exe --wake --system` made it start its Manual SYSTEM service through COM, then its log said `This version 1.2.0.10, active version 1.3.0.4` and `Uninstalling version 1.2.0.10`, and it deleted its own wake task, both of its services and its version folder (versions here are synthetic). That cannot be undone without reinstalling the vendor's updater.

- Before fighting an old version's services (a denied service change, a `knownFailure`), read `active_version` from `prefs.json` and record it with each version folder's version in the ledger.
- The vendor's own wake is then a cleanup option for the old version: it removes the services and task the engine could not disable. It is irreversible and changes vendor state outside the plan, so it needs the owner's explicit approval, runs once by hand (not from the manifest), and is recorded as an `RI` ledger entry (writer, trigger, what it removed, before and after listings), with the `knownFailure` actions it makes moot dropped at the next plan update.
- The same applies to the P6 repair or update trigger (`pipeline-apply.md`, P6 step 4): waking the updater's task exe can start this cleanup, so ask first.

## Gates

- **`Local State` and `Preferences`**: plain JSON, read at start and rewritten on exit. Edit them only while the app is fully closed (background mode keeps it alive after the last window closes; stop it with `scripts/stop_app.ps1`). Use the engine's `json-set` action with a JSON pointer and `onlyWhenNotRunning`, and list the files in `core.preserve`.
- **Background mode**: `Local State` `/background_mode/enabled` keeps the browser's processes, tray icons and any local listener alive after the last window closes, so actions with `onlyWhenNotRunning` wait until a full exit or a restart. `json-set` it to `false` while the app is closed. Ship it as an option until a close test (close every window, then list the processes with `launch_monitor.ps1 -Attach`) shows processes stay; then it is observed and may be a default. Say in plan section 3 whether it stays on.
- **Secure Preferences MACs**: Chromium stores HMACs for protected preference keys. Editing a protected value makes the browser reset it or flag the profile. Prefer keys in `Local State` or unprotected `Preferences` keys; never compute or publish the MAC seed.
- **Remote config**: find the key behind a popup by matching its timing, URL or text against the cached config, then confirm with a toggle test. Editing the cache is not durable (it is refetched). See `generic.md`, "Remote Config Popups".
- **Command-line switches and policies**: Chromium enterprise policy keys may be honored by a fork, but they are machine-wide and also read by other Chromium browsers when the vendor reuses Google's policy path. Owner option only, never default.
- **Shell extension toggles**: the vendor's own "show in context menu" switch may disable a handler by appending `-` to its CLSID value. The handler is then already off for that user, and an exact CLSID match will miss it. Match the suffixed form and read the effective state from the merged HKCR view.

## Core: Do Not Touch

- The main exe, the current `<version>\` folder, `chrome_elf.dll` and every Chromium child.
- The user data dir except the specific JSON keys the plan sets; bookmarks, passwords, cookies and extensions are user data.
- The cloud drive's transfer engine if the drive is in the contract (see `netdisk-downloader.md`).
- Bundled runtimes (`node.exe`, Python) inside the install root: they serve in-process features. Do not let their generic names pull unrelated system items (other apps' firewall rules, shortcuts, `.py` associations) into the plan; require the path to be under a resolved root.

## Levers

Use:
1. Vendor settings for default browser nag, autostart, background mode, context menu, side panels, via `json-set` while closed.
2. Updater services: Disabled (not Manual), with recovery actions cleared; journal the originals. If a security suite denies the change for one service, record it as `knownFailure` with the evidence and fall back to its wake tasks and a firewall rule on its exe (`levers.md`, Service Disable); never work around the suite.
3. Wake tasks: disable, matched by action path pattern, re-scanned each run. Give the `task-disable` action a `taskPath` for the vendor folder (matched recursively) plus the name pattern; a bare name pattern searches only the root folder and finds nothing.
4. Updater exes and the staged `new_<app>.exe` name: placeholder or IFEO on vendor-unique names (normal tier), re-asserted by `-Install`.
5. Shell extension block for the context menu CLSIDs, suffixed forms included.
6. Native messaging host: `reg-delete-key` on the host keys with `reapply`, plus a placeholder on the host manifest JSON once one launch shows the app starts cleanly without it.
7. Staged installer folder under the user data dir: `acl-deny-write` with `emptyFirst` (folder in `allowedRoots`).

Avoid:
- Blocking or firewalling the main exe (it is the browser and the AI runtime host).
- Editing `.pak` resources or the remote config cache.
- Removing old `<version>\` folders yourself; the vendor cleanup already does it, and an in-use folder breaks the app.

Security-update cost: blocking the updater freezes the Chromium version, so the browser stops receiving security fixes. `plan.md` section 5 must say so and tell the owner how to update by hand.

## Integrity and Ban Risk

- The browser part is accountless; a bundled cloud drive or AI assistant may be account-bound. Ask per app.
- Integrity probe: rename an unused locale `.pak` in the version folder, start, watch for a repair download, restore. The first launch may also swap the exe; follow `pipeline.md` P0 step 8.

## Verification Probes

1. Browser starts, opens a page, keeps bookmarks and the logged-in state after restart.
2. The settings changed by `json-set` read back as written after a full restart. A "restore pages?" bubble after a forced stop is expected (`pipeline-field-notes.md`).
3. Launch capture: no updater service changes to Running, no `new_<app>.exe` appears, the fingerprint is unchanged after restart and after reboot.
4. No popup window for 10 minutes idle and after a fresh start (enumerate the app's top-level windows; `scripts/shot_windows.ps1`).
5. Context menu entries gone in Explorer after an Explorer restart.

## Public Projects and Recipes

- Chromium preference MACs and tracked preferences: https://chromium.googlesource.com/chromium/src/+/HEAD/services/preferences/tracked/ (design reference).
- Chromium policy list (machine-wide, owner option only): https://chromeenterprise.google/policies/
- Older Quark netdisk recipes (Electron era) are in `electron-cef-app.md`; they do not apply to 7.x.
