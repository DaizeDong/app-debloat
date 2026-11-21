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
| Wake tasks | Scheduled tasks that start the updater on a timer or at logon, some as SYSTEM | Non-elevated `Get-ScheduledTask` hides SYSTEM tasks; use `scripts/elevated_readonly.ps1` |
| Exe swap on launch | A staged `new_<app>.exe` is renamed over `<app>.exe` when the app starts | The fingerprint changes during P1 without any installer running |
| Old version folder cleanup | The previous `<version>\` folder is deleted on the next start | Any action targeting a fixed version path drifts; resolve by name |
| Installer or repair re-run | Full installer from the vendor CDN | Rewrites services, tasks and shortcuts |
| Shell extensions re-registered on update | Context menu CLSIDs under HKLM and HKCU | |

## Gates

- **`Local State` and `Preferences`**: plain JSON, read at start and rewritten on exit. Edit them only while the app is fully closed (background mode keeps it alive after the last window closes; stop it with `scripts/stop_app.ps1`). Use the engine's `json-set` action with a JSON pointer and `onlyWhenNotRunning`, and list the files in `core.preserve`.
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
2. Updater services: Disabled (not Manual), with recovery actions cleared; journal the originals.
3. Wake tasks: disable, matched by action path pattern, re-scanned each run.
4. Updater exes and the staged `new_<app>.exe` name: placeholder or IFEO on vendor-unique names (normal tier), re-asserted by `-Install`.
5. Shell extension block for the context menu CLSIDs, suffixed forms included.

Avoid:
- Blocking or firewalling the main exe (it is the browser and the AI runtime host).
- Editing `.pak` resources or the remote config cache.
- Removing old `<version>\` folders yourself; the vendor cleanup already does it, and an in-use folder breaks the app.

Security-update cost: blocking the updater freezes the Chromium version, so the browser stops receiving security fixes. `plan.md` section 5 must say so and tell the owner how to update by hand.

## Integrity and Ban Risk

- The browser part is accountless; a bundled cloud drive or AI assistant may be account-bound. Ask per app.
- Integrity probe: rename an unused locale `.pak` in the version folder, start, watch for a repair download, restore. The first launch may also swap the exe; follow `pipeline.md` P0 step 7.

## Verification Probes

1. Browser starts, opens a page, keeps bookmarks and the logged-in state after restart.
2. The settings changed by `json-set` read back as written after a full restart.
3. Launch capture: no updater service changes to Running, no `new_<app>.exe` appears, the fingerprint is unchanged after restart and after reboot.
4. No popup window for 10 minutes idle and after a fresh start (enumerate the app's top-level windows; `scripts/shot_windows.ps1`).
5. Context menu entries gone in Explorer after an Explorer restart.

## Public Projects and Recipes

- Chromium preference MACs and tracked preferences: https://chromium.googlesource.com/chromium/src/+/HEAD/services/preferences/tracked/ (design reference).
- Chromium policy list (machine-wide, owner option only): https://chromeenterprise.google/policies/
- Older Quark netdisk recipes (Electron era) are in `electron-cef-app.md`; they do not apply to 7.x.
